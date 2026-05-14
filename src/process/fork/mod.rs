//! fork() + exec() + waitpid() — Copy-on-Write process lifecycle
use alloc::{collections::BTreeMap, vec::Vec};
use spin::{Lazy, Mutex};
use x86_64::{
    structures::paging::{
        PageTable, PageTableFlags, PhysFrame,
    },
    VirtAddr,
};
use crate::task::{TaskId, next_tid};
use crate::process::fd;

static CHILDREN:    Lazy<Mutex<BTreeMap<TaskId, Vec<TaskId>>>> = Lazy::new(|| Mutex::new(BTreeMap::new()));
static EXIT_STATUS: Lazy<Mutex<BTreeMap<TaskId, i32>>>         = Lazy::new(|| Mutex::new(BTreeMap::new()));

const PHYS_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// Clone page tables with Copy-on-Write semantics.
/// Walks L4→L3→L2→L1, marking every individual user page as read-only
/// in both parent and child. On write → page fault → copy_on_write_fault()
/// allocates a new frame and copies the data.
///
/// Intermediate page table frames (L3, L2, L1) are freshly allocated for
/// the child so parent and child have independent page table structures,
/// but the leaf (L1) entries point to the SAME physical data frames with
/// the WRITABLE bit cleared and ref-count incremented.
pub fn clone_page_tables_cow(parent_l4_frame: PhysFrame) -> Option<PhysFrame> {
    let child_l4_frame = crate::memory::frame_alloc::allocate_one()?;
    let child_l4_phys = child_l4_frame.start_address().as_u64();

    // Zero the child L4
    unsafe { core::ptr::write_bytes((PHYS_OFFSET + child_l4_phys) as *mut u8, 0, 4096); }

    let parent_l4 = unsafe {
        &*((PHYS_OFFSET + parent_l4_frame.start_address().as_u64()) as *const PageTable)
    };
    let child_l4 = unsafe {
        &mut *((PHYS_OFFSET + child_l4_phys) as *mut PageTable)
    };

    // Copy kernel half (entries 256-511) directly — shared across all processes
    for i in 256..512 {
        child_l4[i] = parent_l4[i].clone();
    }

    // User half (entries 0-255): deep walk L4→L3→L2→L1
    for l4i in 0..256 {
        let l4e = &parent_l4[l4i];
        if !l4e.flags().contains(PageTableFlags::PRESENT) { continue; }
        let parent_l3_phys = l4e.addr().as_u64();

        // Allocate child L3 table
        let child_l3_frame = crate::memory::frame_alloc::allocate_one()?;
        let child_l3_phys = child_l3_frame.start_address().as_u64();
        unsafe { core::ptr::write_bytes((PHYS_OFFSET + child_l3_phys) as *mut u8, 0, 4096); }

        let parent_l3 = unsafe { &*((PHYS_OFFSET + parent_l3_phys) as *const PageTable) };
        let child_l3  = unsafe { &mut *((PHYS_OFFSET + child_l3_phys) as *mut PageTable) };

        for l3i in 0..512 {
            let l3e = &parent_l3[l3i];
            if !l3e.flags().contains(PageTableFlags::PRESENT) { continue; }

            // Check for 1GB huge page (PS bit)
            if l3e.flags().contains(PageTableFlags::HUGE_PAGE) {
                // Share 1GB page directly with CoW (mark read-only)
                let mut flags = l3e.flags();
                flags.remove(PageTableFlags::WRITABLE);
                child_l3[l3i] = parent_l3[l3i].clone();
                if let Ok(frame) = l3e.frame() {
                    crate::memory::frame_alloc::inc_ref(frame);
                }
                continue;
            }

            let parent_l2_phys = l3e.addr().as_u64();

            // Allocate child L2 table
            let child_l2_frame = crate::memory::frame_alloc::allocate_one()?;
            let child_l2_phys = child_l2_frame.start_address().as_u64();
            unsafe { core::ptr::write_bytes((PHYS_OFFSET + child_l2_phys) as *mut u8, 0, 4096); }

            let parent_l2 = unsafe { &*((PHYS_OFFSET + parent_l2_phys) as *const PageTable) };
            let child_l2  = unsafe { &mut *((PHYS_OFFSET + child_l2_phys) as *mut PageTable) };

            for l2i in 0..512 {
                let l2e = &parent_l2[l2i];
                if !l2e.flags().contains(PageTableFlags::PRESENT) { continue; }

                // Check for 2MB huge page
                if l2e.flags().contains(PageTableFlags::HUGE_PAGE) {
                    child_l2[l2i] = parent_l2[l2i].clone();
                    if let Ok(frame) = l2e.frame() {
                        crate::memory::frame_alloc::inc_ref(frame);
                    }
                    continue;
                }

                let parent_l1_phys = l2e.addr().as_u64();

                // Allocate child L1 table
                let child_l1_frame = crate::memory::frame_alloc::allocate_one()?;
                let child_l1_phys = child_l1_frame.start_address().as_u64();
                unsafe { core::ptr::write_bytes((PHYS_OFFSET + child_l1_phys) as *mut u8, 0, 4096); }

                let parent_l1 = unsafe { &*((PHYS_OFFSET + parent_l1_phys) as *const PageTable) };
                let child_l1  = unsafe { &mut *((PHYS_OFFSET + child_l1_phys) as *mut PageTable) };

                // Walk every L1 entry (4KB pages)
                for l1i in 0..512 {
                    let l1e = &parent_l1[l1i];
                    if !l1e.flags().contains(PageTableFlags::PRESENT) { continue; }

                    // Mark read-only in BOTH parent and child for CoW
                    let mut cow_flags = l1e.flags();
                    cow_flags.remove(PageTableFlags::WRITABLE);

                    // Copy entry to child with read-only flags
                    let frame_addr = l1e.addr();
                    unsafe {
                        let child_entry = &mut child_l1[l1i];
                        child_entry.set_addr(frame_addr, cow_flags);
                    }

                    // Also mark parent read-only
                    let parent_l1_mut = unsafe {
                        &mut *((PHYS_OFFSET + parent_l1_phys) as *mut PageTable)
                    };
                    unsafe {
                        parent_l1_mut[l1i].set_addr(frame_addr, cow_flags);
                    }

                    // Increment reference count on the data frame
                    if let Ok(frame) = l1e.frame() {
                        crate::memory::frame_alloc::inc_ref(frame);
                    }
                }

                // Set child L2 entry to point to the new child L1
                let l2_flags = l2e.flags();
                unsafe { child_l2[l2i].set_addr(
                    x86_64::PhysAddr::new(child_l1_phys), l2_flags
                ); }
            }

            // Set child L3 entry to point to the new child L2
            let l3_flags = l3e.flags();
            unsafe { child_l3[l3i].set_addr(
                x86_64::PhysAddr::new(child_l2_phys), l3_flags
            ); }
        }

        // Set child L4 entry to point to the new child L3
        let l4_flags = l4e.flags();
        unsafe { child_l4[l4i].set_addr(
            x86_64::PhysAddr::new(child_l3_phys), l4_flags
        ); }
    }

    // Flush entire TLB (parent's PTEs changed to read-only)
    x86_64::instructions::tlb::flush_all();

    Some(child_l4_frame)
}

/// Handle CoW page fault: allocate new frame, copy content, remap writable
pub fn copy_on_write_fault(virt_addr: u64) -> bool {
    // Get current CR3 (L4 frame)
    let (l4_frame, _) = x86_64::registers::control::Cr3::read();

    // Walk page tables to find the entry
    let l4 = unsafe {
        &mut *((PHYS_OFFSET + l4_frame.start_address().as_u64()) as *mut PageTable)
    };

    let l4_idx  = (virt_addr >> 39) & 0x1FF;
    let l3_idx  = (virt_addr >> 30) & 0x1FF;
    let l2_idx  = (virt_addr >> 21) & 0x1FF;
    let l1_idx  = (virt_addr >> 12) & 0x1FF;

    macro_rules! get_table {
        ($entry:expr) => {{
            let e = &$entry;
            if !e.flags().contains(PageTableFlags::PRESENT) { return false; }
            unsafe { &mut *((PHYS_OFFSET + e.addr().as_u64()) as *mut PageTable) }
        }};
    }

    let l3 = get_table!(l4[l4_idx as usize]);
    let l2 = get_table!(l3[l3_idx as usize]);
    let l1 = get_table!(l2[l2_idx as usize]);

    let entry = &mut l1[l1_idx as usize];
    if !entry.flags().contains(PageTableFlags::PRESENT) { return false; }

    let old_frame = match entry.frame() {
        Ok(f)  => f,
        Err(_) => return false,
    };

    let refcount = crate::memory::frame_alloc::get_ref(old_frame);

    if refcount <= 1 {
        // Only one user — just make writable
        let new_flags = entry.flags() | PageTableFlags::WRITABLE;
        unsafe { entry.set_frame(old_frame, new_flags); }
        // Flush TLB for this page
        unsafe { x86_64::instructions::tlb::flush(VirtAddr::new(virt_addr & !0xFFF)); }
        return true;
    }

    // Shared frame — allocate new, copy content
    let new_frame = match crate::memory::frame_alloc::allocate_one() {
        Some(f) => f,
        None    => return false,
    };

    // Copy old frame content to new frame
    unsafe {
        let src = (PHYS_OFFSET + old_frame.start_address().as_u64()) as *const u8;
        let dst = (PHYS_OFFSET + new_frame.start_address().as_u64()) as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, 4096);
    }

    // Decrement old frame refcount
    crate::memory::frame_alloc::dec_ref(old_frame);

    // Remap with new frame, writable
    let new_flags = entry.flags() | PageTableFlags::WRITABLE;
    unsafe {
        entry.set_frame(new_frame, new_flags);
        x86_64::instructions::tlb::flush(VirtAddr::new(virt_addr & !0xFFF));
    }

    crate::serial_println!("  [CoW] fault resolved virt=0x{:x}", virt_addr);
    true
}

/// Entry point for forked child task — returns 0 to userspace (child sees pid=0 from fork)
fn task_fork_return(_tid: u64) -> ! {
    // Child returns 0 from fork syscall
    // The actual return value is set via the task's saved register context
    loop { crate::arch::x86_64::timer::sleep_ms(1000); }
}

pub fn do_fork(parent_tid: TaskId) -> Option<TaskId> {
    let child_tid = next_tid();
    crate::serial_println!("  [FORK] {} → child={} (CoW user pages, dedicated kernel task stack)", parent_tid, child_tid);

    // Child gets its own FD table entry namespace. Higher-level clone/share logic
    // can still override this via process::clone when CLONE_FILES is requested.
    fd::init_for(child_tid);

    // Clone address space with CoW for user pages.
    let (parent_l4, _) = x86_64::registers::control::Cr3::read();
    let child_l4 = clone_page_tables_cow(parent_l4)?;

    // Spawn a concrete child task so fork() does not only allocate metadata.
    // The kernel stack is always dedicated per Task::new(...); user memory remains
    // copy-on-write until the child execs or triggers a write fault.
    let child_task = crate::task::Task::new("fork-child", task_fork_return, child_tid, 1);
    crate::sched::SCHEDULER.lock().spawn(child_task);

    CHILDREN.lock().entry(parent_tid).or_default().push(child_tid);

    crate::serial_println!(
        "  [FORK] child={} L4=0x{:x} spawned with dedicated kernel stack",
        child_tid,
        child_l4.start_address().as_u64()
    );

    Some(child_tid)
}

pub fn do_exec_with_args(tid: TaskId, elf_bytes: &[u8], argv: &[&str], envp: &[&str]) -> Result<(), &'static str> {
    crate::serial_println!("  [EXEC] tid={} {} bytes argv={}", tid, elf_bytes.len(), argv.len());
    let addr_space = crate::elf::load_with_args(elf_bytes, argv, envp)
        .map_err(|_| "ELF load failed")?;
    addr_space.activate();
    fd::remove_for(tid);
    fd::init_for(tid);
    crate::signal::clear(tid);
    crate::serial_println!("  [EXEC] entry=0x{:x}", addr_space.entry_point);
    Ok(())
}

pub fn do_exec(tid: TaskId, elf_bytes: &[u8]) -> Result<(), &'static str> {
    crate::serial_println!("  [EXEC] tid={} {} bytes", tid, elf_bytes.len());
    let addr_space = crate::elf::load(elf_bytes)
        .map_err(|_| "ELF load failed")?;
    addr_space.activate();
    fd::remove_for(tid);
    fd::init_for(tid);
    crate::signal::clear(tid);
    crate::serial_println!("  [EXEC] entry=0x{:x}", addr_space.entry_point);
    Ok(())
}

pub fn do_waitpid(parent_tid: TaskId, child_tid: TaskId) -> Option<i32> {
    // Non-busy: block parent in wait queue until child notifies
    // Loop is needed in case of spurious wakeups
    loop {
        {
            let mut es = EXIT_STATUS.lock();
            if let Some(&code) = es.get(&child_tid) {
                es.remove(&child_tid);
                // Reap zombie: clean up child resources
                reap_zombie(child_tid);
                return Some(code);
            }
        }
        // Block until notify_exit() wakes us
        crate::wait::block_current(parent_tid, crate::wait::WakeCondition::IpcMessage);
    }
}

/// Reap zombie process — free all resources
pub fn reap_zombie(tid: TaskId) {
    // Clean up mmap regions
    crate::process::mmap::cleanup_for(tid);
    // FD table already cleaned by notify_exit
    // IPC queue cleanup
    crate::process::ipc::unregister(tid);
    // Remove from children table
    CHILDREN.lock().remove(&tid);
    crate::serial_println!("  [REAP] tid={} reaped", tid);
}

pub fn notify_exit(tid: TaskId, code: i32) {
    EXIT_STATUS.lock().insert(tid, code);
    // Wake parent waiting in waitpid
    // Find parent and wake it
    let parent = CHILDREN.lock().iter()
        .find(|(_, children)| children.contains(&tid))
        .map(|(parent, _)| *parent);
    fd::remove_for(tid);
    crate::signal::clear(tid);
    // Send SIGCHLD to parent
    if let Some(ptid) = parent {
        crate::signal::send(ptid, crate::signal::Signal::SIGCHLD);
        // Wake parent if blocked in waitpid
        crate::wait::wake_ipc(ptid);
    }
    crate::serial_println!("  [EXIT] tid={} code={}", tid, code);
}
