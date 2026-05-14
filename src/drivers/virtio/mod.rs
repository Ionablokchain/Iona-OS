//! Virtio driver — interfața comună pentru toate device-urile virtio
//!
//! Virtio este standardul pentru device-uri virtuale în QEMU/KVM.
//! Avantaje: simplu, performant, bine documentat (spec virtio 1.1+)
//!
//! Subsisteme:
//!   virtio-blk  → storage (citit/scris sectoare)
//!   virtio-net  → rețea (frame-uri Ethernet)
//!
//! VirtQueue: structura de date shared între driver și hypervisor.
//!   - Descriptor Table: array de descriptori (buffer ptr + len + flags + next)
//!   - Available Ring:   driver → device (ce buffere sunt gata)
//!   - Used Ring:        device → driver (ce buffere au fost procesate)

use x86_64::instructions::port::Port;
use crate::pci::PciDevice;

pub mod blk;
pub mod net;

/// Dimensiunea unui VirtQueue (trebuie să fie putere a lui 2)
pub const QUEUE_SIZE: usize = 64;

/// Descriptor virtio — un buffer din queue
#[repr(C)]
pub struct VirtqDesc {
    pub addr:  u64,    // adresa fizică a buffer-ului
    pub len:   u32,    // lungimea
    pub flags: u16,    // NEXT=1, WRITE=2, INDIRECT=4
    pub next:  u16,    // index următor dacă NEXT set
}

/// Available ring — driver → device
#[repr(C)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx:   u16,
    pub ring:  [u16; QUEUE_SIZE],
    pub used_event: u16,
}

/// Used ring element
#[repr(C)]
pub struct VirtqUsedElem {
    pub id:  u32,
    pub len: u32,
}

/// Used ring — device → driver
#[repr(C)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx:   u16,
    pub ring:  [VirtqUsedElem; QUEUE_SIZE],
    pub avail_event: u16,
}

/// VirtQueue complet — descriptor table + available + used
pub struct VirtQueue {
    pub desc:  *mut VirtqDesc,
    pub avail: *mut VirtqAvail,
    pub used:  *mut VirtqUsed,
    pub queue_index: u16,
    pub io_base:     u16,   // PCI I/O BAR base
    pub next_desc:   usize,
    pub last_used:   u16,
}

impl VirtQueue {
    /// Inițializează un VirtQueue pentru un device virtio PCI (legacy interface)
    pub fn new(io_base: u16, queue_index: u16) -> Option<Self> {
        unsafe {
            // Selectăm queue-ul
            Port::<u16>::new(io_base + 14).write(queue_index);

            // Citim size-ul maxim suportat de device
            let max_size = Port::<u16>::new(io_base + 12).read();
            if max_size == 0 { return None; }
            let size = (max_size as usize).min(QUEUE_SIZE) as u16;

            // Calculăm dimensiunea totală a queue-ului în memorie
            // Layout: desc[] | avail | padding | used
            let desc_size  = size as usize * core::mem::size_of::<VirtqDesc>();
            let avail_size = core::mem::size_of::<u16>() * 3 + size as usize * 2;
            let total_size = desc_size + avail_size + 4096; // + pagină pentru used

            // Alocăm memorie contiguă (pentru simplitate, din heap cu aliniere la 4096)
            let layout = alloc::alloc::Layout::from_size_align(total_size, 4096).ok()?;
            let ptr = alloc::alloc::alloc_zeroed(layout);
            if ptr.is_null() { return None; }

            let desc  = ptr as *mut VirtqDesc;
            let avail = ptr.add(desc_size) as *mut VirtqAvail;
            let used  = ptr.add(desc_size + ((avail_size + 4095) & !4095)) as *mut VirtqUsed;

            // Comunicăm adresa fizică queue-ului la device
            // (pe QEMU, virtual = fizic în zone joase de memorie)
            let phys_addr = ptr as u64 / 4096;
            Port::<u16>::new(io_base + 12).write(size);
            Port::<u32>::new(io_base + 8).write(phys_addr as u32);

            Some(VirtQueue {
                desc, avail, used,
                queue_index, io_base,
                next_desc: 0,
                last_used: 0,
            })
        }
    }

    /// Adaugă un descriptor în queue și notifică device-ul
    pub fn send(&mut self, phys_addr: u64, len: u32, flags: u16) -> u16 {
        let idx = self.next_desc % QUEUE_SIZE;
        unsafe {
            (*self.desc.add(idx)).addr  = phys_addr;
            (*self.desc.add(idx)).len   = len;
            (*self.desc.add(idx)).flags = flags;
            (*self.desc.add(idx)).next  = 0;

            let avail_idx = ((*self.avail).idx as usize) % QUEUE_SIZE;
            (*self.avail).ring[avail_idx] = idx as u16;
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            (*self.avail).idx = (*self.avail).idx.wrapping_add(1);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        }
        // Notificăm device-ul (queue kick)
        unsafe { Port::<u16>::new(self.io_base + 16).write(self.queue_index); }
        self.next_desc += 1;
        idx as u16
    }

    /// Așteaptă și returnează indicele descriptorului procesat
    pub fn wait_used(&mut self) -> u16 {
        loop {
            let used_idx = unsafe { (*self.used).idx };
            if used_idx != self.last_used {
                let idx = unsafe {
                    (*self.used).ring[(self.last_used as usize) % QUEUE_SIZE].id as u16
                };
                self.last_used = self.last_used.wrapping_add(1);
                return idx;
            }
            core::hint::spin_loop();
        }
    }
}

/// Inițializează un device virtio PCI (negotiation)
pub fn init_device(dev: &PciDevice) -> Option<u16> {
    let io_base = (dev.bar[0] & !3) as u16;

    unsafe {
        // Reset device
        Port::<u8>::new(io_base + 18).write(0);

        // Acknowledge + Driver
        Port::<u8>::new(io_base + 18).write(3);

        // Feature negotiation (acceptăm toate feature-urile device-ului)
        let _features = Port::<u32>::new(io_base + 0).read();
        Port::<u32>::new(io_base + 4).write(0); // Nu cerem feature-uri speciale

        // Driver OK
        Port::<u8>::new(io_base + 18).write(0xF);
    }

    crate::pci::enable_device(dev.addr.bus, dev.addr.device, dev.addr.function);
    Some(io_base)
}
