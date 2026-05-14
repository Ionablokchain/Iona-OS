//! Saved CPU context pentru fiecare task
//!
//! La context switch salvăm registrele callee-saved (System V AMD64 ABI):
//! rbx, rbp, r12, r13, r14, r15, rsp
//!
//! rip nu e salvat explicit — e pe stack (adresa de return din switch_to).
//! rax, rcx, rdx, rsi, rdi, r8-r11 sunt caller-saved — nu le salvăm.

/// Starea CPU a unui task — ceea ce salvăm/restaurăm la context switch
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Context {
    /// r15 — callee-saved
    pub r15: u64,
    /// r14 — callee-saved
    pub r14: u64,
    /// r13 — callee-saved
    pub r13: u64,
    /// r12 — callee-saved
    pub r12: u64,
    /// rbp — frame pointer, callee-saved
    pub rbp: u64,
    /// rbx — callee-saved
    pub rbx: u64,
    /// rsp — stack pointer (salvat explicit)
    pub rsp: u64,
}

impl Context {
    /// Context vid — pentru task nou care nu a mai rulat
    /// Compile-time zero context — used for static arrays
    pub const ZERO: Self = Self { r15:0, r14:0, r13:0, r12:0, rbp:0, rbx:0, rsp:0 };

    pub const fn empty() -> Self {
        Self { r15: 0, r14: 0, r13: 0, r12: 0, rbp: 0, rbx: 0, rsp: 0 }
    }

    /// Creează un context inițial pentru un task nou cu stack-ul și entry point-ul date.
    ///
    /// Stack layout la prima rulare:
    ///   rsp → [task_entry_trampoline] ← `ret` din switch_to va sări aici
    ///
    /// task_entry_trampoline apelează task_fn(arg) și la final apelează task_exit().
    pub fn new_task(stack_top: u64, entry: u64, arg: u64) -> Self {
        // Punem pe stack (în ordine inversă push):
        // [task_exit_stub]     ← dacă task_fn returnează (nu ar trebui)
        // [entry]              ← adresa funcției task-ului
        // [task_trampoline]    ← prima instrucțiune executată după switch_to
        //
        // Folosim o trampolină pentru că la primul switch_to,
        // context switch-ul face `ret` care sare la adresa de pe stack.
        // Trampoline setează argumentul în rdi și apelează entry.

        // Scriem stack-ul inițial — rsp trebuie să fie aliniat la 16 bytes
        // conform ABI la momentul `call` (adică rsp % 16 == 8 înainte de call)
        let sp = stack_top as *mut u64;
        unsafe {
            // [rsp-8]  = task_exit (sentinel — dacă task-ul returnează)
            sp.offset(-1).write(task_exit_stub as *const () as u64);
            // [rsp-16] = argumentul task-ului (stocat temporar, luat de trampolină)
            sp.offset(-2).write(arg);
            // [rsp-24] = entry point al task-ului
            sp.offset(-3).write(entry);
            // [rsp-32] = trampolina — prima adresă la care sare `ret` din switch_to
            sp.offset(-4).write(task_entry_trampoline as *const () as u64);
        }

        Self {
            r15: 0, r14: 0, r13: 0, r12: 0, rbp: 0, rbx: 0,
            rsp: stack_top - 4 * 8, // 4 u64 pe stack
        }
    }
}

/// Trampolina de intrare în task.
/// Apelată prin `ret` la primul context switch al unui task.
/// Ia entry și arg de pe stack, apelează entry(arg).
#[naked]
unsafe extern "C" fn task_entry_trampoline() {
    // La intrare stack-ul arată:
    //   [rsp+0] = entry (adresa funcției task)
    //   [rsp+8] = arg
    //   [rsp+16] = task_exit_stub
    core::arch::naked_asm!(
        "pop rdi",          // entry → rdi (caller va folosi ca fn pointer)
        "pop rsi",          // arg → rsi (primul argument al funcției)
        "xchg rdi, rsi",    // rdi = arg (primul arg), rsi = entry (fn ptr)
        "sti",              // enable interrupts — new tasks are switched to from
                            // timer ISR context where IF=0; without this, the task
                            // runs with interrupts disabled forever
        "call rsi",         // apelăm entry(arg)
        // dacă entry returnează:
        "call {exit}",
        exit = sym task_exit_stub,
    );
}

/// Apelat dacă un task returnează (nu ar trebui în mod normal)
pub fn task_exit_stub() -> ! {
    crate::serial_println!("[SCHED] task exited unexpectedly — halting");
    loop { x86_64::instructions::hlt(); }
}
