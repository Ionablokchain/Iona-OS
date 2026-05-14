//! IONA WASM Hello — modul demo pentru kernel userspace
//! Compilare: cargo build --target wasm32-unknown-unknown --release

extern "C" {
    fn log_write(msg_ptr: i32, msg_len: i32);
    fn emit_event(topic_ptr: i32, topic_len: i32, data_ptr: i32, data_len: i32);
}

#[no_mangle]
pub extern "C" fn run() -> i32 {
    let msg   = b"Hello from IONA OS Kernel userspace WASM!";
    let topic = b"HelloEvent";
    let data  = b"kernel-wasm-demo";
    unsafe {
        log_write(msg.as_ptr() as i32, msg.len() as i32);
        emit_event(
            topic.as_ptr() as i32, topic.len() as i32,
            data.as_ptr() as i32, data.len() as i32,
        );
    }
    0
}

#[no_mangle]
pub extern "C" fn health() -> i32 { 0 }
