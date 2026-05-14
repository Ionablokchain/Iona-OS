//! IONA WASM Counter — storage persistent demo

extern "C" {
    fn storage_get(key_ptr: i32, key_len: i32, val_ptr: i32, val_cap: i32) -> i32;
    fn storage_set(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32);
    fn log_write(msg_ptr: i32, msg_len: i32);
    fn emit_event(topic_ptr: i32, topic_len: i32, data_ptr: i32, data_len: i32);
}

const KEY: &[u8] = b"counter";
static mut IO_BUF: [u8; 64] = [0u8; 64];

fn read_counter() -> u64 {
    let n = unsafe {
        storage_get(KEY.as_ptr() as i32, KEY.len() as i32, IO_BUF.as_mut_ptr() as i32, 8)
    };
    if n == 8 {
        let mut b = [0u8; 8];
        b.copy_from_slice(unsafe { &IO_BUF[..8] });
        u64::from_le_bytes(b)
    } else { 0 }
}

fn write_counter(v: u64) {
    let b = v.to_le_bytes();
    unsafe {
        IO_BUF[..8].copy_from_slice(&b);
        storage_set(KEY.as_ptr() as i32, KEY.len() as i32, IO_BUF.as_ptr() as i32, 8);
    }
}

#[no_mangle]
pub extern "C" fn run() -> i32 {
    let cur  = read_counter();
    let next = cur + 1;
    write_counter(next);

    // Log
    let msg = alloc_format(cur, next);
    unsafe { log_write(msg.as_ptr() as i32, msg.len() as i32); }

    // Emit event
    let topic = b"CounterTick";
    let val   = next.to_le_bytes();
    unsafe {
        emit_event(
            topic.as_ptr() as i32, topic.len() as i32,
            val.as_ptr() as i32, val.len() as i32,
        );
    }
    0
}

// Format fără std (no_std)
fn alloc_format(cur: u64, next: u64) -> [u8; 64] {
    let mut buf = [0u8; 64];
    let msg = b"counter: ";
    buf[..msg.len()].copy_from_slice(msg);
    let mut pos = msg.len();
    pos += write_u64(&mut buf[pos..], cur);
    buf[pos] = b'-'; buf[pos+1] = b'>'; pos += 2;
    pos += write_u64(&mut buf[pos..], next);
    buf
}

fn write_u64(buf: &mut [u8], mut v: u64) -> usize {
    if v == 0 { buf[0] = b'0'; return 1; }
    let mut tmp = [0u8; 20];
    let mut n = 0;
    while v > 0 { tmp[n] = b'0' + (v % 10) as u8; v /= 10; n += 1; }
    for i in 0..n { buf[i] = tmp[n-1-i]; }
    n
}

#[no_mangle]
pub extern "C" fn health() -> i32 { 0 }
#[no_mangle]
pub extern "C" fn get_count() -> i32 { read_counter() as i32 }
#[no_mangle]
pub extern "C" fn reset() -> i32 { write_counter(0); 0 }
