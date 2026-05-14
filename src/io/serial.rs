//! UART Serial output — COM1 (0x3F8)
//!
//! Primul output disponibil în kernel — funcționează înainte de framebuffer,
//! înainte de interrupt, înainte de memory management.
//! QEMU redirectează COM1 la stdout cu `-serial stdio`.

use spin::Mutex;
use x86_64::instructions::port::Port;

pub struct Serial {
    data:          Port<u8>,
    interrupt_en:  Port<u8>,
    fifo_ctrl:     Port<u8>,
    line_ctrl:     Port<u8>,
    modem_ctrl:    Port<u8>,
    line_status:   Port<u8>,
}

impl Serial {
    const unsafe fn new(base: u16) -> Self {
        Self {
            data:         Port::new(base),
            interrupt_en: Port::new(base + 1),
            fifo_ctrl:    Port::new(base + 2),
            line_ctrl:    Port::new(base + 3),
            modem_ctrl:   Port::new(base + 4),
            line_status:  Port::new(base + 5),
        }
    }

    fn init(&mut self) {
        unsafe {
            self.interrupt_en.write(0x00); // dezactivăm întreruperile serial
            self.line_ctrl.write(0x80);    // DLAB=1 pentru setare baud rate
            self.data.write(0x03);         // baud rate = 38400 (divisor low)
            self.interrupt_en.write(0x00); // divisor high
            self.line_ctrl.write(0x03);    // 8 biți, no parity, 1 stop bit
            self.fifo_ctrl.write(0xC7);    // enable FIFO, clear, 14-byte threshold
            self.modem_ctrl.write(0x0B);   // IRQ enable, RTS/DSR
        }
    }

    fn line_ready(&mut self) -> bool {
        unsafe { self.line_status.read() & 0x20 != 0 }
    }

    fn write_byte(&mut self, byte: u8) {
        // Poll până e gata transmitter
        while !self.line_ready() {
            core::hint::spin_loop();
        }
        unsafe { self.data.write(byte); }
    }

    pub fn write_str(&mut self, s: &str) {
        for byte in s.bytes() {
            match byte {
                b'\n' => {
                    self.write_byte(b'\r');
                    self.write_byte(b'\n');
                }
                _ => self.write_byte(byte),
            }
        }
    }
}

impl core::fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.write_str(s);
        Ok(())
    }
}

// ── Global instance ──────────────────────────────────────────────────────────
static SERIAL: Mutex<Serial> = Mutex::new(unsafe { Serial::new(0x3F8) });

pub fn init() {
    SERIAL.lock().init();
}

/// Scrie un caracter pe serial
pub fn write_byte(byte: u8) {
    SERIAL.lock().write_byte(byte);
}

/// Macro-uri publice — serial_print! / serial_println!
#[doc(hidden)]
pub fn _print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    SERIAL.lock().write_fmt(args).unwrap_or(());
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => ($crate::io::serial::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! serial_println {
    ()           => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => ($crate::serial_print!("{}\n", format_args!($($arg)*)));
}

/// Non-blocking read from COM1 — returns None if no data available
#[inline]
pub fn try_read_byte() -> Option<u8> {
    unsafe {
        use x86_64::instructions::port::Port;
        // Check LSR bit 0 (Data Ready)
        let mut lsr: Port<u8> = Port::new(0x3FD);
        if lsr.read() & 1 != 0 {
            let mut data: Port<u8> = Port::new(0x3F8);
            Some(data.read())
        } else {
            None
        }
    }
}
