/* IONA OS Kernel Linker Script — x86_64 bare metal
 *
 * Load address: 1MB physical (0x100000) — above BIOS reserved area.
 * Memory layout:
 *   - 0x0000_0000_0010_0000 : Kernel base (text, rodata, data, bss)
 *   - kernel stack: 64 KiB at the end of BSS (aligned to 4K)
 *   - heap: 32 MiB after stack (configurable)
 */

ENTRY(_start)

/* ------------------------------------------------------------------------- */
/* Memory regions (optional, for clarity) */
/* ------------------------------------------------------------------------- */
MEMORY
{
    RAM (rwx) : ORIGIN = 0x0000000000100000, LENGTH = 128M
}

/* ------------------------------------------------------------------------- */
/* Sections */
/* ------------------------------------------------------------------------- */
SECTIONS
{
    /* Kernel load address — 1 MiB physical */
    . = 0x0000000000100000;

    /* ----- Code section (executable, read-only) ----- */
    .text ALIGN(4K) : {
        /* Multiboot2 header must appear first (within first 8KB) */
        KEEP(*(.multiboot2))
        /* Entry point (_start) must be early */
        *(.text._start)
        *(.text*)
    } > RAM

    /* ----- Read-only data ----- */
    .rodata ALIGN(4K) : {
        *(.rodata*)
        *(.eh_frame)            /* Exception unwinding (optional) */
    } > RAM

    /* ----- Read-write initialized data ----- */
    .data ALIGN(4K) : {
        *(.data*)
    } > RAM

    /* ----- Global offset table (for position‑independent code) ----- */
    .got ALIGN(4K) : {
        *(.got*)
    } > RAM

    /* ----- BSS — zero‑initialized at boot ----- */
    .bss ALIGN(4K) : {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        __bss_end = .;
    } > RAM

    /* ----- Kernel stack (64 KiB, aligned to 4K) ----- */
    . = ALIGN(4K);
    __stack_bottom = .;
    . += 65536;                 /* 64 KiB stack */
    __stack_top = .;

    /* ----- Kernel heap (32 MiB initial, can be expanded later) ----- */
    . = ALIGN(4K);
    __heap_start = .;
    __heap_size  = 0x2000000;   /* 32 MiB */
    __heap_end   = __heap_start + __heap_size;

    /* ----- Discard unwanted sections ----- */
    /DISCARD/ : {
        *(.debug*)
        *(.comment)
        *(.note*)
        *(.gcc_except_table*)
        *(.eh_frame_hdr)
    }
}
