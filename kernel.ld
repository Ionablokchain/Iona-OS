/* IONA OS Kernel Linker Script — x86_64 bare metal */
/* Load address: 1MB physical (0x100000) — above BIOS reserved area */

ENTRY(_start)

SECTIONS {
    . = 0x0000000000100000;

    /* Kernel code — executable, read-only */
    .text ALIGN(4K) : {
        KEEP(*(.multiboot2))   /* multiboot2 header must be first 8KB */
        *(.text._start)
        *(.text*)
    }

    /* Read-only data */
    .rodata ALIGN(4K) : {
        *(.rodata*)
        *(.eh_frame)
    }

    /* Read-write initialized data */
    .data ALIGN(4K) : {
        *(.data*)
    }

    /* Global offset table (position-independent references) */
    .got ALIGN(4K) : {
        *(.got*)
    }

    /* BSS — zero-initialized at boot */
    .bss ALIGN(4K) : {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        __bss_end = .;
    }

    /* Kernel stack — 64KB, 16-byte aligned */
    . = ALIGN(4K);
    __stack_bottom = .;
    . += 65536;              /* 64KB */
    __stack_top = .;

    /* Kernel heap start — heap allocator uses this as base */
    . = ALIGN(4K);
    __heap_start = .;
    __heap_size  = 0x2000000;   /* 32MB initial heap */
    __heap_end   = __heap_start + __heap_size;

    /* Discard debug/unwinding sections — no_std bare metal */
    /DISCARD/ : {
        *(.debug*)
        *(.comment)
        *(.note*)
        *(.gcc_except_table*)
    }
}
