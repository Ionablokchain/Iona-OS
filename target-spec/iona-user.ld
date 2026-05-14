/* IONA OS Userspace Linker Script
 * Produces a static ELF64 executable loadable by the IONA OS ELF loader.
 * Entry point: _start
 * Text segment: 0x400000 (standard Linux convention)
 * Stack: allocated by kernel at USER_STACK_TOP - 2MB
 */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS {
    . = 0x400000;

    .text : {
        *(.text._start)
        *(.text*)
    }

    . = ALIGN(0x1000);
    .rodata : { *(.rodata*) }

    . = ALIGN(0x1000);
    .data : {
        *(.data*)
        *(.got*)
        *(.got.plt*)
    }

    . = ALIGN(0x1000);
    .bss : {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        __bss_end = .;
    }

    /* Discard */
    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
