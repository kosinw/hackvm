OUTPUT_ARCH( "riscv" );
ENTRY( _main );

SECTIONS
{
    /*
     * ensure that _main is at 0
     */
    . = 0x80000000;

    .text : {
        *(.text.entry)
        *(.text .text.*)
    }

    .rodata : {
        /* . = ALIGN(16); */
        *(.srodata .srodata.*) /* do not need to distinguish this from .rodata */
        /* . = ALIGN(16); */
        *(.rodata .rodata.*)
    }

    .crypto : {
        . = ALIGN(32);
        *(.data.crypto)
    }

    .data : {
        /* . = ALIGN(16); */
        *(.sdata .sdata.*) /* do not need to distinguish this from .data */
        /* . = ALIGN(16); */
        *(.data .data.*)
    }

    .bss : {
        /* . = ALIGN(16); */
        *(.sbss .sbss.*) /* do not need to distinguish this from .bss */
        /* . = ALIGN(16); */
        *(.bss .bss.*)
    }
}