/*
 * Linker script for linux_boot @ iBEC loadaddr 0x80000000.
 * Must stay under 0x8000 so zImage can sit at 0x80008000 in the bundle.
 *
 * Verbatim from Project Cascadia's pongo/linux-boot.ld (GPL-2.0 OR MIT) —
 * the load address and size budget are identical for k93.
 */
ENTRY(_start)

SECTIONS
{
	. = 0x80000000;

	.text : {
		KEEP(*(.text.start))
		*(.text .text.*)
		*(.rodata .rodata.*)
		*(.data .data.*)
		*(.bss .bss.*)
		*(COMMON)
		. = ALIGN(4);
	}

	.ARM.attributes 0 : { *(.ARM.attributes) }

	/DISCARD/ : {
		*(.comment)
		*(.note*)
		*(.eh_frame*)
	}
}
