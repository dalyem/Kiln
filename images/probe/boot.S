.code16
.section .text
.global _start

_start:
    cli
    cld
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw $0x7c00, %sp

    # Initialise COM1 for 115200 8N1 and enable its FIFO.
    movw $0x3fb, %dx
    movb $0x80, %al
    outb %al, %dx
    movw $0x3f8, %dx
    movb $0x01, %al
    outb %al, %dx
    movw $0x3f9, %dx
    xorb %al, %al
    outb %al, %dx
    movw $0x3fb, %dx
    movb $0x03, %al
    outb %al, %dx
    # DLAB is clear now: disable UART interrupts for this polling driver.
    movw $0x3f9, %dx
    xorb %al, %al
    outb %al, %dx
    movw $0x3fa, %dx
    movb $0xc7, %al
    outb %al, %dx

    sti

write_message:
    movw $ready_message, %si

write_next:
    lodsb
    testb %al, %al
    jz wait_one_second
    pushw %ax

wait_for_transmitter:
    movw $0x3fd, %dx
    inb %dx, %al
    testb $0x20, %al
    jz wait_for_transmitter

    popw %ax
    movw $0x3f8, %dx
    outb %al, %dx
    jmp write_next

wait_one_second:
    # BIOS advances this counter about 18 times per second.
    movw 0x046c, %bx
    addw $18, %bx

wait_for_tick:
    hlt
    movw 0x046c, %ax
    subw %bx, %ax
    js wait_for_tick
    jmp write_message

ready_message:
    .asciz "KILN-PROBE-READY\r\n"

.org 510
.word 0xaa55
