.intel_syntax noprefix

# LLVM-MCA-BEGIN MontgomeryLoop
loop_start:
    mov    rsi, QWORD PTR [r10+rdx*8]
    mov    rdi, rdx
    mov    rdx, rsi
    mulx   rsi, rbx, r12
    mov    rdx, QWORD PTR [r9]
    mulx   rcx, rdx, QWORD PTR [r11+rdi*8]
    mov    QWORD PTR [rsp+0x48], rsi
    mov    QWORD PTR [rsp+0x40], rbx
    mov    rsi, QWORD PTR [rsp+0x40]
    add    rsi, QWORD PTR [rax+rdi*8]
    mov    QWORD PTR [rsp+0x30], rdx
    mov    r15, rsi
    mov    QWORD PTR [rsp+0x38], rcx
    setb   sil
    mov    rcx, QWORD PTR [rsp+0x30]
    mov    QWORD PTR [rsp+0x58], r15
    add    rcx, QWORD PTR [rax+0x190]
    movzx  esi, sil
    mov    QWORD PTR [rsp+0x60], rcx
    setb   r8b
    add    rcx, r15
    mov    QWORD PTR [rax+0x188], rcx
    mov    rcx, QWORD PTR [rsp+0x38]
    setb   r15b
    add    rsi, QWORD PTR [rsp+0x48]
    add    r8b, 0xff
    adc    rcx, rsi
    mov    QWORD PTR [rsp+0x68], rcx
    setb   sil
    add    r15b, 0xff
    adc    rcx, QWORD PTR [rax+0x198]
    mov    QWORD PTR [rax+0x190], rcx
    movzx  esi, sil
    mov    rcx, QWORD PTR [rax+0x188]
    adc    rsi, 0x0
    mov    QWORD PTR [rax+0x198], rsi
    mov    QWORD PTR [rax+rdi*8-0x8], rcx
    add    rdi, 0x1
    cmp    rdi, 0x30
    mov    rdx, rdi
# LLVM-MCA-END
