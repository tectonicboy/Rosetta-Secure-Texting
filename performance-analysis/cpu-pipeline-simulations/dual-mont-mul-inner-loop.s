.intel_syntax noprefix

# LLVM-MCA-BEGIN DualMontgomeryLoop
loop_start:
mov    r8,QWORD PTR [r10+rax*8]
mov    rdx,QWORD PTR [rsp+0x70]
mulx   rdi,rsi,r8
mov    rdx,QWORD PTR [rbx]
mov    QWORD PTR [rsp+0xa0],rsi
mov    r14,QWORD PTR [rsp+0xa0]
mov    QWORD PTR [rsp+0xa8],rdi
mulx   rdi,rsi,QWORD PTR [r12+rax*8]
mov    rdx,QWORD PTR [rsp+0x68]
add    r14,QWORD PTR [rdx+rax*8]
mov    QWORD PTR [rsp+0xc8],r14
setb   r8b
mov    QWORD PTR [rsp+0x90],rsi
mov    rsi,QWORD PTR [rsp+0x90]
add    rsi,QWORD PTR [rdx+0x190]
mov    QWORD PTR [rsp+0x98],rdi
mov    QWORD PTR [rsp+0xd0],rsi
setb   r14b
add    rsi,QWORD PTR [rsp+0xc8]
mov    QWORD PTR [rdx+0x188],rsi
setb   r15b
movzx  esi,r8b
mov    rdi,QWORD PTR [rsp+0x98]
add    rsi,QWORD PTR [rsp+0xa8]
add    r14b,0xff
adc    rsi,rdi
mov    QWORD PTR [rsp+0xd8],rsi
setb   dil
add    r15b,0xff
adc    rsi,QWORD PTR [rdx+0x198]
mov    QWORD PTR [rdx+0x190],rsi
movzx  edi,dil
mov    r8,QWORD PTR [r10+rax*8]
mov    rsi,QWORD PTR [rdx+0x188]
adc    rdi,0x0
mov    QWORD PTR [rdx+0x198],rdi
mov    QWORD PTR [rdx+rax*8-0x8],rsi
mov    rdx,QWORD PTR [rsp+0x80]
mulx   rdi,rsi,r8
mov    rdx,QWORD PTR [r11]
mov    QWORD PTR [rsp+0xa0],rsi
mov    r8,QWORD PTR [rsp+0xa0]
mov    QWORD PTR [rsp+0xa8],rdi
mulx   rdi,rsi,QWORD PTR [r13+rax*8+0x0]
add    r8,QWORD PTR [rcx+rax*8]
mov    QWORD PTR [rsp+0xc8],r8
setb   r8b
mov    QWORD PTR [rsp+0x90],rsi
mov    rsi,QWORD PTR [rsp+0x90]
add    rsi,QWORD PTR [rcx+0x190]
mov    QWORD PTR [rsp+0x98],rdi
mov    QWORD PTR [rsp+0xd0],rsi
setb   r14b
add    rsi,QWORD PTR [rsp+0xc8]
mov    QWORD PTR [rcx+0x188],rsi
setb   r15b
movzx  esi,r8b
mov    rdi,QWORD PTR [rsp+0x98]
add    rsi,QWORD PTR [rsp+0xa8]
add    r14b,0xff
adc    rsi,rdi
mov    QWORD PTR [rsp+0xd8],rsi
setb   dil
add    r15b,0xff
adc    rsi,QWORD PTR [rcx+0x198]
mov    QWORD PTR [rcx+0x190],rsi
movzx  edi,dil
mov    rsi,QWORD PTR [rcx+0x188]
adc    rdi,0x0
mov    QWORD PTR [rcx+0x198],rdi
mov    QWORD PTR [rcx+rax*8-0x8],rsi
add    rax,0x1
cmp    rax,0x30
# LLVM-MCA-END
