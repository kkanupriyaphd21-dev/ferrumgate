#include "../include/ferrumgate.h"
#include <stdint.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

/* Seccomp-BPF syscall allowlist for the ferrumgate tunnel process */

#define ALLOW_SYSCALL(nr) \
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)), \
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)

#define KILL_PROCESS \
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS)

int fg_seccomp_install(void) {
    struct sock_filter filter[] = {
        /* validate arch */
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
                 (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL),

        /* load syscall number */
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
                 (offsetof(struct seccomp_data, nr))),

        /* allowed syscalls */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_read,        0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_write,       0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_sendto,      0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_recvfrom,    0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_epoll_wait,  0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_epoll_ctl,   0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_clock_gettime,0,1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_nanosleep,   0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_futex,       0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_exit_group,  0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_close,       0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_mmap,        0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_munmap,      0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_brk,         0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL),
    };

    struct sock_fprog prog = {
        .len    = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return FG_ERR_IO;
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0)
        return FG_ERR_IO;
    return FG_OK;
}
