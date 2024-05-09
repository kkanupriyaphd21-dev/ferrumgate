#include "../include/ferrumgate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

/* cgroup v2 resource limiter for ferrumgate tunnel processes */

#define CGPATH "/sys/fs/cgroup/ferrumgate"

static int cg_write(const char* path, const char* val) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return FG_ERR_IO;
    ssize_t n = write(fd, val, strlen(val));
    close(fd);
    return (n > 0) ? FG_OK : FG_ERR_IO;
}

int fg_cgroup_init(void) {
    /* create cgroup directory */
    if (mkdir(CGPATH, 0755) < 0 && errno != EEXIST) return FG_ERR_IO;
    return FG_OK;
}

int fg_cgroup_set_memory_limit(uint64_t bytes) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%llu\n", (unsigned long long)bytes);
    return cg_write(CGPATH "/memory.max", buf);
}

int fg_cgroup_set_cpu_weight(uint32_t weight) {
    /* weight 1-10000, default 100 */
    char buf[16];
    snprintf(buf, sizeof(buf), "%u\n", weight);
    return cg_write(CGPATH "/cpu.weight", buf);
}

int fg_cgroup_set_cpu_max(uint64_t quota_us, uint64_t period_us) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%llu %llu\n",
             (unsigned long long)quota_us,
             (unsigned long long)period_us);
    return cg_write(CGPATH "/cpu.max", buf);
}

int fg_cgroup_add_pid(pid_t pid) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%d\n", (int)pid);
    return cg_write(CGPATH "/cgroup.procs", buf);
}

int fg_cgroup_read_memory_current(uint64_t* out) {
    if (!out) return FG_ERR_INVAL;
    FILE* f = fopen(CGPATH "/memory.current", "r");
    if (!f) return FG_ERR_IO;
    fscanf(f, "%llu", (unsigned long long*)out);
    fclose(f);
    return FG_OK;
}

void fg_cgroup_destroy(void) {
    rmdir(CGPATH);
}
