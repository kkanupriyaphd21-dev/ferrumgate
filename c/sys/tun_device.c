#include "../include/ferrumgate.h"
#include <linux/if_tun.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

#define TUN_DEV_PATH "/dev/net/tun"

typedef struct {
    int  fd;
    char name[IFNAMSIZ];
    bool persistent;
} FgTunDevice;

static FgTunDevice* tun_alloc(const char* name, bool tap) {
    int fd = open(TUN_DEV_PATH, O_RDWR);
    if (fd < 0) {
        perror("open /dev/net/tun");
        return NULL;
    }

    struct ifreq ifr = {0};
    ifr.ifr_flags = tap ? IFF_TAP : IFF_TUN;
    ifr.ifr_flags |= IFF_NO_PI; /* no packet info header */

    if (name && *name) {
        strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    }

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("ioctl TUNSETIFF");
        close(fd);
        return NULL;
    }

    FgTunDevice* dev = calloc(1, sizeof(FgTunDevice));
    if (!dev) { close(fd); return NULL; }

    dev->fd = fd;
    strncpy(dev->name, ifr.ifr_name, IFNAMSIZ - 1);
    dev->persistent = false;
    return dev;
}

int fg_tun_open(const char* name, int* fd_out, char* actual_name) {
    if (!fd_out) return FG_ERR_INVAL;

    FgTunDevice* dev = tun_alloc(name, false);
    if (!dev) return FG_ERR_IO;

    *fd_out = dev->fd;
    if (actual_name) strncpy(actual_name, dev->name, IFNAMSIZ - 1);

    free(dev);
    return FG_OK;
}

ssize_t fg_tun_read(int fd, uint8_t* buf, size_t len) {
    ssize_t n;
    do { n = read(fd, buf, len); } while (n < 0 && errno == EINTR);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return FG_ERR_IO;
    }
    return n;
}

ssize_t fg_tun_write(int fd, const uint8_t* buf, size_t len) {
    ssize_t n;
    do { n = write(fd, buf, len); } while (n < 0 && errno == EINTR);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return FG_ERR_IO;
    }
    return n;
}

int fg_tun_set_mtu(const char* name, int mtu) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return FG_ERR_IO;

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_mtu = mtu;

    int rc = ioctl(sock, SIOCSIFMTU, &ifr);
    close(sock);
    return rc == 0 ? FG_OK : FG_ERR_IO;
}

int fg_tun_set_up(const char* name) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return FG_ERR_IO;

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        close(sock);
        return FG_ERR_IO;
    }

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    int rc = ioctl(sock, SIOCSIFFLAGS, &ifr);
    close(sock);
    return rc == 0 ? FG_OK : FG_ERR_IO;
}

void fg_tun_close(int fd) {
    if (fd >= 0) close(fd);
}
