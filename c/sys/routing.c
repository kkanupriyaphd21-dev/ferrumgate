#include "../include/sys.h"
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>

#define NLMSG_BUF 4096

static int nl_socket_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return FG_ERR_IO;

    struct sockaddr_nl sa = {0};
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(fd);
        return FG_ERR_IO;
    }
    return fd;
}

static int nl_send_recv(int fd, struct nlmsghdr* req, size_t req_len) {
    struct iovec iov  = { req, req_len };
    struct msghdr msg = {0};
    msg.msg_iov    = &iov;
    msg.msg_iovlen = 1;

    if (sendmsg(fd, &msg, 0) < 0) return FG_ERR_IO;

    char buf[NLMSG_BUF];
    struct iovec iov2  = { buf, sizeof(buf) };
    msg.msg_iov    = &iov2;
    msg.msg_iovlen = 1;

    ssize_t n = recvmsg(fd, &msg, 0);
    if (n < 0) return FG_ERR_IO;

    struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
    if (NLMSG_OK(nlh, n) && nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr* err = (struct nlmsgerr*)NLMSG_DATA(nlh);
        if (err->error) return FG_ERR_IO;
    }
    return FG_OK;
}

int fg_route_add(const char* iface, uint32_t dst, uint8_t prefix_len, uint32_t gw) {
    int fd = nl_socket_open();
    if (fd < 0) return fd;

    struct {
        struct nlmsghdr  nlh;
        struct rtmsg     rtm;
        char             buf[512];
    } req = {0};

    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type  = RTM_NEWROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    req.nlh.nlmsg_seq   = 1;

    req.rtm.rtm_family   = AF_INET;
    req.rtm.rtm_dst_len  = prefix_len;
    req.rtm.rtm_table    = RT_TABLE_MAIN;
    req.rtm.rtm_protocol = RTPROT_STATIC;
    req.rtm.rtm_scope    = RT_SCOPE_UNIVERSE;
    req.rtm.rtm_type     = RTN_UNICAST;

    /* add RTA_DST */
    struct rtattr* rta;
    rta = (struct rtattr*)(((char*)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = RTA_DST;
    rta->rta_len  = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), &dst, 4);
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + rta->rta_len;

    /* add RTA_GATEWAY if provided */
    if (gw) {
        rta = (struct rtattr*)(((char*)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
        rta->rta_type = RTA_GATEWAY;
        rta->rta_len  = RTA_LENGTH(4);
        memcpy(RTA_DATA(rta), &gw, 4);
        req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + rta->rta_len;
    }

    /* add RTA_OIF */
    if (iface) {
        int oif = if_nametoindex(iface);
        if (oif > 0) {
            rta = (struct rtattr*)(((char*)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
            rta->rta_type = RTA_OIF;
            rta->rta_len  = RTA_LENGTH(4);
            memcpy(RTA_DATA(rta), &oif, 4);
            req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + rta->rta_len;
        }
    }

    int rc = nl_send_recv(fd, &req.nlh, req.nlh.nlmsg_len);
    close(fd);
    return rc;
}

int fg_route_del(const char* iface, uint32_t dst, uint8_t prefix_len) {
    int fd = nl_socket_open();
    if (fd < 0) return fd;

    struct {
        struct nlmsghdr nlh;
        struct rtmsg    rtm;
        char            buf[256];
    } req = {0};

    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type  = RTM_DELROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_seq   = 2;

    req.rtm.rtm_family  = AF_INET;
    req.rtm.rtm_dst_len = prefix_len;
    req.rtm.rtm_table   = RT_TABLE_MAIN;

    struct rtattr* rta = (struct rtattr*)(((char*)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = RTA_DST;
    rta->rta_len  = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), &dst, 4);
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + rta->rta_len;

    (void)iface;
    int rc = nl_send_recv(fd, &req.nlh, req.nlh.nlmsg_len);
    close(fd);
    return rc;
}
