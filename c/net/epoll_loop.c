#include "../include/ferrumgate.h"
#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <stdbool.h>

#define EPOLL_MAX_EVENTS 1024

typedef void (*FgEventCallback)(int fd, uint32_t events, void* userdata);

typedef struct {
    int              epfd;
    bool             running;
    pthread_t        thread;
    FgEventCallback  on_event;
    void*            userdata;
    int              wakeup_pipe[2]; /* pipe[0]=read, pipe[1]=write */
    uint64_t         total_events;
    uint64_t         errors;
} FgEpollLoop;

FgEpollLoop* fg_epoll_create(FgEventCallback cb, void* userdata) {
    FgEpollLoop* loop = calloc(1, sizeof(FgEpollLoop));
    if (!loop) return NULL;

    loop->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (loop->epfd < 0) { free(loop); return NULL; }

    if (pipe(loop->wakeup_pipe) < 0) {
        close(loop->epfd); free(loop); return NULL;
    }

    struct epoll_event ev = {0};
    ev.events  = EPOLLIN;
    ev.data.fd = loop->wakeup_pipe[0];
    epoll_ctl(loop->epfd, EPOLL_CTL_ADD, loop->wakeup_pipe[0], &ev);

    loop->on_event = cb;
    loop->userdata = userdata;
    return loop;
}

int fg_epoll_add(FgEpollLoop* loop, int fd, uint32_t events) {
    if (!loop || fd < 0) return FG_ERR_INVAL;
    struct epoll_event ev = {0};
    ev.events  = events;
    ev.data.fd = fd;
    return epoll_ctl(loop->epfd, EPOLL_CTL_ADD, fd, &ev) == 0 ?
           FG_OK : FG_ERR_IO;
}

int fg_epoll_mod(FgEpollLoop* loop, int fd, uint32_t events) {
    if (!loop) return FG_ERR_INVAL;
    struct epoll_event ev = {0};
    ev.events  = events;
    ev.data.fd = fd;
    return epoll_ctl(loop->epfd, EPOLL_CTL_MOD, fd, &ev) == 0 ?
           FG_OK : FG_ERR_IO;
}

int fg_epoll_del(FgEpollLoop* loop, int fd) {
    if (!loop) return FG_ERR_INVAL;
    return epoll_ctl(loop->epfd, EPOLL_CTL_DEL, fd, NULL) == 0 ?
           FG_OK : FG_ERR_IO;
}

static void* epoll_run(void* arg) {
    FgEpollLoop* loop = arg;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    while (loop->running) {
        int n = epoll_wait(loop->epfd, events, EPOLL_MAX_EVENTS, 200);
        if (n < 0) {
            if (errno == EINTR) continue;
            loop->errors++;
            break;
        }

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            if (fd == loop->wakeup_pipe[0]) {
                char buf[16];
                read(fd, buf, sizeof(buf)); /* drain wakeup */
                continue;
            }
            loop->total_events++;
            if (loop->on_event)
                loop->on_event(fd, events[i].events, loop->userdata);
        }
    }
    return NULL;
}

int fg_epoll_start(FgEpollLoop* loop) {
    if (!loop) return FG_ERR_INVAL;
    loop->running = true;
    return pthread_create(&loop->thread, NULL, epoll_run, loop) == 0 ?
           FG_OK : FG_ERR_IO;
}

void fg_epoll_stop(FgEpollLoop* loop) {
    if (!loop) return;
    loop->running = false;
    /* wake up the thread */
    write(loop->wakeup_pipe[1], "x", 1);
    pthread_join(loop->thread, NULL);
}

void fg_epoll_free(FgEpollLoop* loop) {
    if (!loop) return;
    fg_epoll_stop(loop);
    close(loop->wakeup_pipe[0]);
    close(loop->wakeup_pipe[1]);
    close(loop->epfd);
    free(loop);
}

uint64_t fg_epoll_total_events(const FgEpollLoop* loop) {
    return loop ? loop->total_events : 0;
}
