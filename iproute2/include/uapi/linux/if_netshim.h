/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_IF_NETSHIM_H
#define _UAPI_LINUX_IF_NETSHIM_H

#include <linux/types.h>

/*
 * Netlink attributes for netshim driver
 */
enum {
    IFLA_NETSHIM_UNSPEC,
    IFLA_NETSHIM_REALDEV,   /* name or ifindex of real device */
    __IFLA_NETSHIM_MAX,
};
#define IFLA_NETSHIM_MAX (__IFLA_NETSHIM_MAX - 1)

#endif /* _UAPI_LINUX_IF_NETSHIM_H */

