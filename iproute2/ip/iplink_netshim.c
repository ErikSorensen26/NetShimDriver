/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * iplink_netshim.c - NetShim device support
 *
 * Author: Erik Sorensen
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_netshim.h>
#include <linux/if_link.h>

#include "utils.h"
#include "ip_common.h"

static void netshim_explain(FILE *f)
{
    fprintf(f,
        "Usage: ip link add NAME type netshim realdev DEV\n"
        "       Example: ip link add shim0 type netshim realdev wlo1\n"
    );
}

static void netshim_print_help(struct link_util *lu, int argc, char **argv, FILE *f)
{
    netshim_explain(f);
}

static int netshim_parse_opt(struct link_util *lu, int argc, char **argv,
                             struct nlmsghdr *n)
{
    while (argc > 0) {
        if (matches(*argv, "realdev") == 0) {
            NEXT_ARG();
            addattr_l(n, 1024, IFLA_NETSHIM_REALDEV, *argv, strlen(*argv) + 1);
        } else if (matches(*argv, "help") == 0) {
            netshim_explain(stderr);
            return -1;
        } else {
            invarg("unknown option", *argv);
        }
        argc--; argv++;
    }
    return 0;
}

static void netshim_print_opt(struct link_util *lu, FILE *f, struct rtattr *tb[])
{
    if (tb[IFLA_NETSHIM_REALDEV]) {
        fprintf(f, " realdev %s", rta_getattr_str(tb[IFLA_NETSHIM_REALDEV]));
    }
}

struct link_util netshim_link_util = {
    .id         = "netshim",
    .maxattr    = IFLA_NETSHIM_MAX,
    .parse_opt  = netshim_parse_opt,
    .print_opt  = netshim_print_opt,
    .print_help = netshim_print_help,
};

