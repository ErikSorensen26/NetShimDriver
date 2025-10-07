/*
 * NetShimDriver - A Linux kernel shim network interface driver
 * Copyright (C) 2025 Erik Sorensen
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <net/rtnetlink.h>
#include <linux/string.h>
#include <linux/notifier.h>
#include <linux/mutex.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <net/addrconf.h>
#endif

#ifndef NETIF_F_NETNS_LOCAL
#define NETIF_F_NETNS_LOCAL 0
#endif

/* Module-wide flag to prevent new bindings during shutdown */
static atomic_t module_exiting = ATOMIC_INIT(0);

/* -------------------------------
 * Per-shim private state
 * ------------------------------- */
struct mask_priv {
    struct net_device *real_dev;          // backing device (RCU-protected)
    char realdev_name[IFNAMSIZ];          // configured realdev name
    struct mutex bind_lock;               // protects bind/unbind operations
};

/* -------------------------------
 * Netlink attributes
 * ------------------------------- */
enum {
    IFLA_NETSHIM_UNSPEC,
    IFLA_NETSHIM_REALDEV,
    __IFLA_NETSHIM_MAX,
};
#define IFLA_NETSHIM_MAX (__IFLA_NETSHIM_MAX - 1)

static const struct nla_policy mask_nl_policy[IFLA_NETSHIM_MAX + 1] = {
    [IFLA_NETSHIM_REALDEV] = { .type = NLA_STRING, .len = IFNAMSIZ - 1 },
};

/* -------------------------------
 * TX path: shim → realdev
 * ------------------------------- */
static netdev_tx_t mask_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct mask_priv *priv = netdev_priv(dev);
    struct net_device *real_dev;

    rcu_read_lock();
    real_dev = rcu_dereference(priv->real_dev);
    if (real_dev && netif_running(real_dev)) {
        skb->dev = real_dev;
        rcu_read_unlock();
        return dev_queue_xmit(skb);
    }
    rcu_read_unlock();

    dev_kfree_skb(skb);
    return NETDEV_TX_OK;
}

static int mask_open(struct net_device *dev)
{
    netif_carrier_off(dev);
    netif_tx_stop_all_queues(dev);
    pr_info("netshim: %s opened\n", dev->name);
    return 0;
}

static int mask_stop(struct net_device *dev)
{
    netif_stop_queue(dev);
    pr_info("netshim: %s stopped\n", dev->name);
    return 0;
}

static const struct net_device_ops mask_netdev_ops = {
    .ndo_open       = mask_open,
    .ndo_stop       = mask_stop,
    .ndo_start_xmit = mask_start_xmit,
};

/* -------------------------------
 * RX path: realdev → shim
 * ------------------------------- */
static rx_handler_result_t mask_handle_frame(struct sk_buff **pskb)
{
    struct sk_buff *skb = *pskb;
    struct net_device *shim;

    rcu_read_lock();
    shim = rcu_dereference(skb->dev->rx_handler_data);
    if (shim && netif_running(shim)) {
        struct sk_buff *nskb = skb_copy(skb, GFP_ATOMIC);
        if (nskb) {
            nskb->dev = shim;
            rcu_read_unlock();
            netif_receive_skb(nskb);
            return RX_HANDLER_PASS;
        }
    }
    rcu_read_unlock();

    return RX_HANDLER_PASS;
}

/* -------------------------------
 * Setup for shim devices
 * ------------------------------- */
static void mask_setup(struct net_device *dev)
{
    struct mask_priv *priv = netdev_priv(dev);

    ether_setup(dev);
    dev->netdev_ops = &mask_netdev_ops;
    eth_hw_addr_random(dev);

    priv->real_dev = NULL;
    priv->realdev_name[0] = '\0';
    mutex_init(&priv->bind_lock);

    dev->flags |= IFF_NOARP;
    dev->flags &= ~(IFF_MULTICAST | IFF_BROADCAST);

#ifdef IFF_DONT_BRIDGE
    dev->priv_flags |= IFF_DONT_BRIDGE;
#endif

#ifdef IFF_NO_USERSPACE_MANAGED
    dev->priv_flags |= IFF_NO_USERSPACE_MANAGED;
#endif
    
#ifdef IFF_DISABLE_NETPOLL
    dev->priv_flags |= IFF_DISABLE_NETPOLL;
#endif

    dev->features = 0;
    dev->hw_features = 0;
    dev->wanted_features = 0;
    dev->vlan_features = 0;
    dev->gso_max_segs = 0;
    dev->gso_max_size = 0;

    netif_carrier_off(dev);

    dev->type = ARPHRD_NONE;
    dev->hard_header_len = 0;
    dev->addr_len = 0;

    dev->tx_queue_len = 0;
    dev->watchdog_timeo = 0;

    dev->needs_free_netdev = true;

    pr_info("netshim: setup complete for %s (visible, kernel-silent)\n", dev->name);
}

/* -------------------------------
 * Unbind helper - can be called with or without RTNL
 * CRITICAL: Does NOT call synchronize_net() to avoid deadlock
 * ------------------------------- */
static void mask_unbind_realdev_nolock(struct mask_priv *priv)
{
    struct net_device *real_dev;

    real_dev = priv->real_dev;
    if (!real_dev)
        return;

    /* Unregister handler - this is safe even under RTNL */
    netdev_rx_handler_unregister(real_dev);
    
    /* Clear pointer atomically */
    rcu_assign_pointer(priv->real_dev, NULL);
    
    /* NOTE: We do NOT call synchronize_net() here to avoid deadlock.
     * Caller must ensure synchronization happens safely. */
    
    /* Release reference */
    dev_put(real_dev);
    
    priv->realdev_name[0] = '\0';
}

/* Safe unbind that can be called from anywhere */
static void mask_unbind_realdev(struct net_device *shim)
{
    struct mask_priv *priv = netdev_priv(shim);

    mutex_lock(&priv->bind_lock);
    
    if (priv->real_dev) {
        pr_info("netshim: %s unbinding from %s\n", shim->name, priv->realdev_name);
        mask_unbind_realdev_nolock(priv);
    }
    
    mutex_unlock(&priv->bind_lock);
}

/* -------------------------------
 * Bind backing device
 * ------------------------------- */
static int mask_bind_realdev(struct net_device *shim, const char *name)
{
    struct mask_priv *priv = netdev_priv(shim);
    struct net_device *target = NULL;
    int err = 0;

    if (atomic_read(&module_exiting))
        return -ENODEV;

    mutex_lock(&priv->bind_lock);

    /* Unbind existing without sync (safe since we hold bind_lock) */
    if (priv->real_dev) {
        mask_unbind_realdev_nolock(priv);
    }

    if (name && *name) {
        strscpy(priv->realdev_name, name, IFNAMSIZ);

        target = dev_get_by_name(dev_net(shim), name);
        if (!target) {
            pr_info("netshim: %s will bind when %s appears\n",
                    shim->name, priv->realdev_name);
            goto out;
        }

        err = netdev_rx_handler_register(target, mask_handle_frame, shim);
        if (err) {
            pr_warn("netshim: %s failed to bind %s (err=%d)\n",
                    shim->name, priv->realdev_name, err);
            dev_put(target);
            target = NULL;
            priv->realdev_name[0] = '\0';
            goto out;
        }

        rcu_assign_pointer(priv->real_dev, target);
        pr_info("netshim: %s bound to %s\n", shim->name, priv->realdev_name);
    } else {
        pr_info("netshim: %s unbound\n", shim->name);
    }

out:
    mutex_unlock(&priv->bind_lock);
    return err;
}

/* -------------------------------
 * rtnl link_ops
 * ------------------------------- */
static int mask_newlink(struct net *src_net, struct net_device *dev,
                        struct nlattr *tb[], struct nlattr *data[],
                        struct netlink_ext_ack *extack)
{
    int ret;
    struct mask_priv *priv = netdev_priv(dev);

    if (atomic_read(&module_exiting))
        return -ENODEV;

    priv->real_dev = NULL;
    priv->realdev_name[0] = '\0';
    mutex_init(&priv->bind_lock);

    ret = register_netdevice(dev);
    if (ret)
        return ret;

    if (data && data[IFLA_NETSHIM_REALDEV]) {
        const char *name = nla_data(data[IFLA_NETSHIM_REALDEV]);
        mask_bind_realdev(dev, name);
    }

    pr_info("netshim: new device %s created\n", dev->name);
    return 0;
}

static int mask_changelink(struct net_device *dev, struct nlattr *tb[],
                           struct nlattr *data[], struct netlink_ext_ack *extack)
{
    if (atomic_read(&module_exiting))
        return -EBUSY;

    if (data && data[IFLA_NETSHIM_REALDEV]) {
        const char *name = nla_data(data[IFLA_NETSHIM_REALDEV]);
        return mask_bind_realdev(dev, name);
    }
    return 0;
}

static void mask_dellink(struct net_device *dev, struct list_head *head)
{
    struct mask_priv *priv = netdev_priv(dev);

    /* CRITICAL: We're called with RTNL held. Just unbind, don't sync.
     * The synchronize_net() will happen naturally during device teardown. */
    mutex_lock(&priv->bind_lock);
    if (priv->real_dev) {
        mask_unbind_realdev_nolock(priv);
    }
    mutex_unlock(&priv->bind_lock);
    
    unregister_netdevice_queue(dev, head);

    pr_info("netshim: device %s deleted\n", dev->name);
}

static size_t mask_get_size(const struct net_device *dev)
{
    struct mask_priv *priv = netdev_priv((struct net_device *)dev);
    size_t size = 0;
    
    mutex_lock(&priv->bind_lock);
    if (priv->realdev_name[0])
        size = nla_total_size(strlen(priv->realdev_name) + 1);
    mutex_unlock(&priv->bind_lock);
    
    return size;
}

static int mask_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
    struct mask_priv *priv = netdev_priv((struct net_device *)dev);
    int ret = 0;
    
    mutex_lock(&priv->bind_lock);
    if (priv->realdev_name[0]) {
        if (nla_put_string(skb, IFLA_NETSHIM_REALDEV, priv->realdev_name))
            ret = -EMSGSIZE;
    }
    mutex_unlock(&priv->bind_lock);
    
    return ret;
}

static struct rtnl_link_ops mask_link_ops __read_mostly = {
    .kind        = "netshim",
    .setup       = mask_setup,
    .newlink     = mask_newlink,
    .changelink  = mask_changelink,
    .dellink     = mask_dellink,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
    .maxtype     = IFLA_NETSHIM_MAX,
#else
    .maxattr     = IFLA_NETSHIM_MAX,
#endif
    .policy      = mask_nl_policy,
    .priv_size   = sizeof(struct mask_priv),
    .get_size    = mask_get_size,
    .fill_info   = mask_fill_info,
};

/* -------------------------------
 * Netdevice notifier
 * ------------------------------- */
static int mask_netdev_event(struct notifier_block *nb,
                             unsigned long event, void *ptr)
{
    struct net_device *realdev = netdev_notifier_info_to_dev(ptr);
    struct net_device *dev;
    struct mask_priv *priv;
    struct net *net = dev_net(realdev);

    if (atomic_read(&module_exiting))
        return NOTIFY_DONE;

    /* RTNL is held by the notifier chain */
    for_each_netdev(net, dev) {
        if (dev->netdev_ops != &mask_netdev_ops)
            continue;

        priv = netdev_priv(dev);

        if (!priv->realdev_name[0])
            continue;
        if (strcmp(priv->realdev_name, realdev->name) != 0)
            continue;

        switch (event) {
        case NETDEV_REGISTER:
            {
#if IS_ENABLED(CONFIG_IPV6)
                if (dev->netdev_ops == &mask_netdev_ops)
                {
                    struct inet6_dev* idev = __in6_dev_get(dev);
                    if (idev)
                    {
                        idev->cnf.disable_ipv6 = 1;
                        idev->cnf.autoconf = 0;
                        idev->cnf.accept_ra = 0;
                        pr_info("netshim: IPv6 autoconf disabled for %s\n", dev->name);
                    }
                }
#endif
                mutex_lock(&priv->bind_lock);
                if (!priv->real_dev)
                    mask_bind_realdev(dev, priv->realdev_name);
                mutex_unlock(&priv->bind_lock);
            }
            break;
        case NETDEV_UNREGISTER:
            mutex_lock(&priv->bind_lock);
            if (priv->real_dev == realdev) {
                pr_info("netshim: %s backing dev %s removed\n",
                        dev->name, realdev->name);
                mask_unbind_realdev_nolock(priv);
            }
            mutex_unlock(&priv->bind_lock);
            break;
        }
    }

    return NOTIFY_DONE;
}

static struct notifier_block mask_nb = {
    .notifier_call = mask_netdev_event,
};

/* -------------------------------
 * Module init/exit
 * ------------------------------- */
static int __init mask_init(void)
{
    int ret;

    atomic_set(&module_exiting, 0);

    ret = register_netdevice_notifier(&mask_nb);
    if (ret)
        return ret;

    ret = rtnl_link_register(&mask_link_ops);
    if (ret)
    {
        unregister_netdevice_notifier(&mask_nb);
        return ret;
    }

    pr_info("netshim: registered rtnl link type\n");
    return 0;
}

static void __exit mask_exit(void)
{
    pr_info("netshim: unloading...\n");

    /* Signal that we're exiting - prevents new operations */
    atomic_set(&module_exiting, 1);

    /* Stop receiving notifier events */
    unregister_netdevice_notifier(&mask_nb);

    /* Unregister link type - this will trigger dellink for all devices */
    rtnl_link_unregister(&mask_link_ops);

    /* Final sync after everything is unregistered */
    synchronize_net();

    pr_info("netshim: unloaded cleanly\n");
}

module_init(mask_init);
module_exit(mask_exit);

MODULE_AUTHOR("Erik Sorensen <erik.sorensen2006@gmail.com>");
MODULE_DESCRIPTION("NetShimDriver - shim network interface driver");
MODULE_LICENSE("GPL");
