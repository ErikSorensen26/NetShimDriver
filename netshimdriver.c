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

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <net/rtnetlink.h>
#include <linux/sysfs.h>
#include <linux/string.h>
#include <linux/notifier.h>

// Private per-device state
struct mask_priv {
    struct net_device *real_dev; // Backend device
    char realdev_name[IFNAMSIZ]; // name string for sysfs
};

// Tx path: called when linux sends a packet to shim
static netdev_tx_t mask_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct mask_priv *priv = netdev_priv(dev);

    if (priv->real_dev && netif_running(priv->real_dev))
    {
        // Redirect packet to backing device
        skb->dev = priv->real_dev;
        return dev_queue_xmit(skb);
    }

    // silently drop if no backing device
    dev_kfree_skb(skb);
    return NETDEV_TX_OK;
}

// open/close
static int mask_open(struct net_device* dev)
{
    netif_start_queue(dev);
    pr_info("netshim: %s opened\n", dev->name);
    return 0;
}

static int mask_stop(struct net_device* dev)
{
    netif_stop_queue(dev);
    pr_info("netshim: %s stopped\n", dev->name);
    return 0;
}

// Define netdev ops globally so the pointer is always valid
static const struct net_device_ops mask_netdev_ops = {
    .ndo_open = mask_open,
    .ndo_stop = mask_stop,
    .ndo_start_xmit = mask_start_xmit,
};

// Rx handler: realdev -> shim
static rx_handler_result_t mask_handle_frame(struct sk_buff **pskb)
{
    struct sk_buff* skb = *pskb;
    struct mask_priv* priv;
    struct net_device* shim;

    rcu_read_lock();
    for_each_netdev(&init_net, shim)
    {
        if (shim->netdev_ops != &mask_netdev_ops)
            continue;

        priv = netdev_priv(shim);

        if (priv->real_dev == skb->dev)
        {
            struct sk_buff* nskb = skb_clone(skb, GFP_ATOMIC);
            if (nskb)
            {
                nskb->dev = shim;
                netif_receive_skb(nskb);
            }
        }
    }
    rcu_read_unlock();

    return RX_HANDLER_PASS;
}

// Netdevice setup
static void mask_setup(struct net_device* dev)
{
    struct mask_priv* priv = netdev_priv(dev);

    ether_setup(dev);
    dev->netdev_ops = &mask_netdev_ops;
    eth_hw_addr_random(dev);

    priv->real_dev = NULL;
    priv->realdev_name[0] = '\0';
}

// Sysfs: /sys/class/net/maskX/realdev
static ssize_t realdev_show(struct device *d, struct device_attribute* attr, char* buf)
{
    struct net_device* dev = to_net_dev(d);
    struct mask_priv* priv = netdev_priv(dev);

    return scnprintf(buf, IFNAMSIZ, "%s\n", priv->real_dev ? priv->real_dev->name : priv->realdev_name);
}

static ssize_t realdev_store(struct device *d, struct device_attribute* attr, const char* buf, size_t len)
{
    struct net_device* dev = to_net_dev(d);
    struct mask_priv* priv = netdev_priv(dev);
    char name[IFNAMSIZ];
    struct net_device* target = NULL;

    if (len >= IFNAMSIZ)
        return -EINVAL;

    strscpy(name, buf, IFNAMSIZ);
    if (strlen(name) > 0 && name[strlen(name) - 1] == '\n')
        name[strlen(name) - 1] = '\0';

    rtnl_lock();

    // Release old ref
    if (priv->real_dev)
    {
        netdev_rx_handler_unregister(priv->real_dev);
        dev_put(priv->real_dev);
        priv->real_dev = NULL;
    }

    if (name[0] != '\0')
    {
        strscpy(priv->realdev_name, name, IFNAMSIZ);
        target = dev_get_by_name(&init_net, name);
        if (target)
        {
            priv->real_dev = target;
            if (netdev_rx_handler_register(target, mask_handle_frame, NULL))
            {
                pr_warn("netshim: %s failed to bind %s (already in use)\n", dev->name, priv->realdev_name);
                dev_put(priv->real_dev);
                priv->real_dev = NULL;
            }
            else
            {
                pr_info("netshim: %s now references %s\n", dev->name, priv->realdev_name);
            }
        }
        else
        {
            pr_info("netshim: %s will bind when %s appears\n", dev->name, priv->realdev_name);
        }
    }
    else
    {
        priv->realdev_name[0] = '\0';
        pr_info("netshim: %s detached from backing device\n", dev->name);
    }

    rtnl_unlock();
    return len;
}

static DEVICE_ATTR_RW(realdev);

// rtnl link ops
static int mask_newlink(struct net* src_net, struct net_device* dev, struct nlattr* tb[], struct nlattr* data[], struct netlink_ext_ack* extack)
{
    int ret;

    struct mask_priv* priv = netdev_priv(dev);
    priv->real_dev = NULL;
    priv->realdev_name[0] = '\0';

    ret = register_netdevice(dev);
    if (ret)
        return ret;

    ret = device_create_file(&dev->dev, &dev_attr_realdev);
    if (ret)
        pr_warn("netshim: failed to create sysfs attr for %s\n", dev->name);

    pr_info("netshim: new device %s created\n", dev->name);
    return 0;
}

static void mask_dellink(struct net_device* dev, struct list_head* head)
{
    struct mask_priv *priv = netdev_priv(dev);

    device_remove_file(&dev->dev, &dev_attr_realdev);

    if (priv->real_dev)
    {
        netdev_rx_handler_unregister(priv->real_dev);
        dev_put(priv->real_dev);
        priv->real_dev = NULL;
    }
    priv->realdev_name[0] = '\0';

    unregister_netdevice_queue(dev, head);
    pr_info("netshim: device %s deleted\n", dev->name);
}

static struct rtnl_link_ops mask_link_ops __read_mostly = {
    .kind = "netshim",
    .setup = mask_setup,
    .newlink = mask_newlink,
    .dellink = mask_dellink,
};

// Netdevice notifier: watch for creation/deletion of backing dev
static int mask_netdev_event(struct notifier_block* nb, unsigned long event, void* ptr)
{
    struct net_device* realdev = netdev_notifier_info_to_dev(ptr);
    struct net_device* dev;
    struct mask_priv *priv;

    rcu_read_lock();
    for_each_netdev(&init_net, dev)
    {
        if (dev->netdev_ops != &mask_netdev_ops)
            continue;

        priv = netdev_priv(dev);

        if (!priv->realdev_name[0])
            continue;

        if (strcmp(priv->realdev_name, realdev->name) != 0)
            continue;

        switch (event)
        {
        case NETDEV_REGISTER:
            if (!priv->real_dev)
            {
                priv->real_dev = dev_get_by_name(&init_net, realdev->name);
                if (priv->real_dev)
                {
                    netdev_rx_handler_register(priv->real_dev, mask_handle_frame, NULL);
                    pr_info("netshim: %s auto-bound to new %s\n", dev->name, realdev->name);
                }
            }
            break;
        case NETDEV_UNREGISTER:
            if (priv->real_dev)
            {
                netdev_rx_handler_unregister(priv->real_dev);
                dev_put(priv->real_dev);
                priv->real_dev = NULL;
                pr_info("netshim: %s backing dev %s removed\n", dev->name, realdev->name);
            }
            break;
        }
    }
    rcu_read_unlock();

    return NOTIFY_DONE;
}

static struct notifier_block mask_nb = {
    .notifier_call = mask_netdev_event,
};

// Module init/exit
static int __init mask_init(void)
{
    int ret;

    register_netdevice_notifier(&mask_nb);

    ret = rtnl_link_register(&mask_link_ops);
    if (ret)
        return ret;

    pr_info("netshim: registered rtnl link type\n");
    return 0;
}

static void __exit mask_exit(void)
{
    unregister_netdevice_notifier(&mask_nb);
    rtnl_link_unregister(&mask_link_ops);
    pr_info("netshim: unloaded\n");
}

module_init(mask_init);
module_exit(mask_exit);

MODULE_AUTHOR("Erik Sorensen erik.sorensen2006@gmail.com");
MODULE_DESCRIPTION("NetShimDriver - shim network interface driver");
MODULE_LICENSE("GPL");
