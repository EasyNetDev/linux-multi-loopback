// SPDX-License-Identifier: GPL-2.0-only
/* lo.c: a dummy net driver to be used as additional loopback interfaces in linux

	The purpose of this driver is to provide a device additonal loopbacks interfaces
	under Linux. Is based on dummy and vrf driver.

	Why? When your Linux is running router mode you need sometimes m
	multiple loopbacks interfaces in your system.
	The dummy driver have an issue using VRFs. When is enslave to a
	VRF interface is receiving the data but is not sending back.
	This behavior is not true when the dummy interface is under default VRF.

	The solution to this is to modify the dummy interface and sent back
	the processed packet which was destinated to local host, aka your router.

			Adrian Ban <devel@easynet.dev>, 11rd March 2022
*/

#include <linux/ethtool.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/netfilter.h>
#include <linux/rtnetlink.h>
#include <net/rtnetlink.h>
#include <linux/u64_stats_sync.h>
#include <linux/hashtable.h>
#include <linux/spinlock_types.h>

#include <linux/inetdevice.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/ip_fib.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#include <net/route.h>
#include <net/addrconf.h>
#include <net/l3mdev.h>
#include <net/fib_rules.h>
#include <net/sch_generic.h>
#include <net/netns/generic.h>
#include <net/netfilter/nf_conntrack.h>

#define DRV_NAME	"lo"
#define DRV_VERSION	"0.9"

static int numloopbacks = 1;

/* fake multicast ability */
static void set_multicast_list(struct net_device *dev)
{
}

/* This was replaced by a helper: dev_lstats_add */
/*
static void lo_rx_stats(struct net_device *dev, int len)
{
    struct pcpu_dstats *dstats = this_cpu_ptr(dev->dstats);

    u64_stats_update_begin(&dstats->syncp);
    dstats->rx_pkts++;
    dstats->rx_bytes += len;
    u64_stats_update_end(&dstats->syncp);
}
*/

static void lo_tx_error(struct net_device *lo_dev, struct sk_buff *skb)
{
    lo_dev->stats.tx_errors++;
    kfree_skb(skb);
}

static void lo_get_stats64(struct net_device *dev,
			      struct rtnl_link_stats64 *stats)
{
	dev_lstats_read(dev, &stats->tx_packets, &stats->tx_bytes);
}

/* by default LO devices do not have a qdisc and are expected
 * to be created with only a single queue.
 */
/*
static bool qdisc_tx_is_default(const struct net_device *dev)
{
    struct netdev_queue *txq;
    struct Qdisc *qdisc;

    if (dev->num_tx_queues > 1)
	return false;

    txq = netdev_get_tx_queue(dev, 0);
    qdisc = rcu_access_pointer(txq->qdisc);

    return !qdisc->enqueue;
}
*/

/* If the traffic is for local, then process it as local */
static netdev_tx_t lo_local_xmit(struct sk_buff *skb, struct net_device *dev,
	      struct dst_entry *dst)
{
	int len = skb->len;

	skb_orphan(skb);

	skb_dst_set(skb, dst);

	/* set pkt_type to avoid skb hitting packet taps twice -
	 * once on Tx and again in Rx processing
	 */
	skb->pkt_type = PACKET_LOOPBACK;

	skb->protocol = eth_type_trans(skb, dev);

	if (likely(netif_rx(skb) == NET_RX_SUCCESS))
	    dev_lstats_add(dev, len);

/*	else
	    this_cpu_inc(dev->dstats->rx_drps);
*/
	return NETDEV_TX_OK;
}

/* Avoid netfilter tracking */
/*
static void lo_nf_set_untracked(struct sk_buff *skb)
{
    if (skb_get_nfct(skb) == 0)
	nf_ct_set(skb, NULL, IP_CT_UNTRACKED);
}
*/

/* Reset netfiter conntracks */
static void lo_nf_reset_ct(struct sk_buff *skb)
{
    if (skb_get_nfct(skb) == IP_CT_UNTRACKED)
	nf_reset_ct(skb);
}

/* Process IPv6 traffic */
#if IS_ENABLED(CONFIG_IPV6)
static int lo_ip6_local_out(struct net *net, struct sock *sk,
	         struct sk_buff *skb)
{
    int err;

    lo_nf_reset_ct(skb);

    err = nf_hook(NFPROTO_IPV6, NF_INET_LOCAL_OUT, net,
	      sk, skb, NULL, skb_dst(skb)->dev, dst_output);

    if (likely(err == 1))
	err = dst_output(net, sk, skb);

    return err;
}

static netdev_tx_t lo_process_v6_outbound(struct sk_buff *skb,
		       struct net_device *dev)
{
    const struct ipv6hdr *iph;
    struct net *net = dev_net(skb->dev);
    struct flowi6 fl6;
    int ret = NET_XMIT_DROP;
    struct dst_entry *dst;
    struct dst_entry *dst_null = &net->ipv6.ip6_null_entry->dst;

    if (!pskb_may_pull(skb, ETH_HLEN + sizeof(struct ipv6hdr)))
	goto err;

    iph = ipv6_hdr(skb);

    memset(&fl6, 0, sizeof(fl6));
    /* needed to match OIF rule */
    fl6.flowi6_oif = dev->ifindex;
    fl6.flowi6_iif = LOOPBACK_IFINDEX;
    fl6.daddr = iph->daddr;
    fl6.saddr = iph->saddr;
    fl6.flowlabel = ip6_flowinfo(iph);
    fl6.flowi6_mark = skb->mark;
    fl6.flowi6_proto = iph->nexthdr;
    fl6.flowi6_flags = FLOWI_FLAG_SKIP_NH_OIF;

    dst = ip6_dst_lookup_flow(net, NULL, &fl6, NULL);
    if (IS_ERR(dst) || dst == dst_null)
	goto err;

    skb_dst_drop(skb);

    /* if dst.dev is the LO device again this is locally originated traffic
     * destined to a local address. Short circuit to Rx path.
     */
    if (dst->dev == dev)
	return lo_local_xmit(skb, dev, dst);

    skb_dst_set(skb, dst);

    /* strip the ethernet header added for pass through LO device */
    //__skb_pull(skb, skb_network_offset(skb));

    memset(IP6CB(skb), 0, sizeof(*IP6CB(skb)));
    ret = lo_ip6_local_out(net, skb->sk, skb);
    if (unlikely(net_xmit_eval(ret)))
	dev->stats.tx_errors++;
    else
	ret = NET_XMIT_SUCCESS;

    return ret;
err:
    lo_tx_error(dev, skb);
    return NET_XMIT_DROP;
}
#else
static netdev_tx_t lo_process_v6_outbound(struct sk_buff *skb,
		       struct net_device *dev)
{
    lo_tx_error(dev, skb);
    return NET_XMIT_DROP;
}
#endif

/* Process IPv4 traffic */
/* based on ip_local_out; can't use it b/c the dst is switched pointing to us */
static int lo_ip_local_out(struct net *net, struct sock *sk,
	        struct sk_buff *skb)
{
    int err;

    lo_nf_reset_ct(skb);

    err = nf_hook(NFPROTO_IPV4, NF_INET_LOCAL_OUT, net, sk,
	      skb, NULL, skb_dst(skb)->dev, dst_output);
    if (likely(err == 1))
	err = dst_output(net, sk, skb);

    return err;
}

static netdev_tx_t lo_process_v4_outbound(struct sk_buff *skb,
		       struct net_device *lo_dev)
{
    struct iphdr *ip4h;
    int ret = NET_XMIT_DROP;
    struct flowi4 fl4;
    struct net *net = dev_net(lo_dev);
    struct rtable *rt;

    if (!pskb_may_pull(skb, ETH_HLEN + sizeof(struct iphdr)))
	goto err;

    ip4h = ip_hdr(skb);

    memset(&fl4, 0, sizeof(fl4));
    /* needed to match OIF rule */
    fl4.flowi4_oif = lo_dev->ifindex;
    fl4.flowi4_iif = LOOPBACK_IFINDEX;
    fl4.flowi4_tos = RT_TOS(ip4h->tos);
    fl4.flowi4_flags = FLOWI_FLAG_ANYSRC | FLOWI_FLAG_SKIP_NH_OIF;
    fl4.flowi4_proto = ip4h->protocol;
    fl4.daddr = ip4h->daddr;
    fl4.saddr = ip4h->saddr;

    rt = ip_route_output_flow(net, &fl4, NULL);
    if (IS_ERR(rt))
	goto err;

    skb_dst_drop(skb);

    /* if dst.dev is the LO device again this is locally originated traffic
     * destined to a local address. Short circuit to Rx path.
     */
    if (rt->dst.dev == lo_dev)
	return lo_local_xmit(skb, lo_dev, &rt->dst);

    skb_dst_set(skb, &rt->dst);

    /* strip the ethernet header added for pass through VRF device */
    __skb_pull(skb, skb_network_offset(skb));

    if (!ip4h->saddr) {
	ip4h->saddr = inet_select_addr(skb_dst(skb)->dev, 0,
		           RT_SCOPE_LINK);
    }

    memset(IPCB(skb), 0, sizeof(*IPCB(skb)));

    ret = lo_ip_local_out(dev_net(skb_dst(skb)->dev), skb->sk, skb);
    if (unlikely(net_xmit_eval(ret)))
	lo_dev->stats.tx_errors++;
    else
	ret = NET_XMIT_SUCCESS;

out:
    return ret;
err:
    lo_tx_error(lo_dev, skb);
    goto out;
}

static netdev_tx_t is_ip_tx_frame(struct sk_buff *skb, struct net_device *dev)
{
    switch (skb->protocol) {
    case htons(ETH_P_IP):
	return lo_process_v4_outbound(skb, dev);
    case htons(ETH_P_IPV6):
	return lo_process_v6_outbound(skb, dev);
    default:
	lo_tx_error(dev, skb);
	return NET_XMIT_DROP;
    }
}

static netdev_tx_t lo_xmit(struct sk_buff *skb, struct net_device *dev)
{
    int len = skb->len;
    netdev_tx_t ret = is_ip_tx_frame(skb, dev);

    if (likely(ret == NET_XMIT_SUCCESS || ret == NET_XMIT_CN)) {
/* This is obsolete. Use only if you don't have dev_lstats_add helper
	struct pcpu_dstats *dstats = this_cpu_ptr(dev->dstats);

	u64_stats_update_begin(&dstats->syncp);
	dstats->tx_pkts++;
	dstats->tx_bytes += len;
	u64_stats_update_end(&dstats->syncp);
*/
	dev_lstats_add(dev, len);
    }
/*
 else {
	this_cpu_inc(dev->dstats->tx_drps);
    }
*/
    return ret;
}

static int lo_dev_init(struct net_device *dev)
{
	dev->lstats = netdev_alloc_pcpu_stats(struct pcpu_lstats);
	if (!dev->lstats)
		return -ENOMEM;

	return 0;
}

static void lo_dev_uninit(struct net_device *dev)
{
	free_percpu(dev->lstats);
}

static int lo_change_carrier(struct net_device *dev, bool new_carrier)
{
	if (new_carrier)
		netif_carrier_on(dev);
	else
		netif_carrier_off(dev);
	return 0;
}

static const struct net_device_ops lo_netdev_ops = {
	.ndo_init		= lo_dev_init,
	.ndo_uninit		= lo_dev_uninit,
	.ndo_start_xmit		= lo_xmit,
//	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_rx_mode	= set_multicast_list,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_get_stats64	= lo_get_stats64,
	.ndo_change_carrier	= lo_change_carrier,
};

static void lo_get_drvinfo(struct net_device *dev,
			      struct ethtool_drvinfo *info)
{
	strlcpy(info->driver, DRV_NAME, sizeof(info->driver));
	strlcpy(info->version, DRV_VERSION, sizeof(info->version));
}

static u32 always_on(struct net_device *dev)
{
	return 1;
}

static const struct ethtool_ops lo_ethtool_ops = {
	.get_link		= always_on,
	.get_drvinfo            = lo_get_drvinfo,
	.get_ts_info		= ethtool_op_get_ts_info,
};

static void lo_setup(struct net_device *dev)
{
	ether_setup(dev);

	/* Initialize the device structure. */
	dev->netdev_ops = &lo_netdev_ops;
	dev->ethtool_ops = &lo_ethtool_ops;
	dev->needs_free_netdev = true;

	/* Fill in device structure with ethernet-generic values. */
	dev->hard_header_len	= ETH_HLEN;	/* 14	*/
	dev->min_header_len	= ETH_HLEN;	/* 14	*/
	dev->addr_len		= ETH_ALEN;	/* 6	*/
	dev->type   = ARPHRD_LOOPBACK;
	eth_zero_addr(dev->broadcast);
	//dev->flags  = IFF_LOOPBACK;
	dev->flags  = IFF_NOARP;		// Set to no ARP protocol
	dev->flags &= ~IFF_MULTICAST;		// Disable Multicast
	//dev->flags |= IFF_UP | IFF_RUNNING;	// Always UP and RUNNING
	//netif_keep_dst(dev);	// Not sure if is needed
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE | IFF_NO_QUEUE;

	dev->hw_features = NETIF_F_GSO_SOFTWARE;
	dev->features	 = NETIF_F_SG | NETIF_F_FRAGLIST;
	dev->features	|= NETIF_F_GSO_SOFTWARE;
	dev->features	|= NETIF_F_HW_CSUM | NETIF_F_RXCSUM | NETIF_F_SCTP_CRC;
	dev->features	|= NETIF_F_HIGHDMA | NETIF_F_LLTX;
	dev->features	|= NETIF_F_NETNS_LOCAL;
	dev->features	|= NETIF_F_VLAN_CHALLENGED;
	//dev->features	|= NETIF_F_GSO_ENCAP_ALL;
	dev->features	|= NETIF_F_LOOPBACK;

	//dev->hw_features |= dev->features;
	dev->hw_enc_features |= dev->features;
	//eth_hw_addr_random(dev);

	dev->min_mtu = IPV6_MIN_MTU;
	dev->max_mtu = IP6_MAX_MTU;
	dev->mtu    = (64 * 1024);
}

static int lo_validate(struct nlattr *tb[], struct nlattr *data[],
			  struct netlink_ext_ack *extack)
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}
	return 0;
}

static struct rtnl_link_ops lo_link_ops __read_mostly = {
	.kind		= DRV_NAME,
	.setup		= lo_setup,
	.validate	= lo_validate,
};

/* Number of lo devices to be set up by this module. */
module_param(numloopbacks, int, 0);
MODULE_PARM_DESC(numloopbacks, "Number of additional loopback devices");

static int __init lo_init_one(void)
{
	struct net_device *dev_lo;
	int err;

	dev_lo = alloc_netdev(0, "lo%d", NET_NAME_ENUM, lo_setup);
	if (!dev_lo)
		return -ENOMEM;

	dev_lo->rtnl_link_ops = &lo_link_ops;
	err = register_netdevice(dev_lo);
	if (err < 0)
		goto err;

	netif_carrier_on(dev_lo);
	return 0;

err:
	free_netdev(dev_lo);
	return err;
}

static int __init lo_init_module(void)
{
	int i, err = 0;

	down_write(&pernet_ops_rwsem);
	rtnl_lock();
	err = __rtnl_link_register(&lo_link_ops);
	if (err < 0)
		goto out;

	for (i = 0; i < numloopbacks && !err; i++) {
		err = lo_init_one();
		cond_resched();
	}
	if (err < 0)
		__rtnl_link_unregister(&lo_link_ops);

out:
	rtnl_unlock();
	up_write(&pernet_ops_rwsem);

	return err;
}

static void __exit lo_cleanup_module(void)
{
	rtnl_link_unregister(&lo_link_ops);
}

module_init(lo_init_module);
module_exit(lo_cleanup_module);
MODULE_LICENSE("GPL");
MODULE_ALIAS_RTNL_LINK(DRV_NAME);
MODULE_VERSION(DRV_VERSION);
