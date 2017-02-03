/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2016  BMW Car IT GmbH.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

/*
 * This file is based on the libnftnl examples:
 *   https://git.netfilter.org/libnftnl/tree/examples
 * by Pablo Neira Ayuso. and inspiration from systemd nft implemention
 *   https://github.com/zonque/systemd/blob/rfc-nftnl/src/shared/firewall-util.c
 * by Daniel Mack.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <alloca.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <sys/types.h>
#include <pwd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include <glib.h>

#include "connman.h"

#define CONNMAN_TABLE "connman"
#define CONNMAN_CHAIN_NAT_PRE "nat-prerouting"
#define CONNMAN_CHAIN_NAT_POST "nat-postrouting"
#define CONNMAN_CHAIN_ROUTE_OUTPUT "route-output"

static bool debug_enabled = true;

struct firewall_handle {
	uint64_t handle;
	const char *chain;
};

struct firewall_context {
	struct firewall_handle rule;
};

struct nftables_info {
	struct firewall_handle ct;
};

static struct nftables_info *nft_info;

enum callback_return_type {
        CALLBACK_RETURN_NONE = 0,
        CALLBACK_RETURN_HANDLE,
        CALLBACK_RETURN_BYTE_COUNTER,
        _CALLBACK_RETURN_MAX,
};

struct callback_data {
        enum callback_return_type type;
        uint64_t value;
        bool success;
};

static void debug_netlink_dump_rule(struct nftnl_rule *nlr)
{
	char buf[4096];

	if (!debug_enabled)
		return;

	nftnl_rule_snprintf(buf, sizeof(buf), nlr, 0, 0);
	fprintf(stdout, "%s\n", buf);
}

static void debug_mnl_dump_rule(const void *req, size_t req_size)
{
	if (!debug_enabled)
		return;

	mnl_nlmsg_fprintf(stdout, req, req_size, 0);
	printf("\n");
}

static int rule_expr_cb(struct nftnl_expr *expr, void *data) {

        struct callback_data *cb = data;
        const char *name;

        name = nftnl_expr_get_str(expr, NFTNL_EXPR_NAME);

        if (strcmp(name, "counter")) {
                cb->value = nftnl_expr_get_u64(expr, NFTNL_EXPR_CTR_BYTES);
                cb->success = true;
        }

        return 0;
}

static int rule_cb(const struct nlmsghdr *nlh, int event,
		struct callback_data *cb)
{
	struct nftnl_rule *rule;

	rule = nftnl_rule_alloc();
	if (!rule)
		return MNL_CB_OK;

	if (nftnl_rule_nlmsg_parse(nlh, rule) < 0)
		goto out;

	switch (cb->type) {
	case CALLBACK_RETURN_HANDLE:
		cb->value = nftnl_rule_get_u64(rule, NFTNL_RULE_HANDLE);
		cb->success = true;
		break;

	case CALLBACK_RETURN_BYTE_COUNTER:
		nftnl_expr_foreach(rule, rule_expr_cb, cb);
		break;

	default:
		DBG("unhandled callback type %d\n", cb->type);
		break;
	}

out:
	nftnl_rule_free(rule);
	return MNL_CB_STOP;
}

static int chain_cb(const struct nlmsghdr *nlh, int event,
			struct callback_data *cb)
{
	struct nftnl_chain *chain;

	chain = nftnl_chain_alloc();
	if (!chain)
		return MNL_CB_OK;

	if (nftnl_chain_nlmsg_parse(nlh, chain) < 0)
		goto out;

	switch (cb->type) {
	case CALLBACK_RETURN_HANDLE:
		cb->value = nftnl_chain_get_u64(chain, NFTNL_CHAIN_HANDLE);
		cb->success = true;
		break;

	default:
		DBG("unhandled callback type %d\n", cb->type);
		break;
	}

out:
	nftnl_chain_free(chain);
	return MNL_CB_OK;
}

static const char *event_to_str(enum nf_tables_msg_types type)
{
	const char *table[] = {
		"NFT_MSG_NEWTABLE",
		"NFT_MSG_GETTABLE",
		"NFT_MSG_DELTABLE",
		"NFT_MSG_NEWCHAIN",
		"NFT_MSG_GETCHAIN",
		"NFT_MSG_DELCHAIN",
		"NFT_MSG_NEWRULE",
		"NFT_MSG_GETRULE",
		"NFT_MSG_DELRULE",
		"NFT_MSG_NEWSET",
		"NFT_MSG_GETSET",
		"NFT_MSG_DELSET",
		"NFT_MSG_NEWSETELEM",
		"NFT_MSG_GETSETELEM",
		"NFT_MSG_DELSETELEM",
		"NFT_MSG_NEWGEN",
		"NFT_MSG_GETGEN",
		"NFT_MSG_TRACE"
	};

	if (type < sizeof(table)/sizeof(table[0]))
		return table[type];

	return "unknown";
}

static int events_cb(const struct nlmsghdr *nlh, void *data)
{
        int event = NFNL_MSG_TYPE(nlh->nlmsg_type);
        struct callback_data *cb = data;
        int err = MNL_CB_OK;

        if (!cb || cb->type == CALLBACK_RETURN_NONE)
                return err;

	DBG("handle event %s", event_to_str(event));

        switch(event) {
	case NFT_MSG_NEWCHAIN:
		err = chain_cb(nlh, event, cb);
		break;

        case NFT_MSG_NEWRULE:
		err = rule_cb(nlh, event, cb);
		break;
        default:
		DBG("unhandled event type %s", event_to_str(event));
                break;
        }

        return err;
}

static int socket_open_and_bind(struct mnl_socket **n)
{

	struct mnl_socket *nl = NULL;
        int err;

        nl = mnl_socket_open(NETLINK_NETFILTER);
        if (!nl)
                return -errno;

        err = mnl_socket_bind(nl, 1 << (NFNLGRP_NFTABLES-1),
				MNL_SOCKET_AUTOPID);
        if (err < 0) {
		err = errno;
		mnl_socket_close(nl);
                return -err;
	}

        *n = nl;
        return 0;
}

static int send_and_dispatch(struct mnl_socket *nl, const void *req,
                size_t req_size, enum callback_return_type callback_type,
                uint64_t *callback_value)
{
        struct callback_data cb = {};
        uint32_t portid;
        int err;

	debug_mnl_dump_rule(req, req_size);

        err = mnl_socket_sendto(nl, req, req_size);
        if (err < 0)
                return -errno;

        portid = mnl_socket_get_portid(nl);
        cb.type = callback_type;

        for (;;) {
                char buf[MNL_SOCKET_BUFFER_SIZE];

                err = mnl_socket_recvfrom(nl, buf, sizeof(buf));
                if (err <= 0)
                        break;

                err = mnl_cb_run(buf, err, 0, portid, events_cb, &cb);
                if (err <= 0)
                        break;
        }

        if (err < 0)
                return -errno;

        if (callback_type == CALLBACK_RETURN_NONE)
                return 0;

        if (cb.success) {
                if (callback_value)
                        *callback_value = cb.value;

                return 0;
        }

        return -ENOENT;
}

static void put_batch_headers(char *buf, uint16_t type, uint32_t seq)
{

        struct nlmsghdr *nlh;
        struct nfgenmsg *nfg;

        nlh = mnl_nlmsg_put_header(buf);
        nlh->nlmsg_type = type;
        nlh->nlmsg_flags = NLM_F_REQUEST;
        nlh->nlmsg_seq = seq;

        nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
        nfg->nfgen_family = AF_INET;
        nfg->version = NFNETLINK_V0;
        nfg->res_id = NFNL_SUBSYS_NFTABLES;
}

static int add_payload(struct nftnl_rule *rule, uint32_t base,
			uint32_t dreg, uint32_t offset, uint32_t len)
{
        struct nftnl_expr *expr;

        expr = nftnl_expr_alloc("payload");
        if (!expr)
                return -ENOMEM;

        nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, base);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_DREG, dreg);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, len);

        nftnl_rule_add_expr(rule, expr);

        return 0;
}

static int add_bitwise(struct nftnl_rule *rule, int reg, const void *mask,
			size_t len)
{
        struct nftnl_expr *expr;
        uint8_t *xor;

        expr = nftnl_expr_alloc("bitwise");
        if (!expr)
                return -ENOMEM;

        xor = alloca(len);
	memset(xor, 0, len);

        nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_SREG, reg);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_DREG, reg);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_LEN, len);
        nftnl_expr_set(expr, NFTNL_EXPR_BITWISE_MASK, mask, len);
        nftnl_expr_set(expr, NFTNL_EXPR_BITWISE_XOR, xor, len);

        nftnl_rule_add_expr(rule, expr);

        return 0;
}

static int add_cmp(struct nftnl_rule *rule, uint32_t sreg, uint32_t op,
			const void *data, uint32_t data_len)
{
        struct nftnl_expr *expr;

        expr = nftnl_expr_alloc("cmp");
        if (!expr)
                return -ENOMEM;

        nftnl_expr_set_u32(expr, NFT_EXPR_CMP_SREG, sreg);
        nftnl_expr_set_u32(expr, NFT_EXPR_CMP_OP, op);
        nftnl_expr_set(expr, NFT_EXPR_CMP_DATA, data, data_len);

        nftnl_rule_add_expr(rule, expr);

        return 0;
}

static int table_cmd(struct mnl_socket *nl, struct nftnl_table *t,
		uint16_t cmd, uint16_t family, uint16_t type)
{
        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct mnl_nlmsg_batch *batch;
        struct nlmsghdr *nlh;
        uint32_t seq = 0;
        int err;

        batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
        nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				cmd, family, type, seq++);
        nftnl_table_nlmsg_build_payload(nlh, t);
	nftnl_table_free(t);
        mnl_nlmsg_batch_next(batch);

        nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

	/* The current table commands do not support any callback returns. */
        err = send_and_dispatch(nl, mnl_nlmsg_batch_head(batch),
				mnl_nlmsg_batch_size(batch), 0, NULL);

        mnl_nlmsg_batch_stop(batch);
        return err;
}

static int chain_cmd(struct mnl_socket *nl, struct nftnl_chain *chain,
		uint16_t cmd, int family, uint16_t type,
		enum callback_return_type cb_type, uint64_t *cb_val)
{
        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct mnl_nlmsg_batch *batch;
        struct nlmsghdr *nlh;
        uint32_t seq = 0;
        int err;

        batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
        nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					cmd, family, type, seq++);
        nftnl_chain_nlmsg_build_payload(nlh, chain);
	nftnl_chain_free(chain);
        mnl_nlmsg_batch_next(batch);

        nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        err = send_and_dispatch(nl, mnl_nlmsg_batch_head(batch),
			mnl_nlmsg_batch_size(batch), cb_type, cb_val);

        mnl_nlmsg_batch_stop(batch);
        return err;
}

static int rule_cmd(struct mnl_socket *nl, struct nftnl_rule *rule,
			uint16_t cmd, uint16_t family, uint16_t type,
			enum callback_return_type callback_type,
			uint64_t *callback_value)
{

        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct mnl_nlmsg_batch *batch;
        struct nlmsghdr *nlh;
        uint32_t seq = 0;
        int err;

	debug_netlink_dump_rule(rule);

        batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
        put_batch_headers(mnl_nlmsg_batch_current(batch),
				NFNL_MSG_BATCH_BEGIN, seq++);
        mnl_nlmsg_batch_next(batch);

        nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					cmd, family, type, seq++);
        nftnl_rule_nlmsg_build_payload(nlh, rule);
        mnl_nlmsg_batch_next(batch);

        put_batch_headers(mnl_nlmsg_batch_current(batch),
				NFNL_MSG_BATCH_END, seq++);
        mnl_nlmsg_batch_next(batch);

        err = send_and_dispatch(nl, mnl_nlmsg_batch_head(batch),
				mnl_nlmsg_batch_size(batch),
				callback_type, callback_value);
        mnl_nlmsg_batch_stop(batch);

        return err;
}

static int rule_delete(struct firewall_handle *handle)
{
	struct nftnl_rule *rule;
	struct mnl_socket *nl;
	int err;

	DBG("");

	rule = nftnl_rule_alloc();
	if (!rule)
		return -ENOMEM;

	nftnl_rule_set(rule, NFTNL_RULE_TABLE, CONNMAN_TABLE);
	nftnl_rule_set(rule, NFTNL_RULE_CHAIN, handle->chain);
	nftnl_rule_set_u64(rule, NFTNL_RULE_HANDLE, handle->handle);

	err = socket_open_and_bind(&nl);
	if (err < 0) {
		nftnl_rule_free(rule);
		return err;
	}

	err = rule_cmd(nl, rule, NFT_MSG_DELRULE, NFPROTO_IPV4,
			NLM_F_ACK, 0, NULL);
	nftnl_rule_free(rule);
	mnl_socket_close(nl);

	return err;
}

struct firewall_context *__connman_firewall_create(void)
{
	struct firewall_context *ctx;

	DBG("");

	ctx = g_new0(struct firewall_context, 1);

	return ctx;
}

void __connman_firewall_destroy(struct firewall_context *ctx)
{
	DBG("");

	g_free(ctx);
}

static int build_rule_nat(const char *address, unsigned char prefixlen,
				const char *interface, struct nftnl_rule **res)
{
	struct nftnl_rule *rule;
	struct in_addr ipv4_addr, ipv4_mask;
	struct nftnl_expr *expr;
	int err;

	/*
	 * # nft --debug netlink add rule connman nat-postrouting	\
	 *	oifname eth0 ip saddr 10.10.0.0/24 masquerade
	 *
	 *	ip connman nat-postrouting
	 *	  [ meta load oifname => reg 1 ]
	 *	  [ cmp eq reg 1 0x30687465 0x00000000 0x00000000 0x00000000 ]
	 *	  [ payload load 4b @ network header + 12 => reg 1 ]
	 *	  [ bitwise reg 1 = (reg=1 & 0x00ffffff ) ^ 0x00000000 ]
	 *	  [ cmp eq reg 1 0x00000a0a ]
	 *	  [ masq ]
	 */

	rule = nftnl_rule_alloc();
	if (!rule)
		return -ENOMEM;

	nftnl_rule_set(rule, NFTNL_RULE_TABLE, CONNMAN_TABLE);
	nftnl_rule_set(rule, NFTNL_RULE_CHAIN, CONNMAN_CHAIN_NAT_POST);

	/* family ipv4 */
	nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, NFPROTO_IPV4);

	/* oifname */
	expr = nftnl_expr_alloc("meta");
	if (!expr)
		goto err;
	nftnl_expr_set_u32(expr, NFT_EXPR_META_KEY, NFT_META_OIFNAME);
	nftnl_expr_set_u32(expr, NFT_EXPR_META_DREG, NFT_REG_1);
	nftnl_rule_add_expr(rule, expr);
	err = add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, interface,
			strlen(interface) + 1);
	if (err < 0)
		goto err;

	/* source */
	ipv4_mask.s_addr = htonl((0xffffffff << (32 - prefixlen)) & 0xffffffff);
	ipv4_addr.s_addr = inet_addr(address);
	ipv4_addr.s_addr &= ipv4_mask.s_addr;

	err = add_payload(rule, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
			offsetof(struct iphdr, saddr), sizeof(struct in_addr));
	if (err < 0)
		goto err;
	err = add_bitwise(rule, NFT_REG_1, &ipv4_mask.s_addr,
				sizeof(struct in_addr));
	if (err < 0)
		goto err;
	err = add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, &ipv4_addr.s_addr,
			sizeof(struct in_addr));
	if (err < 0)
		goto err;

	/* masquerade */
        expr = nftnl_expr_alloc("masq");
        if (!expr)
		goto err;
        nftnl_rule_add_expr(rule, expr);

	*res = rule;
	return 0;

err:
	nftnl_rule_free(rule);
	return -ENOMEM;
}

int __connman_firewall_enable_nat(struct firewall_context *ctx,
					char *address, unsigned char prefixlen,
					char *interface)
{
	struct mnl_socket *nl;
	struct nftnl_rule *rule;
	int err;

	DBG("address %s/%d interface %s", address, (int)prefixlen, interface);

        err = socket_open_and_bind(&nl);
        if (err < 0)
		return err;

	err = build_rule_nat(address, prefixlen, interface, &rule);
	if (err)
		goto out;

	ctx->rule.chain = CONNMAN_CHAIN_NAT_POST;
        err = rule_cmd(nl, rule, NFT_MSG_NEWRULE, NFPROTO_IPV4,
			NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK,
			CALLBACK_RETURN_HANDLE, &ctx->rule.handle);
	nftnl_rule_free(rule);
out:
	mnl_socket_close(nl);
	return err;
}

int __connman_firewall_disable_nat(struct firewall_context *ctx)
{
	return rule_delete(&ctx->rule);
}

static int build_rule_snat(int index, const char *address,
				struct nftnl_rule **res)
{
	struct nftnl_rule *rule;
	struct nftnl_expr *expr;
	uint32_t snat;
	int err;

	/*
	 * # nft --debug netlink add rule connman nat-postrouting \
	 *	oif eth0 snat 1.2.3.4
	 *	ip connman nat-postrouting
	 *	  [ meta load oif => reg 1 ]
	 *	  [ cmp eq reg 1 0x0000000b ]
	 *	  [ immediate reg 1 0x04030201 ]
	 *	  [ nat snat ip addr_min reg 1 addr_max reg 0 ]
	 */

	rule = nftnl_rule_alloc();
	if (!rule)
		return -ENOMEM;

	nftnl_rule_set(rule, NFTNL_RULE_TABLE, CONNMAN_TABLE);
	nftnl_rule_set(rule, NFTNL_RULE_CHAIN, CONNMAN_CHAIN_NAT_POST);

	/* IOF */
	expr = nftnl_expr_alloc("meta");
	if (!expr)
		goto err;
	nftnl_expr_set_u32(expr, NFT_EXPR_META_KEY, NFT_META_OIF);
	nftnl_expr_set_u32(expr, NFT_EXPR_META_DREG, NFT_REG_1);
	nftnl_rule_add_expr(rule, expr);
	err = add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, &index, sizeof(index));
	if (err < 0)
		goto err;

	/* snat */
	expr = nftnl_expr_alloc("immediate");
	if (!expr)
		goto err;
	snat = inet_addr(address);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_DREG, NFT_REG_1);
	nftnl_expr_set(expr, NFTNL_EXPR_IMM_DATA, &snat, sizeof(snat));
	nftnl_rule_add_expr(rule, expr);

	expr = nftnl_expr_alloc("nat");
        if (!expr)
		goto err;
	nftnl_expr_set_u32(expr, NFTNL_EXPR_NAT_TYPE, NFT_NAT_SNAT);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_NAT_FAMILY, NFPROTO_IPV4);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_NAT_REG_ADDR_MIN, NFT_REG_1);
        nftnl_rule_add_expr(rule, expr);

	*res = rule;
	return 0;

err:
	nftnl_rule_free(rule);
	return -ENOMEM;
}

int __connman_firewall_enable_snat(struct firewall_context *ctx,
				int index, const char *ifname, const char *addr)
{
	struct nftnl_rule *rule;
	struct mnl_socket *nl;
	int err;

	DBG("");

        err = socket_open_and_bind(&nl);
        if (err < 0)
		return err;

	err = build_rule_snat(index, addr, &rule);
	if (err)
		goto out;

	ctx->rule.chain = CONNMAN_CHAIN_NAT_POST;
        err = rule_cmd(nl, rule, NFT_MSG_NEWRULE, NFPROTO_IPV4,
			NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK,
			CALLBACK_RETURN_HANDLE, &ctx->rule.handle);
	nftnl_rule_free(rule);
out:
	mnl_socket_close(nl);
	return err;
}

int __connman_firewall_disable_snat(struct firewall_context *ctx)
{
	DBG("");

	return rule_delete(&ctx->rule);
}

static int build_rule_marking(uid_t uid, uint32_t mark, struct nftnl_rule **res)
{
	struct nftnl_rule *rule;
	struct nftnl_expr *expr;
	int err;

	/*
	 * http://wiki.nftables.org/wiki-nftables/index.php/Setting_packet_metainformation
	 * http://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation
	 *
	 * # nft --debug netlink add rule connman route-output	\
	 *	meta skuid wagi mark set 1234
	 *
	 *	ip connman route-output
	 *	  [ meta load skuid => reg 1 ]
	 *	  [ cmp eq reg 1 0x000003e8 ]
	 *	  [ immediate reg 1 0x000004d2 ]
	 *	  [ meta set mark with reg 1 ]
	 */

	rule = nftnl_rule_alloc();
	if (!rule)
		return -ENOMEM;

	nftnl_rule_set(rule, NFTNL_RULE_TABLE, CONNMAN_TABLE);
	nftnl_rule_set(rule, NFTNL_RULE_CHAIN, CONNMAN_CHAIN_ROUTE_OUTPUT);

	expr = nftnl_expr_alloc("meta");
	if (!expr)
		goto err;
	nftnl_expr_set_u32(expr, NFTNL_EXPR_META_KEY, NFT_META_SKUID);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_META_DREG, NFT_REG_1);
	nftnl_rule_add_expr(rule, expr);
	err = add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, &uid, sizeof(uid));
	if (err < 0)
		goto err;

	expr = nftnl_expr_alloc("immediate");
	if (!expr)
		goto err;
	nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_DREG, NFT_REG_1);
	nftnl_expr_set(expr, NFTNL_EXPR_IMM_DATA, &mark, sizeof(mark));
	nftnl_rule_add_expr(rule, expr);

	expr = nftnl_expr_alloc("meta");
	if (!expr)
		goto err;
	nftnl_expr_set_u32(expr, NFTNL_EXPR_META_KEY, NFT_META_MARK);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_META_SREG, NFT_REG_1);
	nftnl_rule_add_expr(rule, expr);

	*res = rule;
	return 0;

err:
	return -ENOMEM;
}

static int build_rule_src_ip(const char *src_ip, uint32_t mark, struct nftnl_rule **res)
{
	struct nftnl_rule *rule;
	struct nftnl_expr *expr;
	int err;
	in_addr_t s_addr;

	/*
	 * # nft --debug netlink add rule connman route-output \
	 *	ip saddr 192.168.10.31 mark set 1234
	 *
	 *	ip connman route-output
	 *	  [ payload load 4b @ network header + 12 => reg 1 ]
	 *	  [ cmp eq reg 1 0x1f0aa8c0 ]
	 *	  [ immediate reg 1 0x000004d2 ]
	 *	  [ meta set mark with reg 1 ]
	 */

	rule = nftnl_rule_alloc();
	if (!rule)
		return -ENOMEM;

	nftnl_rule_set(rule, NFTNL_RULE_TABLE, CONNMAN_TABLE);
	nftnl_rule_set(rule, NFTNL_RULE_CHAIN, CONNMAN_CHAIN_ROUTE_OUTPUT);

	/* family ipv4 */
	nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, NFPROTO_IPV4);

	/* source IP */
	err = add_payload(rule, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
			offsetof(struct iphdr, saddr), sizeof(struct in_addr));
	if (err < 0)
		goto err;

	s_addr = inet_addr(src_ip);
	err = add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, &s_addr, sizeof(s_addr));
	if (err < 0)
		goto err;

	expr = nftnl_expr_alloc("immediate");
	if (!expr)
		goto err;
	nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_DREG, NFT_REG_1);
	nftnl_expr_set(expr, NFTNL_EXPR_IMM_DATA, &mark, sizeof(mark));
	nftnl_rule_add_expr(rule, expr);

	expr = nftnl_expr_alloc("meta");
	if (!expr)
		goto err;
	nftnl_expr_set_u32(expr, NFTNL_EXPR_META_KEY, NFT_META_MARK);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_META_SREG, NFT_REG_1);
	nftnl_rule_add_expr(rule, expr);

	*res = rule;
	return 0;

err:
	return -ENOMEM;
}

int __connman_firewall_enable_marking(struct firewall_context *ctx,
					enum connman_session_id_type id_type,
					char *id, const char *src_ip,
					uint32_t mark)
{
	struct nftnl_rule *rule;
	struct mnl_socket *nl;
	struct passwd *pw;
	uid_t uid;
	int err;

	DBG("");

	if (id_type == CONNMAN_SESSION_ID_TYPE_UID) {
		pw = getpwnam(id);
		if (!pw)
			return -EINVAL;
		uid = pw->pw_uid;
	}
	else if (!src_ip)
		return -ENOTSUP;

        err = socket_open_and_bind(&nl);
        if (err < 0)
		return err;

	if (id_type == CONNMAN_SESSION_ID_TYPE_UID) {
		err = build_rule_marking(uid, mark, &rule);
		if (err < 0)
			goto out;

		ctx->rule.chain = CONNMAN_CHAIN_ROUTE_OUTPUT;
		err = rule_cmd(nl, rule, NFT_MSG_NEWRULE, NFPROTO_IPV4,
				NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK,
				CALLBACK_RETURN_HANDLE, &ctx->rule.handle);

		nftnl_rule_free(rule);
	}

	if (src_ip) {
		err = build_rule_src_ip(src_ip, mark, &rule);
		if (err < 0)
			goto out;

		ctx->rule.chain = CONNMAN_CHAIN_ROUTE_OUTPUT;
		err = rule_cmd(nl, rule, NFT_MSG_NEWRULE, NFPROTO_IPV4,
				NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK,
				CALLBACK_RETURN_HANDLE, &ctx->rule.handle);

		nftnl_rule_free(rule);
	}
out:
	mnl_socket_close(nl);
	return err;
}

int __connman_firewall_disable_marking(struct firewall_context *ctx)
{
	int err;

	DBG("");

	err = rule_delete(&ctx->rule);
	return err;
}

static struct nftnl_table *build_table(const char *name, uint16_t family)
{
        struct nftnl_table *table;

        table = nftnl_table_alloc();
        if (!table)
                return NULL;

	nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY, family);
        nftnl_table_set_str(table, NFTNL_TABLE_NAME, name);

	return table;
}


static struct nftnl_chain *build_chain(const char *name, const char *table,
				const char *type, int hooknum, int prio)
{
	struct nftnl_chain *chain;

        chain = nftnl_chain_alloc();
        if (!chain)
                return NULL;

        nftnl_chain_set(chain, NFTNL_CHAIN_TABLE, table);
        nftnl_chain_set(chain, NFTNL_CHAIN_NAME, name);

	if (type)
		nftnl_chain_set_str(chain, NFTNL_CHAIN_TYPE, type);

        if (hooknum >= 0)
                nftnl_chain_set_u32(chain, NFTNL_CHAIN_HOOKNUM, hooknum);

        if (prio >= 0)
                nftnl_chain_set_u32(chain, NFTNL_CHAIN_PRIO, prio);

	return chain;
}

static int create_table_and_chains(struct nftables_info *nft_info)
{
	struct mnl_socket *nl;
	struct nftnl_table *table;
	struct nftnl_chain *chain;
	int err;


	DBG("");

        err = socket_open_and_bind(&nl);
        if (err < 0)
		return err;

	/*
	 * Add table
	 * http://wiki.nftables.org/wiki-nftables/index.php/Configuring_tables
	 */

	/*
	 * # nft add table connman
	 */
	table = build_table(CONNMAN_TABLE, NFPROTO_IPV4);
	if (!table) {
		err = -ENOMEM;
		goto out;
	}

        err = table_cmd(nl, table, NFT_MSG_NEWTABLE, NFPROTO_IPV4,
			NLM_F_CREATE|NLM_F_ACK);
        if (err < 0)
                goto out;

	/*
	 * Add basic chains
	 * http://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains
	 */

	/*
	 * # nft add chain connman nat-prerouting		\
	 *	{ type nat hook prerouting priortiy 0 ; }
	 */
	chain = build_chain(CONNMAN_CHAIN_NAT_PRE, CONNMAN_TABLE,
				"nat", NF_INET_PRE_ROUTING, 0);
	if (!chain) {
		err = -ENOMEM;
		goto out;
	}

	err = chain_cmd(nl, chain, NFT_MSG_NEWCHAIN,
			NFPROTO_IPV4, NLM_F_CREATE | NLM_F_ACK,
			CALLBACK_RETURN_NONE, NULL);
	if (err < 0)
		goto out;

	/*
	 * # nft add chain connman nat-postrouting		\
	 *	{ type nat hook postrouting priortiy 0 ; }
	 */
	chain = build_chain(CONNMAN_CHAIN_NAT_POST, CONNMAN_TABLE,
				"nat", NF_INET_POST_ROUTING, 0);
	if (!chain) {
		err = -ENOMEM;
		goto out;
	}

	err = chain_cmd(nl, chain, NFT_MSG_NEWCHAIN,
			NFPROTO_IPV4, NLM_F_CREATE | NLM_F_ACK,
			CALLBACK_RETURN_NONE, NULL);
	if (err < 0)
		goto out;

	/*
	 * # nft add chain connman route-output		\
	 *	{ type route hook output priority 0 ; }
	 */
	chain = build_chain(CONNMAN_CHAIN_ROUTE_OUTPUT, CONNMAN_TABLE,
				"route", NF_INET_LOCAL_OUT, 0);
	if (!chain) {
		err = -ENOMEM;
		goto out;
	}

	err = chain_cmd(nl, chain, NFT_MSG_NEWCHAIN,
			NFPROTO_IPV4, NLM_F_CREATE | NLM_F_ACK,
			CALLBACK_RETURN_NONE, NULL);
	if (err < 0)
		goto out;

out:
	if (err)
		connman_warn("Failed to create basic chains: %s",
				strerror(-err));
	mnl_socket_close(nl);
	return err;
}

static int cleanup_table_and_chains(void)
{
	struct nftnl_table *table;
	struct mnl_socket *nl;
	int err;

	DBG("");

        err = socket_open_and_bind(&nl);
        if (err < 0)
		return -ENOMEM;

	/*
	 * Cleanup everythying in one go. There is little point in
	 * step-by-step removal of rules and chains if you can get it
	 * as simple as this.
	 */
	/*
	 * # nft delete table connman
	 */
	table = build_table(CONNMAN_TABLE, NFPROTO_IPV4);
	err = table_cmd(nl, table, NFT_MSG_DELTABLE, NFPROTO_IPV4, NLM_F_ACK);

	mnl_socket_close(nl);
	return err;
}

int __connman_firewall_init(void)
{
	int err;

	DBG("");

	if (getenv("CONNMAN_NFTABLES_DEBUG"))
		debug_enabled = true;

	/*
	 * EAFNOSUPPORT is return whenever the nf_tables_ipv4 hasn't been
	 * loaded yet. ENOENT is return in case the table is missing.
	 */
	err = cleanup_table_and_chains();
	if (err < 0 && (err != EAFNOSUPPORT && err != -ENOENT)) {
		connman_warn("initializing nftable failed with '%s' %d. Check if kernel module nf_tables_ipv4 is missing\n",
			strerror(-err), err);
		return err;
	}

	nft_info = g_new0(struct nftables_info, 1);
	err = create_table_and_chains(nft_info);
	if (err) {
		g_free(nft_info);
		nft_info = NULL;
	}

	return err;
}

void __connman_firewall_cleanup(void)
{
	int err;

	DBG("");

	err = cleanup_table_and_chains();
	if (err < 0)
		connman_warn("cleanup table and chains failed with '%s' %d\n",
			strerror(-err), err);

	g_free(nft_info);
	nft_info = NULL;
}
