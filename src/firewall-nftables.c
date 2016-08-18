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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>

#include "connman.h"

struct firewall_context *__connman_firewall_create(void)
{
	return NULL;
}

void __connman_firewall_destroy(struct firewall_context *ctx)
{
}

int __connman_firewall_enable_nat(struct firewall_context *ctx,
					char *address, unsigned char prefixlen,
					char *interface)
{
	return -EPROTONOSUPPORT;
}

int __connman_firewall_disable_nat(struct firewall_context *ctx)
{
	return -EPROTONOSUPPORT;
}

int __connman_firewall_enable_snat(struct firewall_context *ctx,
				int index, const char *ifname, const char *addr)
{
	return -EPROTONOSUPPORT;
}

int __connman_firewall_disable_snat(struct firewall_context *ctx)
{
	return -EPROTONOSUPPORT;
}

int __connman_firewall_enable_marking(struct firewall_context *ctx,
					enum connman_session_id_type id_type,
					char *id, uint32_t mark)
{
	return -EPROTONOSUPPORT;
}

int __connman_firewall_disable_marking(struct firewall_context *ctx)
{
	return -EPROTONOSUPPORT;
}

int __connman_firewall_init(void)
{
	return 0;
}

void __connman_firewall_cleanup(void)
{
}
