/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2018  Chris Novakovic
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

#define _GNU_SOURCE
#include <errno.h>

#include "connman.h"

int __connman_stats_service_register(struct connman_service *service)
{
	return -ENOTSUP;
}

void __connman_stats_service_unregister(struct connman_service *service)
{
}

int  __connman_stats_update(struct connman_service *service,
				bool roaming,
				struct connman_stats_data *data)
{
	return 0;
}

int __connman_stats_get(struct connman_service *service,
				bool roaming,
				struct connman_stats_data *data)
{
	return 0;
}

int __connman_stats_init(void)
{
	return 0;
}

void __connman_stats_cleanup(void)
{
}
