/*
 * sfe.h
 *	Shortcut forwarding engine.
 *
 * Copyright (c) 2013-2015 The Linux Foundation. All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef _SFE_H
#define _SFE_H

#define ETH_ALEN	6		/* Octets in one ethernet addr	 */

/*
 * Debug output verbosity level.
 */
#define DEBUG_LEVEL 2

#define __FILENAME__ (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1):__FILE__)

#if (DEBUG_LEVEL < 1)
#define SFE_LOG_ERROR(s, ...)
#else
#define SFE_LOG_ERROR(s, ...) \
do { \
	printk(KERN_ERR "%s[%u]: ERROR:", __FILENAME__, __LINE__); \
	printk(KERN_ERR s, ##__VA_ARGS__); \
} while (0)
#endif

#if (DEBUG_LEVEL < 2)
#define SFE_LOG_WARN(s, ...)
#else
#define SFE_LOG_WARN(s, ...) \
do { \
	printk(KERN_WARNING "%s[%u]: WARN:", __FILENAME__, __LINE__); \
	printk(KERN_WARNING s, ##__VA_ARGS__); \
} while (0)
#endif

#if (DEBUG_LEVEL < 3)
#define SFE_LOG_INFO(s, ...)
#else
#define SFE_LOG_INFO(s, ...) \
do { \
	printk(KERN_INFO "%s[%u]: INFO:", __FILENAME__, __LINE__); \
	printk(KERN_INFO s, ##__VA_ARGS__); \
} while (0)
#endif

#if (DEBUG_LEVEL < 4)
#define SFE_LOG_DEBUG(s, ...)
#else
#define SFE_LOG_DEBUG(s, ...) \
do { \
	printk(KERN_DEBUG "%s[%u]: TRACE:", __FILENAME__, __LINE__); \
	printk(KERN_DEBUG s, ##__VA_ARGS__); \
} while (0)
#endif

extern struct sfe_ipv4 *si;

#define SFE_EXP_STAT_INC(count) 	__this_cpu_inc(si->stat->exception[count])
#define SFE_STAT_INC(count) 	__this_cpu_inc(si->stat->count)
#define SFE_STAT_DEC(count) 	__this_cpu_dec(si->stat->count)

int sfe_debug_init(struct sfe_ipv4 *si);
void sfe_debug_exit(struct sfe_ipv4 *si);
int sfe_fm_init(void);
void sfe_fm_exit(void);
int sfe_netlink_init(void);
void sfe_netlink_exit(void);

#endif /* _SFE_H */

