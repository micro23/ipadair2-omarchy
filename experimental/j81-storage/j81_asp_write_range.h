/* SPDX-License-Identifier: GPL-2.0 OR MIT */
#ifndef J81_ASP_WRITE_RANGE_H
#define J81_ASP_WRITE_RANGE_H
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdbool.h>
#endif
/* All values are 4096-byte logical blocks. Avoid overflow in every bound. */
static inline bool j81_asp_write_range_allowed(unsigned long long capacity,
        unsigned long long first, unsigned long long count,
        unsigned long long start, unsigned long long blocks)
{
    if (!count || !blocks || first > capacity || count > capacity - first)
        return false;
    if (start < first || blocks > count)
        return false;
    return start - first <= count - blocks;
}
#endif
