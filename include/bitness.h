/* Copyright (c) 2012, Stratus, Inc. - All rights reserved. */
#ifndef __UTIL_KDUMP_BITNESS_H__
#define __UTIL_KDUMP_BITNESS_H__

#include "kdump.h"

extern mem_range_t * get_page_ranges_xen_32();
extern mem_range_t * get_page_ranges_xen_64();

#endif /* __UTIL_KDUMP_BITNESS_H__ */
