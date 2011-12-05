/* Copyright (c) 2007, XenSource, Inc. - All rights reserved. */

#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>

#define PRIxMADDR PRIx64
typedef uint64_t maddr_t;
#define PRIxPADDR PRIx64
typedef uint64_t paddr_t;
#define PRIxVADDR PRIx64
typedef uint64_t vaddr_t;

#define PRIxPFN   PRIx64
#define PRIdPFN   PRId64
typedef uint64_t  pfn_t;

#endif
