/* Copyright (c) 2012, Stratus, Inc. - All rights reserved. */
#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "kdump.h"
#include "memory.h"
#include "symbols.h"
#include "bitness.h"

// this file compiles twice with different BITS_PER_LONG
// see Makefile

#if BITS_PER_LONG == 64 && BITS_PER_LONG != 32
#define FN(x) x##_64
#elif BITS_PER_LONG == 32
#define FN(x) x##_32
#else
#error
#endif

#define BITS BITS_PER_LONG
/*
 * Page info macros.
 */

#define PG_shift(idx)     (BITS_PER_LONG - (idx))
#define PG_mask(x, idx)   (((uint64_t)x) << PG_shift(idx))
#define PGC_allocated     PG_mask(1, 1)
#define PGC_xen_heap      PG_mask(1, 2)
#define PGC_page_table    PG_mask(1, 3)

#define PGT_count_width   PG_shift(9)
#define PGT_count_mask    ((((uint64_t)1) <<PGT_count_width)-1)

#define PGC_state           PG_mask(3, 9)
#define PGC_state_inuse     PG_mask(0, 9)
#define PGC_state_offlining PG_mask(1, 9)
#define PGC_state_offlined  PG_mask(2, 9)
#define PGC_state_free      PG_mask(3, 9)
#define page_state_is(count_info, st) (((count_info) & PGC_state) == PGC_state_##st)

static maddr_t xen_phys_start = 0;

static vaddr_t xen__maddr_to_virt(maddr_t ma) {
	return (vaddr_t) (XEN_virt_start + (ma - xen_phys_start));
}

static void bitness_init() {
	static int __init = 0;
	struct symbol *sym;
	if (__init) {
		return;
	}
	__init = 1;

	sym = symtab_lookup_name(dump->symtab, "xen_phys_start");
	if (!sym) {
		debug("Error Symbol not found xen_phys_start\n");
	} else {
		xen_phys_start = kdump_read_uint64_vaddr(NULL, sym->address);
		debug("xen_phys_start = %#" PRIxMADDR "\n", xen_phys_start);
	}
}

mem_range_t * FN(get_page_ranges_xen)() {
	char buffer[PAGE_SIZE];
	char *text_state;
	maddr_t frame_table;
	unsigned long buffer_shift;
	uint64_t *count_info_p;
	struct symbol *sym;
	uint64_t max_page;
	unsigned long mfn;
	maddr_t mfn_start, mfn_end;
	unsigned long xen_page_count = 0;

	mem_range_t *mr = NULL;
	mem_range_t *mr_first = NULL;

	bitness_init(dump);

	debug("dump_xen_memory_new()\n");

	fprintf(output, "  XEN_virt_start: %016"PRIxMADDR" XEN_page_offset: %016"PRIxMADDR"\n", XEN_virt_start, XEN_page_offset);
	fprintf(output, "  xen_phys_start: %016"PRIxMADDR"\n", xen_phys_start);

	sym = symtab_lookup_name(dump->symtab, "max_page");
	if (!sym) {
		fprintf(output, "\tSymbol not found max_page\n");
		goto return_error;
	}
	max_page = kdump_read_uint64_vaddr(NULL, sym->address);
	debug("max_page: %016"PRIxMADDR"\n", max_page);

	// get mfn_start
	sym = symtab_lookup_name(dump->symtab, "_start");
	if (!sym) {
		fprintf(output, "\tSymbol not found _start\n");
		goto return_error;
	}

	mfn_start = kdump_virt_to_mach(&dump->cpus[0], sym->address) >> PAGE_SHIFT;
	debug("mfn_start: = %016"PRIxMADDR"\n", mfn_start);

	// get mfn_end
	sym = symtab_lookup_name(dump->symtab, "_end");
	if (!sym) {
		fprintf(output, "\tSymbol not found _end\n");
		goto return_error;
	}
	mfn_end = kdump_virt_to_mach(&dump->cpus[0], sym->address) >> PAGE_SHIFT;
	debug("mfn_end =  %#" PRIxMADDR "\n", mfn_end);

	// frame table is defined as
	// struct page_info *frame_table
	frame_table = kdump_read_uint64_vaddr(NULL, dump->frame_table);
	debug("frame_table = 0x%016" PRIx64 "\n", frame_table);

	for (mfn = 0; mfn < max_page; mfn++) {
		if ((mfn * dump->sizeof_page_info) % PAGE_SIZE == 0) {
			buffer_shift = mfn * dump->sizeof_page_info;
			if (kdump_read_vaddr(NULL, frame_table + buffer_shift, buffer, PAGE_SIZE) != PAGE_SIZE) {
				debug("Failed to read frame_table\n");
				fprintf(output, "\tFailed to read frame_table\n");
				goto return_error;
			}
		}
		count_info_p = (uint64_t*) (buffer + dump->offset_page_info_count_info + (mfn * dump->sizeof_page_info) % PAGE_SIZE);
		// filter out non-xen pages
		if (mfn < mfn_start || mfn > mfn_end) {
			if (*count_info_p == 0 || page_state_is(*count_info_p, free) || !(*count_info_p & PGC_xen_heap)) {
				continue;
			}
		}

		if (!mr) {
			mr_first = mr = alloc_mem_range();
			mr->mfn = mfn;
			mr->vaddr = xen__maddr_to_virt(mfn << PAGE_SHIFT);
			// to reduce number of mem ranges we ignore less than 16 pages gaps
		} else if (mr->mfn + mr->page_count + 16 < mfn) {
			mr->next = alloc_mem_range();
			mr = mr->next;
			mr->mfn = mfn;
			mr->vaddr = xen__maddr_to_virt(mfn << PAGE_SHIFT);
		}
		mr->page_count = mfn - mr->mfn + 1;

		text_state = "?????????";
		if (page_state_is(*count_info_p, free)) {
			text_state = "free     ";
		} else if (page_state_is(*count_info_p, inuse)) {
			text_state = "inuse    ";
		} else if (page_state_is(*count_info_p, offlining)) {
			text_state = "offlining";
		} else if (page_state_is(*count_info_p, offlined)) {
			text_state = "offlined ";
		}
		xen_page_count++;
		debug("mfn = %#lx count_info = 0x%016" PRIx64 " state %s %s\n", mfn, *count_info_p, text_state, (*count_info_p
				& PGC_xen_heap) ? "Xen" : "");
		count_info_p = (uint64_t*) (buffer + (mfn * dump->sizeof_page_info) % PAGE_SIZE);
		debug("word = 0x%016" PRIx64 "\n", *count_info_p);
		count_info_p++;
		debug("word = 0x%016" PRIx64 "\n", *count_info_p);
		count_info_p++;
		debug("word = 0x%016" PRIx64 "\n", *count_info_p);
		count_info_p++;
		debug("word = 0x%016" PRIx64 "\n", *count_info_p);
		count_info_p++;
	}
	debug("xen_page_cont = %ld total mem = %ld\n", xen_page_count, xen_page_count << PAGE_SHIFT);
	mr = mr_first;
	while (mr) {
		debug("=== XEN mem range mfn 0x%" PRIx64 " - 0x%" PRIx64 " pages %" PRIu64 " ===\n", mr->mfn, mr->mfn + mr->page_count,
				mr->page_count);
		mr = mr->next;
	}
	return mr_first;
	return_error: if (mr_first) {
		free_mem_range(mr_first);
	}
	return NULL;
}
