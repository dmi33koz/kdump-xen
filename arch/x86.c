/* Copyright (c) 2007, XenSource, Inc. - All rights reserved. */

#include <stdint.h>

#include "kdump.h"
#include "memory.h"

int x86_virt_to_mach(uint64_t cr3, int paging_levels, vaddr_t vaddr, maddr_t *maddr)
{
	maddr_t pdp;
	maddr_t pd;
	maddr_t pt;
	maddr_t page;
	int dbg = 0;
	int status = 0;
	*maddr = -1ULL;

debug_retry:
	if (dbg) {
		debug("Translating %"PRIxVADDR" with CR3 %"PRIx64" and %d levels of page table\n", vaddr, cr3, paging_levels);
	}

	if (paging_levels == 2)
	{
		debug("TODO: 2 level page table translation\n");
		return 1;
	}

	if (paging_levels >= 4)
	{
		maddr_t offset = (vaddr >> 39) & ((1<<9)-1);
		uint64_t pml4e;
		pml4e = kdump_read_uint64_maddr(cr3 + 8*offset);
		if (dbg) {
			debug("PML4 @ %"PRIx64"\n", cr3);
			debug("PML4[%"PRIxMADDR"] @ %"PRIxMADDR" = %"PRIx64"\n", offset, cr3 + 8*offset, pml4e);
		}
		if (!(pml4e&1)) /* Not present */
		{
			if (dbg)
				debug("PML4 not present\n");
			status = 1;
			goto done;
		}

		pdp = pml4e & 0x000FFFFFFFFFF000ULL;
	}
	else
	{
		pdp = cr3 & ~0x1f;
	}

	if (paging_levels >= 3)
	{
		maddr_t offset;
		uint64_t pdpe;

		if (paging_levels >= 4)
			offset = (vaddr >> 30) & ((1<<9)-1);
		else
			offset = (vaddr >> 30) & ((1<<2)-1);

		pdpe = kdump_read_uint64_maddr(pdp + 8*offset);
		if (dbg) {
			debug("PDP @ %"PRIxMADDR"\n", pdp);
			debug("PDP[%"PRIxMADDR"] @ %"PRIxMADDR" = %"PRIx64"\n", offset, pdp + 8*offset, pdpe);
		}

		if (!(pdpe&1)) /* Not present */
		{
			if (dbg)
				debug("PDP not present\n");
			status = 1;
			goto done;
		}

		pd = pdpe & 0x000FFFFFFFFFF000ULL;
	}
	else
	{
		pd = cr3 & ~0xfff;
	}

	if (paging_levels >= 2)
	{
		maddr_t offset = (vaddr >> 21) & ((1<<9)-1);
		uint64_t pde;
		pde = kdump_read_uint64_maddr(pd + 8*offset);
		if (dbg) {
			debug("PD @ %"PRIxMADDR"\n", pd);
			debug("PD[%"PRIxMADDR"] @ %"PRIxMADDR" = %"PRIx64"\n", offset,	pd + 8*offset,	pde);
		}
		if (!(pde&1)) /* Not present */
		{
			if (dbg)
				debug("PD not present\n");
			status = 1;
			goto done;
		}

		if (pde&0x80ULL) /* 2M page */
		{
			//debug("2M mapping\n");
			page = pde & 0x0000000FFFF00000ULL;
			*maddr = page | (vaddr&((1<<21)-1));
			goto done;
		}
		else
		{
			pt = pde & 0x000FFFFFFFFFF000ULL;
		}
	}
	else
	{
		goto done;
	}


	{
		maddr_t offset = (vaddr >> 12) & ((1<<9)-1);
		uint64_t pte;
		pte = kdump_read_uint64_maddr(pt + 8*offset);
		if (dbg) {
			debug("PT @ %"PRIxMADDR"\n", pt);
			debug("PT[%"PRIxMADDR"] @ %"PRIxMADDR" = %"PRIx64"\n", offset, pt + 8*offset,	pte);
		}
		if (!(pte&1)) /* Not present */
		{
			if (dbg)
				debug("PT not present\n");
			status = 1;
			goto done;
		}

		page = pte & 0x000FFFFFFFFFF000ULL;

		*maddr = page | (vaddr&((1<<12)-1));
	}

done:
	if (status) {
		if (!dbg) {
			dbg = 1;
			goto debug_retry;
		}
		debug("Error: In address translation\n");
	}
	if (dbg) {
		debug("vaddr %"PRIxVADDR" ==> maddr %"PRIxMADDR"\n", vaddr, *maddr);
	}
	return status;
}
