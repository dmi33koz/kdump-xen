/* Copyright (c) 2007, XenSource, Inc. - All rights reserved. */

#include <stdint.h>

#include "kdump.h"
#include "memory.h"

int x86_virt_to_mach(maddr_t cr3, int paging_levels, vaddr_t vaddr, maddr_t *maddr)
{
	maddr_t pdp;
	maddr_t pd;
	maddr_t pt;
	maddr_t page;

	//debug("translating %"PRIxVADDR" with CR3 %"PRIx64" and %d levels of page table\n", vaddr, cr3, paging_levels);

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
		if (!(pml4e&1)) /* Not present */
		{
			debug("PML4 @ %"PRIx64"\n", cr3);
			debug("PML4[%"PRIxMADDR"] @ %"PRIxMADDR" = %"PRIx64" not present\n",
				offset, cr3 + 8*offset, pml4e);
			return 1;
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

		if (!(pdpe&1)) /* Not present */
		{
			debug("PDP @ %"PRIxMADDR"\n", pdp);
			debug("PDP[%"PRIxMADDR"] @ %"PRIxMADDR" = %"PRIx64" not present\n",
				offset,
				pdp + 8*offset,
				pdpe);
			return 1;
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

		if (!(pde&1)) /* Not present */
		{
			debug("PD @ %"PRIxMADDR"\n", pd);
			debug("PD[%"PRIxMADDR"] @ %"PRIxMADDR" = %"PRIx64" not present\n",
				offset,
				pd + 8*offset,
				pde);

			return 1;
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
		return 1;
	}


	{
		maddr_t offset = (vaddr >> 12) & ((1<<9)-1);
		uint64_t pte;
		pte = kdump_read_uint64_maddr(pt + 8*offset);

		if (!(pte&1)) /* Not present */
		{
			debug("PT @ %"PRIxMADDR"\n", pt);
			debug("PT[%"PRIxMADDR"] @ %"PRIxMADDR" = %"PRIx64" not present\n",
				offset,
				pt + 8*offset,
				pte);
			return 1;
		}

		page = pte & 0x000FFFFFFFFFF000ULL;

		*maddr = page | (vaddr&((1<<12)-1));
	}

 done:
	//debug("PAGE %"PRIxMADDR"\n", page);

	//debug("MADDR %"PRIxMADDR"\n", *maddr);

	return 0;
}
