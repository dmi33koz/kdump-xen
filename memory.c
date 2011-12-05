/* Copyright (c) 2007, XenSource, Inc. - All rights reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kdump.h"
#include "memory.h"

/* Locate struct memory_extent containing a specific address. */
static struct memory_extent *locate_maddr(struct dump *dump, maddr_t maddr)
{
	int i;
	struct memory_extent *mext;

	for (i=0; i<dump->nr_machine_memory; i++) {
		mext = &dump->machine_memory[i];
		if (mext->maddr <= maddr && maddr < mext->maddr+mext->length)
			return mext;
	}
	fprintf(debug, "could not locate machine address extent containing %"PRIxMADDR"\n",
		maddr);

	return NULL;
}

/* Read an arbitrary number of bytes from a machine address. */
/* FIXME: does not handle reads which cross extents. */
size_t kdump_read_maddr(struct dump *dump, maddr_t maddr, void *buf, size_t size)
{
	struct memory_extent *mext;
	off64_t offset;

	mext = locate_maddr(dump, maddr);
	if (mext == NULL)
		return 0;

	offset = maddr - mext->maddr + mext->offset;

	if (lseek64(dump->fd, offset, SEEK_SET) != offset) {
		fprintf(debug, "failed to seek to %"PRIx64"\n", offset);
		return 0;
	}
	return read(dump->fd, buf, size);
}
extern size_t kdump_read_vaddr_cpu(struct dump *dump, struct cpu_state *cpu,
				   vaddr_t vaddr, void *buf, size_t size)
{
	maddr_t maddr = kdump_virt_to_mach(dump, cpu, vaddr);

	if (maddr == -1ULL)
		return 0;

	return kdump_read_maddr(dump, maddr, buf, size);
}

/* Read a pfn sized value from a machine address */
pfn_t kdump_read_pfn_maddr(struct dump *dump, maddr_t maddr)
{
	vaddr_t ptr = 0;
	size_t sz_pfn = kdump_sizeof_pfn(dump);

	if (kdump_read_maddr(dump, maddr, &ptr, sz_pfn) != sz_pfn)
	{
		fprintf(debug, "failed read pfn\n");
		return 0;
	}

	return ptr;
}

pfn_t kdump_read_pfn_vaddr_cpu(struct dump *dump, struct cpu_state *cpu, vaddr_t vaddr)
{
	maddr_t maddr = kdump_virt_to_mach(dump, cpu, vaddr);
	return kdump_read_pfn_maddr(dump, maddr);
}

/* Read a pointer sized value from a machine address */
vaddr_t kdump_read_pointer_maddr(struct dump *dump, maddr_t maddr)
{
	vaddr_t ptr = 0;
	size_t sz_ptr = kdump_sizeof_pointer(dump);

	if (kdump_read_maddr(dump, maddr, &ptr, sz_ptr) != sz_ptr)
	{
		fprintf(debug, "failed read pointer\n");
		return 0;
	}

	return ptr;
}

vaddr_t kdump_read_pointer_vaddr_cpu(struct dump *dump, struct cpu_state *cpu, vaddr_t vaddr)
{
	maddr_t maddr = kdump_virt_to_mach(dump, cpu, vaddr);
	return kdump_read_pointer_maddr(dump, maddr);
}


/* Read a NULL terminated string from a machine address. */
char *kdump_read_string_maddr(struct dump *dump, maddr_t maddr)
{
	struct memory_extent *mext;
	off64_t lim, offset;
	int len;
	char *str;
	int err;

	mext = locate_maddr(dump, maddr);
	if (mext == NULL)
		return NULL;

	offset = maddr - mext->maddr + mext->offset;
	lim = mext->maddr + mext->length - maddr;
	if (lseek64(dump->fd, offset, SEEK_SET) != offset) {
		fprintf(debug, "failed to seek to %"PRIx64"\n", offset);
		return NULL;
	}

	str = strdup("");
	len = 1;

	while(lim > 0) {
#define BLOCK 16
		char buf[BLOCK+1];
		char *tmp;
		int newlen;

		buf[BLOCK] = 0;

		err = read(dump->fd, buf, BLOCK);
		if (err == -1)
			return NULL;

		newlen = strlen(buf);
		if (err < newlen)
			newlen = err;

		//fprintf(debug, "read %d bytes with strlen %d\n", err, newlen);

		tmp = realloc(str,len+newlen);
		if (tmp == NULL)
			return NULL;
		str = tmp;

		strncat(str, buf, newlen);

		len += newlen;
		lim -= 0;
		if(newlen != err)
			break;
#undef BLOCK
	}

	return str;
}

uint8_t kdump_read_uint8_maddr(struct dump *dump, maddr_t maddr)
{
	uint8_t res;

	if (kdump_read_maddr(dump, maddr, &res, sizeof(uint8_t)) != sizeof(uint8_t))
	{
		fprintf(debug, "failed read uint8_t\n");
		return 0;
	}
	return res;
}
uint8_t kdump_read_uint8_vaddr_cpu(struct dump *dump, struct cpu_state *cpu, vaddr_t vaddr)
{
	maddr_t maddr = kdump_virt_to_mach(dump, cpu, vaddr);
	return kdump_read_uint8_maddr(dump, maddr);
}

uint16_t kdump_read_uint16_maddr(struct dump *dump, maddr_t maddr)
{
	uint16_t res;

	if (kdump_read_maddr(dump, maddr, &res, sizeof(uint16_t)) != sizeof(uint16_t))
	{
		fprintf(debug, "failed read uint16_t\n");
		return 0;
	}
	return res;
}
uint16_t kdump_read_uint16_vaddr_cpu(struct dump *dump, struct cpu_state *cpu, vaddr_t vaddr)
{
	maddr_t maddr = kdump_virt_to_mach(dump, cpu, vaddr);
	return kdump_read_uint16_maddr(dump, maddr);
}

uint32_t kdump_read_uint32_maddr(struct dump *dump, maddr_t maddr)
{
	uint32_t res;

	if (kdump_read_maddr(dump, maddr, &res, sizeof(uint32_t)) != sizeof(uint32_t))
	{
		fprintf(debug, "failed read uint32_t\n");
		return 0;
	}
	return res;
}
uint32_t kdump_read_uint32_vaddr_cpu(struct dump *dump, struct cpu_state *cpu, vaddr_t vaddr)
{
	maddr_t maddr = kdump_virt_to_mach(dump, cpu, vaddr);
	return kdump_read_uint32_maddr(dump, maddr);
}

uint64_t kdump_read_uint64_maddr(struct dump *dump, maddr_t maddr)
{
	uint64_t res;

	if (kdump_read_maddr(dump, maddr, &res, sizeof(uint64_t)) != sizeof(uint64_t))
	{
		fprintf(debug, "failed read uint64_t\n");
		return 0;
	}
	return res;
}
uint64_t kdump_read_uint64_vaddr_cpu(struct dump *dump, struct cpu_state *cpu, vaddr_t vaddr)
{
	maddr_t maddr = kdump_virt_to_mach(dump, cpu, vaddr);
	return kdump_read_uint64_maddr(dump, maddr);
}
