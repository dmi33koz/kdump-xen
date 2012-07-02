/* Copyright (c) 2007, XenSource, Inc. - All rights reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kdump.h"
#include "memory.h"

/* Locate struct memory_extent containing a specific address. */
static struct memory_extent *locate_maddr(maddr_t maddr)
{
	int i;
	struct memory_extent *mext;

	for (i=0; i<dump->nr_machine_memory; i++) {
		mext = &dump->machine_memory[i];
		if (mext->maddr <= maddr && maddr < mext->maddr+mext->length)
			return mext;
	}
	debug("could not locate machine address extent containing %"PRIxMADDR"\n",
		maddr);

	return NULL;
}

#define DUMP_CACHE_SIZE 8
struct dump_cache_entry {
	char *buf;
	int n_hits;
	maddr_t mfn;
} dump_cache[DUMP_CACHE_SIZE];

static int cache_initialized = 0;

static void init_cache() {
	int i;
	for (i =0; i < DUMP_CACHE_SIZE; i++) {
		dump_cache[i].buf = (char*)malloc(PAGE_SIZE);
		dump_cache[i].n_hits = 0;
		dump_cache[i].mfn = -1;
	}
}

int cache_hits = 0;

/* Read an arbitrary number of bytes from a machine address. */
/* FIXME: does not handle reads which cross extents. */
size_t kdump_read_maddr(maddr_t maddr, void *buf, size_t size)
{
	struct memory_extent *mext;
	off64_t offset;
	int least_used = 0;
	maddr_t mfn;
	int i;

	if (!cache_initialized) {
		init_cache();
		cache_initialized = 1;
	}

	mext = locate_maddr(maddr);
	if (mext == NULL)
		return 0;

	if (((maddr & (PAGE_SIZE - 1)) + size)  > PAGE_SIZE) {

		offset = maddr - mext->maddr + mext->offset;

		if (lseek64(dump->fd, offset, SEEK_SET) != offset) {
			debug("failed to seek to %"PRIx64"\n", offset);
			return 0;
		}
		return read(dump->fd, buf, size);
	}
	// search mfn in cache
	mfn = maddr >> PAGE_SHIFT;
	for (i =0; i < DUMP_CACHE_SIZE; i++) {
		if (mfn == dump_cache[i].mfn) {
			cache_hits++;
			dump_cache[i].n_hits++;
			memcpy(buf, dump_cache[i].buf + (maddr & (PAGE_SIZE - 1)), size);
			return size;
		}
		if (dump_cache[least_used].n_hits > dump_cache[i].n_hits) {
			least_used = i;
		}
	}

	offset = (mfn << PAGE_SHIFT) - mext->maddr + mext->offset;

	if (lseek64(dump->fd, offset, SEEK_SET) != offset) {
		debug("failed to seek to %"PRIx64"\n", offset);
		return 0;
	}
	if (read(dump->fd, dump_cache[least_used].buf, PAGE_SIZE) != PAGE_SIZE) {
		dump_cache[least_used].mfn = -1;
		dump_cache[least_used].n_hits = 0;
		return 0;
	}
	dump_cache[least_used].mfn = mfn;
	dump_cache[least_used].n_hits = 1;
	memcpy(buf, dump_cache[least_used].buf + (maddr & (PAGE_SIZE - 1)), size);
	return size;
}

extern size_t kdump_read_vaddr_cpu(struct cpu_state *cpu,
				   vaddr_t vaddr, void *buf, size_t size)
{
	maddr_t maddr = kdump_virt_to_mach(cpu, vaddr);

	if (maddr == (maddr_t)-1ULL)
		return 0;

	return kdump_read_maddr(maddr, buf, size);
}

/* Read a pfn sized value from a machine address */
pfn_t kdump_read_pfn_maddr(struct domain *dom, maddr_t maddr)
{
	vaddr_t ptr = 0;
	size_t sz_pfn = kdump_sizeof_pfn(dom);

	if (kdump_read_maddr(maddr, &ptr, sz_pfn) != sz_pfn)
	{
		debug("failed read pfn\n");
		return 0;
	}

	return ptr;
}

pfn_t kdump_read_pfn_vaddr_cpu(struct domain *dom, struct cpu_state *cpu, vaddr_t vaddr)
{
	maddr_t maddr = kdump_virt_to_mach(cpu, vaddr);
	return kdump_read_pfn_maddr(dom, maddr);
}

/* Read a pointer sized value from a machine address */
vaddr_t kdump_read_pointer_maddr(maddr_t maddr)
{
	vaddr_t ptr = 0;
	size_t sz_ptr = kdump_sizeof_pointer(dump);

	if (kdump_read_maddr(maddr, &ptr, sz_ptr) != sz_ptr)
	{
		debug("failed read pointer\n");
		return 0;
	}

	return ptr;
}

vaddr_t kdump_read_pointer_vaddr_cpu(struct cpu_state *cpu, vaddr_t vaddr)
{
	maddr_t maddr = kdump_virt_to_mach(cpu, vaddr);
	return kdump_read_pointer_maddr(maddr);
}


/* Read a NULL terminated string from a machine address. */
char *kdump_read_string_maddr(maddr_t maddr)
{
	struct memory_extent *mext;
	off64_t lim, offset;
	int len;
	char *str;
	int err;

	mext = locate_maddr(maddr);
	if (mext == NULL)
		return NULL;

	offset = maddr - mext->maddr + mext->offset;
	lim = mext->maddr + mext->length - maddr;
	if (lseek64(dump->fd, offset, SEEK_SET) != offset) {
		debug("failed to seek to %"PRIx64"\n", offset);
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

		//debug("read %d bytes with strlen %d\n", err, newlen);

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

uint8_t kdump_read_uint8_maddr(maddr_t maddr)
{
	uint8_t res;

	if (kdump_read_maddr(maddr, &res, sizeof(uint8_t)) != sizeof(uint8_t))
	{
		debug("failed read uint8_t\n");
		return 0;
	}
	return res;
}
uint8_t kdump_read_uint8_vaddr_cpu(struct cpu_state *cpu, vaddr_t vaddr)
{
	maddr_t maddr = kdump_virt_to_mach(cpu, vaddr);
	return kdump_read_uint8_maddr(maddr);
}

uint16_t kdump_read_uint16_maddr(maddr_t maddr)
{
	uint16_t res;

	if (kdump_read_maddr(maddr, &res, sizeof(uint16_t)) != sizeof(uint16_t))
	{
		debug("failed read uint16_t\n");
		return 0;
	}
	return res;
}
uint16_t kdump_read_uint16_vaddr_cpu(struct cpu_state *cpu, vaddr_t vaddr)
{
	maddr_t maddr = kdump_virt_to_mach(cpu, vaddr);
	return kdump_read_uint16_maddr(maddr);
}

uint32_t kdump_read_uint32_maddr(maddr_t maddr)
{
	uint32_t res;

	if (kdump_read_maddr(maddr, &res, sizeof(uint32_t)) != sizeof(uint32_t))
	{
		debug("failed read uint32_t\n");
		return 0;
	}
	return res;
}
uint32_t kdump_read_uint32_vaddr_cpu(struct cpu_state *cpu, vaddr_t vaddr)
{
	maddr_t maddr = kdump_virt_to_mach(cpu, vaddr);
	return kdump_read_uint32_maddr(maddr);
}

uint64_t kdump_read_uint64_maddr(maddr_t maddr)
{
	uint64_t res;

	if (kdump_read_maddr(maddr, &res, sizeof(uint64_t)) != sizeof(uint64_t))
	{
		debug("failed read uint64_t\n");
		return 0;
	}
	return res;
}
uint64_t kdump_read_uint64_vaddr_cpu(struct cpu_state *cpu, vaddr_t vaddr)
{
	maddr_t maddr = kdump_virt_to_mach(cpu, vaddr);
	return kdump_read_uint64_maddr(maddr);
}
