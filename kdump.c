/* Copyright (c) 2007, XenSource, Inc. - All rights reserved. */

#include <sys/types.h>
#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <fcntl.h>

#include "kdump.h"
#include "memory.h"
#include "symbols.h"

size_t kdump_read(void *buf, off64_t offset, size_t length)
{
	int fd = dump->fd;

	if (lseek64(fd, offset, SEEK_SET) != offset) {
		printf("failed to seek to %"PRIx64"\n", offset);
		return 0;
	}

	return read(fd, buf, length);
}

static inline int is_elf(const unsigned char *ident)
{
        /*
         * Since we are only accessing the e_ident field we can
         * acccess the bytes directly without needing to figure out
         * which version of Elf*_Ehdr structure to use.
         */
        return ( ident[EI_MAG0] == ELFMAG0 &&
                 ident[EI_MAG1] == ELFMAG1 &&
                 ident[EI_MAG2] == ELFMAG2 &&
                 ident[EI_MAG3] == ELFMAG3 );
}

void close_dump()
{
	struct domain *d;

	if (dump == NULL)
		return;

	free(dump->machine_memory);
	free(dump->cpus);
	free(dump->xen_extra_version);
	free(dump->xen_changeset);
	free(dump->xen_compiler);
	free(dump->xen_compile_date);
	free(dump->xen_compile_time);
	close(dump->fd);

	symtab_free(dump->symtab);

	for_each_domain(d)
		free_domain(d);

	free(dump->domains);
	dump->domains = NULL;

	free(dump);
}

int parse_idle_vcpus()
{
	struct cpu_state *pcpu;
	vaddr_t va;

	ASSERT_REQUIRED_SYMBOLS(1);

	va = idle_vcpu;

	for_each_pcpu(pcpu)
	{
		pcpu->physical.v_idle_vcpu = kdump_read_pointer_vaddr(NULL, va);
		va += kdump_sizeof_pointer(dump);
	}

	va = per_cpu__curr_vcpu;

	for_each_pcpu(pcpu)
	{
		pcpu->physical.v_curr_vcpu = kdump_read_pointer_vaddr(NULL, va);
		va += kdump_sizeof_percpu(dump);
	}

	return 0;
}


void open_dump(const char *fn, struct symbol_table *xen_symtab,
		       int nr_symtabs, const char **symtabs)
{
	extern int parse_dump();

	unsigned char ident[EI_NIDENT];
	int fd, i;

	fd = open(fn, O_RDONLY|O_LARGEFILE);
	if (fd == -1) {
		fprintf(debug, "failed to open %s: %s\n", fn, strerror(errno));
		return;
	}

	i = read(fd, ident, EI_NIDENT);
	if (i != EI_NIDENT) {
		fprintf(debug, "failed to read elf header: %s\n", strerror(errno));
		return;
	}

	if (!is_elf(ident)) {
		fprintf(debug, "not an elf file\n");
		return;
	}

	dump = malloc(sizeof(*dump));
	if (dump == NULL) {
		fprintf(debug, "out of memory");
		return;
	}
	memset(dump, 0, sizeof(*dump));

	dump->fd = fd;
	dump->symtab = xen_symtab;

	switch ( ident[EI_CLASS] ) {
	case ELFCLASS32:
		if (parse_dump(dump))
		{
			fprintf(debug,  "Error 32 bit ELF dumps are not supported.\n");
			fprintf(debug,  "Use kexec with --elf64-core-headers parameter.\n");
			fprintf(stderr, "Error 32 bit ELF dumps are not supported.\n");
			fprintf(stderr, "Use kexec with --elf64-core-headers parameter.\n");
			goto out_err;
		}
		break;
	case ELFCLASS64:
		if (parse_dump(dump))
		{
			fprintf(debug, "failed to parse 64 bit dump\n");
			goto out_err;
		}
		break;
	case ELFCLASSNONE:
	default:
		fprintf(debug, "invalid ELF class: %d\n", ident[EI_CLASS]);
		goto out_err;

	}

	if (have_required_symbols)
	{
		parse_idle_vcpus(dump);

		parse_domain_list(nr_symtabs, symtabs);
	}

	return;

 out_err:
	close_dump(dump);
	dump = NULL;
	return;
}

void hex_dump(int offset, void *ptr, int size) {
	char *data = ptr;
	int mask = 15;
	int i = 0;
	int c = 0;
	fprintf(debug, " ------------------ \n");
	fprintf(debug, "  %08x:", offset & ~mask);
	if (offset & mask) {
		for (i = 0; i < (offset & mask); i++) {
			fprintf(debug, "   ");
		}
	}
	for (c = 0; c < size; c++) {
		if ((i != 0) && ((i & mask) == 0)) {
			fprintf(debug, "\n  %08x:", offset + c);
		}
		fprintf(debug, " %02x", (unsigned char) data[c]);
		i++;
	}
	fprintf(debug, "\n");
}

mem_range_t * alloc_mem_range(void) {
	mem_range_t * mr;
	mr = malloc(sizeof(mem_range_t));
	if (!mr) {
		fprintf(debug, "Error unable to allocate mem_range_t\n");
		exit(-1);
	}
	memset(mr, '\0', sizeof(mem_range_t));
	return mr;
}

void free_mem_range(mem_range_t *mr_first) {
	mem_range_t *mr, *next;
	mr = mr_first;
	while (mr) {
		next = mr->next;
		free(mr);
		mr = next;
	}
}
