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
		debug("failed to open %s: %s\n", fn, strerror(errno));
		return;
	}

	i = read(fd, ident, EI_NIDENT);
	if (i != EI_NIDENT) {
		debug("failed to read elf header: %s\n", strerror(errno));
		return;
	}

	if (!is_elf(ident)) {
		debug("not an elf file\n");
		return;
	}

	dump = malloc(sizeof(*dump));
	if (dump == NULL) {
		debug("out of memory");
		return;
	}
	memset(dump, 0, sizeof(*dump));

	dump->fd = fd;
	dump->symtab = xen_symtab;

	switch ( ident[EI_CLASS] ) {
	case ELFCLASS32:
		if (parse_dump(dump))
		{
			debug( "Error 32 bit ELF dumps are not supported.\n");
			debug( "Use kexec with --elf64-core-headers parameter.\n");
			fprintf(stderr, "Error 32 bit ELF dumps are not supported.\n");
			fprintf(stderr, "Use kexec with --elf64-core-headers parameter.\n");
			goto out_err;
		}
		break;
	case ELFCLASS64:
		if (parse_dump(dump))
		{
			debug("failed to parse 64 bit dump\n");
			goto out_err;
		}
		break;
	case ELFCLASSNONE:
	default:
		debug("invalid ELF class: %d\n", ident[EI_CLASS]);
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

void __hex_dump(const char *file, const char *function, int line, int offset, void *ptr, int size) {
	char *data = ptr;
	int mask = 15;
	int i = 0;
	int c = 0;
	fprintf(debug_file, "%s:%d %s() hex_dump:\n", file, line, function);
	fprintf(debug_file, "  %08x:", offset & ~mask);
	if (offset & mask) {
		for (i = 0; i < (offset & mask); i++) {
			fprintf(debug_file, "   ");
		}
	}
	for (c = 0; c < size; c++) {
		if ((i != 0) && ((i & mask) == 0)) {
			fprintf(debug_file, "\n  %08x:", offset + c);
		}
		fprintf(debug_file, " %02x", (unsigned char) data[c]);
		i++;
	}
	fprintf(debug_file, "\n");
}

mem_range_t * alloc_mem_range(void) {
	mem_range_t * mr;
	mr = malloc(sizeof(mem_range_t));
	if (!mr) {
		debug("Error unable to allocate mem_range_t\n");
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

int init_xen_memory_symbols() {
	struct symbol *sym;
	char *s_name;

	if (dump->xen_phys_start == 0) {
		debug("Error:!!! xen_phys_start is 0. We cannot access xen addresses without it\n");
		return -1;
	}
	/*
	 * dump->pg_table MUST be used for Xen address translation.
	 * Must not rely on cr3 of any CPU for Xen address translation.
	 */
	s_name = "idle_pg_table_4";
	sym = symtab_lookup_name(dump->symtab, s_name);
	if (!sym) {
		s_name = "idle_pg_table";
		sym = symtab_lookup_name(dump->symtab, s_name);
	}
	if (!sym) {
		debug("Error Symbols not found idle_pg_table_4 or idle_pg_table\n");
		return -1;
	} else {
		debug("sym %s address = %" PRIx64 "\n", s_name, sym->address);
		dump->pg_table = kdump_virt_to_mach(NULL, sym->address);
		debug("Xen: pg_table maddr = %#" PRIxMADDR "\n", dump->pg_table);
	}
	return 0;
}
