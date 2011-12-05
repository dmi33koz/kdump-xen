/* Copyright (c) 2007, XenSource, Inc. - All rights reserved. */

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "kdump.h"
#include "memory.h"
#include "symbols.h"

size_t kdump_read(struct dump *dump, void *buf, off64_t offset, size_t length)
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

void close_dump(struct dump* dump)
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

	for_each_domain(dump, d)
		free_domain(d);

	free(dump->domains);
	dump->domains = NULL;

	free(dump);
}

int parse_idle_vcpus(struct dump *dump)
{
	struct cpu_state *pcpu;
	vaddr_t va;

	ASSERT_REQUIRED_SYMBOLS(1);

	va = idle_vcpu;

	for_each_pcpu(dump, pcpu)
	{
		pcpu->physical.v_idle_vcpu = kdump_read_pointer_vaddr(dump, NULL, va);
		va += kdump_sizeof_pointer(dump);
	}

	va = per_cpu__curr_vcpu;

	for_each_pcpu(dump, pcpu)
	{
		pcpu->physical.v_curr_vcpu = kdump_read_pointer_vaddr(dump, NULL, va);
		va += kdump_sizeof_percpu(dump);
	}

	return 0;
}


struct dump *open_dump(const char *fn, struct symbol_table *xen_symtab,
		       int nr_symtabs, const char **symtabs)
{
	extern int parse_dump_32(struct dump *dump);
	extern int parse_dump_64(struct dump *dump);

	unsigned char ident[EI_NIDENT];
	struct dump *dump;
	int fd, i;

	fd = open(fn, O_RDONLY|O_LARGEFILE);
	if (fd == -1) {
		fprintf(debug, "failed to open %s: %s\n", fn, strerror(errno));
		return NULL;
	}

	i = read(fd, ident, EI_NIDENT);
	if (i != EI_NIDENT) {
		fprintf(debug, "failed to read elf header: %s\n", strerror(errno));
		return NULL;
	}

	if (!is_elf(ident)) {
		fprintf(debug, "not an elf file\n");
		return NULL;
	}

	dump = malloc(sizeof(*dump));
	if (dump == NULL) {
		fprintf(debug, "out of memory");
		return NULL;
	}
	memset(dump, 0, sizeof(*dump));

	dump->fd = fd;
	dump->symtab = xen_symtab;

	switch ( ident[EI_CLASS] ) {
	case ELFCLASS32:
		if (parse_dump_32(dump))
		{
			fprintf(debug, "failed to parse 32 bit dump\n");
			goto out_err;
		}
		break;
	case ELFCLASS64:
		if (parse_dump_64(dump))
		{
			fprintf(debug, "failed to parse 64 bit dump\n");
			goto out_err;
		}
		break;
	case ELFCLASSNONE:
	default:
		fprintf(debug, "invalid ELF class: %d\n", ident[EI_CLASS]);
		return NULL;

	}

	if (have_required_symbols)
	{
		parse_idle_vcpus(dump);

		parse_domain_list(dump, nr_symtabs, symtabs);
	}

	return dump;

 out_err:
	close_dump(dump);
	return NULL;
}
