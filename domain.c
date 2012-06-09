/* Copyright (c) 2007, XenSource, Inc. - All rights reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kdump.h"
#include "memory.h"
#include "symbols.h"

/* XXX: hardcoded. differs on IA64 */
#define MAX_VIRT_CPUS 32

/* XXX: duplicates elf.c:allocate_cpus */
/* Allocate `dump->cpus' to handle `nr' cpus. */
static int allocate_vcpus(struct domain *d, int nr)
{
	void *tmp;

	if (d->nr_vcpus>=nr)
		return 0;

	tmp = realloc(d->vcpus, nr*sizeof(struct cpu_state));
	if (tmp == NULL)
		return 1;

	d->vcpus = tmp;

	tmp = realloc(d->guest_cpus, nr*sizeof(struct cpu_state));
	if (tmp == NULL)
		return 1;

	d->guest_cpus = tmp;

	/* Zero the new cpu(s) */
	memset(&d->vcpus[d->nr_vcpus], 0, (nr-d->nr_vcpus)*sizeof(struct cpu_state));
	memset(&d->guest_cpus[d->nr_vcpus], 0, (nr-d->nr_vcpus)*sizeof(struct cpu_state));

	d->nr_vcpus = nr;

	return 0;
}

static int allocate_domains(int nr)
{
	void *tmp;

	if (dump->nr_domains>=nr)
		return 0;

	//printf("allocating domains from %d to %d\n", dump->nr_domains, nr);

	tmp = realloc(dump->domains, nr*sizeof(struct domain));
	if (tmp == NULL)
		return 1;

	dump->domains = tmp;

	/* Zero the new domain(s) */
	memset(&dump->domains[dump->nr_domains], 0, (nr-dump->nr_domains)*sizeof(struct domain));

	dump->nr_domains = nr;

	return 0;

}

void free_domain(struct domain *domain)
{
	free(domain->vcpus);
	symtab_free(domain->symtab);
	domain->vcpus=0;
}

// FIXME these two symbols better be exposed in XEN symbols
#define SHARED_compat_pfn_to_mfn_list_list 0x910
#define SHARED_compat_max_pfn 0x90c


static int parse_domain(vaddr_t domain, int nr_symtabs, const char **symtabs)
{
	unsigned char tmp[DOMAIN_sizeof];
	struct domain *d;
	int i;
	unsigned int max_vcpus;
	vaddr_t vcpu_array;
	struct symbol *high_memory_s;

	ASSERT_REQUIRED_SYMBOLS(1);

	if (kdump_read_vaddr(NULL, domain, tmp, DOMAIN_sizeof) != DOMAIN_sizeof)
	{
		fprintf(debug, "Failed to read domain info\n");
		return 1;
	}

	if (allocate_domains(dump->nr_domains+1))
	{
		fprintf(debug, "failed to allocate memory for domain\n");
		return 1;
	}

	d = &dump->domains[dump->nr_domains-1];

	d->domid = *(uint16_t*)(tmp+DOMAIN_id);
	d->v_domain_info = domain;
	d->v_shared_info = kdump_read_pointer_vaddr(NULL, domain+DOMAIN_shared_info);
	d->has_32bit_shinfo = kdump_read_pointer_vaddr(NULL, domain+DOMAIN_has_32bit_shinfo);
	d->is_hvm = kdump_read_uint8_vaddr(NULL, domain+DOMAIN_is_hvm);
	d->is_privileged = kdump_read_uint8_vaddr(NULL, domain+DOMAIN_is_privileged);
	d->is_32bit_pv = kdump_read_uint8_vaddr(NULL, domain+DOMAIN_is_32bit_pv);

	max_vcpus = kdump_read_uint32_vaddr(NULL, domain+DOMAIN_max_vcpus);
	vcpu_array = kdump_read_pointer_vaddr(NULL, domain+DOMAIN_vcpus);

	for(i=0; i<max_vcpus ;i++) {
		vaddr_t vcpu_info = kdump_read_pointer_vaddr(NULL, vcpu_array+(i*kdump_sizeof_pointer(dump)));
		struct cpu_state *vcpu;

		/* XXX: doesn't properly handle sparse VCPU map. Not sure if that can occur */
		if (vcpu_info == 0)
			continue;

		if (allocate_vcpus(d, d->nr_vcpus+1))
		{
			fprintf(debug, "failed to allocate memory for DOM%d VCPU%d\n",
				d->domid, d->nr_vcpus+1);
			return 1;
		}
		vcpu = &d->vcpus[d->nr_vcpus-1];
		if (vcpu_info && kdump_parse_vcpu(vcpu, vcpu_info))
		{
			fprintf(debug, "failed to parse DOM%d VCPU%d\n",
				d->domid, vcpu->nr);
			return 1;
		}
		if (d->has_32bit_shinfo) {
			vcpu->bitnes = 32;
		} else {
			vcpu->bitnes = 64;
		}
	}
	if (d->has_32bit_shinfo) {
		d->shared_info.max_pfn = kdump_read_pfn_vaddr(d, d->v_shared_info + SHARED_compat_max_pfn);
		d->shared_info.pfn_to_mfn_list_list =
				kdump_read_pfn_vaddr(d,
						d->v_shared_info + SHARED_compat_pfn_to_mfn_list_list) << PAGE_SHIFT;

	} else {
		d->shared_info.max_pfn = kdump_read_pfn_vaddr(d, d->v_shared_info + SHARED_max_pfn);
		d->shared_info.pfn_to_mfn_list_list =
				kdump_read_pfn_vaddr(d,
					 d->v_shared_info + SHARED_pfn_to_mfn_list_list) << PAGE_SHIFT;
	}

	if (nr_symtabs >= d->domid && symtabs[d->domid])
	{
		d->symtab = symtab_parse(symtabs[d->domid], d->domid);
		if (d->symtab == NULL)
			fprintf(debug, "Failed to parse symbol table for domain %d = %s.\n",
				d->domid, symtabs[d->domid]);
		else
			fprintf(output, "Domain %d symbol table: %s\n", d->domid, symtabs[d->domid]);
	}
	high_memory_s = symtab_lookup_name(d->symtab, "high_memory");
	if (!high_memory_s) {
		fprintf(debug, "Error Symbol not found high_memory\n");
	} else {
		if (d->has_32bit_shinfo) {
			d->high_memory = kdump_read_uint32_vaddr(d, high_memory_s->address);
		} else {
			d->high_memory = kdump_read_uint64_vaddr(d, high_memory_s->address);
		}
		fprintf(debug, "Symbol high_memory fount 0x%llx\n", d->high_memory);
	}

	if (kdump_parse_guest_cpus(d))
	{
		fprintf(debug, "failed to parse DOM%d guest cpus\n",
			d->domid);
	}

	return 0;
}

int parse_domain_list(int nr_symtabs, const char **symtabs)
{
	vaddr_t domain;
	struct domain *d;
	struct cpu_state *v, *p;

	if (!have_required_symbols)
		return 1;

	domain = kdump_read_pointer_vaddr(NULL, domain_list);

	while(domain != 0)
	{
		if (parse_domain(domain, nr_symtabs, symtabs))
		{
			fprintf(debug, "Failed to parse domain at %"PRIxVADDR"\n",
				domain);
			return 1;
		}
		domain = kdump_read_pointer_vaddr(NULL, domain+DOMAIN_next);
	}

	for_each_domain(d)
	{
		for_each_vcpu(d, v)
		{
			v->virtual.domain = d;

			for_each_pcpu(p)
			{
				if (p->physical.v_curr_vcpu == v->virtual.v_struct_vcpu)
					p->physical.curr_vcpu = v;
				if (p->physical.v_current == v->virtual.v_struct_vcpu)
					p->physical.current = v;
			}
		}
		for_each_guest_cpu(d, v)
		{
			v->virtual.domain = d;
		}
	}

	return 0;
}
