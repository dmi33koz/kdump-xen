/* Copyright (c) 2007, XenSource, Inc. - All rights reserved. */

/* Code shared with xenctx.c in Xen is dual licensed under the GPL. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kdump.h"
#include "symbols.h"

#include "hypercall-names.h"

#define DUMP_ON_SANITY_CHECK (0)

int is_kernel_text(struct symbol_table *symtab, vaddr_t addr)
{
    if (symtab == NULL)
	return 0;

    if (symtab->symbol_table == NULL)
        return (addr > symtab->lowest_kernel_address);

    if (symtab->kernel_stext && symtab->kernel_etext &&
	addr >= symtab->kernel_stext &&
        addr <= symtab->kernel_etext)
        return 1;
    if (symtab->kernel_hypercallpage &&
	addr >= symtab->kernel_hypercallpage &&
        addr <= symtab->kernel_hypercallpage + 4096)
        return 1;
    if (symtab->kernel_sinittext && symtab->kernel_einittext &&
	addr >= symtab->kernel_sinittext &&
        addr <= symtab->kernel_einittext)
        return 1;

    return 0;
}

static void __insert_symbol(struct symbol **head, struct symbol *symbol)
{
    static struct symbol *prev = NULL;
    struct symbol *s = *head;

    /* The System.map is usually already sorted... */
    if (prev
        && prev->address < symbol->address
        && (!prev->next || prev->next->address > symbol->address)) {
        s = prev;
    } else {
        /* ... otherwise do crappy/slow search for the correct place */
        while(s && s->next && s->next->address < symbol->address)
            s = s->next;
    }

    if (s == NULL || (s == *head && symbol->address < s->address))
    {
	    symbol->next = s;
	    *head = symbol;
    }
    else
    {
	    symbol->next = s->next;
	    s->next = symbol;
    }
    prev = symbol;
}

static void insert_symbol(struct symbol_table *symtab, struct symbol *symbol)
{
	__insert_symbol(&symtab->symbol_table, symbol);
}
static void insert_offset(struct symbol_table *symtab, struct symbol *symbol)
{
//	fprintf(debug, "offset %s=%"PRIxVADDR"\n",
//		symbol->name, symbol->address);
	__insert_symbol(&symtab->offset_table, symbol);
}


struct symbol *symtab_lookup_address(struct symbol_table *symtab, vaddr_t address)
{
    struct symbol *s = symtab->symbol_table;

    if (symtab == NULL)
	    return NULL;

    while(s && s->next && s->next->address < address)
        s = s->next;

    if (s && s->address < address)
        return s;

    return NULL;
}

static struct symbol *__symtab_lookup_name(struct symbol *s, const char *name)
{
	while(s) {
		if (strcmp(s->name, name)==0)
			return s;
		s = s->next;
	}

	return NULL;
}

struct symbol *symtab_lookup_name(struct symbol_table *symtab, const char *name)
{
	if (!symtab) {
		return NULL;
	}
	return __symtab_lookup_name(symtab->symbol_table, name);
}

static const char *hypercall_name(int nr)
{
	if ( nr < sizeof(hypercall_names)/sizeof(hypercall_names[0]) )
		return hypercall_names[nr];
	return "unknown";
}

void print_symbol(FILE *f, struct symbol_table *symtab, vaddr_t addr)
{
    struct symbol *s;

    if (symtab == NULL)
	return;

    if (!is_kernel_text(symtab, addr))
        return;

    s = symtab_lookup_address(symtab, addr);

    if (s==NULL)
        return;

    if (addr==s->address)
        fprintf(f, "%s", s->name);
    else
        fprintf(f, "%s+%#x", s->name, (unsigned int)(addr - s->address));

    if (strcmp(s->name, "hypercall_page") == 0)
    {
	int nr = (addr - s->address)/32;
	fprintf(f, " (%d: %s)", nr, hypercall_name(nr));
    }
}

void __symtab_free(struct symbol *s)
{
    struct symbol *next;

    while(s) {
	    next = s->next;
	    free(s->name);
	    free(s);
	    s = next;
    }
}
void symtab_free(struct symbol_table *symtab)
{
	if (symtab == NULL)
		return;

	__symtab_free(symtab->symbol_table);
	symtab->symbol_table = NULL;

	__symtab_free(symtab->offset_table);
	symtab->offset_table = NULL;

	free(symtab);
}

static void symtab_sanity_check(const char * p, struct symbol *s)
{
	vaddr_t last = 0ULL;

	if (DUMP_ON_SANITY_CHECK)
		fprintf(stderr, "Dumping %s table\n", p);

	while(s)
	{
		if (s->address < last)
			fprintf(stderr, "symbol table not sorted\n");
		if (DUMP_ON_SANITY_CHECK)
			fprintf(stderr, "%#016"PRIxVADDR" %s\n", s->address, s->name);
		s = s->next;
	}
}

vaddr_t conring, conring_size, conringp, conringc;
vaddr_t idle_vcpu, per_cpu__curr_vcpu;
vaddr_t domain_list, __context_switch;

vaddr_t DOMAIN_sizeof, DOMAIN_id, DOMAIN_shared_info;
vaddr_t DOMAIN_is_hvm, DOMAIN_is_privileged, DOMAIN_is_32bit_pv, DOMAIN_has_32bit_shinfo;
vaddr_t DOMAIN_vcpus, DOMAIN_next, DOMAIN_max_vcpus;

vaddr_t VCPU_sizeof, VCPU_vcpu_id, VCPU_processor;
vaddr_t VCPU_pause_flags, VCPU_thread_flags, VCPU_user_regs;
vaddr_t VCPU_cr3;

vaddr_t CPUINFO_sizeof;
vaddr_t CPUINFO_processor_id, CPUINFO_current_vcpu;

vaddr_t SHARED_max_pfn, SHARED_pfn_to_mfn_list_list;

vaddr_t XEN_virt_start, XEN_page_offset;

static const struct required_symbol
{
	const char *n;
	vaddr_t *address;
	int required; /* Yes, optional required symbols... */
} required_symbols[] =
{
#define REQUIRED(x) { .n = #x , .address = &x, .required = 1 }
#define OPTIONAL(x) { .n = #x , .address = &x, .required = 0 }
	REQUIRED(conring),
	REQUIRED(conring_size),
	REQUIRED(conringp),
	REQUIRED(conringc),
	REQUIRED(idle_vcpu),
	REQUIRED(per_cpu__curr_vcpu),
	REQUIRED(domain_list),
	REQUIRED(__context_switch),

	REQUIRED(DOMAIN_sizeof),
	REQUIRED(DOMAIN_id),
	REQUIRED(DOMAIN_shared_info),
	REQUIRED(DOMAIN_is_hvm),
	REQUIRED(DOMAIN_is_privileged),
	REQUIRED(DOMAIN_is_32bit_pv),
	REQUIRED(DOMAIN_has_32bit_shinfo),
	REQUIRED(DOMAIN_vcpus),
	REQUIRED(DOMAIN_next),
	REQUIRED(DOMAIN_max_vcpus),

	REQUIRED(VCPU_sizeof),
	REQUIRED(VCPU_vcpu_id),
	REQUIRED(VCPU_processor),
	REQUIRED(VCPU_pause_flags),
	REQUIRED(VCPU_thread_flags),
	REQUIRED(VCPU_user_regs),
	REQUIRED(VCPU_cr3),

	REQUIRED(CPUINFO_sizeof),
	REQUIRED(CPUINFO_processor_id),
	REQUIRED(CPUINFO_current_vcpu),

	REQUIRED(SHARED_max_pfn),
	REQUIRED(SHARED_pfn_to_mfn_list_list),

	REQUIRED(XEN_virt_start),
	REQUIRED(XEN_page_offset),

	{ .n = NULL, }
#undef REQUIRED
#undef OPTIONAL
};

int have_required_symbols;

static int load_required_symbols(struct symbol_table *symtab)
{
	const struct required_symbol *r;
	struct symbol *s;
	int rc=0;

	for (r=&required_symbols[0]; r->n; r++)
	{
		if ((s = __symtab_lookup_name(symtab->symbol_table, r->n)) == NULL &&
		    (s = __symtab_lookup_name(symtab->offset_table, r->n)) == NULL)
		{
			if (r->required)
			{
				rc++;
				fprintf(debug, "Required symbol %s not found.\n", r->n);
			}
		}
		else
		{
			*r->address = s->address;
		}
	}

	have_required_symbols = (rc==0);

	return rc;
}

struct symbol_table *symtab_parse(const char *symtab_file, int domnr)
{
    char line[256];
    char *p;
    struct symbol_table *symtab;
    struct symbol *symbol;
    FILE *f;
    int rc;
    FILE *err = domnr == -1 ? stderr : debug;

    symtab = malloc(sizeof(struct symbol_table));
    if ( symtab == NULL )
    {
	    fprintf(err, "unable to allocate memory for symtab %s\n", symtab_file);
	    return NULL;
    }

    memset(symtab, 0, sizeof(struct symbol_table));

    if ( domnr == -1 )
    {
#if defined (__i386__)
	    symtab->lowest_kernel_address = 0xFF000000UL;
#elif defined (__x86_64__)
	    symtab->lowest_kernel_address = 0xffff800000000000UL;
#elif defined (__ia64__)
	    symtab->lowest_kernel_address = 0xa000000000000000UL;
#endif
    }
    else
    {
#if defined (__i386__)
	    symtab->lowest_kernel_address = 0xC0000000UL;
#elif defined (__x86_64__)
	    symtab->lowest_kernel_address = 0xffff880000000000UL;
#elif defined (__ia64__)
#error "lowest Linux kernel address for __ia64__"
#endif
    }

    f = fopen(symtab_file, "r");
    if( f == NULL )
    {
	    fprintf(err, "unable to open symtab %s\n", symtab_file);
	    free(symtab);
	    return NULL;
    }

    while(!feof(f)) {
        if(fgets(line,256,f)==NULL)
            break;

        symbol = malloc(sizeof(*symbol));

        /* need more checks for syntax here... */
        symbol->address = strtoull(line, &p, 16);
        p++;
        symbol->type = *p++;
        p++;

        /* in the future we should handle the module name
         * being appended here, this would allow us to use
         * /proc/kallsyms as our symbol table
         */
        if (p[strlen(p)-1] == '\n')
            p[strlen(p)-1] = '\0';

	if (p[0] == '+')
	{
		symbol->name = strdup(p+1);
		insert_offset(symtab, symbol);
	}
	else
	{
		symbol->name = strdup(p);
		insert_symbol(symtab, symbol);
	}

        if (strcmp(symbol->name, "_stext") == 0)
            symtab->kernel_stext = symbol->address;
        else if (strcmp(symbol->name, "_etext") == 0)
            symtab->kernel_etext = symbol->address;
        else if (strcmp(symbol->name, "_sinittext") == 0)
            symtab->kernel_sinittext = symbol->address;
        else if (strcmp(symbol->name, "_einittext") == 0)
            symtab->kernel_einittext = symbol->address;
        else if (strcmp(symbol->name, "hypercall_page") == 0)
            symtab->kernel_hypercallpage = symbol->address;
    }

    if (domnr == -1)
    {
	rc = load_required_symbols(symtab);
	if (rc)
	{
	    fprintf(debug, "%d required %s not found. Some functionality will be disabled.\n",
		    rc, rc == 1 ? "symbol" : "symbols");
	}
    }

    symtab_sanity_check("symbol", symtab->symbol_table);
    symtab_sanity_check("offset", symtab->offset_table);

    fclose(f);

    return symtab;
}
