/* Copyright (c) 2007, XenSource, Inc. - All rights reserved. */

#ifndef SYMBOLS_H
#define SYMBOLS_H

#include "types.h"

struct symbol {
    vaddr_t address;
    char type;
    char *name;
    struct symbol *next;
};

struct symbol_table {
	vaddr_t lowest_kernel_address;
	struct symbol *symbol_table;
	struct symbol *offset_table;

	vaddr_t kernel_stext, kernel_etext;
	vaddr_t kernel_sinittext, kernel_einittext;

	vaddr_t kernel_hypercallpage;
};

extern int is_kernel_text(struct symbol_table *symtab, vaddr_t addr);

extern struct symbol *symtab_lookup_address(struct symbol_table *symtab, vaddr_t address);

extern struct symbol *symtab_lookup_name(struct symbol_table *symtab, const char *name);

extern void print_symbol(FILE *f, struct symbol_table *symtab, vaddr_t addr);

extern struct symbol_table *symtab_parse(const char *symtab, int domnr);

extern void symtab_free(struct symbol_table *symtab);

extern int have_required_symbols;

/* The following are only valid if have_required_symbols is true. */

#define ASSERT_REQUIRED_SYMBOLS(__ret__) \
if (!have_required_symbols) \
{ \
	fprintf(debug, "ERROR: attempt to access unavailable symbols %s:%d\n", __FILE__, __LINE__); \
	return __ret__; \
}

extern vaddr_t conring, conringp, conringc;
extern vaddr_t idle_vcpu, per_cpu__curr_vcpu;
extern vaddr_t domain_list, __context_switch;

extern vaddr_t DOMAIN_sizeof, DOMAIN_id, DOMAIN_shared_info;
extern vaddr_t DOMAIN_is_hvm, DOMAIN_is_privileged, DOMAIN_is_32bit_pv, DOMAIN_has_32bit_shinfo;
extern vaddr_t DOMAIN_vcpus, DOMAIN_next;

extern vaddr_t VCPU_sizeof, VCPU_vcpu_id, VCPU_processor;
extern vaddr_t VCPU_pause_flags, VCPU_thread_flags, VCPU_user_regs;
extern vaddr_t VCPU_cr3;

extern vaddr_t CPUINFO_sizeof;

extern vaddr_t SHARED_max_pfn, SHARED_pfn_to_mfn_list_list;

extern vaddr_t XEN_virt_start, XEN_page_offset;

#endif /* SYMBOLS_H */
