/* Copyright (c) 2007, XenSource, Inc. - All rights reserved. */

#ifndef __UTIL_KDUMP_H__
#define __UTIL_KDUMP_H__

#include <inttypes.h>
#include <stdio.h>

#include <sys/types.h>

#include "symbols.h"
#include "types.h"

struct dump;
struct domain;

struct cpu_state {
	unsigned long flags;
#define CPU_PHYSICAL      1<<0 /* otherwise virtual */
#define CPU_CORE_STATE    1<<1 /* basic state available */
#define CPU_EXTD_STATE    1<<2 /* extended state available, PCPU only */
#define CPU_RUNNING       1<<3 /* VCPU is currently running */
#define CPU_CONTEXT_SWITCH 1<<4 /* Is currently involved in a context switch. */

	int nr;

	union {
		struct {
			struct cpu_state *current, /**idle_vcpu,*/ *curr_vcpu;
			vaddr_t v_current, v_idle_vcpu, v_curr_vcpu;
		} physical;
		struct {
			vaddr_t v_struct_vcpu;
			int pcpu;
			struct domain *domain;
			uint64_t flags, arch_flags;
		} virtual;
	};

	union {
		struct {
			uint32_t ebx;
			uint32_t ecx;
			uint32_t edx;
			uint32_t esi;
			uint32_t edi;
			uint32_t ebp;
			uint32_t eax;
			uint16_t ds;
			uint16_t es;
			uint16_t fs;
			uint16_t gs;
			uint32_t orig_eax;
			uint32_t eip;
			uint16_t cs;
			uint32_t eflags;
			uint32_t esp;
			uint16_t ss;
			uint32_t cr[8];
		} x86_32;
		struct {
/* XXX check this */
			uint64_t r15;
			uint64_t r14;
			uint64_t r13;
			uint64_t r12;
			uint64_t r11;
			uint64_t r10;
			uint64_t r9;
			uint64_t r8;
			uint64_t rbx;
			uint64_t rcx;
			uint64_t rdx;
			uint64_t rsi;
			uint64_t rdi;
			uint64_t rbp;
			uint64_t rax;
			uint16_t ds;
			uint16_t es;
			uint16_t fs;
			uint16_t gs;
			uint64_t orig_rax;
			uint64_t rip;
			uint16_t cs;
			uint64_t rflags;
			uint64_t rsp;
			uint16_t ss;
			uint64_t cr[8];
		} x86_64;
	};
};

struct memory_extent {
	maddr_t maddr;
	vaddr_t vaddr;
	uint64_t length;
	off64_t offset;  /* offset within core file */
};

struct arch {
	/* Number of bytes in various type. */
	int sizeof_pointer;
	int sizeof_pfn;

	/* Size of the PERCPU region. */
	int sizeof_percpu;

	/* Return the limits of the Xen heap. */
	int (*heap_limits)(struct dump *dump, maddr_t *s, maddr_t *e);

	/* Parse Hypervisor state... */
	/* ...XEN_ELFNOTE_CRASH_INFO. */
	int (*parse_hypervisor)(struct dump *dump, void *note);

	/* Parse Physical CPU state... */
	/* ...NT_PRSTATUS ELF note `prs' and populate `cpu'. */
	int (*parse_prstatus)(struct dump *dump, void *prs, struct cpu_state *cpu);
	/* ...XEN_ELFNOTE_CRASH_REGS note `cr' and populate `cpu'. */
	int (*parse_crash_regs)(struct dump *dump, void *cr, struct cpu_state *cpu);

	/* Parse Virtual CPU state... */
	/* ...struct vcpu_info. */
	int (*parse_vcpu)(struct dump *dump, struct cpu_state *cpu, vaddr_t vcpu_info);

	/* Print state of `cpu' to global variable `output'. */
	int (*print_cpu_state)(FILE *o, struct dump *dump, struct cpu_state *cpu);

	/* Return virtual address of stack on `cpu'. */
	vaddr_t (*stack)(struct dump *dump, struct cpu_state *cpu);

	/* Return virtual address of instruction pointer on `cpu'. */
	vaddr_t (*instruction_pointer)(struct dump *dump, struct cpu_state *cpu);

	/* Translate virtual address `virt' into a machine address
	 * using current page tables of `cpu'. Returns -1 if this
	 * isn't possible.
	 */
	maddr_t (*virt_to_mach)(struct dump *dump, struct cpu_state *cpu, vaddr_t virt);
};

struct domain {
	uint16_t domid;
	vaddr_t v_domain_info;
	vaddr_t v_shared_info;

	struct symbol_table *symtab;

	struct {
		pfn_t max_pfn;
		maddr_t pfn_to_mfn_list_list;
	} shared_info;

	int nr_vcpus;
	struct cpu_state *vcpus;

	int is_hvm;
	int is_privileged;
	int is_32bit_pv;
	int has_32bit_shinfo;
};

struct dump {
	int fd;

	int e_machine; /* Ehdr->e_machine */
	struct arch *_arch;
	struct arch *compat_arch;

	/* Hypervisor information */
	uint64_t tainted;
	uint64_t xen_major_version;
	uint64_t xen_minor_version;
	char *xen_extra_version;
	char *xen_changeset;
	char *xen_compiler;
	char *xen_compile_date;
	char *xen_compile_time;
	struct symbol_table *symtab;

	/* Processor state */
	int nr_cpus;
	struct cpu_state *cpus;

	/* Memory */
	int nr_machine_memory;
	struct memory_extent *machine_memory;

	/* Domains */
	int nr_domains;
	struct domain *domains;
};

#define PAGE_SHIFT 12
#define PAGE_SIZE (1<<PAGE_SHIFT)

extern struct dump *open_dump(const char *fn, struct symbol_table *symtab,
			      int nr_symtabs, const char **symtabs);
extern void close_dump(struct dump *dump);
extern size_t kdump_read(struct dump *dump, void *buf, off64_t offset, size_t length);

extern FILE *debug, *output;

static inline int kdump_cpu_is_32bit_pv(struct dump *dump, struct cpu_state *cpu)
{
	if (cpu->flags & CPU_PHYSICAL)
		return 0;

	return cpu->virtual.domain->is_32bit_pv;
}

static inline vaddr_t kdump_parse_prstatus(struct dump *dump, void *prs, struct cpu_state *cpu)
{
	return dump->_arch->parse_prstatus(dump, prs, cpu);
}
static inline vaddr_t kdump_parse_crash_regs(struct dump *dump, void *note, struct cpu_state *cpu)
{
	return dump->_arch->parse_crash_regs(dump, note, cpu);
}
static inline vaddr_t kdump_parse_hypervisor(struct dump *dump, void *note)
{
	return dump->_arch->parse_hypervisor(dump, note);
}
static inline vaddr_t kdump_parse_vcpu(struct dump *dump, struct cpu_state *cpu, vaddr_t vcpu_info)
{
	return dump->_arch->parse_vcpu(dump, cpu, vcpu_info);
}
static inline vaddr_t kdump_stack(struct dump *dump, struct cpu_state *cpu)
{
	return dump->_arch->stack(dump, cpu);
}
static inline vaddr_t kdump_instruction_pointer(struct dump *dump, struct cpu_state *cpu)
{
	return dump->_arch->instruction_pointer(dump, cpu);
}
static inline vaddr_t kdump_print_cpu_state(FILE *o, struct dump *dump, struct cpu_state *cpu)
{
	return dump->_arch->print_cpu_state(o, dump, cpu);
}
static inline 	maddr_t kdump_virt_to_mach(struct dump *dump, struct cpu_state *cpu, vaddr_t virt)
{
	return dump->_arch->virt_to_mach(dump, cpu, virt);
}
static inline int kdump_sizeof_pointer(struct dump *dump)
{
	return dump->_arch->sizeof_pointer;
}
static inline int kdump_sizeof_compat_pointer(struct dump *dump)
{
	if (dump->compat_arch)
		return dump->compat_arch->sizeof_pointer;
	else
		return dump->_arch->sizeof_pointer;
}
static inline int kdump_sizeof_cpu_pointer(struct dump *dump, struct cpu_state *cpu)
{
	if (kdump_cpu_is_32bit_pv(dump, cpu))
		return kdump_sizeof_compat_pointer(dump);
	else
		return kdump_sizeof_pointer(dump);
}

static inline int kdump_sizeof_pfn(struct dump *dump, struct domain *d)
{
	if(d->has_32bit_shinfo && dump->compat_arch) {
		return dump->compat_arch->sizeof_pfn;
	} else {
		return dump->_arch->sizeof_pfn;
	}
}
static inline int kdump_sizeof_percpu(struct dump *dump)
{
	return dump->_arch->sizeof_percpu;
}
static inline int kdump_heap_limits(struct dump *dump, maddr_t *s, maddr_t *e)
{
	return dump->_arch->heap_limits(dump, s, e);
}
static inline struct symbol_table *kdump_symtab_for_cpu(struct dump *dump, struct cpu_state *cpu)
{
	if (cpu->flags & CPU_PHYSICAL)
		return dump->symtab;
	else
		return cpu->virtual.domain->symtab;
}

#define for_each_pcpu(dump, cpu) \
	for ((cpu) = &(dump)->cpus[0]; \
	     (cpu) < &(dump)->cpus[(dump)->nr_cpus]; \
	     (cpu)++)

extern int parse_domain_list(struct dump *dump, int nr_symtabs, const char **symtabs);
#define for_each_domain(dump, dom) \
	for ((dom) = &(dump)->domains[0]; \
	     (dom) < &(dump)->domains[(dump)->nr_domains]; \
	     (dom)++)

#define for_each_vcpu(dom, vcpu) \
	for ((vcpu) = &(dom)->vcpus[0]; \
	     (vcpu) < &(dom)->vcpus[(dom)->nr_vcpus]; \
	     (vcpu)++)

void free_domain(struct domain *domain);

#endif
