/* Copyright (c) 2007, XenSource, Inc. - All rights reserved. */

#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "kdump.h"
#include "memory.h"
#include "symbols.h"

#include <xen/foreign/x86_32.h>

typedef struct
{
	int32_t signo;			/* signal number */
	int32_t code;			/* extra code */
	int32_t errno;			/* errno */
} ELF_Signifo;

typedef int32_t ELF_Pid;

typedef struct {
	int32_t tv_sec;
	int32_t tv_usec;
} ELF_Timeval;

typedef struct
{
	ELF_Signifo pr_info;		/* Info associated with signal */
	int16_t pr_cursig;		/* Current signal */
	uint32_t pr_sigpend;		/* Set of pending signals */
	uint32_t pr_sighold;		/* Set of held signals */
	ELF_Pid pr_pid;
	ELF_Pid pr_ppid;
	ELF_Pid pr_pgrp;
	ELF_Pid pr_sid;
	ELF_Timeval pr_utime;		/* User time */
	ELF_Timeval pr_stime;		/* System time */
	ELF_Timeval pr_cutime;		/* Cumulative user time */
	ELF_Timeval pr_cstime;		/* Cumulative system time */
	uint32_t pr_reg[17];		/* GP registers */
	int32_t pr_fpvalid;		/* True if math co-processor being used.  */
} ELF_Prstatus;

#define PR_REG_EBX       0
#define PR_REG_ECX       1
#define PR_REG_EDX       2
#define PR_REG_ESI       3
#define PR_REG_EDI       4
#define PR_REG_EBP       5
#define PR_REG_EAX       6
#define PR_REG_DS        7
#define PR_REG_ES        8
#define PR_REG_FS        9
#define PR_REG_GS       10
#define PR_REG_ORIG_EAX 11
#define PR_REG_EIP      12
#define PR_REG_CS       13
#define PR_REG_EFLAGS   14
#define PR_REG_ESP      15
#define PR_REG_SS       16

#define CR4_PAE (1<<5)

/* copied from xen/include/xen/elfcore.h */
typedef struct {
    uint32_t xen_major_version;
    uint32_t xen_minor_version;
    uint32_t xen_extra_version;
    uint32_t xen_changeset;
    uint32_t xen_compiler;
    uint32_t xen_compile_date;
    uint32_t xen_compile_time;
    uint32_t tainted;
    uint64_t xen_phys_start;
    uint64_t dom0_pfn_to_mfn_frame_list_list;
} xen_crash_xen_regs_t;

typedef struct {
    uint32_t cr0, cr2, cr3, cr4;
} crash_xen_core_t;

/* XXX: hardcoding */
#define STACK_SIZE (4096<<2)

static struct symbol *__context_switch_symbol = NULL;

static vaddr_t get_cpu_info(vaddr_t stack)
{
	vaddr_t cpu_info = stack;

	ASSERT_REQUIRED_SYMBOLS(0ULL);

	cpu_info &= ~(STACK_SIZE-1);
	cpu_info |= STACK_SIZE - CPUINFO_sizeof;
	return cpu_info;
}

static int x86_32_heap_limits(struct dump *dump, maddr_t *start, maddr_t *end)
{
	*start = 0x100000ULL; /* Skip everything before 1M. */
	*end   = 0xc00000ULL; /* DIRECTMAP_PHYS_END. */
	return 0;
}

static int x86_32_parse_prstatus(struct dump *dump, void *_prs, struct cpu_state *cpu)
{
	ELF_Prstatus *prs = _prs;

	cpu->flags |= CPU_PHYSICAL;
	cpu->flags |= CPU_CORE_STATE;

	cpu->x86_regs.eip = prs->pr_reg[PR_REG_EIP];
	cpu->x86_regs.cs = prs->pr_reg[PR_REG_CS];
	cpu->x86_regs.eflags = prs->pr_reg[PR_REG_EFLAGS];

	cpu->x86_regs.eax = prs->pr_reg[PR_REG_EAX];
	cpu->x86_regs.ebx = prs->pr_reg[PR_REG_EBX];
	cpu->x86_regs.ecx = prs->pr_reg[PR_REG_ECX];
	cpu->x86_regs.edx = prs->pr_reg[PR_REG_EDX];

	cpu->x86_regs.esi = prs->pr_reg[PR_REG_ESI];
	cpu->x86_regs.edi = prs->pr_reg[PR_REG_EDI];
	cpu->x86_regs.ebp = prs->pr_reg[PR_REG_EBP];
	cpu->x86_regs.esp = prs->pr_reg[PR_REG_ESP];

	cpu->x86_regs.ds = prs->pr_reg[PR_REG_DS];
	cpu->x86_regs.es = prs->pr_reg[PR_REG_ES],
	cpu->x86_regs.fs = prs->pr_reg[PR_REG_FS];
	cpu->x86_regs.gs = prs->pr_reg[PR_REG_GS],
	cpu->x86_regs.ss = prs->pr_reg[PR_REG_SS];
	cpu->x86_regs.cs = prs->pr_reg[PR_REG_CS];

	return 0;
}

int x86_32_set_prstatus(struct domain *d, void *_prs, struct cpu_state *cpu) {
	ELF_Prstatus *prs = _prs;
	memset(prs, '\0', sizeof(ELF_Prstatus));
	prs->pr_reg[0] = cpu->x86_regs._ebx;
	prs->pr_reg[1] = cpu->x86_regs._ecx;
	prs->pr_reg[2] = cpu->x86_regs._edx;
	prs->pr_reg[3] = cpu->x86_regs._esi;
	prs->pr_reg[4] = cpu->x86_regs._edi;
	prs->pr_reg[5] = cpu->x86_regs._ebp;
	prs->pr_reg[6] = cpu->x86_regs._eax;
	prs->pr_reg[7] = cpu->x86_regs.ds;
	prs->pr_reg[8] = cpu->x86_regs.es;
	prs->pr_reg[9] = cpu->x86_regs.fs;
	prs->pr_reg[10] = cpu->x86_regs.gs;
	prs->pr_reg[11] = cpu->x86_regs._eorig_rax;
	prs->pr_reg[12] = cpu->x86_regs._eip;
	prs->pr_reg[13] = cpu->x86_regs.cs;
	prs->pr_reg[14] = cpu->x86_regs._eflags;
	prs->pr_reg[15] = cpu->x86_regs._esp;
	prs->pr_reg[16] = cpu->x86_regs.ss;
	fprintf(debug, "cpu registers:\n");
	//hex_dump(0, prs->pr_reg, 4 * 17);

	return sizeof(ELF_Prstatus);
}

/* bits in flags of vmalloc's vm_struct below */
#define VM_IOREMAP	0x00000001	/* ioremap() and friends */
#define VM_ALLOC	0x00000002	/* vmalloc() */
#define VM_MAP		0x00000004	/* vmap()ed pages */
#define VM_USERMAP	0x00000008	/* suitable for remap_vmalloc_range */
#define VM_VPAGES	0x00000010	/* buffer for pages was vmalloc'ed */

struct vm_struct {
	struct vm_struct *next;
	void *addr;
	unsigned long size;
	unsigned long flags;
	void **pages; // struct pages
	unsigned int nr_pages;
	unsigned long phys_addr;
	void *caller;
};

int x86_32_get_vmalloc_extents(struct dump *dump, struct domain *d, struct cpu_state *cpu, struct memory_extent ** extents_out) {
	struct symbol *vmlist_s;
	struct vm_struct ve;
	vaddr_t ve_addr, vaddr;
	maddr_t maddr;
	struct memory_extent *ext = NULL;
	int n_ext = 0;
	int n, i;

	vmlist_s = symtab_lookup_name(d->symtab, "vmlist");
	if (!vmlist_s) {
		fprintf(debug, "Error Symbol not found vmlist\n");
		goto err;
	}
	ve_addr = kdump_read_uint32_vaddr(dump, d, vmlist_s->address);

	while (ve_addr) {
		if (kdump_read_vaddr(dump, NULL, ve_addr, &ve, sizeof(ve)) != sizeof(ve)) {
			fprintf(debug, "vmlist entry error unavailable.");
			goto err;
		}
		if ((ve.flags & VM_ALLOC) && ve.nr_pages != 0) {
			ext = realloc(ext, sizeof(struct memory_extent) * (n_ext + ve.nr_pages));
			vaddr = (vaddr_t) (uint32_t) ve.addr;
			fprintf(debug, "vmlist 0x%llx === next %p addr %p flags %ld nr_pages %d \n", ve_addr, ve.next, ve.addr, ve.flags, ve.nr_pages);
			// for every page of vmalloc area find machine address and fill extents
			for (n = 0; n < ve.nr_pages; n++) {
				vaddr = (vaddr_t) (uint32_t) ve.addr + (n << PAGE_SHIFT);
				maddr = kdump_virt_to_mach(dump, &dump->cpus[0], vaddr);
				(ext + n_ext)->maddr = maddr;
				(ext + n_ext)->vaddr = vaddr;
				(ext + n_ext)->paddr = -1;
				(ext + n_ext)->length = PAGE_SIZE;
				(ext + n_ext)->offset = 0;
				n_ext++;
			}
		}
		ve_addr = (vaddr_t) (uint32_t) ve.next;
	}
	// this takes extents array and and fills
	// pseudo physical address for every machine address - paddr
	xen_m2p(dump, d, ext, n_ext);

	// find contiguous vaddr - paddr segments ang glue them together
	for (n = 1, i = 0; n < n_ext; n++) {
		if (((ext + i)->vaddr + (ext + i)->length == (ext + n)->vaddr) && ((ext + i)->maddr + (ext + i)->length == (ext + n)->maddr)) {
			(ext + i)->length += (ext + n)->length;
			(ext + n)->length = 0;
			//memset((ext+n), 0, sizeof(struct memory_extent));
		} else {
			i = n;
		}
	}

	//compact array removing glued extents
	for (n = 2, i = 1; n < n_ext; n++) {
		if ((ext + n)->length != 0) {
			memcpy(ext + i, ext + n, sizeof(struct memory_extent));
			(ext + n)->length = 0;
			i++;
		}
	}

	n_ext = i;
	ext = realloc(ext, sizeof(struct memory_extent) * n_ext);

	extern int cache_hits;
	fprintf(debug, "     n_ext %d\n", n_ext);
	fprintf(debug, "     cache_hits %d\n", cache_hits);
	*extents_out = ext;
	return n_ext;
	err: if (ext) {
		free(ext);
		*extents_out = NULL;
	}
	return 0;
}

/*
 * Parse guest crash_notes and set guest cpu states
 * crash_notes is allocated per-cpu in kernel. This depends stronglu on
 * kernel config
 * TODO add support for non-smp, slab per-cpu and array based per-cpu
 */
extern int parse_crash_note_32(struct dump *dump, struct domain *d, vaddr_t note_p, struct cpu_state *guest_cpu);

int x86_32_parse_guest_cpus(struct dump *dump, struct domain *d) {
	struct symbol *sym;
	vaddr_t crash_notes = 0;
	vaddr_t cpu_note = 0;
	vaddr_t cpu_offset = 0;
	struct cpu_state tmp_cpu;
	char * sname;
	int c;

	// find crash_notes
	sname = "crash_notes";
	sym = symtab_lookup_name(d->symtab, sname);
	if (!sym) {
		fprintf(debug, "Error Symbol not found: %s\n", sname);
		goto err;
	}
	crash_notes = kdump_read_uint32_vaddr(dump, d, sym->address);

	fprintf(debug, "crash_notes: %llx\n", crash_notes);

	// find __per_cpu_offset
	sname = "__per_cpu_offset";
	sym = symtab_lookup_name(d->symtab, sname);
	if (!sym) {
		fprintf(debug, "Error Symbol not found: %s\n", sname);
		goto err;
	}

	for (c = 0; c < d->nr_vcpus; c++) {
		cpu_offset = kdump_read_uint32_vaddr(dump, d, sym->address + 4 * c);
		cpu_note = crash_notes + cpu_offset;
		fprintf(debug, "cpu %d cpu_offset: %llx cpu_note %llx \n", c, cpu_offset, cpu_note);
		if (parse_crash_note_32(dump, d, cpu_note, &d->guest_cpus[c])) {
			continue;
		}

		// hack - guest cpus should be the same as vcpu but with different registers
		memcpy(&tmp_cpu, &d->vcpus[c], sizeof(tmp_cpu));
		tmp_cpu.x86_regs = d->guest_cpus[c].x86_regs;
		memcpy(&d->guest_cpus[c], &tmp_cpu, sizeof(tmp_cpu));

		d->guest_cpus[c].valid = 1;
		fprintf(debug, "cpu %d crashnote OK\n", c);
	}
	return 0;

	err: return 1;
}

static int x86_32_parse_crash_regs(struct dump *dump, void *_cr, struct cpu_state *cpu)
{
	crash_xen_core_t *cr = _cr;
	maddr_t current;

	cpu->flags |= CPU_EXTD_STATE;

	cpu->x86_regs.cr[0] = cr->cr0;
	cpu->x86_regs.cr[2] = cr->cr2;
	cpu->x86_regs.cr[3] = cr->cr3;
	cpu->x86_regs.cr[4] = cr->cr4;

	if (have_required_symbols)
	{
		/* Read current struct vcpu pointer from base of Xen stack */
		/* XXX: if esp < HYPERVISOR_VIRT_START need to look in TSS? */
		current = get_cpu_info(cpu->x86_regs.esp);
		current += CPUINFO_sizeof;
		current -= kdump_sizeof_pointer(dump);

		cpu->nr = kdump_read_uint32_vaddr_cpu(dump, cpu, current-4);

		cpu->physical.v_current =
			kdump_read_pointer_vaddr_cpu(dump, cpu, current);

		if (symtab_lookup_address(dump->symtab, cpu->x86_regs.eip) == __context_switch_symbol)
			cpu->flags |= CPU_CONTEXT_SWITCH;
	}

	return 0;
}

static int x86_32_parse_vcpu(struct dump *dump, struct cpu_state *cpu, vaddr_t vcpu_info)
{
	unsigned char vcpu[VCPU_sizeof];
	struct cpu_user_regs_x86_32 user_regs;

	struct cpu_state *pcpu;

	ASSERT_REQUIRED_SYMBOLS(1);

	cpu->flags &= ~CPU_PHYSICAL;
	cpu->flags |= CPU_CORE_STATE;

	if (kdump_read_vaddr(dump, NULL, vcpu_info, vcpu, VCPU_sizeof) != VCPU_sizeof)
		return 1;

	cpu->nr = *(uint32_t*)&vcpu[VCPU_vcpu_id];

	cpu->virtual.pcpu = *(uint32_t*)&vcpu[VCPU_processor];
	cpu->virtual.v_struct_vcpu = vcpu_info;

	cpu->virtual.flags = *(uint32_t *)&vcpu[VCPU_pause_flags];
	cpu->virtual.arch_flags = *(uint32_t *)&vcpu[VCPU_thread_flags];

	pcpu = &dump->cpus[cpu->virtual.pcpu];

	/*
         * If per_cpu curr_vcpu points to this vcpu and the pcpu is
         * not in __context_switch then the state for this VCPU is on
         * the PCPU stack not in struct VCPU info.
         */
	if (pcpu->physical.v_curr_vcpu == vcpu_info &&
	    (pcpu->flags & CPU_CONTEXT_SWITCH) == 0)
	{
		int i;

		/*
                 * Current points to the currently running vcpu. This
                 * can differ from the curr_vcpu variable when the
                 * PCPU is idle. In that case the PCPU stack contains
                 * the state of the last non-idle vcpu that was run.
		 */
		if (pcpu->physical.v_current == vcpu_info)
			cpu->flags |= CPU_RUNNING;

		if (kdump_read_vaddr_cpu(dump, pcpu,
					 get_cpu_info(pcpu->x86_regs.esp),
					 &user_regs, sizeof(struct cpu_user_regs_x86_32))
		    != sizeof(struct cpu_user_regs_x86_32))
			return 1;

		cpu->flags |= CPU_EXTD_STATE;
		for(i=0; i<8; i++)
			cpu->x86_regs.cr[i] = pcpu->x86_regs.cr[i];
	}
	else
	{
		memcpy(&user_regs, &vcpu[VCPU_user_regs], sizeof(struct cpu_user_regs_x86_32));

		/*
                 * If we are in __context_switch() and either
                 * curr_vcpu or current point to this VCPU then the
                 * location of the vcpu state is indeterminate as we
                 * are in the middle of copying it either to or from
                 * the PCPU stack.
                 *
                 * In this case we take the vpcu state from struct
                 * vcpu but print a warning that the true state may
                 * actually be on the pcpu stack.
		 */
		if ((pcpu->physical.v_curr_vcpu == vcpu_info ||
		     pcpu->physical.v_current == vcpu_info) &&
		    (pcpu->flags & CPU_CONTEXT_SWITCH))
			cpu->flags |= CPU_CONTEXT_SWITCH;

		cpu->flags |= CPU_EXTD_STATE;
		//cpu->x86_regs.cr[3] = *(uint32_t*)&vcpu[VCPU_guest_table];
		cpu->x86_regs.cr[3] = *(uint32_t*)&vcpu[VCPU_cr3];
	}

	cpu->x86_regs.eip = user_regs.eip;
	cpu->x86_regs.cs = user_regs.cs;
	cpu->x86_regs.eflags = user_regs.eflags;

	cpu->x86_regs.eax = user_regs.eax;
	cpu->x86_regs.ebx = user_regs.ebx;
	cpu->x86_regs.ecx = user_regs.ecx;
	cpu->x86_regs.edx = user_regs.edx;

	cpu->x86_regs.esi = user_regs.esi;
	cpu->x86_regs.edi = user_regs.edi;
	cpu->x86_regs.ebp = user_regs.ebp;
	cpu->x86_regs.esp = user_regs.esp;

	cpu->x86_regs.ds = user_regs.ds;
	cpu->x86_regs.es = user_regs.es;
	cpu->x86_regs.fs = user_regs.fs;
	cpu->x86_regs.gs = user_regs.gs;
	cpu->x86_regs.ss = user_regs.ss;
	cpu->x86_regs.cs = user_regs.cs;
	fprintf(debug, "%s user_regs.eflags 0x%x\n", __FUNCTION__, user_regs.eflags);

	return 0;
}

static int x86_32_parse_hypervisor(struct dump *dump, void *note)
{
	xen_crash_xen_regs_t *x = note;

	dump->xen_major_version = x->xen_major_version;
	dump->xen_minor_version = x->xen_minor_version;
	dump->tainted = x->tainted;
	if (x->xen_extra_version)
		dump->xen_extra_version = kdump_read_string_maddr(dump, x->xen_extra_version);
	if (x->xen_changeset)
		dump->xen_changeset     = kdump_read_string_maddr(dump, x->xen_changeset);
	if (x->xen_compiler)
		dump->xen_compiler      = kdump_read_string_maddr(dump, x->xen_compiler);
	if (x->xen_compile_date)
		dump->xen_compile_date  = kdump_read_string_maddr(dump, x->xen_compile_date);
	if (x->xen_compile_time)
		dump->xen_compile_time  = kdump_read_string_maddr(dump, x->xen_compile_time);

	return 0;
}

static int x86_32_print_cpu_state(FILE *o, struct dump *dump, struct cpu_state *cpu)
{
	struct symbol_table *symtab = kdump_symtab_for_cpu(dump, cpu);
	int len = 0;

	if (cpu->flags & CPU_CORE_STATE)
	{
		len += fprintf(o, "\tEIP:    %04x:[<%08x>] ",
			       cpu->x86_regs.cs, cpu->x86_regs._eip);
		print_symbol(o, symtab, cpu->x86_regs.eip);
		len += fprintf(o, "\n");
		len += fprintf(o, "\tEFLAGS: %08x\n", cpu->x86_regs._eflags);
		len += fprintf(o, "\teax: %08x   ebx: %08x   ecx: %08x   edx: %08x\n",
			       cpu->x86_regs._eax, cpu->x86_regs._ebx,
			       cpu->x86_regs._ecx, cpu->x86_regs._edx);
		len += fprintf(o, "\tesi: %08x   edi: %08x   ebp: %08x   esp: %08x\n",
			       cpu->x86_regs._esi, cpu->x86_regs._edi,
			       cpu->x86_regs._ebp, cpu->x86_regs._esp);
	}
	if (cpu->flags & CPU_EXTD_STATE)
	{
		len += fprintf(o, "\tcr0: %08x   cr4: %08x   cr3: %08x   cr2: %08x\n",
			       (uint32_t)cpu->x86_regs.cr[0], (uint32_t)cpu->x86_regs.cr[4], (uint32_t)cpu->x86_regs.cr[3], (uint32_t)cpu->x86_regs.cr[2]);
	}
	if (cpu->flags & CPU_CORE_STATE)
	{
		len += fprintf(o, "\tds: %04x   es: %04x   fs: %04x   gs: %04x   ss: %04x   cs: %04x\n",
			       cpu->x86_regs.ds, cpu->x86_regs.es, cpu->x86_regs.fs,
			       cpu->x86_regs.gs, cpu->x86_regs.ss, cpu->x86_regs.cs);
	}

	fprintf(o, "\n");

	if (cpu->flags & CPU_PHYSICAL)
	{
		if ( !have_required_symbols )
		{
			len += fprintf(o, "\tcurrent:\tRequired symbols are unavailable.\n");
		}
		else if ( cpu->physical.current )
		{
			len += fprintf(o, "\tcurrent:\tDOM%"PRId16" VCPU%d (%"PRIxVADDR")\n",
				       cpu->physical.current->virtual.domain->domid,
				       cpu->nr,
				       cpu->physical.v_current);
		}
		else if ( cpu->physical.v_idle_vcpu && cpu->physical.v_current == cpu->physical.v_idle_vcpu )
		{
			len += fprintf(o, "\tcurrent:\tidle (%"PRIxVADDR")\n",
				       cpu->physical.v_current);
		}
		else
		{
			len += fprintf(o, "\tcurrent:\t<unknown> (%"PRIxVADDR")\n",
				       cpu->physical.v_current);
		}

		if ( cpu->physical.curr_vcpu )
		{
			len += fprintf(o, "\tstack context:\tDOM%"PRId16" VCPU%d (%"PRIxVADDR")\n",
				       cpu->physical.curr_vcpu->virtual.domain->domid,
				       cpu->nr,
				       cpu->physical.v_curr_vcpu);
		}
		else if ( cpu->physical.v_idle_vcpu && cpu->physical.v_curr_vcpu == cpu->physical.v_idle_vcpu )
		{
			len += fprintf(o, "\tstack context:\tidle (%"PRIxVADDR")\n",
				       cpu->physical.v_curr_vcpu);
		}
		else if (have_required_symbols)
		{
			len += fprintf(o, "\tstack context:\t<unknown> (%"PRIxVADDR")\n",
				       cpu->physical.v_curr_vcpu);
		}

		if (cpu->flags & CPU_CONTEXT_SWITCH)
			len += fprintf(o, "\tNOTE: Context switch in progress.\n");

		if ( cpu->physical.v_idle_vcpu )
			len += fprintf(o, "\tidle VCPU:\t%"PRIxVADDR"\n", cpu->physical.v_idle_vcpu);
		else if (have_required_symbols)
			len += fprintf(o, "\tidle VCPU:\t<unknown>\n");
	}
	else
	{
		len += fprintf(o, "\tVCPU pause flags: %#"PRIx64" ", cpu->virtual.flags);
		len += fprintf(o, "arch flags %#"PRIx64"\n", cpu->virtual.arch_flags);
		len += fprintf(o, "\n");

		if (cpu->flags & CPU_RUNNING)
		{
			len += fprintf(o, "\tcurrent on PCPU%d\n", cpu->virtual.pcpu);
		}
		else if (cpu->flags & CPU_CONTEXT_SWITCH)
		{
			len += fprintf(o, "\tNOTE: Context switch in progress. "
				       "True VCPU state may be on PCPU stack.\n");
		}
		else
		{
			len += fprintf(o, "\tnot running. last ran on PCPU%d\n",
				       cpu->virtual.pcpu);
		}

		len += fprintf(o, "\tstruct vcpu at %"PRIxVADDR"\n",
			       cpu->virtual.v_struct_vcpu);
	}

	len += fprintf(o, "\n");

	return len;
}

static vaddr_t x86_32_stack(struct dump *dump, struct cpu_state *cpu)
{
	return cpu->x86_regs.esp;
}
static vaddr_t x86_32_instruction_pointer(struct dump *dump, struct cpu_state *cpu)
{
	return cpu->x86_regs.eip;
}

static maddr_t x86_32_virt_to_mach(struct dump *dump, struct cpu_state *cpu, vaddr_t virt)
{
	vaddr_t page_offset;

	if (have_required_symbols)
		page_offset = XEN_page_offset;
	else
		page_offset = 0xFF000000;

	//int paging_levels = cpu->x86_regs.cr[4] & CR4_PAE ? 3 : 2;
	/* always use host paging level... */
	int paging_levels = dump->cpus[0].x86_regs.cr[4] & CR4_PAE ? 3 : 2;

	fprintf(debug, "translate address %"PRIxVADDR" %x %lx %d\n",
		virt, (uint32_t)cpu->x86_regs.cr[3], cpu->flags&CPU_EXTD_STATE,
		(cpu->flags&CPU_EXTD_STATE) && (uint32_t)cpu->x86_regs.cr[3]);

	if ((cpu->flags&CPU_EXTD_STATE) && cpu->x86_regs.cr[3]) {
		extern int x86_virt_to_mach(struct dump *dump, uint64_t cr3,
					    int paging_levels,
					    vaddr_t virt, maddr_t *maddr);
		maddr_t maddr;

		if(x86_virt_to_mach(dump, cpu->x86_regs.cr[3], paging_levels, virt, &maddr))
			goto page_offset;

		return maddr;
	}

 page_offset:
	/* Fall back to using PAGE_OFFSET if possible */
	if (virt < page_offset) {
		fprintf(debug, "cannot translate address %"PRIxVADDR" < %"PRIxVADDR" "
			"without cr3\n", virt, page_offset);
		return -1ULL;
	}
	return virt - page_offset;
}

struct arch arch_x86_32 = {
	.sizeof_pointer = 4,
	.sizeof_pfn = 4,
	.sizeof_percpu = 1<<12,
	.heap_limits = x86_32_heap_limits,
	.parse_prstatus = x86_32_parse_prstatus,
	.parse_crash_regs = x86_32_parse_crash_regs,
	.parse_vcpu = x86_32_parse_vcpu,
	.parse_hypervisor = x86_32_parse_hypervisor,
	.print_cpu_state = x86_32_print_cpu_state,
	.stack = x86_32_stack,
	.instruction_pointer = x86_32_instruction_pointer,
	.virt_to_mach = x86_32_virt_to_mach
};
