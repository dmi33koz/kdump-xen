/* Copyright (c) 2007, XenSource, Inc. - All rights reserved. */

#define _FILE_OFFSET_BITS 64

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "kdump.h"
#include "memory.h"
#include "symbols.h"
#include "bitness.h"

FILE *debug, *output;
struct dump *dump = NULL;

struct symbol_table *xen_symtab = NULL;

static int working_directory = -1;
static int output_directory = -1;

struct options {
	int version;
	int console_ring;
	int pcpu_state;
	int machine_memory_map;
	enum {
		DOMAIN_LIST_NONE,
		DOMAIN_LIST_DOM0,
		DOMAIN_LIST_ALL,
	} domain_list;
	int domain_list_separate;
	int pcpu_stacks;
	int vcpu_stacks;
	const char *xen_memory_dump;
	const char *dom0_memory_dump;
};

#define DEFAULT_XEN_MEMORY_DUMP "xen-memory-dump"
#define DEFAULT_DOM0_MEMORY_DUMP "dom0-memory-dump"

struct options options = {
	.version = 1,
	.console_ring = 0,
	.pcpu_state = 1,
	.machine_memory_map = 0,
	.domain_list = DOMAIN_LIST_NONE,
	.domain_list_separate = -1,
	.xen_memory_dump = NULL,
	.dom0_memory_dump = NULL,
};

const struct options mini_option = {
	.version = 1,
	.console_ring = 1,
	.pcpu_state = 1,
	.machine_memory_map = 0,
	.domain_list = DOMAIN_LIST_DOM0,
	.domain_list_separate = -1,
	.xen_memory_dump = NULL,
	.dom0_memory_dump = NULL,
};
const struct options maxi_option = {
	.version = 1,
	.console_ring = 1,
	.pcpu_state = 1,
	.machine_memory_map = 1,
	.domain_list = DOMAIN_LIST_ALL,
	.domain_list_separate = -1,
	.xen_memory_dump = DEFAULT_XEN_MEMORY_DUMP,
	.dom0_memory_dump = NULL,
};
const struct options full_option = {
	.version = 1,
	.console_ring = 1,
	.pcpu_state = 1,
	.machine_memory_map = 1,
	.domain_list = DOMAIN_LIST_ALL,
	.domain_list_separate = -1,
	.xen_memory_dump = DEFAULT_XEN_MEMORY_DUMP,
	.dom0_memory_dump = DEFAULT_DOM0_MEMORY_DUMP,
};

#define FIRST_LONG_OPT 128
#define OPT_MINI             FIRST_LONG_OPT + 0
#define OPT_MAXI             FIRST_LONG_OPT + 1
#define OPT_FULL             FIRST_LONG_OPT + 2
#define OPT_DOMAIN_LIST	     FIRST_LONG_OPT + 3
#define OPT_XEN_MEMORY_DUMP  FIRST_LONG_OPT + 4
#define OPT_DOM0_MEMORY_DUMP FIRST_LONG_OPT + 5

static void usage(void)
{
	printf("usage:\n\n");
	printf("err, not yet\n");
}

static FILE *fopen_in_output_directory(const char *file, const char *mode)
{
	FILE *f;

	if (fchdir(output_directory)<0)
	{
		fprintf(debug, "%s: failed to change to output directory: %s\n",
			__FUNCTION__, strerror(errno));
		return NULL;
	}

	f = fopen(file, mode);

	if (fchdir(working_directory) < 0)
	{
		fprintf(debug, "%s: failed to return to working directory: %s\n",
			__FUNCTION__, strerror(errno));
	}

	return f;
}

static void dump_xen_version_info()
{
	fprintf(output, "Xen Version:\n");
	fprintf(output, "  Xen version %"PRId64".%"PRId64"%s (%s) %s %s\n",
		dump->xen_major_version,
		dump->xen_minor_version,
		dump->xen_extra_version ?:"<none>",
		dump->xen_compiler,
		dump->xen_compile_date, dump->xen_compile_time);
	fprintf(output, "  Latest ChangeSet: %s\n", dump->xen_changeset);
	fprintf(output, "\n");
}

static void dump_cpu_stack(FILE *o, struct cpu_state *cpu)
{
	vaddr_t stack_vaddr, stack_base, stack_limit;
	uint8_t stack[PAGE_SIZE/sizeof(uint8_t)];
	int i;
	vaddr_t mask = 31;
	vaddr_t instr, instr2;
	struct symbol_table *symtab = kdump_symtab_for_cpu(cpu);
	int sizeof_pointer = kdump_sizeof_cpu_pointer(cpu);

	stack_vaddr = kdump_stack(cpu);
	stack_base = stack_vaddr &~(PAGE_SIZE-1);
	stack_limit = stack_base + 4096;

	if (kdump_read_vaddr_cpu(cpu, stack_base, stack, PAGE_SIZE) != PAGE_SIZE)
	{
		fprintf(o, "\tStack unavailable.\n\n");
		return;
	}

	fprintf(o, "\tStack at %#"PRIxVADDR": ", stack_vaddr);

	if (stack_vaddr&mask) {
		fprintf(o, "\n\t  %08"PRIxVADDR":", stack_vaddr & ~mask);
		for (i=((stack_vaddr&~mask)-stack_base)/4; i<(stack_vaddr-stack_base)/4; i++)
			fprintf(o, "         ");
	} else {
		i=(stack_vaddr-stack_base)/4;
	}
	for (; i<PAGE_SIZE/4; i++) {
		if (i && i%8 == 0)
			fprintf(o, "\n\t  %04"PRIxVADDR":", (stack_base + 4*i) & ~7);
		fprintf(o, " %08"PRIx32, *(uint32_t*)&stack[i*sizeof(uint32_t)]);
	}
	fprintf(o, "\n");

	fprintf(o, "\n");
	fprintf(o, "\tCode:\n\t  ");
	instr = instr2 = kdump_instruction_pointer(cpu);
	if(instr == 0)
		goto no_code;

	instr2 -= 21;
	for(i=0; i<32; i++) {
		uint8_t c = kdump_read_uint8_vaddr_cpu(cpu, instr2+i);
		if (instr2+i == instr)
			fprintf(o, "<%02x> ", c);
		else
			fprintf(o, "%02x ", c);
	}
	fprintf(o, "\n\n");

 no_code:
	if (!is_kernel_text(symtab, instr))
		goto no_trace;

	fprintf(o, "\tCall Trace:\n");
	fprintf(o, "\t  [%0*"PRIxVADDR"] ", sizeof_pointer*2, instr);
	print_symbol(o, symtab, instr);
	fprintf(o, "\n");
	for (i=stack_vaddr-stack_base; i<PAGE_SIZE; i += sizeof_pointer)
	{
		vaddr_t entry = *(vaddr_t*)&stack[i];

		if (sizeof_pointer < sizeof(entry))
			entry &= (1ULL<<sizeof_pointer*8)-1;

		if (!is_kernel_text(symtab, entry))
			continue;
		fprintf(o, "\t   %0*"PRIxVADDR"  ", sizeof_pointer*2, entry );
		print_symbol(o, symtab, entry);
		fprintf(o, "\n");
	}
	fprintf(o, "\n");
 no_trace:
	return;
}

static void dump_pcpu_state()
{
	struct cpu_state *cpu;

	fprintf(output, "Physical Processor State:\n");
	for_each_pcpu(cpu)
	{
		fprintf(output, "  PCPU%d host state:\n", cpu->nr);
		kdump_print_cpu_state(output, cpu);
		dump_cpu_stack(output, cpu);

		fprintf(output, "  PCPU%d guest state:\n", cpu->nr);

		if ( cpu->physical.current )
		{
			struct cpu_state *vcpu = cpu->physical.current;
			fprintf(output, "\tDOMAIN%d VCPU%d\n",
				vcpu->virtual.domain->domid, vcpu->nr);
			kdump_print_cpu_state(output, vcpu);
			dump_cpu_stack(output, vcpu);
		}
		else
		{
			fprintf(output, "\tNone (idle)\n");
		}
		fprintf(output, "\n");
	}
}

static void dump_machine_memory_map()
{
	int i;

	fprintf(output, "Machine Memory Map:\n");
	fprintf(output, "  %-*s  %-*s  %-*s\n",
		16, "Physical",
		16, "",
		kdump_sizeof_pointer(dump)*2, "Virtual");

	for (i=0; i<dump->nr_machine_memory; i++) {
		struct memory_extent *mext = &dump->machine_memory[i];

		fprintf(output, "  %0*"PRIxMADDR"..%0*"PRIxMADDR,
			/*kdump_sizeof_pointer(dump)*2*/16,
			mext->maddr,
			/*kdump_sizeof_pointer(dump)*2*/16,
			mext->maddr+mext->length);

		if (mext->vaddr != -1)
			fprintf(output, "  %0*"PRIxVADDR"..%0*"PRIxVADDR,
				kdump_sizeof_pointer(dump)*2,
				mext->vaddr,
				kdump_sizeof_pointer(dump)*2,
				mext->vaddr+mext->length);

		fprintf(output, "\n");
	}
	fprintf(output, "\n");
}

static void __dump_console_ring(FILE *o,
				struct domain *domain,
				const char *indent,
				vaddr_t ring_addr, uint32_t len,
				uint32_t producer, uint32_t consumer)
{
	char ring[len];

	if (kdump_read_vaddr(domain, ring_addr, ring, len) != len)
	{
		fprintf(stderr, "failed to read console ring\n");
		return;
	}

	fprintf(o, indent);
	while (consumer < producer)
	{
		int idx = consumer++ & (len - 1);
		fprintf(o, "%c", ring[idx]);
		if ( ring[idx] == '\n' )
			fprintf(o, indent);
	}

	fprintf(o, "\n\n");
}

static void dump_xen_console_ring()
{
	uint32_t  producer, consumer, ring_size;
	vaddr_t   ring_address;

	fprintf(output, "Console Ring:\n");

	if (!have_required_symbols)
	{
		fprintf(output, "\tUnavailable, symbol table required.\n\n");
		return;

	}
	ring_address = kdump_read_pointer_vaddr(NULL, conring);
	ring_size = kdump_read_uint32_vaddr(NULL, conring_size);
	producer = kdump_read_uint32_vaddr(NULL, conringp);
	consumer = kdump_read_uint32_vaddr(NULL, conringc);

	/* XXX size hardcoded in xen too */
	__dump_console_ring(output, NULL, "  ", ring_address, ring_size, producer, consumer);
}

static void dump_domain_console_ring(FILE *o, struct domain *d)
{
	struct symbol *log_start, *log_end, *log_buf, *__log_buf, *log_buf_len;
	uint32_t len, producer, consumer;
	vaddr_t ring;

	fprintf(o, "  Console Ring:\n");

	if ( d->symtab == NULL )
	{
		fprintf(o, "\tUnavailable, a symbol table for domain %d is required.\n\n",
			d->domid);
		return;
	}

	log_start = symtab_lookup_name(d->symtab, "log_start");
	log_end = symtab_lookup_name(d->symtab, "log_end");
	log_buf = symtab_lookup_name(d->symtab, "log_buf");
	__log_buf = symtab_lookup_name(d->symtab, "__log_buf");
	log_buf_len = symtab_lookup_name(d->symtab, "log_buf_len");

	if ( log_start == NULL || log_end == NULL || log_buf == NULL || log_buf_len == NULL )
	{
		fprintf(o, "\tUnavailable, the following symbols are not available:\n");
		fprintf(o, "  %s%s%s%s.\n\n",
			log_start   == NULL ? " log_start"   : "",
			log_end     == NULL ? " log_end"     : "",
			log_buf     == NULL ? " log_buf"     : "",
			log_buf_len == NULL ? " log_buf_len" : "");
		return;
	}

	if ( d->is_32bit_pv )
		ring = kdump_read_uint32_vaddr(d, log_buf->address);
	else
		ring = kdump_read_uint64_vaddr(d, log_buf->address);
	producer = kdump_read_uint32_vaddr(d, log_end->address);
	len = kdump_read_uint32_vaddr(d, log_buf_len->address);

	/*
	 * Obviously bogus values for ring and len have been observed
	 * in the past and can cause crashes (e.g. if the length is
	 * huge we overflow the stack in __dump_console_ring()).
	 *
	 * I believe this has been fixed by ensuring that we do
	 * address translation using the cr3 of a VCPU in the domain
	 * instead of arbitrarily using PCPU0. Therefore the following
	 * two checks should never trigger.
	 *
	 * However if we think we have got into a dangerous situation
	 * then fallback to the default log anyway. The only way that
	 * log_buf can differ from __log_buf is if a kernel parameter
	 * is given which isn't something we do.
	 */
	if ( __log_buf && __log_buf->address != ring )
		fprintf(o, "\tWARNING: console ring location %"PRIxVADDR" "
			"is not the default (%"PRIxVADDR")\n",
			ring, __log_buf->address);
	if ( len > (1<<21) )
	{
		fprintf(o, "\tWARNING: console ring at %"PRIxVADDR" "
			"with length %#"PRIx32" seems rather large. \n", ring, len);
		fprintf(o, "\t         Using default __log_buf at %"PRIxVADDR" "
			"and length 0x4000 instead.\n", __log_buf->address);
		ring = __log_buf->address;
		len = 0x4000;
	}

	consumer = producer > len ? producer - len : 0;

	__dump_console_ring(o, d, "\t", ring, len, producer, consumer);
}

static void dump_domain_version_info(FILE *o, struct domain *d) {
	struct symbol *sym;
	char * sname;
	char * txt;
	maddr_t maddr;

	fprintf(o, "  Kernel info:\n");

	txt = NULL;
	sname = "linux_banner";
	sym = symtab_lookup_name(d->symtab, sname);
	if (sym) {
		maddr = kdump_virt_to_mach(&d->vcpus[0], sym->address);
		txt = kdump_read_string_maddr(maddr);
	} else {
		fprintf(debug, "Error Symbol not found: %s\n", sname);
	}
	if (txt) {
		fprintf(o, "  %s", txt);
	}

	// find git ish
	txt = NULL;
	sname = "linux_git_ish";
	sym = symtab_lookup_name(d->symtab, sname);
	if (sym) {
		maddr = kdump_virt_to_mach(&d->vcpus[0], sym->address);
		txt = kdump_read_string_maddr(maddr);
	} else {
		fprintf(debug, "Error Symbol not found: %s\n", sname);
	}
	if (txt) {
		fprintf(o, "  %s\n", txt);
	}
	fprintf(o, "\n");
}

static void __dump_domain(struct domain *d)
{
	struct cpu_state *vcpu;
	FILE *o = NULL;

	if ( options.domain_list_separate )
	{
		char fname[32]; /* Plenty room for "domain65535.log" */
		snprintf(fname, 16, "domain%d.log", d->domid);
		o = fopen_in_output_directory(fname, "w");
	}

	if ( o == NULL )
		o = output;

	fprintf(o, "Domain %d:\n", d->domid);

	dump_domain_version_info(o, d);

	fprintf(o, "  Flags:      %s%s%s\n",
		d->is_hvm ? " HVM" : "",
		d->is_privileged ? " PRIVILEGED" : "",
		d->is_32bit_pv ? " 32BIT-PV" : "");

	fprintf(o, "  Domain info: %"PRIxVADDR"\n", d->v_domain_info);
	fprintf(o, "  Shared info: %"PRIxVADDR"\n", d->v_shared_info);
	fprintf(o, "    Max PFN:              %"PRIxPADDR"\n", d->shared_info.max_pfn);
	fprintf(o, "    PFN to MFN list list: %"PRIxPADDR"\n", d->shared_info.pfn_to_mfn_list_list);
	fprintf(o, "\n");

	for_each_vcpu(d, vcpu)
	{
		fprintf(o, "  VCPU%d", vcpu->nr);
		kdump_print_cpu_state(o, vcpu);
		dump_cpu_stack(o, vcpu);
	}

	for_each_guest_cpu(d, vcpu) {
		if (vcpu->valid) {
			fprintf(o, "  Guest Crash Note found for cpu %d\n", vcpu->nr);
			fprintf(o, "  VCPU%d", vcpu->nr);
			kdump_print_cpu_state(o, vcpu);
			dump_cpu_stack(o, vcpu);
		}
	}

	if (options.console_ring)
		dump_domain_console_ring(o, d);

	if ( options.domain_list_separate )
		fclose(o);
}

static void dump_domains(int which)
{
	struct domain *d;

	if (dump->nr_domains == 0)
	{
		fprintf(output, "No domains found\n\n");
		return;
	}

	for_each_domain(d)
	{
		if (which == -1 || d->domid == which)
			__dump_domain(d);
	}
}

static void dump_xen_memory_new(const char *file) {
	FILE *mem;
	maddr_t addr;
	size_t ret;
	mem_range_t *mr, *mr_first;
	int elf_header_size = 0;
	unsigned char buf[PAGE_SIZE];

	fprintf(debug, "dump_xen_memory_old()\n");

	mem = fopen_in_output_directory(file, "w");
	if (mem == NULL) {
		fprintf(output, "  Failed to open output %s\n", file);
		return;
	}

	if (dump->e_machine == EM_X86_64) {
		mr_first = get_page_ranges_xen_64(dump);
	} else {
		mr_first = get_page_ranges_xen_32(dump);
	}
	if (!mr_first) {
		fprintf(output, "  Failed to collect XEN memory ranges\n");
		return;
	}

	elf_header_size = create_elf_header_xen(mem, mr_first);

	for (mr = mr_first; mr != NULL; mr = mr->next) {
		for (addr = mr->mfn << PAGE_SHIFT; addr < (mr->mfn + mr->page_count) << PAGE_SHIFT; addr += PAGE_SIZE) {
			ret = kdump_read_maddr(addr, buf, PAGE_SIZE);
			if (ret == 0) {
				fprintf(debug, "error reading offset %"PRIxMADDR" in xen memory dump: %s\n", addr, strerror(errno));
				goto out;
			}

			/* Don't worry about short writes too much but exit on error. */
			if (fwrite(buf, 1, ret, mem) < 0) {
				fprintf(debug, "error writing to offset %"PRIxMADDR" in xen memory dump: %s\n", addr, strerror(errno));
				goto out;
			}
		}
	}
	out: free_mem_range(mr_first);
	fclose(mem);
}

static void dump_xen_memory_old(const char *file)
{
	maddr_t addr;
	unsigned char buf[PAGE_SIZE];
	size_t ret;
	mem_range_t * mr;

	maddr_t start, end, offset;
	FILE *mem;
	int elf_header_size = 0;
	
	fprintf(debug, "dump_xen_memory_old()\n");

	fprintf(output, "Xen Physical Memory:\n");

	if (kdump_heap_limits(&start, &end))
	{
		fprintf(output, "\tUnavailable, failed to determine heap limits.\n\n");
		return;
	}

	if (!have_required_symbols)
	{
		fprintf(output, "\tUnavailable, symbol table required.\n\n");
		return;
	}

	mem = fopen_in_output_directory(file, "w");
	if (mem == NULL)
	{
		fprintf(output, "  Failed to open output %s\n", file);
		return;
	}

	fprintf(output, "  Heap: %016"PRIxMADDR"-%016"PRIxMADDR"\n",
		start, end);

	fprintf(output, "  XEN_virt_start: %016"PRIxMADDR" XEN_page_offset: %016"PRIxMADDR"\n", XEN_virt_start, XEN_page_offset);
	fprintf(output, "  Writing to: %s\n", file);
	fprintf(output, "\n");
	mr = alloc_mem_range();
	mr->mfn = start;
	mr->page_count = (end - start) >> PAGE_SHIFT;
	mr->vaddr = XEN_virt_start;

	elf_header_size = create_elf_header_xen(mem, mr);
	offset = elf_header_size;

	for (addr = start; addr < end; addr += PAGE_SIZE) {
		ret = kdump_read_maddr(addr, buf, PAGE_SIZE);
		if (ret == 0)
			continue;

		/* Don't worry about short writes too much but exit on error. */
		if (fwrite(buf, 1, ret, mem) < 0) {
			fprintf(stderr, "error writing to offset %"PRIxMADDR" in xen memory dump: %s\n", addr, strerror(errno));
			goto out;
		}
	}

 out:
	fclose(mem);
}

static void dump_xen_memory(const char *file)
{
	maddr_t start, end;
	fprintf(debug, "dump_xen_memory()\n");
	if (kdump_heap_limits(&start, &end) == 0) {
		dump_xen_memory_old(file);
		return;
	}

	if (dump->frame_table != 0) {
		dump_xen_memory_new(file);
		return;
	}

	fprintf(output, "\tUnavailable, failed to determine heap limits.\n\n");
	return;
}

static void dump_domain_memory(struct domain *d, const char *file) {
	maddr_t p2mll, p2ml, p2m;
	pfn_t max_pfn, pfn, mfn;
	maddr_t ma;
	paddr_t pa;
	unsigned char buf[PAGE_SIZE];
	FILE *mem;
	unsigned long *ptr;
	int skip_page;

	const int fpp = (PAGE_SIZE/kdump_sizeof_pfn(d));

	fprintf(output, "Domain %d Pseudo-Physical Memory:\n", d->domid);

	if (d->is_hvm)
	{
		fprintf(output, "  Cannot dump Pseudo-Physical address space of HVM domain\n");
		return;
	}

	p2mll = d->shared_info.pfn_to_mfn_list_list;
	if (p2mll == 0)
	{
		fprintf(output, "  No frame list list available for this domain\n");
		return;
	}

	max_pfn = d->shared_info.max_pfn;
	if (max_pfn == 0)
	{
		fprintf(output, "  No max_pfn available for this domain\n");
		return;
	}

	mem = fopen_in_output_directory(file, "w");
	if (mem == NULL)
	{
		fprintf(output, "  Failed to open output %s: %s\n", file, strerror(errno));
		return;
	}

	create_elf_header_dom(mem, d->domid);

	fprintf(output, "  Psuedo-physical address range: %016"PRIxPADDR"-%016"PRIxPADDR"\n",
		(paddr_t)0, (paddr_t)(max_pfn << PAGE_SHIFT));
	fprintf(output, "  Writing to: %s\n", file);
	fprintf(output, "\n");

	for (pfn=0; pfn<max_pfn; pfn++)
	{
		skip_page = 0;
		if((pfn % (fpp*fpp)) == 0)
		{
			ma = p2mll + (pfn/(fpp*fpp)*4);
			p2ml = kdump_read_pfn_maddr(d, ma) << PAGE_SHIFT;
			if (p2ml == 0)
			{
				fprintf(output, "  No P2M frame list for frames %"PRIxPFN"-%"PRIxPFN"\n",
					pfn, pfn+(fpp*fpp));
				break;
			}
			//fprintf(output, "  ================================================================\n");
			//fprintf(output, "  P2M frame list for frames %"PRIxPFN"-%"PRIxPFN" "
			//	"from %08"PRIxMADDR" = %08"PRIxMADDR"\n",
			//	pfn, pfn+(fpp*fpp), ma, p2ml);
		}
		if ((pfn % fpp) == 0)
		{
			ma = p2ml + (pfn/fpp*4);
			p2m = kdump_read_pfn_maddr(d, ma) << PAGE_SHIFT;
			if (p2m == 0)
			{
				fprintf(output, "    No P2M for frames %"PRIxPFN"-%"PRIxPFN"\n",
					pfn, pfn+fpp);
				break;
			}
			//fprintf(output, "    --------------------------------------------------------------\n");
			//fprintf(output, "    P2M for frames %"PRIxPFN"-%"PRIxPFN" "
			//	"from %08"PRIxMADDR" = %08"PRIxMADDR"\n",
			//	pfn, pfn+fpp, ma, p2m);
		}
		ma = p2m + (pfn%fpp)*4;

		mfn = kdump_read_pfn_maddr(d, ma);

		//fprintf(output, "      P2M for frame %"PRIxPFN" is %"PRIxPFN" from %08"PRIxMADDR"\n",
		//	pfn, mfn, ma);

		if (mfn == 0x00000000ffffffffULL)
		{
			//fprintf(output, "        Skip PFN %"PRIxPFN", MFN=%"PRIxPFN"\n", pfn, mfn);
			skip_page = 1;
		}

		if (!skip_page && (mfn & (1ULL<<31)))
		{
			//fprintf(output, "      FOREIGN\n");
			mfn &= ~(1<<31);
		}

		ma = (mfn<<PAGE_SHIFT);
		pa = (pfn<<PAGE_SHIFT);

		//fprintf(output, "        Copy MA %"PRIxMADDR" to PA %"PRIxPFN"\n", ma, pa);
		if (!skip_page) {
			if (kdump_read_maddr(ma, buf, PAGE_SIZE) != PAGE_SIZE) {
				fprintf(output, "Warning: failed to read machine addr %#"PRIxMADDR" for dom0\n", ma);
				skip_page = 1;
			}
		}

		/* check for blank page */
		if (!skip_page) {
		   skip_page = 1;
			for (ptr = (unsigned long*) buf; ptr < (unsigned long*) (buf + PAGE_SIZE); ptr++) {
				if (*ptr != 0) {
					skip_page = 0;
					break;
				}
			}
		}

		/* skip blank page if it's not the last one */
		if (skip_page) {
			if (pfn != max_pfn - 1) {
				if (fseeko(mem, PAGE_SIZE, SEEK_CUR)) {
					fprintf(output, "Error: failed to seek pa %"PRIxMADDR" in dom0 memory dump: %s\n", pa, strerror(errno));
					goto out;
				}
				continue;
			} else {
				memset(buf, '\0', PAGE_SIZE);
			}
		}

		if (fwrite(buf, 1, PAGE_SIZE, mem) != PAGE_SIZE)
		{
			fprintf(output, "Error: writing pa %"PRIxMADDR" in dom0 memory dump: %s\n",
				pa, strerror(errno));
			goto out;
		}
	}
	fprintf(output, "Dom0 dumped OK. File size %"PRIxMADDR"\n", ftello(mem));
 out:
	fclose(mem);
}

void xen_m2p(struct domain *d, struct memory_extent *extents, int count) {
	maddr_t p2mll, p2ml, p2m;
	pfn_t max_pfn, pfn, mfn;
	maddr_t ma;
	int i;

	const int fpp = (PAGE_SIZE / kdump_sizeof_pfn(d));

	if (d->is_hvm) {
		//fprintf(output, "  Cannot dump Pseudo-Physical address space of HVM domain\n");
		return;
	}

	p2mll = d->shared_info.pfn_to_mfn_list_list;
	if (p2mll == 0) {
		//fprintf(output, "  No frame list list available for this domain\n");
		return;
	}

	max_pfn = d->shared_info.max_pfn;
	if (max_pfn == 0) {
		//fprintf(output, "  No max_pfn available for this domain\n");
		return;
	}

	//TODO looping through all pages should be optimized
	for (pfn = 0; pfn < max_pfn; pfn++) {
		if ((pfn % (fpp * fpp)) == 0) {
			ma = p2mll + (pfn / (fpp * fpp) * 4);
			p2ml = kdump_read_pfn_maddr(d, ma) << PAGE_SHIFT;
			if (p2ml == 0) {
				//fprintf(output, "  No P2M frame list for frames %"PRIxPFN"-%"PRIxPFN"\n",
				//	pfn, pfn+(fpp*fpp));
				break;
			}
			//fprintf(output, "  ================================================================\n");
			//fprintf(output, "  P2M frame list for frames %"PRIxPFN"-%"PRIxPFN" "
			//	"from %08"PRIxMADDR" = %08"PRIxMADDR"\n",
			//	pfn, pfn+(fpp*fpp), ma, p2ml);
		}
		if ((pfn % fpp) == 0) {
			ma = p2ml + (pfn / fpp * 4);
			p2m = kdump_read_pfn_maddr(d, ma) << PAGE_SHIFT;
			if (p2m == 0) {
				//fprintf(output, "    No P2M for frames %"PRIxPFN"-%"PRIxPFN"\n",
				//	pfn, pfn+fpp);
				break;
			}
			//fprintf(output, "    --------------------------------------------------------------\n");
			//fprintf(output, "    P2M for frames %"PRIxPFN"-%"PRIxPFN" "
			//	"from %08"PRIxMADDR" = %08"PRIxMADDR"\n",
			//	pfn, pfn+fpp, ma, p2m);
		}
		ma = p2m + (pfn % fpp) * 4;

		mfn = kdump_read_pfn_maddr(d, ma);

		//fprintf(output, "      P2M for frame %"PRIxPFN" is %"PRIxPFN" from %08"PRIxMADDR"\n",
		//	pfn, mfn, ma);

		if (mfn == 0x00000000ffffffffULL) {
			//fprintf(output, "        Skip PFN %"PRIxPFN", MFN=%"PRIxPFN"\n", pfn, mfn);
			continue;
		}

		if (mfn & (1ULL << 31)) {
			//fprintf(output, "      FOREIGN\n");
			mfn &= ~(1 << 31);
		}
		for (i = 0; i < count; i++) {
			if (((extents + i)->maddr >> PAGE_SHIFT) == mfn) {
				(extents + i)->paddr = (pfn << PAGE_SHIFT) + ((extents + i)->maddr & (PAGE_SIZE - 1));
			}
		}
	}
}

int main(int argc, char **argv)
{
	int ch;
	const char *sopts = "do:s:h";
	const char *outdir = NULL;
	int opt_debug = 0;

	const struct option lopts[] = {
		/* short options */
		{"debug",        no_argument,       NULL, 'd'},
		{"output",       required_argument, NULL, 'o'},
		{"symbol-table", required_argument, NULL, 's'},
		{"help",         no_argument,       NULL, 'h'},

		/* long options */
		{"version",           no_argument,       &options.version,             1},
		{"noversion",         no_argument,       &options.version,             0},
		{"console-ring",      no_argument,       &options.console_ring,        1},
		{"noconsole-ring",    no_argument,       &options.console_ring,        0},
		{"machine-memory",    no_argument,       &options.machine_memory_map,  1},
		{"nomachine-memory",  no_argument,       &options.machine_memory_map,  0},
		{"pcpu-state",        no_argument,       &options.pcpu_state,          1},
		{"nopcpu-state",      no_argument,       &options.pcpu_state,          0},
		{"domain-list-separate", no_argument,    &options.domain_list_separate,1},
		{"domain-list-combined", no_argument,    &options.domain_list_separate,0},
		{"domain-list",       optional_argument, NULL,                         OPT_DOMAIN_LIST},
		{"nodomain-list",     no_argument,       NULL,                        -OPT_DOMAIN_LIST},
		{"xen-memory-dump",   optional_argument, NULL,                         OPT_XEN_MEMORY_DUMP},
		{"noxen-memory-dump", no_argument,       NULL,                        -OPT_XEN_MEMORY_DUMP},
		{"dom0-memory-dump",  optional_argument, NULL,                         OPT_DOM0_MEMORY_DUMP},
		{"nodom0-memory-dump",optional_argument, NULL,                        -OPT_DOM0_MEMORY_DUMP},

		/* group options */
		{"mini", 0, NULL, OPT_MINI},
		{"maxi", 0, NULL, OPT_MAXI},
		{"full", 0, NULL, OPT_FULL},

		{0, 0, 0, 0}
	};

	const char **symtab_files = NULL;
	int nr_symtab_files = -1;

	const char *xen_symtab_file = NULL;
	struct symbol_table *xen_symtab = NULL;

	const char *fn = "/proc/vmcore";

	while ((ch = getopt_long(argc, argv, sopts, lopts, NULL)) != -1) {
		switch(ch) {
		case 'd':
			opt_debug = 1;
			break;
		case 'o':
			outdir = optarg;
			break;
		case 's':
			if (strchr(optarg, '='))
			{
				void *tmp;
				int dom;
				char *fname;

				errno = 0;
				dom = strtol(optarg, &fname, 0);
				if (errno != 0)
				{
					fprintf(stderr, "unable to parse --symbol-table=\"%s\"\n", optarg);
					return 1;
				}

				fname++; /* skip '=' */

				if (dom > nr_symtab_files)
				{
					tmp = realloc(symtab_files, (dom+1) * sizeof(char *));
					if ( tmp == NULL )
					{
						fprintf(stderr, "failed to allocate memory for symbol table %s\n",
							fname);
						break;
					}

					symtab_files = tmp;

					memset(&symtab_files[nr_symtab_files + 1], 0,
					       (dom - nr_symtab_files) * sizeof (char *));

					nr_symtab_files = dom;
				}

				if ( symtab_files[dom] )
				{
					fprintf(stderr, "ignoring second symbol table for domain %d:\n"
						"\tprevious is %s\n"
						"\tnew is %s\n",
						dom, symtab_files[dom], fname);
					break;
				}

				symtab_files[dom] = fname;
			}
			else
			{
				xen_symtab_file = optarg;
			}
			break;
		case 'h':
			usage();
			return 1;

		case OPT_DOMAIN_LIST:
			if (optarg)
			{
				if (strcmp(optarg, "dom0") ==0)
					options.domain_list = DOMAIN_LIST_DOM0;
				else if (strcmp(optarg, "all") == 0)
					options.domain_list = DOMAIN_LIST_ALL;
				else
				{
					fprintf(stderr, "unknown domain list argument \"%s\"\n", optarg);
					return 1;
				}
			}
			else
			{
				options.domain_list = DOMAIN_LIST_ALL;
			}

			break;

		case -OPT_DOMAIN_LIST:
			options.domain_list = DOMAIN_LIST_NONE;
			break;

		case OPT_XEN_MEMORY_DUMP:
			options.xen_memory_dump = optarg ?: DEFAULT_XEN_MEMORY_DUMP;
			break;
		case -OPT_XEN_MEMORY_DUMP:
			options.xen_memory_dump = NULL;
			break;

		case OPT_DOM0_MEMORY_DUMP:
			options.dom0_memory_dump = optarg ?: DEFAULT_DOM0_MEMORY_DUMP;
			break;
		case -OPT_DOM0_MEMORY_DUMP:
			options.dom0_memory_dump = NULL;
			break;

		case OPT_MINI:
			//fprintf(stderr, "performing mini dump\n");
			options = mini_option;
			break;
		case OPT_MAXI:
			//fprintf(stderr, "performing maxi dump\n");
			options = maxi_option;
			break;
		case OPT_FULL:
			//fprintf(stderr, "performing full dump\n");
			options = full_option;
			break;
		case '?':
			fprintf(stderr, "%s --help for more options\n", argv[0]);
			return 1;
		}
	}

	argv += optind; argc -= optind;

	if (argc > 1) {
		fprintf(stderr, "too many arguments\n");
		return 1;
	}

	if (argc == 1)
		fn = argv[0];

	working_directory = open(".", O_RDONLY);
	if ( working_directory == -1 )
	{
		fprintf(stderr, "failed to save current directory: %s\n", strerror(errno));
		return 1;
	}

	if (outdir)
	{
		if (mkdir(outdir,0700))
		{
			fprintf(stderr, "failed to create output directory %s: %s\n",
				outdir, strerror(errno));
		}

		output_directory = open(outdir, O_RDONLY);
		if ( output_directory == -1 )
		{
			fprintf(stderr, "failed to open output directory %s: %s\n",
				outdir, strerror(errno));
			return 1;
		}

		output = fopen_in_output_directory("crash.log", "w");
		if (output == NULL)
		{
			fprintf(stderr, "failed to open crash.log: %s\n", strerror(errno));
			return 1;
		}

		if ( options.domain_list_separate == -1 )
			options.domain_list_separate = 1;

		debug = fopen_in_output_directory("debug.log", "w");
		if (debug == NULL)
		{
			fprintf(stderr, "failed to open debug.log: %s\n", strerror(errno));
			debug = stderr;
		}
	} else {
		output_directory = working_directory;

		output = stdout;

		if ( options.domain_list_separate == -1 )
			options.domain_list_separate = 0;

		if ( opt_debug )
		{
			debug = stderr;
		}
		else
		{
			debug = fopen("/dev/null", "w");
			if ( debug == NULL )
			{
				fprintf(stderr, "failed to redirect debugging to /dev/null: %s\n",
					strerror(errno));
				debug = stderr;
			}
		}
	}

	if (xen_symtab_file)
	{
		xen_symtab = symtab_parse(xen_symtab_file, -1);

		if (xen_symtab == NULL)
			fprintf(debug, "Failed to parse xen symbol table %s.\n", xen_symtab_file);
		else
			fprintf(output, "Xen Symbol table: %s\n", xen_symtab_file);
	}

	if ((options.console_ring || options.domain_list || options.dom0_memory_dump)
	    && !have_required_symbols)
	{
		fprintf(output, "Required symbols are not available. Disabling: \n");
		if(options.domain_list)
			fprintf(output, "  domain-list\n");
		if(options.console_ring)
			fprintf(output, "  console-ring\n");
		if(options.xen_memory_dump)
			fprintf(output, "  xen-memory-dump\n");
		if(options.dom0_memory_dump)
			fprintf(output, "  dom0-memory-dump\n");

		options.console_ring = 0;
		options.domain_list = 0;
		options.xen_memory_dump = 0;
		options.dom0_memory_dump = 0;

		fprintf(output, "\n");
	}


	open_dump(fn, xen_symtab, nr_symtab_files, symtab_files);

	fprintf(output, "Read crash dump from %s\n", fn);
	fprintf(output, "\n");

	if (dump == NULL) {
		fprintf(stderr, "failed to parse: %s\n", fn);
		return 1;
	}

	if (options.version)
		dump_xen_version_info(dump);
	if (options.pcpu_state)
		dump_pcpu_state(dump);
	if (options.machine_memory_map)
		dump_machine_memory_map(dump);
	if (options.console_ring)
		dump_xen_console_ring(dump);

	if (options.xen_memory_dump)
		dump_xen_memory(options.xen_memory_dump);
	if (options.dom0_memory_dump)
		dump_domain_memory(&dump->domains[0], options.dom0_memory_dump);

	switch (options.domain_list)
	{
	case DOMAIN_LIST_NONE:
		break;
	case DOMAIN_LIST_DOM0:
		dump_domains(0);
		break;
	case DOMAIN_LIST_ALL:
		dump_domains(-1);
		break;
	}

	close_dump(dump);

	free(symtab_files);

	close(working_directory);
	if (output_directory != working_directory)
		close(output_directory);
	if (output != stdout)
		fclose(output);
	if (debug != stderr)
		fclose(debug);

	return 0;
}
