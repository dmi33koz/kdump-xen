/* Copyright (c) 2007, XenSource, Inc. - All rights reserved. */

#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <xen/elfnote.h>

#include "kdump.h"
#include "bitness.h"
#include "memory.h"

/* NOTE!!!
 * Even on 32 bit platform we use Elf64_Ehdr and Elf64_Phdr
 * in order to describe large memory configuration like PAE.
 * kexec should always use --elf64-core-headers option
 *
 * It also helps that
 * sizeof(Elf32_Word) == sizeof(Elf64_Word)
 * sizeof(Elf32_Nhdr) == sizeof(Elf64_Nhdr)
 *
 * for more details see /usr/include/elf.h
 */
typedef Elf32_Nhdr Elf_Nhdr;
typedef Elf32_Word Elf_Word;

#define DYNAMICALLY_FILLED   0
#define RAW_OFFSET         256

#define ALIGN(n) ((n+3)&~3)



#define ELFNOTE_NAMESZ(_n_) (((_n_)->n_namesz+3)&~3)
#define ELFNOTE_DESCSZ(_n_) (((_n_)->n_descsz+3)&~3)
#define ELFNOTE_SIZE(_n_) (sizeof(*(_n_)) + ELFNOTE_NAMESZ(_n_) + ELFNOTE_DESCSZ(_n_))

#define ELFNOTE_NAME(_n_) (const char *)((void*)(_n_) + sizeof(*(_n_)))
#define ELFNOTE_DESC(_n_) (void *)(ELFNOTE_NAME(_n_) + ELFNOTE_NAMESZ(_n_))
#define ELFNOTE_NEXT(_n_) (Elf_Nhdr*)(ELFNOTE_DESC(_n_) + ELFNOTE_DESCSZ(_n_))

typedef struct phdr_info {
	Elf64_Phdr phdr;
	char *data; // used by note header if null - data will be written separately
	uint64_t size;
} phdr_info_t;

typedef struct {
	int count;
	phdr_info_t *pinfos; //array of pinfos
} phdr_all_t;

typedef struct elf_all {
	Elf64_Ehdr ehdr;
	phdr_all_t phdrs;
} elf_all_t;

// global holder of saved xen elf headers
elf_all_t elfall;

// add phdr_info into elf_all.phdr_all
// it reallocated structures so old pointers become invalid.
static phdr_info_t * __add_phdr_info(elf_all_t *all, Elf_Word type, Elf_Word flags) {
	phdr_all_t *p_all;
	phdr_info_t *pi;

	p_all = &all->phdrs;

	p_all->pinfos = realloc(p_all->pinfos, sizeof(phdr_info_t) * (p_all->count + 1));

	pi = &p_all->pinfos[p_all->count];
	memset(pi, '\0', sizeof(phdr_info_t));
	p_all->count++;
	pi->phdr.p_type = type;
	pi->phdr.p_flags = flags;
	all->ehdr.e_phnum++;

	return &p_all->pinfos[p_all->count - 1];
}

static void __add_note(phdr_info_t *pi, const char * name, Elf_Word type, char * data, size_t size) {
	Elf_Nhdr *nhdr;
	char *buf, *ptr;
	int buf_size;

	buf_size = sizeof(Elf_Nhdr) + ALIGN(strlen(name)+1) + ALIGN(size);
	buf = ptr = malloc(buf_size);
	memset(buf, '\0', buf_size);
	nhdr = (Elf_Nhdr*) buf;
	//set note heder
	nhdr->n_namesz = strlen(name) + 1;
	nhdr->n_type = type;
	nhdr->n_descsz = size;
	ptr += sizeof(Elf_Nhdr);
	//set name
	strcpy(ptr, name);
	ptr += ALIGN(strlen(name)+1);
	//set data
	memcpy(ptr, data, size);

	// add to phdr_info
	if (!pi->data) {
		pi->data = buf;
		pi->size = buf_size;
	} else {
		ptr = realloc(pi->data, pi->size + buf_size);
		pi->data = ptr;
		memcpy(pi->data + pi->size, buf, buf_size);
		pi->size += buf_size;
		free(buf);
	}
	pi->phdr.p_filesz = pi->phdr.p_memsz = pi->size;
}

static void __fix_section_offsets(elf_all_t *all) {
	phdr_all_t *p_all = &all->phdrs;
	phdr_info_t *pi, *piv;
	int i, v;
	uint64_t offset;
	offset = sizeof(Elf64_Ehdr) + p_all->count * sizeof(Elf64_Phdr);

	// Notes come before loads
	for (i = 0; i < p_all->count; i++) {
		pi = &p_all->pinfos[i];
		if (pi->phdr.p_type == PT_NOTE) {
			pi->phdr.p_offset = offset;
			offset += pi->size;
			debug("Note phdr %d data_offset %#" PRIx64 " p_paddr %#" PRIx64 " p_offset %#" PRIx64 " data %p size %#" PRIx64 "\n",
					i, offset, pi->phdr.p_paddr, pi->phdr.p_offset, pi->data, pi->size);
		}
	}

	// Loads with actual data
	for (i = 0; i < p_all->count; i++) {
		pi = &p_all->pinfos[i];
		if (pi->phdr.p_type == PT_LOAD && pi->size) {
			pi->phdr.p_offset = offset;
			offset += pi->size;
			debug("Load phdr %d data_offset %#" PRIx64 " p_paddr %#" PRIx64 " p_offset %#" PRIx64 " data %p size %#" PRIx64 "\n",
					i, offset, pi->phdr.p_paddr, pi->phdr.p_offset, pi->data, pi->size);
		}
	}

	// Extra Loads for virtual addresses pointing to data in other loads
	for (v = 0; v < p_all->count; v++) {
		piv = &p_all->pinfos[v];
		if (piv->phdr.p_type == PT_LOAD && piv->size == 0) {
			for (i = 0; i < p_all->count; i++) {
				pi = &p_all->pinfos[i];
				if (pi->phdr.p_type == PT_LOAD && pi->size) {
					if (pi->phdr.p_paddr <= piv->phdr.p_paddr && pi->phdr.p_paddr + pi->phdr.p_memsz >= piv->phdr.p_paddr + piv->phdr.p_memsz) {
						piv->phdr.p_offset = pi->phdr.p_offset + piv->phdr.p_paddr - pi->phdr.p_paddr;
						debug("Virtual phdr %d data_offset %#" PRIx64 " p_paddr %#" PRIx64 " p_offset %#" PRIx64 " data %p size %#" PRIx64 "\n",
								v, offset, piv->phdr.p_paddr, piv->phdr.p_offset, piv->data, piv->size);
						break;
					}
				}
			}
			if (i == p_all->count) {
				debug("Error: unable to find p_offset for load header %d\n", v);
				piv->phdr.p_offset = 0;
			}
		}
	}
}

static void __write_buf(FILE *f, void *b, int size) {
	static int offset = 0;
	//hex_dump(offset, (char*) b, size);
	offset += size;
	if (fwrite(b, 1, size, f) < 0) {
		exit(-1);
	}
}

static void __write_all_elfs(FILE *f, elf_all_t *all) {
	Elf64_Ehdr *ehdr = &all->ehdr;
	phdr_all_t *p_all = &all->phdrs;
	int i = 0;
	phdr_info_t *pi;
	p_all = &all->phdrs;

	// write Ehdr
	__write_buf(f, ehdr, sizeof(Elf64_Ehdr));

	// write all Note Phdr(s)
	for (i = 0; i < p_all->count; i++) {
		pi = &p_all->pinfos[i];
		if (pi->phdr.p_type == PT_NOTE) {
			__write_buf(f, &pi->phdr, sizeof(Elf64_Phdr));
		}
	}
	// write all Note Phdr(s)
	for (i = 0; i < p_all->count; i++) {
		pi = &p_all->pinfos[i];
		if (pi->phdr.p_type == PT_LOAD && pi->phdr.p_offset) {
			__write_buf(f, &pi->phdr, sizeof(Elf64_Phdr));
		}
	}
	// write all Phdr(s) data
	// only note phdr has data for now
	// load data will be written separately
	for (i = 0; i < p_all->count; i++) {
		pi = &p_all->pinfos[i];
		if (pi->data && pi->size) {
			__write_buf(f, pi->data, pi->size);
		}
	}
}
static void __init_elf_header(Elf64_Ehdr *h) {
	memset(h, '\0', sizeof(*h));

	h->e_ident[0] = ELFMAG0;
	h->e_ident[1] = ELFMAG1;
	h->e_ident[2] = ELFMAG2;
	h->e_ident[3] = ELFMAG3;
	h->e_ident[4] = ELFCLASS64;
	h->e_ident[5] = ELFDATA2LSB;
	h->e_ident[6] = EV_CURRENT;
	h->e_type = ET_CORE;
	h->e_machine = EM_X86_64;
	h->e_version = EV_CURRENT;
	h->e_entry = DYNAMICALLY_FILLED;
	h->e_phoff = sizeof(Elf64_Ehdr);
	h->e_shoff = DYNAMICALLY_FILLED;
	h->e_flags = 0;
	h->e_ehsize = sizeof(Elf64_Ehdr);
	h->e_phentsize = sizeof(Elf64_Phdr);
	h->e_phnum = 0; // modify later by adding phdrs
	h->e_shentsize = 0;
	h->e_shnum = 0;
	h->e_shstrndx = 0;
}

/* Allocate `dump->cpus' to handle `nr' cpus. */
static int allocate_cpus(int nr)
{
	void *tmp;

	if (dump->nr_cpus>=nr)
		return 0;

	tmp = realloc(dump->cpus, nr*sizeof(struct cpu_state));
	if (tmp == NULL)
		return 1;

	dump->cpus = tmp;

	/* Zero the new cpu(s) */
	memset(&dump->cpus[dump->nr_cpus], 0, (nr-dump->nr_cpus)*sizeof(struct cpu_state));

	dump->nr_cpus = nr;

	return 0;
}

/*
 * CPU state currently being parsed. Passed from parse_note_CORE to
 * parse_note_Xen.
 */
static struct cpu_state current_cpu;

static int parse_note_CORE(struct arch *arch, off64_t offset, Elf_Nhdr *note)
{
	switch (note->n_type) {
	case NT_PRSTATUS: {
		memset(&current_cpu, 0, sizeof(current_cpu));
		if (kdump_parse_prstatus(arch, ELFNOTE_DESC(note), &current_cpu))
			return 1;

		//debug("CORE PR_STATUS\n");

		break;
	}
	default:
		debug("unhandled CORE note type %d\n", note->n_type);
		return 1;
	}

	return 0;
}

/* Obsolete */
static int parse_note_XEN_CORE(struct arch *arch, off64_t offset, Elf_Nhdr *note)
{
	debug("unhandled \"XEN CORE\" note type %x\n", note->n_type);
	return 1;
}

static int check_note_name(Elf_Nhdr *note) {
	int i;
	const char *name = ELFNOTE_NAME(note);
	uint32_t size = note->n_namesz;
	for (i = 0; i < size; i++) {
		if (name[i] == 0) {
			return 0; // name is \0 terminated
		}
	}
	return 1; // name is not \0 terminated
}

// read crash_note from vaddr and set current_cpu to the state
int parse_crash_note(struct domain *d, vaddr_t note_p, struct cpu_state *guest_cpu) {
	Elf_Nhdr *note = NULL;
	int size = 0;
	note = malloc(sizeof(*note));

	// first find out total note size
	if (kdump_read_vaddr(d, note_p, (void*) note, sizeof(*note)) != sizeof(*note))
		goto err;

	if (note->n_type != NT_PRSTATUS || !ELFNOTE_NAMESZ(note) || !ELFNOTE_DESCSZ(note))
		goto err;

	if (check_note_name(note) != 0)
		goto err;

	size = ELFNOTE_SIZE(note);
	note = realloc(note, size);

	// then read whole note
	if (kdump_read_vaddr(d, note_p, note, size) != size)
		goto err;

	//hex_dump(0, note, size);
	if (strcmp("CORE", ELFNOTE_NAME(note)) != 0)
		goto err;

	if (parse_note_CORE(d->_arch, 0, note))
		goto err;

	memcpy(guest_cpu, &current_cpu, sizeof(current_cpu));
	memset(&current_cpu, 0, sizeof(current_cpu));

	free(note);
	return 0;
err:
	if(note)
		free(note);
	return 1;
}
/*
 * This is a hack - we need to parce "Xen" XEN_ELFNOTE_CRASH_INFO note first
 * in order to find xen_phys_start
 */

static int parce_xen_note_only = 0;

static int parse_note_Xen(struct arch *arch, off64_t offset, Elf_Nhdr *note)
{

	if (note->n_type == XEN_ELFNOTE_CRASH_INFO) {

		//debug("Xen ELFNOTE_CRASH_INFO\n");
		if (parce_xen_note_only) {
			if (kdump_parse_hypervisor(ELFNOTE_DESC(note)))
			{
				debug("failed to parse hypervisor note\n");
				return 1;
			}
		}
		return 0;
	}
	if (parce_xen_note_only) {
		return 0;
	}
	if (note->n_type == XEN_ELFNOTE_CRASH_REGS) {
		/* Haven't parsed the basic state? */
		if (current_cpu.flags == 0) {
			debug("Haven't parsed the basic state skipping\n");
			return 1;
		}

		if (kdump_parse_crash_regs(arch, ELFNOTE_DESC(note), &current_cpu))
			return 1;

		//debug("Xen ELFNOTE_CRASH_REGS for CPU%d\n", current_cpu.nr);

		if (allocate_cpus(current_cpu.nr+1))
			return 1;

		memcpy(&dump->cpus[current_cpu.nr], &current_cpu, sizeof(current_cpu));
		memset(&current_cpu, 0, sizeof(current_cpu));
	} else {
		debug("unhandled \"Xen\" note type %x\n", note->n_type);
		return 1;
	}

	return 0;
}

static int note_get_symbol_hex(char *text, char * name, uint64_t * val) {
	uint64_t v;
	char * ptr_begin;

	ptr_begin = strstr(text, name);
	if (!ptr_begin) {
		debug("note string %s not found\n", name);
		return 1;
	}
	ptr_begin += strlen(name);

	if (sscanf(ptr_begin, "%" PRIx64, &v) != 1) {
		debug("note string %s sscanf failed\n", name);
		return 1;
	}
	*val = v;
	return 0;
}

static int note_get_symbol(char *text, char * name, uint64_t * val) {
	uint64_t v;
	char * ptr_begin;

	ptr_begin = strstr(text, name);
	if (!ptr_begin) {
		debug("note string %s not found\n", name);
		return 1;
	}
	ptr_begin += strlen(name);

	if (sscanf(ptr_begin, "%" PRIu64, &v) != 1) {
		debug("note string %s sscanf failed\n", name);
		return 1;
	}
	*val = v;
	return 0;
}

static int parse_note_VMCOREINFO(struct arch *arch, off64_t offset, Elf_Nhdr *note)
{
	char * text;

	text = malloc(note->n_descsz +1);
	memcpy(text, ELFNOTE_DESC(note), note->n_descsz);
	text[note->n_descsz] = '\0';

	debug("parse_note_VMCOREINFO note type %x size %d len %Zd\n",
			note->n_type, note->n_descsz, strlen(text));
	debug("\n%s\n", text);
	free(text);
	return 0;
}

static int parse_note_VMCOREINFO_XEN(struct arch *arch, off64_t offset, Elf_Nhdr *note)
{
	char * text;
	uint64_t val;

	text = malloc(note->n_descsz +1);
	memcpy(text, ELFNOTE_DESC(note), note->n_descsz);
	text[note->n_descsz] = '\0';

	debug("parse_note_VMCOREINFO_XEN note type %x size %d len %Zd\n",
			note->n_type, note->n_descsz, strlen(text));
	debug("\n%s\n", text);

	if (note_get_symbol_hex(text, "SYMBOL(frame_table)=", &val) == 0) {
		dump->frame_table = kdump_read_pointer_vaddr(NULL, val);
	}
	debug("frame_table = %#" PRIx64 "\n", dump->frame_table);

	if (note_get_symbol(text, "SIZE(page_info)=", &val) == 0) {
		dump->sizeof_page_info = val;
	}
	debug("sizeof_page_info = %d\n", dump->sizeof_page_info);

	if (note_get_symbol(text, "OFFSET(page_info.count_info)=", &val) == 0) {
		dump->offset_page_info_count_info = val;
	}
	debug("offset_page_info_count_info = %d\n", dump->offset_page_info_count_info);

	if (note_get_symbol(text, "OFFSET(page_info._domain)=", &val) == 0) {
		dump->offset_page_info_domain = val;
	}
	debug("offset_page_info_domain = %d\n", dump->offset_page_info_domain);

	free(text);
	return 0;
}

static int parse_pt_note(struct arch *arch, Elf64_Phdr *phdr) {
	off64_t offset = phdr->p_offset;
	Elf_Nhdr *note;
	const char *name;
	uint32_t size;
	unsigned char notes[phdr->p_filesz];
	int n, ret;
	phdr_info_t *p_info;

	if (kdump_read(notes, phdr->p_offset, phdr->p_filesz) != phdr->p_filesz) {
		debug("Failed to read PT_NOTE: %s\n", strerror(errno));
		return 1;
	}
	if (!parce_xen_note_only) {
		p_info = __add_phdr_info(&elfall, phdr->p_type, phdr->p_flags);
	}
	n = 0;
	for (note = (Elf_Nhdr*) notes; (void*) note < (void*) notes + phdr->p_filesz - 1; note = ELFNOTE_NEXT(note)) {
		name = ELFNOTE_NAME(note);
		size = note->n_namesz;
		debug("Parsing Note entry %d type 0x%x name %s\n", n, note->n_type, name);

		if (check_note_name(note) == 0) {
			if (strcmp("Xen", name) == 0) {
				ret = parse_note_Xen(arch, offset, note);
			} else if (parce_xen_note_only) {
				continue;
			} else if (strcmp("CORE", name) == 0) {
				ret = parse_note_CORE(arch, offset, note);
			} else if (strcmp("XEN CORE", name) == 0) {
				ret = parse_note_XEN_CORE(arch, offset, note);
			} else if (strcmp("VMCOREINFO", name) == 0) {
				ret = parse_note_VMCOREINFO(arch, offset, note);
			} else if (strcmp("VMCOREINFO_XEN", name) == 0) {
				ret = parse_note_VMCOREINFO_XEN(arch, offset, note);
			} else {
				debug("Unknown note entry name %s\n", name);
				ret = 0;
			}
			if (ret) {
				debug("Failed to handle note entry %s\n", name);
			}
			if (!parce_xen_note_only) {
				__add_note(p_info, name, note->n_type, (char*) ELFNOTE_DESC(note), note->n_descsz);
			}
		} else {
			debug("Invalid note %d name\n", n);
		}

		offset += (off64_t) (unsigned long) ELFNOTE_NEXT(note) - (off64_t) (unsigned long) note;
		n++;
	}

	return 0;
}

static int parse_pt_load(struct arch *arch, Elf64_Phdr *phdr)
{
	void *mem;
	struct memory_extent *mext;

	mem = realloc(dump->machine_memory,(dump->nr_machine_memory+1)*sizeof(struct memory_extent));
	if (mem == NULL) {
		debug("malloc failed\n");
		return 1;
	}
	dump->machine_memory=mem;

	mext = &dump->machine_memory[dump->nr_machine_memory];

	mext->maddr = phdr->p_paddr;
	mext->vaddr = phdr->p_vaddr;
	mext->length = phdr->p_memsz;
	mext->offset = phdr->p_offset;

	debug("Memory extent: maddr %16"PRIxMADDR" length %16"PRIx64" vaddr %16"PRIxVADDR" offset %16"PRIx64"\n",
		mext->maddr, mext->length, mext->vaddr, mext->offset);
	dump->nr_machine_memory++;

	return 0;
}

static int foreach_phdr_type(Elf64_Ehdr *ehdr, Elf_Word p_type,
			     int (*callback)(struct arch *arch, Elf64_Phdr *phdr))
{
	int i;

	for (i=0; i<ehdr->e_phnum; i++) {
		Elf64_Phdr phdr;

		if (kdump_read(&phdr, ehdr->e_phoff + (i*sizeof(phdr)), sizeof(phdr)) != sizeof(phdr))
		{
			debug("failed to read program header %d: %s\n",
				i, strerror(errno));
			return 1;
		}
		if (phdr.p_type == p_type) {
			debug("parse Phdr entry %d of type 0x%x\n", i, phdr.p_type);
			if ((*callback)(dump->_arch, &phdr)) {
				debug("Error: failed to parse pt entry %d of type 0x%x\n", i,
						phdr.p_type);
			}
		}
	}
	return 0;
}

int create_elf_header_xen(FILE *f, mem_range_t * mr_first) {
	phdr_info_t *p_info;
	mem_range_t * mr = mr_first;

	while (mr) {
		debug("ELF PT_LOAD start mfn %#" PRIxMADDR " end mfn %#" PRIxMADDR " pages %#" PRIx64 " vaddr %#" PRIxVADDR "\n", mr->mfn, mr->mfn + mr->page_count,
				mr->page_count, mr->vaddr);

		p_info = __add_phdr_info(&elfall, PT_LOAD, PF_R | PF_W | PF_X);
		p_info->phdr.p_vaddr = mr->vaddr;
		p_info->phdr.p_paddr = mr->mfn << PAGE_SHIFT;
		p_info->phdr.p_filesz = mr->page_count << PAGE_SHIFT;
		p_info->phdr.p_memsz = p_info->phdr.p_filesz;
		p_info->data = NULL; // data will be written separately
		p_info->size = p_info->phdr.p_filesz;
		mr = mr->next;
	}

	__fix_section_offsets(&elfall);
	__write_all_elfs(f, &elfall);
	return ftell(f);
}

int create_elf_header_dom(FILE *f, int dom_id) {
	struct elf_all all;
	// NOTE! elf header is always 64 bit type even for 32 bit platform
	// but e_machine is different for 32/64
	Elf64_Ehdr *ehdr;
	struct cpu_state *vcpu;
	char prs[1024]; // ELF_Prstatus -- platform dependent
	struct domain *d;
	struct phdr_info *p_info;
	int prstatus_size;
	struct memory_extent *vmalloc_extents;
	int vmalloc_count, n;
	int cpuid;

	debug("Domain id %d\n", dom_id);

	d = &dump->domains[dom_id];

	memset(&all, '\0', sizeof(all));

	// initialize elf header
	ehdr = &all.ehdr;
	__init_elf_header(ehdr);
	if (d->has_32bit_shinfo) {
		ehdr->e_machine = EM_386;
	} else {
		ehdr->e_machine = EM_X86_64;
	}
	// add note(s) program header
	p_info = __add_phdr_info(&all, PT_NOTE, 0);
	// for each domain cpu add "CORE" note
	for (cpuid = 0; cpuid < d->nr_vcpus; cpuid++) {
		if (d->guest_cpus[cpuid].valid) {
			vcpu = &d->guest_cpus[cpuid]; // cpu state from crash_notes
		} else {
			vcpu = &d->vcpus[cpuid]; // xen vcpu state
		}
		prstatus_size = kdump_set_prstatus(d, prs, vcpu);
		debug("adding note ELF_Prstatus size = 0x%x\n", prstatus_size);
		__add_note(p_info, "CORE", NT_PRSTATUS, (char*) &prs, prstatus_size);
	}
	/* setup ELF PT_LOAD program header for the
	 * virtual range 0xc0000000 -> high_memory
	 */
	p_info = __add_phdr_info(&all, PT_LOAD, PF_R | PF_W | PF_X);
	p_info->phdr.p_vaddr = d->symtab->lowest_kernel_address; //0xc0000000
	p_info->phdr.p_paddr = 0;
	//p_info->phdr.p_filesz = d->shared_info.max_pfn << PAGE_SHIFT;
	p_info->phdr.p_filesz = d->high_memory - d->symtab->lowest_kernel_address;
	p_info->phdr.p_memsz = p_info->phdr.p_filesz;
	p_info->phdr.p_align = PAGE_SIZE;
	p_info->data = NULL;
	p_info->size = p_info->phdr.p_memsz;

	/* ELF PT_LOAD program header for the
	 * virtual range high_memory -> max pfn
	 */
	p_info = __add_phdr_info(&all, PT_LOAD, PF_R | PF_W | PF_X);
	p_info->phdr.p_vaddr = 0;
	p_info->phdr.p_paddr = d->high_memory - d->symtab->lowest_kernel_address;
	;
	p_info->phdr.p_filesz = (d->shared_info.max_pfn << PAGE_SHIFT) - (d->high_memory - d->symtab->lowest_kernel_address);
	p_info->phdr.p_memsz = p_info->phdr.p_filesz;
	p_info->phdr.p_align = PAGE_SIZE;
	p_info->data = NULL;
	p_info->size = p_info->phdr.p_memsz;

	vmalloc_count = x86_32_get_vmalloc_extents(d, vcpu, &vmalloc_extents);
	for (n = 0; n < vmalloc_count; n++) {
		p_info = __add_phdr_info(&all, PT_LOAD, PF_R | PF_W | PF_X);
		p_info->phdr.p_vaddr = (vmalloc_extents + n)->vaddr;
		p_info->phdr.p_paddr = (vmalloc_extents + n)->paddr;
		p_info->phdr.p_filesz = (vmalloc_extents + n)->length;
		p_info->phdr.p_memsz = p_info->phdr.p_filesz;
		p_info->phdr.p_align = PAGE_SIZE;
		p_info->data = NULL;
		p_info->size = 0; // fake header - points to data in other headers

	}
	__fix_section_offsets(&all);
	__write_all_elfs(f, &all);
	return ftell(f);
}

int parse_dump()
{
	extern struct arch arch_x86_32;
	extern struct arch arch_x86_64;
	Elf64_Ehdr ehdr;
	Elf64_Ehdr *ehdr_out = &elfall.ehdr;

	memset(&elfall, '\0', sizeof(elfall));

	if (kdump_read(&ehdr, 0, sizeof(ehdr)) != sizeof(ehdr))
	{
		debug("failed to read dump elf header: %s\n", strerror(errno));
		return 1;
	}
	memcpy(ehdr_out, &ehdr, sizeof(ehdr));
	ehdr_out->e_phnum = 0;
	ehdr_out->e_shentsize = 0;
	ehdr_out->e_shnum = 0;
	ehdr_out->e_shstrndx = 0;

	dump->e_machine = ehdr.e_machine;
	switch (dump->e_machine) {
	case EM_386:
		dump->_arch = &arch_x86_32;
		dump->compat_arch = NULL;
		break;
	case EM_X86_64:
		dump->_arch = &arch_x86_64;
		dump->compat_arch = &arch_x86_32;
		break;
	default:
		debug("unknown machine class %d\n", dump->e_machine);
		return 1;
	}

	/*
	 * Parse PT_LOAD first to populate memory map which is used
	 * when parsing the CPU notes.
	 */
	if (foreach_phdr_type(&ehdr, PT_LOAD, &parse_pt_load))
		return 1;
	/*
	 * Now we need to grab some vital data to be able to translate xen
	 * virtual addersses
	 */
	parce_xen_note_only = 1;

	if (foreach_phdr_type(&ehdr, PT_NOTE, &parse_pt_note))
		return 1;

	parce_xen_note_only = 0;

	if (foreach_phdr_type(&ehdr, PT_NOTE, &parse_pt_note))
		return 1;

	return 0;
}
