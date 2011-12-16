/* Copyright (c) 2007, XenSource, Inc. - All rights reserved. */

#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <xen/elfnote.h>

#include "kdump.h"

#if ELFSIZE == 32

#define FN(x) x##_32
#define TYPE(x) Elf32_##x

#elif ELFSIZE == 64

#define FN(x) x##_64
#define TYPE(x) Elf64_##x

#else

#error "unknown elf size"

#endif

typedef TYPE(Ehdr) Elf_Ehdr;
typedef TYPE(Shdr) Elf_Shdr;
typedef TYPE(Phdr) Elf_Phdr;
typedef TYPE(Nhdr) Elf_Nhdr;
typedef TYPE(Word) Elf_Word;

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
	Elf_Phdr phdr;
	char *data;
	int size;
} phdr_info_t;

typedef struct {
	int count;
	phdr_info_t *pinfos; //array of pinfos
} phdr_all_t;

typedef struct elf_all {
	Elf_Ehdr ehdr;
	phdr_all_t phdrs;
} elf_all_t;

// global pointer to elf headers
elf_all_t elfall;

// add phdr_info into elf_all.phdr_all
// it reallocated structures so old pointers become invalid.
static phdr_info_t * __add_phdr_info(elf_all_t *all, Elf_Word type, Elf_Word flags) {
	phdr_all_t *p_all;
	void *tmp;
	phdr_info_t *pi;

	p_all = &all->phdrs;
	if (p_all->count == 0) {
		p_all->pinfos = malloc(sizeof(phdr_info_t));
	} else {
		tmp = realloc(p_all->pinfos, sizeof(phdr_info_t) * (p_all->count + 1));
		p_all->pinfos = tmp;
	}
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
	phdr_info_t *pi;
	int i;
	// shift to the end of program headers
	unsigned int offset = sizeof(Elf_Ehdr) + p_all->count * sizeof(Elf_Phdr);

	for (i = 0; i < p_all->count; i++) {
		pi = &p_all->pinfos[i];
		pi->phdr.p_offset = offset;
		offset += pi->phdr.p_filesz;
	}
}

static void __write_buf(FILE *f, void *b, int size) {
	static int offset = 0;
	hex_dump(offset, (char*) b, size);
	offset += size;
	if (fwrite(b, 1, size, f) < 0) {
		exit(-1);
	}
}

static void __write_all_elfs(FILE *f, elf_all_t *all) {
	Elf_Ehdr *ehdr = &all->ehdr;
	phdr_all_t *p_all = &all->phdrs;
	int pi_index = 0;
	phdr_info_t *p_info;
	p_all = &all->phdrs;

	// write Ehdr
	__write_buf(f, ehdr, sizeof(Elf_Ehdr));
	// write all Phdr(s)
	for (pi_index = 0; pi_index < p_all->count; pi_index++) {
		p_info = &p_all->pinfos[pi_index];
		__write_buf(f, &p_info->phdr, sizeof(Elf_Phdr));
	}
	// write all Phdr(s) data
	for (pi_index = 0; pi_index < p_all->count; pi_index++) {
		p_info = &p_all->pinfos[pi_index];
		if (p_info->data) {
			__write_buf(f, p_info->data, p_info->size);
		}
	}
}

/* Allocate `dump->cpus' to handle `nr' cpus. */
static int allocate_cpus(struct dump *dump, int nr)
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

static int parse_note_CORE(struct dump *dump, off64_t offset, Elf_Nhdr *note)
{
	switch (note->n_type) {
	case NT_PRSTATUS: {
		memset(&current_cpu, 0, sizeof(current_cpu));

		if (kdump_parse_prstatus(dump, ELFNOTE_DESC(note), &current_cpu))
			return 1;

		//fprintf(debug, "CORE PR_STATUS\n");

		break;
	}
	default:
		fprintf(debug, "unhandled CORE note type %d\n", note->n_type);
		return 1;
	}

	return 0;
}

/* Obsolete */
static int parse_note_XEN_CORE(struct dump *dump, off64_t offset, Elf_Nhdr *note)
{
	fprintf(debug, "unhandled \"XEN CORE\" note type %x\n", note->n_type);
	return 1;
}

static int parse_note_Xen(struct dump *dump, off64_t offset, Elf_Nhdr *note)
{

	switch (note->n_type) {
	case XEN_ELFNOTE_CRASH_INFO:

		//fprintf(debug, "Xen ELFNOTE_CRASH_INFO\n");

		if (kdump_parse_hypervisor(dump, ELFNOTE_DESC(note)))
		{
			fprintf(debug, "failed to parse hypervisor note\n");
			return 1;
		}
		break;
	case XEN_ELFNOTE_CRASH_REGS: {
		/* Haven't parsed the basic state? */
		if (current_cpu.flags == 0)
			return 1;

		if (kdump_parse_crash_regs(dump, ELFNOTE_DESC(note), &current_cpu))
			return 1;

		//fprintf(debug, "Xen ELFNOTE_CRASH_REGS for CPU%d\n", current_cpu.nr);

		if (allocate_cpus(dump,current_cpu.nr+1))
			return 1;

		memcpy(&dump->cpus[current_cpu.nr], &current_cpu, sizeof(current_cpu));
		memset(&current_cpu, 0, sizeof(current_cpu));

		break;
	}
	default:
		fprintf(debug, "unhandled \"Xen\" note type %x\n", note->n_type);
		return 1;
	}

	return 0;
}


static struct note_handler {
	const char *name;
	int (*handler)(struct dump *dump, off64_t offset, Elf_Nhdr *note);
} note_handlers[] = {
	{ .name = "CORE", .handler = parse_note_CORE },
	{ .name = "XEN CORE", .handler = parse_note_XEN_CORE },
	{ .name = "Xen", .handler = parse_note_Xen },
};
#define NR_NOTE_HANDLERS (sizeof(note_handlers)/sizeof(note_handlers[0]))

static int parse_pt_note(struct dump *dump, Elf_Phdr *phdr)
{
	off64_t offset = phdr->p_offset;
	Elf_Nhdr *note;
	unsigned char notes[phdr->p_filesz];
	struct note_handler *handler;
	int i, n;
	phdr_info_t *p_info;

	if (kdump_read(dump, notes,  phdr->p_offset, phdr->p_filesz) != phdr->p_filesz)
	{
		fprintf(debug, "failed to read PT_NOTE: %s\n", strerror(errno));
		return 1;
	}

	p_info = __add_phdr_info(&elfall, phdr->p_type, phdr->p_flags);
	n = 0;
	for (note = (Elf_Nhdr*)notes;
	     (void*)note < (void*)notes + phdr->p_filesz - 1;
	     note = ELFNOTE_NEXT(note))	{
		fprintf(debug, "parse Note entry %d type 0x%x name %s\n", n, phdr->p_type, ELFNOTE_NAME(note));
		for(i=0; i<NR_NOTE_HANDLERS;i++) {
			handler = &note_handlers[i];
			if (strncmp(handler->name, ELFNOTE_NAME(note), note->n_namesz)==0) {
				if (handler->handler(dump, offset, note)) {
					fprintf(debug, "failed to handle note %s\n", ELFNOTE_NAME(note));
				}
				break;
			}
		}
		__add_note(p_info, ELFNOTE_NAME(note), note->n_type, (char*) ELFNOTE_DESC(note), note->n_descsz);

		if (i == NR_NOTE_HANDLERS) {
			fprintf(debug, "unknown note type %s\n", ELFNOTE_NAME(note));
		}

		offset += (off64_t)(unsigned long)ELFNOTE_NEXT(note) - (off64_t)(unsigned long)note;
		n++;
	}

	return 0;
}

static int parse_pt_load(struct dump *dump, Elf_Phdr *phdr)
{
	void *mem;
	struct memory_extent *mext;

	mem = realloc(dump->machine_memory,(dump->nr_machine_memory+1)*sizeof(struct memory_extent));
	if (mem == NULL)
		return 1;
	dump->machine_memory=mem;

	mext = &dump->machine_memory[dump->nr_machine_memory];

	mext->maddr = phdr->p_paddr;
	mext->vaddr = phdr->p_vaddr;
	mext->length = phdr->p_memsz;
	mext->offset = phdr->p_offset;

	dump->nr_machine_memory++;

	return 0;
}

static int foreach_phdr_type(struct dump *dump,
			     Elf_Ehdr *ehdr, Elf_Word p_type,
			     int (*callback)(struct dump *dump, Elf_Phdr *phdr))
{
	int i;

	for (i=0; i<ehdr->e_phnum; i++) {
		Elf_Phdr phdr;

		if (kdump_read(dump, &phdr, ehdr->e_phoff + (i*sizeof(phdr)), sizeof(phdr)) != sizeof(phdr))
		{
			fprintf(debug, "failed to read program header %d: %s\n",
				i, strerror(errno));
			return 1;
		}
		if (phdr.p_type == p_type) {
		   fprintf(debug, "parse Phdr entry %d of type 0x%x\n", i, phdr.p_type);
			if ((*callback)(dump, &phdr)) {
				fprintf(debug, "Error: failed to parse pt entry %d of type 0x%x\n", i,
						phdr.p_type);
			}
		}
	}
	return 0;
}

int FN(create_elf_header)(FILE *f, uint64_t start, uint64_t end, uint64_t v_start, uint64_t p_offset) {
	phdr_info_t *p_info;
	fprintf(debug, "start %llx end %llx v_start %llx p_offset %llx\n", start, end, v_start, p_offset);

	p_info = __add_phdr_info(&elfall, PT_LOAD, PF_R | PF_W | PF_X);
	p_info->phdr.p_vaddr = v_start;
	p_info->phdr.p_paddr = start;
	p_info->phdr.p_filesz = end - start;
	p_info->phdr.p_memsz = end - start;
	__fix_section_offsets(&elfall);
	__write_all_elfs(f, &elfall);
	return ftell(f);
}

int FN(parse_dump)(struct dump *dump)
{
	extern struct arch arch_x86_32;
	extern struct arch arch_x86_64;
	Elf_Ehdr ehdr;
	Elf_Ehdr *ehdr_out = &elfall.ehdr;

	memset(&elfall, '\0', sizeof(elfall));

	if (kdump_read(dump, &ehdr, 0, sizeof(ehdr)) != sizeof(ehdr))
	{
		fprintf(debug, "failed to read dump elf header: %s\n", strerror(errno));
		return 1;
	}
	memcpy(ehdr_out, &ehdr, sizeof(ehdr));
	ehdr_out->e_phnum = 0;
	ehdr_out->e_shentsize = 0;
	ehdr_out->e_shnum = 0;
	ehdr_out->e_shstrndx = 0;
	fprintf(debug, "elf header in:\n");
	//hex_dump(0, &ehdr, sizeof(ehdr));

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
		fprintf(debug, "unknown machine class %d\n", dump->e_machine);
		return 1;
	}

	/*
	 * Parse PT_LOAD first to populate memory map which is used
	 * when parsing the CPU notes.
	 */
	if (foreach_phdr_type(dump, &ehdr, PT_LOAD, &parse_pt_load))
		return 1;

	if (foreach_phdr_type(dump, &ehdr, PT_NOTE, &parse_pt_note))
		return 1;

	return 0;
}
