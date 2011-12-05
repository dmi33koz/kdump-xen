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

static Elf_Ehdr out_ehdr = {
    { ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3,    /* EI_MAG{0-3} */
      ELFCLASS64,                            /* EI_CLASS */
      ELFDATA2LSB,                           /* EI_DATA */
      EV_CURRENT,                            /* EI_VERSION */
      0, 0, 0, 0, 0, 0, 0, 0, 0 },           /* e_ident */
    ET_CORE,                                 /* e_type */
    EM_X86_64,                               /* e_machine */
    EV_CURRENT,                              /* e_version */
    DYNAMICALLY_FILLED,                      /* e_entry */
    sizeof(Elf_Ehdr),                      /* e_phoff */
    DYNAMICALLY_FILLED,                      /* e_shoff */
    0,                                       /* e_flags */
    sizeof(Elf_Ehdr),                      /* e_ehsize */
    sizeof(Elf_Phdr),                      /* e_phentsize */
    2,                                       /* e_phnum */
    sizeof(Elf_Shdr),                      /* e_shentsize */
    3,                                       /* e_shnum */
    2                                        /* e_shstrndx */
};

static Elf_Phdr out_phdr = {
    PT_LOAD,                                 /* p_type */
    PF_R|PF_W|PF_X,                          /* p_flags */
    RAW_OFFSET,                              /* p_offset */
    DYNAMICALLY_FILLED,                      /* p_vaddr */
    DYNAMICALLY_FILLED,                      /* p_paddr */
    DYNAMICALLY_FILLED,                      /* p_filesz */
    DYNAMICALLY_FILLED,                      /* p_memsz */
    64                                       /* p_align */
};

static Elf_Phdr out_phdr2 = {
    PT_LOAD,                                 /* p_type */
    PF_R|PF_W|PF_X,                          /* p_flags */
    RAW_OFFSET,                              /* p_offset */
    DYNAMICALLY_FILLED,                      /* p_vaddr */
    DYNAMICALLY_FILLED,                      /* p_paddr */
    DYNAMICALLY_FILLED,                      /* p_filesz */
    DYNAMICALLY_FILLED,                      /* p_memsz */
    64                                       /* p_align */
};

static char out_shstrtab[] = "\0.text\0.shstrtab";

static Elf_Shdr out_shdr[] = {
    { 0 },
    { 1,                                     /* sh_name */
      SHT_PROGBITS,                          /* sh_type */
      SHF_WRITE|SHF_ALLOC|SHF_EXECINSTR,     /* sh_flags */
      DYNAMICALLY_FILLED,                    /* sh_addr */
      RAW_OFFSET,                            /* sh_offset */
      DYNAMICALLY_FILLED,                    /* sh_size */
      0,                                     /* sh_link */
      0,                                     /* sh_info */
      64,                                    /* sh_addralign */
      0                                      /* sh_entsize */
    },
    { 7,                                     /* sh_name */
      SHT_STRTAB,                            /* sh_type */
      0,                                     /* sh_flags */
      0,                                     /* sh_addr */
      DYNAMICALLY_FILLED,                    /* sh_offset */
      sizeof(out_shstrtab),                  /* sh_size */
      0,                                     /* sh_link */
      0,                                     /* sh_info */
      1,                                     /* sh_addralign */
      0                                      /* sh_entsize */
    }
};

#define ELFNOTE_NAMESZ(_n_) (((_n_)->n_namesz+3)&~3)
#define ELFNOTE_DESCSZ(_n_) (((_n_)->n_descsz+3)&~3)
#define ELFNOTE_SIZE(_n_) (sizeof(*(_n_)) + ELFNOTE_NAMESZ(_n_) + ELFNOTE_DESCSZ(_n_))

#define ELFNOTE_NAME(_n_) (const char *)((void*)(_n_) + sizeof(*(_n_)))
#define ELFNOTE_DESC(_n_) (void *)(ELFNOTE_NAME(_n_) + ELFNOTE_NAMESZ(_n_))
#define ELFNOTE_NEXT(_n_) (Elf_Nhdr*)(ELFNOTE_DESC(_n_) + ELFNOTE_DESCSZ(_n_))

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
	int i;

	if (kdump_read(dump, notes,  phdr->p_offset, phdr->p_filesz) != phdr->p_filesz)
	{
		fprintf(debug, "failed to read PT_NOTE: %s\n", strerror(errno));
		return 1;
	}

	for (note = (Elf_Nhdr*)notes;
	     (void*)note < (void*)notes + phdr->p_filesz - 1;
	     note = ELFNOTE_NEXT(note))	{
		for(i=0; i<NR_NOTE_HANDLERS;i++) {
			handler = &note_handlers[i];
			if (strncmp(handler->name, ELFNOTE_NAME(note), note->n_namesz)==0) {
				if (handler->handler(dump, offset, note)) {
					fprintf(debug, "failed to handle note %s\n", ELFNOTE_NAME(note));
				}
				break;
			}
		}

		if (i == NR_NOTE_HANDLERS) {
			fprintf(debug, "unknown note type %s\n", ELFNOTE_NAME(note));
		}

		offset += (off64_t)(unsigned long)ELFNOTE_NEXT(note) - (off64_t)(unsigned long)note;
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
			if ((*callback)(dump, &phdr)) {
				fprintf(debug, "failed to parse pt entry %d of type %d\n", i,
						phdr.p_type);
			}
		}
	}
	return 0;
}

#define ALIGN(n) ((n+3)&~3)

int FN(create_elf_header)(FILE *f, uint64_t memsize, uint64_t loadbase, uint64_t loadbase2)
{
	char r[4];

	/* size of "top" headers */
	unsigned int raw_offset = sizeof(out_ehdr)+sizeof(out_phdr)+sizeof(out_phdr2);

	out_ehdr.e_entry = loadbase;
	out_ehdr.e_shoff = raw_offset;

	out_phdr.p_vaddr  = loadbase;
	out_phdr.p_paddr  = loadbase;
	out_phdr.p_filesz = memsize;
	out_phdr.p_memsz  = memsize;
	out_phdr.p_offset = raw_offset+sizeof(out_shdr)+ALIGN(sizeof(out_shstrtab));

	out_phdr2.p_vaddr  = loadbase2;
	out_phdr2.p_paddr  = loadbase2;
	out_phdr2.p_filesz = memsize;
	out_phdr2.p_memsz  = memsize;
	out_phdr2.p_offset = out_phdr.p_offset;

	out_shdr[1].sh_addr   = loadbase;
	out_shdr[1].sh_size   = memsize;
	out_shdr[1].sh_offset = out_phdr.p_offset;
	out_shdr[2].sh_offset = raw_offset+sizeof(out_shdr);

	/* write em all down */
	fwrite(&out_ehdr , sizeof(out_ehdr), 1, f);
	fwrite(&out_phdr, sizeof(out_phdr), 1, f);
	fwrite(&out_phdr2, sizeof(out_phdr2), 1, f);
	fwrite(&out_shdr, sizeof(out_shdr), 1, f);
	fwrite(out_shstrtab, sizeof(out_shstrtab), 1, f);
	fwrite(r, ALIGN(sizeof(out_shstrtab))-sizeof(out_shstrtab), 1, f);

	return ftell(f);
}

int FN(parse_dump)(struct dump *dump)
{
	extern struct arch arch_x86_32;
	extern struct arch arch_x86_64;

	Elf_Ehdr ehdr;

	if (kdump_read(dump, &ehdr, 0, sizeof(ehdr)) != sizeof(ehdr))
	{
                fprintf(debug, "failed to read dump elf header: %s\n", strerror(errno));
                return 1;
        }

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
