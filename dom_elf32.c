#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <xen/elfnote.h>

#include "kdump.h"

#define DYNAMICALLY_FILLED 0

typedef struct {
   int32_t signo; /* signal number */
   int32_t code; /* extra code */
   int32_t err_no; /* errno */
} ELF_Signifo32;

typedef int32_t ELF_Pid;

typedef struct {
   int32_t tv_sec;
   int32_t tv_usec;
} ELF_Timeval;

typedef struct {
   ELF_Signifo32 pr_info; /* Info associated with signal */
   int16_t pr_cursig; /* Current signal */
   uint32_t pr_sigpend; /* Set of pending signals */
   uint32_t pr_sighold; /* Set of held signals */
   ELF_Pid pr_pid;
   ELF_Pid pr_ppid;
   ELF_Pid pr_pgrp;
   ELF_Pid pr_sid;
   ELF_Timeval pr_utime; /* User time */
   ELF_Timeval pr_stime; /* System time */
   ELF_Timeval pr_cutime; /* Cumulative user time */
   ELF_Timeval pr_cstime; /* Cumulative system time */
   uint32_t pr_reg[17]; /* GP registers */
   int32_t pr_fpvalid; /* True if math co-processor being used.  */
} ELF_Prstatus32;

struct phdr_info {
   Elf64_Phdr phdr;
   char *data;
   int size;
};

struct phdr_all {
   int count;
   struct phdr_info *pinfos; //array of pinfos
};

struct elf_all {
   Elf64_Ehdr ehdr;
   struct phdr_all phdrs;
};

#define Align4(a) (((a) & 3) ? (((a) & ~3) + 4) : (a))

void init_elf_header(Elf64_Ehdr *h) {
   memset(h, '\0', sizeof(*h));

   h->e_ident[0] = ELFMAG0;
   h->e_ident[1] = ELFMAG1;
   h->e_ident[2] = ELFMAG2;
   h->e_ident[3] = ELFMAG3;
   h->e_ident[4] = ELFCLASS64;
   h->e_ident[5] = ELFDATA2LSB;
   h->e_ident[6] = EV_CURRENT;
   h->e_type = ET_CORE;
   h->e_machine = EM_386;
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
/*
 * this is how linux saves registers to elf on i386
 #define ELF_CORE_COPY_REGS(pr_reg, regs)     \
   pr_reg[0] = regs->ebx;           \
   pr_reg[1] = regs->ecx;           \
   pr_reg[2] = regs->edx;           \
   pr_reg[3] = regs->esi;           \
   pr_reg[4] = regs->edi;           \
   pr_reg[5] = regs->ebp;           \
   pr_reg[6] = regs->eax;           \
   pr_reg[7] = regs->xds;           \
   pr_reg[8] = regs->xes;           \
   savesegment(fs,pr_reg[9]);       \
   savesegment(gs,pr_reg[10]);         \
   pr_reg[11] = regs->orig_eax;        \
   pr_reg[12] = regs->eip;          \
   pr_reg[13] = regs->xcs;          \
   pr_reg[14] = regs->eflags;       \
   pr_reg[15] = regs->esp;          \
   pr_reg[16] = regs->xss;
 */

// copy registers from cpu state to elf ELF_Prstatus32
void save_regs(uint32_t *pr_reg, struct cpu_state *vcpu) {
   pr_reg[0] = vcpu->x86_64.r15;
   pr_reg[1] = vcpu->x86_64.r14;
   pr_reg[2] = vcpu->x86_64.r13;
   pr_reg[3] = vcpu->x86_64.r12;
   pr_reg[4] = vcpu->x86_64.rbp;
   pr_reg[5] = vcpu->x86_64.rbx;
   pr_reg[6] = vcpu->x86_64.r11;
   pr_reg[7] = vcpu->x86_64.r10;
   pr_reg[8] = vcpu->x86_64.r9;
   pr_reg[9] = vcpu->x86_64.r8;
   pr_reg[10] = vcpu->x86_64.rax;
   pr_reg[11] = vcpu->x86_64.rcx;
   pr_reg[12] = vcpu->x86_64.rdx;
   pr_reg[13] = vcpu->x86_64.rsi;
   pr_reg[14] = vcpu->x86_64.rdi;
   pr_reg[15] = vcpu->x86_64.rsp;
   pr_reg[16] = vcpu->x86_64.rip;
   fprintf(debug, "cpu registers:\n");
   hex_dump(0, pr_reg, 4 * 17);
}

// add phdr_info into elf_all.phdr_all
// it reallocated structures so old pointers become invalid.
struct phdr_info * add_phdr_info(struct elf_all *all, uint32_t type, uint32_t flags) {
   struct phdr_all *p_all;
   void *tmp;
   struct phdr_info *pi;

   p_all = &all->phdrs;
   if (p_all->count == 0) {
      p_all->pinfos = malloc(sizeof(struct phdr_info));
   } else {
      tmp = realloc(p_all->pinfos, sizeof(struct phdr_info) * (p_all->count + 1));
      p_all->pinfos = tmp;
   }
   pi = &p_all->pinfos[p_all->count];
   memset(pi, '\0', sizeof(struct phdr_info));
   p_all->count++;
   pi->phdr.p_type = type;
   pi->phdr.p_flags = flags;
   all->ehdr.e_phnum++;

   return &p_all->pinfos[p_all->count - 1];
}
void fix_section_offsets(struct elf_all *all) {
   struct phdr_all *p_all = &all->phdrs;
   struct phdr_info *pi;
   int i;
   // shift to the end of program headers
   uint32_t offset = sizeof(Elf64_Ehdr) + p_all->count * sizeof(Elf64_Phdr);

   for (i = 0; i < p_all->count; i++) {
      pi = &p_all->pinfos[i];
      pi->phdr.p_offset = offset;
      offset += pi->phdr.p_filesz;
   }
}
void add_note(struct phdr_info *pi, char * name, uint32_t type, char * data, size_t size) {
   Elf32_Nhdr *nhdr;
   char *buf, *ptr;
   int buf_size;

   buf_size = sizeof(Elf32_Nhdr) + Align4(strlen(name)+1) + Align4(size);
   buf = ptr = malloc(buf_size);
   memset(buf, '\0', buf_size);
   nhdr = (Elf32_Nhdr*) buf;
   //set note heder
   nhdr->n_namesz = strlen(name) + 1;
   nhdr->n_type = type;
   nhdr->n_descsz = size;
   ptr += sizeof(Elf32_Nhdr);
   //set name
   strcpy(ptr, name);
   ptr += Align4(strlen(name)+1);
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

void write_buf(FILE *f, void *b, int size) {
   static int offset = 0;
   hex_dump(offset, (char*) b, size);
   offset += size;
   if (fwrite(b, 1, size, f) < 0) {
      exit(-1);
   }
}

void write_all_elfs(FILE *f, struct elf_all *all) {
   Elf64_Ehdr *ehdr = &all->ehdr;
   struct phdr_all *p_all = &all->phdrs;
   int pi_index = 0;
   struct phdr_info *p_info;
   p_all = &all->phdrs;

   // write Ehdr
   write_buf(f, ehdr, sizeof(Elf64_Ehdr));
   // write all Phdr(s)
   for (pi_index = 0; pi_index < p_all->count; pi_index++) {
      p_info = &p_all->pinfos[pi_index];
      write_buf(f, &p_info->phdr, sizeof(Elf64_Phdr));
   }
   // write all Phdr(s) data
   for (pi_index = 0; pi_index < p_all->count; pi_index++) {
      p_info = &p_all->pinfos[pi_index];
      if (p_info->data) {
         write_buf(f, p_info->data, p_info->size);
      }
   }
}


int create_elf_header_32_dom(FILE *f, struct dump *dump, int dom_id) {
   struct elf_all elfall;

   Elf64_Ehdr *ehdr;
   struct cpu_state *vcpu;
   //Elf32_Nhdr nhdr;
   ELF_Prstatus32 prs;
   struct domain *d;
   struct phdr_info *p_info;

   d = &dump->domains[dom_id];

   memset(&elfall, '\0', sizeof(elfall));

   // initialize elf header
   ehdr = &elfall.ehdr;
   init_elf_header(ehdr);

   // add note(s) program header
   p_info = add_phdr_info(&elfall, PT_NOTE, 0);
   // for each domain cpu add "CORE" note
   for_each_vcpu(d, vcpu) {
      memset(&prs, '\0', sizeof(prs));
      save_regs(prs.pr_reg, vcpu);
      fprintf(debug, "adding note ELF_Prstatus32 size = 0x%x\n", sizeof(ELF_Prstatus32));
      add_note(p_info, "CORE", NT_PRSTATUS, (char*) &prs, sizeof(ELF_Prstatus32));
      //kdump_print_cpu_state(o, dump, vcpu);
   }
   // add memory program header
   p_info = add_phdr_info(&elfall, PT_LOAD, PF_R | PF_W | PF_X);
   // setup header
   p_info->phdr.p_vaddr = 0xc0000000;
   p_info->phdr.p_paddr = 0;
   p_info->phdr.p_filesz = d->shared_info.max_pfn << PAGE_SHIFT;
   p_info->phdr.p_memsz = p_info->phdr.p_filesz;

   fix_section_offsets(&elfall);
   write_all_elfs(f, &elfall);
   return ftell(f);
}
