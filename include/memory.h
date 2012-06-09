/* Copyright (c) 2007, XenSource, Inc. - All rights reserved. */

#ifndef __UTIL_KDUMP_MEMORY_H__
#define __UTIL_KDUMP_MEMORY_H__

/* Routines for accessing virtual and physical memory in a kdump image. */

/* Select a suitable CPU structure to read from (e.g. for v->m translation). */
static inline struct cpu_state *kdump_select_cpu_for_read(struct domain *domain)
{
	if ( domain == NULL )
		return &dump->cpus[0];
	else
		return &domain->vcpus[0];
}

/* Normal read. */
extern size_t kdump_read_maddr(maddr_t maddr, void *buf, size_t size);
extern size_t kdump_read_vaddr_cpu(struct cpu_state *cpu,
				   vaddr_t vaddr, void *buf, size_t size);
static inline size_t kdump_read_vaddr(struct domain *domain,
				      vaddr_t vaddr, void *buf, size_t size)
{
	struct cpu_state *cpu = kdump_select_cpu_for_read(domain);
	return kdump_read_vaddr_cpu(cpu, vaddr, buf, size);
}

/* Read a pfn */
extern pfn_t kdump_read_pfn_maddr(struct domain *dom, maddr_t maddr);
extern pfn_t kdump_read_pfn_vaddr_cpu(struct domain*dom, struct cpu_state *cpu, vaddr_t vaddr);
static inline pfn_t kdump_read_pfn_vaddr(struct domain *domain, vaddr_t vaddr)
{
	struct cpu_state *cpu = kdump_select_cpu_for_read(domain);
	return kdump_read_pfn_vaddr_cpu(domain, cpu, vaddr);
}

/* Read a pointer. */
extern vaddr_t kdump_read_pointer_maddr(maddr_t maddr);
extern vaddr_t kdump_read_pointer_vaddr_cpu(struct cpu_state *cpu, vaddr_t vaddr);
static inline vaddr_t kdump_read_pointer_vaddr(struct domain *domain, vaddr_t vaddr)
{
	struct cpu_state *cpu = kdump_select_cpu_for_read(domain);
	return kdump_read_pointer_vaddr_cpu(cpu, vaddr);
}

/* Read a string. */
extern char *kdump_read_string_maddr(maddr_t maddr);
extern char *kdump_read_string_vaddr(struct cpu_state *cpu, vaddr_t vaddr);

/* Read a uint8_t. */
extern uint8_t kdump_read_uint8_maddr(maddr_t maddr);
extern uint8_t kdump_read_uint8_vaddr_cpu(struct cpu_state *cpu, vaddr_t vaddr);
static inline uint8_t kdump_read_uint8_vaddr(struct domain *domain, vaddr_t vaddr)
{
	struct cpu_state *cpu = kdump_select_cpu_for_read(domain);
	return kdump_read_uint8_vaddr_cpu(cpu, vaddr);
}

/* Read a uint16_t. */
extern uint16_t kdump_read_uint16_maddr(maddr_t maddr);
extern uint16_t kdump_read_uint16_vaddr_cpu(struct cpu_state *cpu, vaddr_t vaddr);
static inline uint16_t kdump_read_uint16_vaddr(struct domain *domain, vaddr_t vaddr)
{
	struct cpu_state *cpu = kdump_select_cpu_for_read(domain);
	return kdump_read_uint16_vaddr_cpu(cpu, vaddr);
}

/* Read a uint32_t. */
extern uint32_t kdump_read_uint32_maddr(maddr_t maddr);
extern uint32_t kdump_read_uint32_vaddr_cpu(struct cpu_state *cpu, vaddr_t vaddr);
static inline uint32_t kdump_read_uint32_vaddr(struct domain *domain, vaddr_t vaddr)
{
	struct cpu_state *cpu = kdump_select_cpu_for_read(domain);
	return kdump_read_uint32_vaddr_cpu(cpu, vaddr);
}

/* Read a uint64_t. */
extern uint64_t kdump_read_uint64_maddr(maddr_t maddr);
extern uint64_t kdump_read_uint64_vaddr_cpu(struct cpu_state *cpu, vaddr_t vaddr);
static inline uint64_t kdump_read_uint64_vaddr(struct domain *domain, vaddr_t vaddr)
{
	struct cpu_state *cpu = kdump_select_cpu_for_read(domain);
	return kdump_read_uint64_vaddr_cpu(cpu, vaddr);
}

#endif
