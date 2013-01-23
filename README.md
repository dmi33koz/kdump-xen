kdump-xen
=========

kdump utility for XEN. Reads /proc/vmcore and creates separate elf core files for xen and domain 0.

Testes with 64bit hypervisor  and 32bit domain0 only.
Resulting xen core "xen-memory-dump" and dom0 core "dom0-memory-dump" can be opened with crash utility and GDB.
