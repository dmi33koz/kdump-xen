# Create with make -C /home/ianc/devel/carbon/trunk/build.hg/myrepos/xen-3.3.hg/tools/include
#XEN_INCLUDES := /home/ianc/devel/carbon/trunk/build.hg/myrepos/xen-3.3.hg/tools/include/xen
XEN_ARCH := x86
XEN_TARGET := xen

CFLAGS  = -I$(shell pwd)/include
# _GNU_SOURCE for asprintf.
CFLAGS += -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_GNU_SOURCE
CFLAGS += -Wall -Werror -g

# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,$(@D)/.$(@F).d
DEPS     = .*.d arch/.*.d

LDFLAGS := -g

OBJS := main.o kdump.o elf32.o elf64.o symbols.o memory.o domain.o dom_elf32.o arch/x86.o arch/x86_32.o arch/x86_64.o

all: kdump
kdump: $(OBJS)
	gcc -o $@ $(LDFLAGS) $(OBJS)

ifneq ($(XEN_INCLUDES),)
$(OBJS): include/xen/.dirstamp

include/xen/.dirstamp:
	mkdir -p include/xen
	mkdir -p include/xen/hvm
	mkdir -p include/xen/io
	mkdir -p include/xen/arch-x86
	mkdir -p include/xen/foreign
	ln -sf $(XEN_INCLUDES)/*.h include/xen
	ln -sf $(XEN_INCLUDES)/foreign/*.h include/xen/foreign
	ln -sf $(XEN_INCLUDES)/hvm/*.h include/xen/hvm
	ln -sf $(XEN_INCLUDES)/io/*.h include/xen/io
	ln -sf $(XEN_INCLUDES)/arch-x86/*.h include/xen/arch-x86
	touch $@

HYPERCALL_NAMES_H := include/xen/xen.h
else
HYPERCALL_NAMES_H := /usr/include/xen/xen.h
endif

.c.o:
	gcc -o $@ $(CFLAGS) -c $<

elf32.o: CFLAGS += -DELFSIZE=32
elf32.o: elf.c
	gcc -o $@ $(CFLAGS) -c $<

elf64.o: CFLAGS += -DELFSIZE=64
elf64.o: elf.c
	gcc -o $@ $(CFLAGS) -c $<

symbols.o: include/hypercall-names.h

include/hypercall-names.h: $(HYPERCALL_NAMES_H) hypercall-names.awk
	awk -f hypercall-names.awk < $(HYPERCALL_NAMES_H) > $@

clean:
	rm -f $(OBJS)
	rm -f $(DEPS)
	rm -f kdump 
	rm -rf include/xen
	rm -f include/hypercall-names.h
	rm -f cscope.files cscope.in.out cscope.out cscope.po.out

.PHONY: cscope
cscope:
	find -name "*.[ch]" > cscope.files
	cscope -b -q

-include $(DEPS)
