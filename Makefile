#
# Makefile for Linux loopback virtual driver.
#

ifneq ($(KERNELRELEASE),)
# call from kernel build system

obj-$(CONFIG_LO) += lo.o

#lo-objs := lo.o

else
# external module build

EXTRA_FLAGS += -I$(PWD)

#
# KDIR is a path to a directory containing kernel source.
# It can be specified on the command line passed to make to enable the module to
# be built and installed for a kernel other than the one currently running.
# By default it is the path to the symbolic link created when
# the current kernel's modules were installed, but
# any valid path to the directory in which the target kernel's source is located
# can be provided on the command line.
#
KDIR	?= /lib/modules/$(shell uname -r)/build
MDIR	?= /lib/modules/$(shell uname -r)
PWD	:= $(shell pwd)
PWD	:= $(shell pwd)

export CONFIG_LO := m

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

help:
	$(MAKE) -C $(KDIR) M=$(PWD) help

install: lo.ko
	rm -f ${MDIR}/drivers/net/lo.ko
	install -m644 -b -D lo.ko ${MDIR}/drivers/net/lo.ko
	depmod -aq

uninstall:
	rm -rf ${MDIR}/drivers/net/lo.ko
	depmod -aq

endif

.PHONY : all clean install uninstall
