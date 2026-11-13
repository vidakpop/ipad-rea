obj-m += raw0.o

KDIR := /lib/modules/$(shell uname -r)/build
SRCDIR := $(HOME)/kernel-src/linux-7.2.15

ccflags-y := -I$(SRCDIR)/drivers/usb/host \
             -Wno-unused-function

all:
	make -C $(KDIR) M=$(CURDIR) modules

clean:
	make -C $(KDIR) M=$(CURDIR) clean
