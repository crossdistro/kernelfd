SRCVERSION = $(shell uname -r | sed 's/-default$$//')
KPATH = /usr/src/linux-$(SRCVERSION)

MAKE_CMD = make -C $(KPATH) M=$(CURDIR)

ccflags-y += -DDEBUG
obj-m = msg.o

all:
	$(MAKE_CMD)
kpath:
	echo $(KPATH)
clean:
	$(MAKE_CMD) clean
run: all
	-sudo rmmod msg
	sudo insmod msg.ko
test: run
	sudo ./test.py
