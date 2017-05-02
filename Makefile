obj-m += vintra_transport.o
vintra_transport-objs := vintra.o control_channel.o mechanics.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
replace:
	scripts/replace_domid.sh
