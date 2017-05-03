obj-m += yasmin_transport.o
yasmin_transport-objs := yasmin.o control_channel.o mechanics.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
replace:
	scripts/replace_domid.sh
