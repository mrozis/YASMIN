# vIntra
vIntra framework for intra-node communication in the Xen Hypervisor

Instructions for testing:
1) Setup guest VM.
2) Run xs_perm.sh in dom0 for granting proper XenStore permissions for dom0 default path to communicating VMs.
3) Run update_hosts.sh for updating hosts file in each guest VM
4) Run replace_domid.sh in each guest VM.
5) make
6) LD_PRELOAD=absolute/path/to/libary/sock_lib.so ./application
7) Enjoy.

Note. To resize shared ring, change RING_ORDER in mechanics.h
