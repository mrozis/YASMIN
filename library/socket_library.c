#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef int (*socket_orig_ftype)(int domain, int type, int protocol);
typedef int (*connect_orig_ftype)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
typedef int (*bind_orig_ftype)(int sockfd, const struct sockaddr *addr,socklen_t addrlen);
typedef int (*getsockopt_orig_ftype)(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
typedef int (*setsockopt_orig_ftype)(int sockfd, int level, int optname, const void *optval, socklen_t optlen);

int map_inet_addr_to_xen_id(struct in_addr addr)
{
	int ret;
	FILE *hosts_file;
	char *token;
	char line[60];
	char *caddr = inet_ntoa(addr);
	int found = 0;

	hosts_file = fopen("/root/hosts","r");
	if (hosts_file == NULL) {
		perror("error opening hosts file\n");
		return -1;
	}
	ret = -1;
	while (found == 0) {
		if (fgets(line, 60, hosts_file) == NULL) 
			break;
		token = strtok(line, "-");
		if (!token) 
			break;
		if (strcmp(caddr, token) == 0) {
			ret = atoi(strtok(NULL, "-"));
			found = 1;
		}
	}
	fclose(hosts_file);
	return ret;
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
	int optval_tmp;
	const char *err;
	setsockopt_orig_ftype setsockopt_original;
	getsockopt_orig_ftype getsockopt_original;
	socklen_t optlen_tmp = sizeof(optval_tmp);


       	setsockopt_original = (setsockopt_orig_ftype) dlsym(RTLD_NEXT,"setsockopt");
	if ((err = dlerror()) != NULL) {
		printf("dlsym(setsockopt): %s\n",err);
		return (setsockopt_original(sockfd,level,optname,optval,optlen));
	}
	if (level == AF_VSOCK)
		return (setsockopt_original(sockfd, level, optname, optval, optlen));

       	getsockopt_original = (getsockopt_orig_ftype) dlsym(RTLD_NEXT,"getsockopt");
	if ((err = dlerror()) != NULL) {
		printf("dlsym(getsockopt): %s\n",err);
		return (setsockopt_original(sockfd,level,optname,optval,optlen));
	}
	/* We test to see if our socket fd point to an AF_VSOCK socket. If not return */
	if (getsockopt_original(sockfd, SOL_SOCKET, SO_DOMAIN, &optval_tmp, &optlen_tmp) < 0) {
		perror("setsockopt\n");
		return (setsockopt_original(sockfd,level,optname,optval,optlen));
	}
	if (optval_tmp != AF_VSOCK) {
		return (setsockopt_original(sockfd,level,optname,optval,optlen));
	}
	/*Here we know that the socket fd points to an AF_VSOCK socket, so we must forward the proper optval request */
	if ((level == SOL_SOCKET) && ((optname == SO_RCVBUF) || (optname == SO_SNDBUF))) {
		/* Because in AF_VSOCK, buffer size is u64, we must make sure optlen >= u64,
		 *  or setsockopt will return EINVAL */
		if (optlen <= sizeof(uint64_t)) {
			uint64_t *big_optval = (uint64_t *) optval;
			socklen_t big_optlen = sizeof(*big_optval);
			return (setsockopt_original(sockfd, AF_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE, big_optval, big_optlen));
		}
		else
			return (setsockopt_original(sockfd, AF_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE, optval, optlen));
			
	}
	else {
		printf("Notice: Operation for level %d, optval %d not yet implemented\n",level, optname);
		return 0;
	}
}

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
	const char *err;
	int optval_tmp;
	int ret;
	socklen_t optlen_tmp = sizeof(optval_tmp);
	getsockopt_orig_ftype getsockopt_original;
       	getsockopt_original = (getsockopt_orig_ftype) dlsym(RTLD_NEXT,"getsockopt");
	if ((err = dlerror()) != NULL) {
		printf("dlsym(getsockopt): %s\n",err);
		return (getsockopt_original(sockfd,level,optname,optval,optlen));
	}
	if (getsockopt_original(sockfd,SOL_SOCKET,SO_DOMAIN,&optval_tmp,&optlen_tmp) < 0) {
		perror("getsockopt\n");
		return (getsockopt_original(sockfd,level,optname,optval,optlen));
	}
	if (optval_tmp != AF_VSOCK) {
		return (getsockopt_original(sockfd,level,optname,optval,optlen));
	}
	/* Here we know that out socket is AF_VSOCK socket */
	if ((level == SOL_SOCKET) && ((optname == SO_RCVBUF) || (optname == SO_SNDBUF))) {
		/* Because in AF_VSOCK, buffer size is u64, we must make sure optlen >= u64,
		 *  or getsockopt will return EINVAL */
		if (*optlen <= sizeof(uint64_t)) {
			uint64_t big_optval;
			socklen_t big_optlen = sizeof(big_optval);
			ret = (getsockopt_original(sockfd,AF_VSOCK,SO_VM_SOCKETS_BUFFER_SIZE,&big_optval,&big_optlen));
			*((int *)optval) = (int) big_optval;
			return ret;
		}
		else
			return (getsockopt_original(sockfd,AF_VSOCK,SO_VM_SOCKETS_BUFFER_SIZE,optval,optlen));
			
	}
	return 0;
}

int socket(int domain, int type, int protocol) 
{
	socket_orig_ftype socket_original;
       	socket_original	= (socket_orig_ftype) dlsym(RTLD_NEXT,"socket");
	if ((domain == AF_INET) || (domain == PF_INET)) {
		if ((type==SOCK_DGRAM) || (protocol==IPPROTO_UDP))
			return (socket_original(domain,type,protocol));
		return (socket_original(AF_VSOCK,SOCK_STREAM,0));
	}
	else {
		return (socket_original(domain,type,protocol));
	}
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	struct sockaddr_vm vmaddr;
	struct sockaddr_in *inaddr;
	int remote_id;
	connect_orig_ftype connect_original;
	getsockopt_orig_ftype getsockopt_original;
	const char *err;
	int optval;
	socklen_t optlen = sizeof(optval);

       	connect_original= (connect_orig_ftype) dlsym(RTLD_NEXT,"connect");
	if ((err = dlerror()) != NULL) {
		printf("dlsym(connect): %s\n",err);
		return (connect_original(sockfd,addr,addrlen));
	}
       	getsockopt_original = (getsockopt_orig_ftype) dlsym(RTLD_NEXT,"getsockopt");
	if ((err = dlerror()) != NULL) {
		printf("dlsym(getsockopt): %s\n",err);
		return (connect_original(sockfd,addr,addrlen));
	}
	if (getsockopt_original(sockfd,SOL_SOCKET,SO_DOMAIN,&optval,&optlen) < 0) {
		perror("getsockopt\n");
		return (connect_original(sockfd,addr,addrlen));
	}
	if (optval!=AF_VSOCK) {
		return (connect_original(sockfd,addr,addrlen));
	}

	inaddr = (struct sockaddr_in *) addr;
	if (inaddr->sin_family != AF_INET) {
		printf("Not inaddr->sin_family INET\n");
		return (connect_original(sockfd,addr,addrlen));
	}
	remote_id = map_inet_addr_to_xen_id(inaddr->sin_addr);
	if (remote_id <= 0) {
		printf("No mapping ip<->domid. Is domain registered in hosts.h file and running?\n");
		return (connect_original(sockfd,addr,addrlen));
	}
	bzero((char *) &vmaddr,sizeof(vmaddr));
	vmaddr.svm_family = AF_VSOCK;
	vmaddr.svm_cid = remote_id;
	vmaddr.svm_port = inaddr->sin_port;
	return (connect_original(sockfd,(struct sockaddr *) &vmaddr, sizeof(vmaddr)));
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) 
{
	struct sockaddr_vm vmaddr;
	struct sockaddr_in *inaddr;
	int xen_id;
	const char *err;
	int optval;
	socklen_t optlen = sizeof(optval);

	getsockopt_orig_ftype getsockopt_original;
	bind_orig_ftype bind_original;
       	bind_original= (bind_orig_ftype) dlsym(RTLD_NEXT,"bind");
	if ((err = dlerror()) != NULL) {
		printf("dlsym(bind): %s\n",err);
		return (bind_original(sockfd,addr,addrlen));
	}

       	getsockopt_original = (getsockopt_orig_ftype) dlsym(RTLD_NEXT,"getsockopt");
	if ((err = dlerror()) != NULL) {
		printf("dlsym(getsockopt): %s\n",err);
		return (bind_original(sockfd,addr,addrlen));
	}
	if (getsockopt_original(sockfd,SOL_SOCKET,SO_DOMAIN,&optval,&optlen) < 0) {
		perror("getsockopt\n");
		return (bind_original(sockfd,addr,addrlen));
	}
	if (optval!=AF_VSOCK)
		return (bind_original(sockfd,addr,addrlen));
	inaddr = (struct sockaddr_in *) addr;
	if (inaddr->sin_family != AF_INET)
		return (bind_original(sockfd,addr,addrlen));
	if (inaddr->sin_addr.s_addr == INADDR_ANY)
		xen_id = VMADDR_CID_ANY;
	else {
		xen_id = map_inet_addr_to_xen_id(inaddr->sin_addr);
		if (xen_id <= 0) {
			printf("No mapping ip<->domid. Is domain registered in hosts.h file and running?\n");
			return (bind_original(sockfd,addr,addrlen));
		}
	}
	bzero((char *) &vmaddr,sizeof(vmaddr));
	vmaddr.svm_family = AF_VSOCK;
	vmaddr.svm_cid = xen_id;
	/* AF_INET port 0 means auto-assign port num. This is AF_VSOCK's port -1 */
	vmaddr.svm_port = (inaddr->sin_port == 0) ? VMADDR_PORT_ANY : inaddr->sin_port;
	return (bind_original(sockfd,(struct sockaddr *) &vmaddr,sizeof(struct sockaddr)));
}


