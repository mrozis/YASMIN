#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/poll.h>
#include <linux/skbuff.h>
#include <linux/smp.h>
#include <linux/socket.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include <net/af_vsock.h>

#include <linux/highmem.h>
#include <xen/xen.h>
#include <xen/events.h>
#include <xen/evtchn.h>
#include <xen/xenbus.h>
#include <xen/page.h>
#include <xen/grant_table.h>
#include <xen/gntalloc.h>
#include <asm/xen/hypervisor.h>
#include <asm/xen/hypercall.h>
#include <asm/xen/page.h>
#include <asm/bitops.h>

#include "vintra.h"
#include "mechanics.h"
#include "debug.h"

#include "control_channel.h"


const char *packet_type_istrings[] = {
	"Request for new socket connection",
	"Connection OK",
	"Remote peer Disconnected"
};

static int xenbus_recv_remoteid(u32 local_id);
static int xenbus_recv_params(int *remote_id,int *ring_ref,int *remote_evtchn_port);
static irqreturn_t cc_handler(int irq,void *data);
static void cc_recv_pkt_work(struct work_struct *work);
static int cc_notify_guest_mapped(struct cchannel *cc);
static void cc_incoming_perport_request(struct cchannel *cc, struct cc_packet_header *pkt_header);
static void debug_cc_packet_print(struct cc_packet_header *pkt);

struct xenbus_watch watch;
struct list_head cc_table[VCHAN_HASH_SIZE];
DEFINE_SPINLOCK(cc_table_lock);

void xenbus_watcher_callback(struct xenbus_watch *watch,const char **vec,unsigned int len)
{
	int remote_id = 0;
	int ring_ref = 0;
       	int cc_evtchn_port = 0;
	int rc =  0;
	struct cchannel *cc = NULL;

	u32 local_id = vchan_transport_get_local_cid();
	rc = xenbus_recv_params(&remote_id,&ring_ref,&cc_evtchn_port);
	if (rc < 0)
		return;
	cc = __cc_channel_create(local_id, remote_id, GUESTDOM, &ring_ref,cc_evtchn_port);
	if (!cc) {
		pr_err("Error creating channel\n");
		return;
	}
	cc_channel_add(cc);
	return;
}

static int xenbus_recv_remoteid(u32 local_id)
{
	const char *xenstore_path;
	const char *local_id_str;
	char **dir;
	unsigned int dir_n = 0;
	int rc;

	xenstore_path = kasprintf(GFP_KERNEL,"%s/vchan",PATH);
	local_id_str = kasprintf(GFP_KERNEL,"%d",local_id);
	dir = xenbus_directory(XBT_NIL,xenstore_path,local_id_str,&dir_n);
	if (IS_ERR(dir) || dir_n==0) {
		rc = -1;
		goto out;
	}
	rc = simple_strtol(dir[0],NULL,10);
out:
	kfree(xenstore_path);
	kfree(local_id_str);
	return rc;
}

static int xenbus_recv_params(int *remote_id,int *ring_ref,int *remote_evtchn_port)
{
	const char *xenstore_path;
	int err,rc;
	struct xenbus_transaction xbt;
	u32 local_id = vchan_transport_get_local_cid();

	rc = xenbus_recv_remoteid(local_id);
	if (rc <= 0) 
		return -1;
	*remote_id = rc;
	xenstore_path = kasprintf(GFP_KERNEL,"%s/vchan/%d/%d",PATH,local_id,*remote_id);
	xenbus_transaction_start(&xbt);
	err = xenbus_scanf(xbt,xenstore_path,"processed","%d",&rc);
	if (err<0 || rc < 0)
		goto out_free;
	if (rc==1)
		goto out_free;
	err = xenbus_scanf(xbt,xenstore_path,"ring_ref","%d",&rc);
	if (err<0 || rc <= 0)
		goto out_free;
	*ring_ref = rc;
	err = xenbus_scanf(xbt,xenstore_path,"evtchn","%d",&rc);
	if (err <0 || rc <= 0)
		goto out_free;
	*remote_evtchn_port = rc;
	err = xenbus_printf(xbt,xenstore_path,"processed","%d",1);
	if (err<0) 
		goto out_free;
	xenbus_transaction_end(xbt,0);
	kfree(xenstore_path);
	return 0;
out_free:
	xenbus_transaction_end(xbt,1);
	kfree(xenstore_path);
	return -1;
}


static void cc_lock(struct cc_bus *bus,unsigned long *flags)
{
	spin_lock_irqsave(&bus->lock,*flags);
}

static void cc_unlock(struct cc_bus *bus,unsigned long *flags)
{
	spin_unlock_irqrestore(&bus->lock,*flags);
}

static irqreturn_t cc_handler(int irq,void *data)
{
	struct cchannel *cc = data;
	struct cc_bus *bus;
	int local_id;
	unsigned long flags;
	struct cc_recv_pkt_info *recv_pkt_info;
	u32 grefs_count;
	size_t grefs_size;


	if (!cc) {
		return IRQ_HANDLED;
	}

	bus = (struct cc_bus *) cc->g_channel.addr;
	if (!bus) 
		goto out;
	/* Fast get packet size to allocate proper-sized work struct */
	cc_lock(bus,&flags);
	grefs_count = bus->pkt_header.count_1 + bus->pkt_header.count_2 + 1;
	grefs_size = grefs_count * sizeof(bus->pkt_header.gref_ids[0]);
	cc_unlock(bus,&flags);

	recv_pkt_info = kzalloc(sizeof(*recv_pkt_info) + grefs_size,GFP_ATOMIC);
	if (!recv_pkt_info) {
		recv_pkt_info = kzalloc(sizeof(*recv_pkt_info) + grefs_size, GFP_KERNEL);
		if (!recv_pkt_info)
			goto out;
	}

	cc_lock(bus,&flags);

	local_id = vchan_transport_get_local_cid();
	if (bus->pkt_header.dst != local_id) {
		cc_unlock(bus,&flags);
		goto out;
	}

	if (bus->pkt_header.type == INC_PACKET_TYPE_CONN_OK) {
		wake_up_interruptible(&cc->g_channel.wait);
		cc_unlock(bus,&flags);
		return IRQ_HANDLED;
	}
	else {
		/* All other packet types need more work,
		 * so we schedule bottom-half context jobs */
		memcpy(&recv_pkt_info->pkt_header,&bus->pkt_header,sizeof(struct cc_packet_header) +
     						  grefs_size);
		cc_unlock(bus,&flags);
		recv_pkt_info->cc = cc;
		INIT_WORK(&recv_pkt_info->work, cc_recv_pkt_work);
		schedule_work(&recv_pkt_info->work);
	}
out:
	return IRQ_HANDLED;
}

static void cc_recv_pkt_work(struct work_struct *work)
{
	struct cc_recv_pkt_info *recv_pkt_info;
	struct cc_packet_header *pkt_header;
	struct cchannel *cc;

	recv_pkt_info = container_of(work, struct cc_recv_pkt_info, work);
	pkt_header = &recv_pkt_info->pkt_header;
	cc = recv_pkt_info->cc;

	switch (pkt_header->type) {
		case INC_PACKET_TYPE_REQUEST:
			cc_incoming_perport_request(cc, pkt_header);
			break;
		case INC_PACKET_TYPE_REMOTE_DC:
			__cc_destruct(cc, false /*remote left, so noone to notify*/);
			break;
		default:
			break;
	}
	kfree(recv_pkt_info);
	return;
}

static int cc_duplex_params_init(struct duplex_params *params, struct cc_packet_header *pkt_header)
{
	if (pkt_header->gref_ids[pkt_header->count_1] != 0xCC)
		return -1;
	params->rx_count = pkt_header->count_1;
	params->tx_count = pkt_header->count_2;
	if (params->tx_count != params->rx_count)
		return -1;
	params->rx_evtchn_port = pkt_header->evtchn_port;
	params->tx_evtchn_port = pkt_header->evtchn_port_2;
	params->rx_grefs = &pkt_header->gref_ids[0];
	params->tx_grefs = &pkt_header->gref_ids[pkt_header->count_1 + 1];
	return 0;
}

static void cc_incoming_perport_request(struct cchannel *cc, struct cc_packet_header *pkt_header)
{
	struct sockaddr_vm dst;
	struct sockaddr_vm src;
	struct sock *sk;
	struct vsock_sock *vsk;
	struct perport_channel *ppchannel;
	struct vchan_pkt_header vpkt_header;
	struct duplex_params params;

	vsock_addr_init(&dst,pkt_header->dst,pkt_header->dst_port);
	vsock_addr_init(&src,pkt_header->src,pkt_header->src_port);
	sk = vsock_find_connected_socket(&src,&dst);
	if (!sk) {
		sk = vsock_find_bound_socket(&dst);
		if (!sk) 
			return;
	}
	/* Queue where host is transmitting is queue where guest is receiving and vice versa */
	if (cc_duplex_params_init(&params, pkt_header) < 0) {
		pr_err("New socket request error. Packet gref ids checksum\n");
		debug_cc_packet_print(pkt_header);
		goto out;
	}
	ppchannel = __perport_channel_create(dst.svm_cid,dst.svm_port, src.svm_cid, src.svm_port,
		       	params.tx_count, GUESTDOM, params);
	if (!ppchannel)
		goto out;
	
	lock_sock(sk);

	vsk = vsock_sk(sk);
	if (!vchan_trans(vsk)->ppchannel) {
		ppchannel->vsk = vsk;
		vchan_trans(vsk)->ppchannel = ppchannel;
	}

	if (sk->sk_state == SS_LISTEN) {
		vpkt_header.type 	= VCHAN_TRANSPORT_PACKET_TYPE_REQUEST;
		vpkt_header.size	= 0;
		vpkt_header.src  	= src.svm_cid;
		vpkt_header.src_port 	= src.svm_port;
		vpkt_header.dst 	= dst.svm_cid;
		vpkt_header.dst_port	= dst.svm_port;
		vchan_transport_recv_listen(vsk,vpkt_header);
	}
	release_sock(sk);
out:
	sock_put(sk);
	return;
}

struct cchannel *cc_channel_bound(int remote_id)
{
	struct cchannel *cc = NULL;
	int src = vchan_transport_get_local_cid();
	spin_lock_bh(&cc_table_lock);
	list_for_each_entry(cc,&cc_table[VCHAN_HASH(src,remote_id)],table) {
		if (cc->g_channel.remote_id == remote_id)
			goto out;
	}
	cc = NULL;
out:
	spin_unlock_bh(&cc_table_lock);
	return cc;
}

struct cchannel *__cc_channel_create(int local_id, int remote_id, bool isHost, int *ring_refs, int remote_evtchn_port)
{
	int err;
	struct cchannel *cc = kmalloc(sizeof(*cc),GFP_KERNEL);

	if (!cc)
		return NULL;

	err = __channel_create(&cc->g_channel, local_id, remote_id, 1, isHost, ring_refs, remote_evtchn_port,
			cc_handler, cc);
	if (err < 0)
		goto out_free;

	INIT_LIST_HEAD(&cc->table);
	atomic_set(&cc->refcnt,0);

	if (!isHost) {
		err = cc_notify_guest_mapped(cc);
		if (err < 0) 
			goto out_free;
	}
	return cc;
out_free:
	kfree(cc);
	return NULL;
}

int xenbus_transmit_cc_params(struct cchannel *cc)
{
	const char *xenstore_path;
	int err;
	struct xenbus_transaction xbt;
	
	xenstore_path = kasprintf(GFP_KERNEL,"%s/vchan/%d/%d",PATH, cc->g_channel.remote_id,
						cc->g_channel.local_id);
	xenbus_transaction_start(&xbt);
	err = xenbus_printf(xbt,xenstore_path,"ring_ref","%d",cc->g_channel.gref_ids[0]);
	if (err<0) 
		goto out_free;
	err = xenbus_printf(xbt,xenstore_path,"evtchn","%d",cc->g_channel.evtchn_port);
	if (err<0) 
		goto out_free;
	err = xenbus_printf(xbt,xenstore_path,"processed","%d",0);
	if (err<0) 
		goto out_free;
	xenbus_transaction_end(xbt,0);
	kfree(xenstore_path);
	return 0;
out_free:
	xenbus_transaction_end(xbt,1);
	kfree(xenstore_path);
	return -1;
}


void cc_channel_add(struct cchannel *cc)
{
	struct list_head *list;
	list = &cc_table[VCHAN_HASH(cc->g_channel.local_id,cc->g_channel.remote_id)];
	spin_lock_bh(&cc_table_lock);
	list_add_tail(&cc->table,list);
	spin_unlock_bh(&cc_table_lock);
}

static void cc_channel_del(struct cchannel *cc)
{
	spin_lock_bh(&cc_table_lock);
	list_del_init(&cc->table);
	spin_unlock_bh(&cc_table_lock);
}

static void debug_cc_packet_print(struct cc_packet_header *pkt)
{
	int i;
	pr_err("Source:%d\n",pkt->src);
	pr_err("Destination:%d\n",pkt->dst);
	pr_err("Type:%d\n",pkt->type);
	pr_err("Evtchn Port 1:%d\n",pkt->evtchn_port);
	pr_err("Evtchn Port 2:%d\n",pkt->evtchn_port_2);
	pr_err("Source port:%d\n",pkt->src_port);
	pr_err("Destination port:%d\n",pkt->dst_port);
	pr_err("Count 1:%d\n",pkt->count_1);
	pr_err("Count 2:%d\n",pkt->count_2);
	for (i=0; i<pkt->count_1 + pkt->count_2 + 1; i++)
		pr_err("Gref is[%d] %d\n",i,pkt->gref_ids[i]);
}


static int cc_send_pkt(struct cchannel *cc,enum cc_packet_type type, struct duplex_params params, int src_port, int dst_port)
{	struct cc_bus *bus;
	unsigned long flags;
	int irq;
	int i,k;

	bus = (struct cc_bus *) (cc->g_channel.addr);
	if (!bus)
		return -1;

	irq = irq_from_evtchn(cc->g_channel.evtchn_port);
	disable_irq_nosync(irq);
	cc_lock(bus,&flags);
	memset(&bus->pkt_header,0,sizeof(bus->pkt_header) + (params.tx_count + params.rx_count) * sizeof(params.tx_grefs[0]));

	bus->pkt_header.src = cc->g_channel.local_id;
	bus->pkt_header.dst = cc->g_channel.remote_id;
	bus->pkt_header.type = type;
	/* following rvalues > 0 only for REQUEST type */
	bus->pkt_header.evtchn_port = params.tx_evtchn_port;
	bus->pkt_header.evtchn_port_2 = params.rx_evtchn_port;
	bus->pkt_header.src_port = src_port;
	bus->pkt_header.dst_port = dst_port;
	bus->pkt_header.count_1 = params.tx_count;
	bus->pkt_header.count_2 = params.rx_count;

	for (i = 0; i< params.tx_count; i++)
		bus->pkt_header.gref_ids[i] = params.tx_grefs[i];
	/* Inserting manually border between rx and tx */
	bus->pkt_header.gref_ids[i++] = 0xCC;

	for (k = 0; k< params.rx_count; k++)
		bus->pkt_header.gref_ids[i++] = params.rx_grefs[k];

	cc_unlock(bus,&flags);
	enable_irq(irq);

	notify_remote_via_evtchn(cc->g_channel.evtchn_port);
	return 0;
}

static int cc_notify_guest_mapped(struct cchannel *cc)
{
	struct duplex_params params;
	memset(&params,0,sizeof(params));
	return cc_send_pkt(cc,INC_PACKET_TYPE_CONN_OK, params, 0, 0);
}

static int cc_notify_remote_dc(struct cchannel *cc)
{
	struct duplex_params params;
	memset(&params,0,sizeof(params));
	return cc_send_pkt(cc,INC_PACKET_TYPE_REMOTE_DC, params, 0, 0);
}

int cc_send_perport_request(struct cchannel *cc, struct perport_channel *ppchannel)
{
	struct duplex_params params;
	params.tx_count = ppchannel->duplex.txq.nr_pages;
	params.tx_grefs = ppchannel->duplex.txq.gref_ids;
	params.tx_evtchn_port = ppchannel->duplex.txq.evtchn_port;
	params.rx_count = ppchannel->duplex.rxq.nr_pages;
	params.rx_grefs = ppchannel->duplex.rxq.gref_ids;
	params.rx_evtchn_port = ppchannel->duplex.rxq.evtchn_port;
	return cc_send_pkt(cc,INC_PACKET_TYPE_REQUEST, params, ppchannel->local_port, ppchannel->remote_port);
}

int __cc_destruct(struct cchannel *cc, bool notify_remote)
{
	int err = 0;
	int ret = 0;
	
	if (!cc)
		return -1;

	if (notify_remote)
		err = cc_notify_remote_dc(cc);

	cc_channel_del(cc);

	ret = channel_destruct(&cc->g_channel);
	kfree(cc);
	return ret;
}

int cc_destroy_channels(void)
{
	int i = 0;
	int err = 0;
	struct cchannel *cc,*tmp;

	spin_lock_bh(&cc_table_lock);

	for (i=0; i<VCHAN_HASH_SIZE;i++) {
		list_for_each_entry_safe(cc,tmp,&cc_table[i],table) {
			if (cc) {
				spin_unlock_bh(&cc_table_lock);
				err = __cc_destruct(cc, true /*I leave, so notify remote */);
				spin_lock_bh(&cc_table_lock);
			}
		}
	}
	spin_unlock_bh(&cc_table_lock);

	return 0;
}
