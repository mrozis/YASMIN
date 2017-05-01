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

/*These header files are included for xen-vchan usage
 * Author Michalis Rozis */
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

#include "control_channel.h"
#include "vintra.h"
#include "mechanics.h"
#include "debug.h"

#define LOCAL_ID 1
/* The default peer timeout indicates how long we will wait for a peer response
 * to a control message.
 */
#define VSOCK_DEFAULT_CONNECT_TIMEOUT (2 * HZ)

static bool hvm;
const char *packet_type_strings[] = {
	"Data",
	"Request for new socket connection",
	"Negotiation packet",
	"Client OK",
	"Connection OK",
	"Connection SHUTDOWN",
	"Peer detach",
	"Guest mapped",
	"Notification that remote wrote in queue",
	"Notification that remote read from queue",
	"Notification that remote waiting read from queue",
	"Notification that remote waiting write to queue",
};

static int perport_notify_guest_mapped(struct perport_channel *ppchannel);
static int vchan_transport_send_connection_ok(struct vsock_sock *vsk);
static int vchan_transport_send_negotiate(struct vsock_sock *vsk);
static int vchan_transport_send_client_ok(struct vsock_sock *vsk);
static int vchan_transport_send_read(struct vsock_sock *vsk);
static int vchan_transport_send_wrote(struct vsock_sock *vsk);

//static int xenbus_recv_params(int *local_port,int *remote_id,int *remote_port,int *ring_ref,int *remote_evtchn_port);
static void vchan_transport_recv_pkt_work(struct work_struct *work);
static int vchan_transport_recv_connecting_client(struct vsock_sock *vsk,struct vchan_pkt_header pkt);
static int vchan_transport_recv_connecting_server(struct sock *listener, struct sock *pending, struct vchan_pkt_header *pkt_header);
static int vchan_transport_recv_connected(struct vsock_sock *vsk,struct vchan_pkt_header pkt);

static s64 vchan_transport_stream_has_space(struct vsock_sock *vsk);
static s64 vchan_transport_stream_has_data(struct vsock_sock *vsk);

static int __ppchannel_destruct(struct perport_channel *ppchannel);

static irqreturn_t vchan_perport_handler_tx(int irq,void *data);
static irqreturn_t vchan_perport_handler_rx(int irq,void *data);
static void packet_handling(struct vchan_bus *bus, struct vchan_pkt_header *pkt_header, int i);

static bool vchan_transport_pktq_has_packet(struct vchan_bus *bus);
static bool vchan_transport_pktq_has_space(struct vchan_bus *bus);
static struct vchan_pkt_header *vchan_transport_pktq_dequeue_packet(struct vchan_bus *bus, int *ret);
static int vchan_transport_pktq_enqueue_packet(struct vchan_bus *bus, int type, int size, int lid, int lport, int rid, int rport, int mode);
static void pktq_update_producer_unlocked(struct vchan_bus *bus,size_t len);
static void pktq_update_consumer_unlocked(struct vchan_bus *bus,size_t len);

static void queue_update_producer_unlocked(struct vchan_bus *bus,size_t len);
static void queue_update_consumer_unlocked(struct vchan_bus *bus,size_t len);
static void queue_get_ring_indices(struct channel_t *channel, u64 *prod, u64 *cons);
static u64 queue_produce_buf_ready(struct vsock_sock *vsk);
static u64 queue_consume_free_space(struct vsock_sock *vsk);

static struct sock *vchan_transport_get_pending(struct sock *listener, struct vchan_pkt_header pkt_header) 
{
	struct vsock_sock *vlistener;
	struct vsock_sock *vpending;
	struct sock *pending;
	struct sockaddr_vm src;

	vsock_addr_init(&src, pkt_header.src,pkt_header.src_port);

	vlistener = vsock_sk(listener);

	list_for_each_entry(vpending, &vlistener->pending_links, pending_links) {
		if (vsock_addr_equals_addr(&src, &vpending->remote_addr)) {
			pending = sk_vsock(vpending);
			sock_hold(pending);
			goto found;
		}
	}
	pending = NULL;
found:
	return pending;
}

static irqreturn_t vchan_perport_handler_tx(int irq,void *data)
{
	/* This is the handler of my transmit queue evtchn. I'm not supposed
	 * to receive messages from this queue. I'm only transmitting here.
	 * So return immediatly */

	return IRQ_HANDLED;
}

static irqreturn_t vchan_perport_handler_rx(int irq,void *data)
{
	struct channel_t *channel = data;
	struct vchan_bus *bus;
	
	if (!channel) {
		pr_err("Why here\n");
		return IRQ_HANDLED;
	}
	bus = (struct vchan_bus *) channel->addr;
	if (!bus) {
		pr_err("No mapped area\n");
		return IRQ_HANDLED;
	}
	if (!vchan_transport_pktq_has_packet(bus))
		return IRQ_HANDLED;

	tasklet_schedule(&channel->tasklet);
	return IRQ_HANDLED;
}

static int handle_fast_packet(struct vsock_sock *vsk, enum vchan_packet_type type)
{
	struct sock *sk = sk_vsock(vsk);
	int ret = 0;
	if (sk->sk_state != SS_CONNECTED)
		return -1;
	switch (type) {
		case VCHAN_TRANSPORT_FAST_PACKET_TYPE_NOTIFY_WRITE:
			vchan_trans(vsk)->notify.sent_waiting_read = false;
			sk->sk_data_ready(sk);
			break;
		case VCHAN_TRANSPORT_FAST_PACKET_TYPE_NOTIFY_READ:
			vchan_trans(vsk)->notify.sent_waiting_write = false;
			sk->sk_write_space(sk);
			break;
		case VCHAN_TRANSPORT_FAST_PACKET_TYPE_NOTIFY_WAITING_WRITE:
			vchan_trans(vsk)->notify.peer_waiting_write = true;
			if (queue_consume_free_space(vsk) > 0) {
				if (vchan_transport_send_read(vsk) < 0)
					return -1;
				vchan_trans(vsk)->notify.peer_waiting_write = false;
			}
			break;
		case VCHAN_TRANSPORT_FAST_PACKET_TYPE_NOTIFY_WAITING_READ:
			vchan_trans(vsk)->notify.peer_waiting_read = true;
			if (queue_produce_buf_ready(vsk) > 0) {
				if (vchan_transport_send_wrote(vsk) < 0)
					return -1;
				vchan_trans(vsk)->notify.peer_waiting_read = false;
			}
			break;
		default:
			ret = -1;
			break;
	}
	return ret;
}

static void pktq_update_producer_unlocked(struct vchan_bus *bus,size_t len)
{
	u64 MAX, new_val;
	if (!bus)
		return;

	MAX = atomic64_read(&bus->pktq_idx.size);
	new_val = atomic64_read(&bus->pktq_idx.prod);

	if (new_val >= MAX - len)
		new_val -= MAX;
	new_val += len;
	atomic64_set(&bus->pktq_idx.prod, new_val);
}

static void pktq_update_consumer_unlocked(struct vchan_bus *bus,size_t len)
{
	u64 MAX, new_val;
	if (!bus)
		return;

	MAX = atomic64_read(&bus->pktq_idx.size);
	new_val = atomic64_read(&bus->pktq_idx.cons);
	if (new_val >= MAX - len)
		new_val -= MAX;
	new_val += len;
	atomic64_set(&bus->pktq_idx.cons, new_val);
}

static bool vchan_transport_pktq_has_space(struct vchan_bus *bus)
{
	u64 free_space;
	u64 size, head, tail;

	if (!bus)
		return false;

	size = atomic64_read(&bus->pktq_idx.size);
	tail = atomic64_read(&bus->pktq_idx.prod);
	head = atomic64_read(&bus->pktq_idx.cons);

	if (tail>= size || head >= size) {
		return false;
	}
	/*
	* Deduct 1 to avoid tail becoming equal to head which causes
	* ambiguity. If head and tail are equal it means that the
	* queue is empty.
	*/

	if (tail >= head)
		free_space = size - (tail-head) - 1;
	else
		free_space = head-tail - 1;
	return free_space > 0;
}

static bool vchan_transport_pktq_has_packet(struct vchan_bus *bus)
{
	u64 buf_ready;
	u64 size, head, tail;

	if (!bus)
		return false;
	size = atomic64_read(&bus->pktq_idx.size);
	head = atomic64_read(&bus->pktq_idx.prod);
	tail = atomic64_read(&bus->pktq_idx.cons);

	if (tail>= size || head >= size) {
		return -false;
	}

	/*
	* Deduct 1 to avoid tail becoming equal to head which causes
	* ambiguity. If head and tail are equal it means that the
	* queue is empty.
	*/

	if (head >= tail)
		buf_ready = head-tail;
	else
		buf_ready = size - (tail-head);
	return buf_ready > 0;
}

static struct vchan_pkt_header *vchan_transport_pktq_dequeue_packet(struct vchan_bus *bus, int *ret)
{
	struct vchan_pkt_header *pkt_header;
	int i;

	if (!bus)
		return NULL;
       	i = atomic64_read(&bus->pktq_idx.cons);
	*ret = i;
	pkt_header = &bus->pkt_header[i];
	pktq_update_consumer_unlocked(bus, 1);
	return pkt_header;
}

void bh_perport_handler_rx(unsigned long data)
{
	struct vchan_bus *bus = (struct vchan_bus *) data;
	struct vchan_pkt_header *pkt_header;
	int i;

	if (!bus)
		return;

	while (vchan_transport_pktq_has_packet(bus)) {
		pkt_header = vchan_transport_pktq_dequeue_packet(bus, &i);
		if (unlikely(!pkt_header)) {
			pr_err("No packet head in tasklet\n");
			continue;
		}
		packet_handling(bus, pkt_header, i);
	}
	return;
}

static void packet_handling(struct vchan_bus *bus, struct vchan_pkt_header *pkt_header, int i)
{
	struct vchan_recv_pkt_info *recv_pkt_info;
	int local_id;
	struct sockaddr_vm dst;
	struct sockaddr_vm src;
	struct sock *sk;
	struct vsock_sock *vsk;

	if (!bus)
		return;

	local_id = vchan_transport_get_local_cid();
	if (pkt_header->dst != local_id) 
		goto out;
	vsock_addr_init(&src,pkt_header->src,pkt_header->src_port);
	vsock_addr_init(&dst,pkt_header->dst,pkt_header->dst_port);

	sk = vsock_find_connected_socket(&src,&dst);
	if (!sk) {
		sk = vsock_find_bound_socket(&dst);
		if (!sk) 
			goto out;
	}
	vsk = vsock_sk(sk);

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		if (sk->sk_state == SS_CONNECTED) {
			if (handle_fast_packet(vsk,pkt_header->type) < 0)
				goto next;
			else
			       	goto out_unlock;
		}
	}
next:
	bh_unlock_sock(sk);

	recv_pkt_info = kmalloc(sizeof(*recv_pkt_info),GFP_ATOMIC);
	if (!recv_pkt_info) {
		recv_pkt_info = kmalloc(sizeof(*recv_pkt_info),GFP_KERNEL);
		if (!recv_pkt_info) {
			pr_err("kmalloc recv_pkt_info -ENOMEM\n");
			goto out;
		}
	}
	recv_pkt_info->pkt_header = pkt_header;
	recv_pkt_info->sk = sk;
	INIT_WORK(&recv_pkt_info->work, vchan_transport_recv_pkt_work);
	schedule_work(&recv_pkt_info->work);
	return;
out_unlock:
	bh_unlock_sock(sk);
	sock_put(sk);
out:
	return;
}


static void vchan_transport_recv_pkt_work(struct work_struct *work)
{
	struct vchan_recv_pkt_info *recv_pkt_info;
	struct vchan_pkt_header *pkt_header;
	struct sock *sk;
	struct vsock_sock *vsk;

	recv_pkt_info = container_of(work, struct vchan_recv_pkt_info, work);
	pkt_header = recv_pkt_info->pkt_header;
	sk = recv_pkt_info->sk;
	if (!sk)
		goto out;
	vsk = vsock_sk(sk);

	lock_sock(sk);

	vsk = vsock_sk(sk);
	if (!vchan_trans(vsk)->ppchannel) {
		pr_err("Why no ppchannel? Something went terribly wrong\n");
		goto out_free;
	}
	/* First check if we were notified for detaching */
	if (pkt_header->type == VCHAN_TRANSPORT_PACKET_TYPE_DETACH) {
		sock_set_flag(sk,SOCK_DONE);
		vsk->peer_shutdown = SHUTDOWN_MASK;
		if (vsock_stream_has_data(vsk) <=0) {
			if (sk->sk_state == SS_CONNECTING) {
				sk->sk_state = SS_UNCONNECTED;
				sk->sk_err = -ECONNRESET;
				sk->sk_error_report(sk);
				goto out_free;
			}
			sk->sk_state = SS_UNCONNECTED;
		}
		sk->sk_state_change(sk);
		goto out_free;
	}
	switch (sk->sk_state) {
		case SS_LISTEN:
			vchan_transport_recv_listen(vsk,*pkt_header);
			break;
		case SS_CONNECTING:
			vchan_transport_recv_connecting_client(vsk,*pkt_header);
			break;
		case SS_CONNECTED:
			vchan_transport_recv_connected(vsk,*pkt_header);
			break;
		default:
			break;
	}
out_free:
	release_sock(sk);
	sock_put(sk);
out:
	kfree(recv_pkt_info);
}


int vchan_transport_recv_listen(struct vsock_sock *vsk,struct vchan_pkt_header pkt_header)
{
	struct sock *listener;
	struct sock *pending;
	struct vsock_sock *vpending;
	int err;

	listener = sk_vsock(vsk);

	pending = vchan_transport_get_pending(listener, pkt_header);
	if (pending) {
		lock_sock(pending);

		switch(pending->sk_state) {
		case SS_CONNECTING:
			err = vchan_transport_recv_connecting_server(listener, pending, &pkt_header);
			break;
		default:
			err = -EINVAL;
			break;
		}
		if (err < 0)
			vsock_remove_pending(listener, pending);

		release_sock(pending);
		sock_put(pending);
		return err;
	}

	if (!pkt_header.type == VCHAN_TRANSPORT_PACKET_TYPE_REQUEST)
		return -EINVAL;
	if (listener->sk_ack_backlog >= listener->sk_max_ack_backlog)
		return -ECONNREFUSED;


	pending = __vsock_create(sock_net(listener), NULL, listener, GFP_KERNEL,listener->sk_type);
	if (!pending)
		return -ENOMEM;
	vpending = vsock_sk(pending);

	vsock_addr_init(&vpending->local_addr, pkt_header.dst,pkt_header.dst_port);
	vsock_addr_init(&vpending->remote_addr, pkt_header.src,pkt_header.src_port);

	err = vchan_transport_send_negotiate(vpending);
	if (err < 0)
		return -EINVAL;

	vsock_add_pending(listener, pending);
	listener->sk_ack_backlog++;
	pending->sk_state = SS_CONNECTING;

	vpending->listener = listener;
	sock_hold(listener);
	sock_hold(pending);
	INIT_DELAYED_WORK(&vpending->dwork, vsock_pending_work);
	schedule_delayed_work(&vpending->dwork, HZ);
	return 0;
}

static int vchan_transport_recv_connecting_server(struct sock *listener, struct sock *pending, struct vchan_pkt_header *pkt_header)
{
	struct vsock_sock *vpending;
	int err;

	vpending = vsock_sk(pending);

	if (pkt_header->type != VCHAN_TRANSPORT_PACKET_TYPE_CLIENT_OK) {
		err = -EINVAL;
		goto out;
	}
	pending->sk_state = SS_CONNECTED;
	vsock_insert_connected(vpending);

	err = vchan_transport_send_connection_ok(vpending);
	if (err < 0) {
		vsock_remove_connected(vpending);
		goto out;
	}

	vsock_remove_pending(listener, pending);
	vsock_enqueue_accept(listener,pending);
	listener->sk_state_change(listener);
	return 0;
out:
	pending->sk_err = err;
	pending->sk_state = SS_UNCONNECTED;
	sock_put(pending);
	return err;
}

static int vchan_transport_recv_connecting_client(struct vsock_sock *vsk,struct vchan_pkt_header pkt_header)
{
	int err;
	int skerr;
	struct sock *sk = sk_vsock(vsk);
	switch(pkt_header.type) {
		case VCHAN_TRANSPORT_PACKET_TYPE_GUEST_MAPPED:
			wake_up_interruptible(&(vchan_trans(vsk)->ppchannel->duplex.rxq.wait));
			break;
		case VCHAN_TRANSPORT_PACKET_TYPE_NEGOTIATE:
			err = vchan_transport_send_client_ok(vsk);
			if (err < 0) {
				skerr = EPROTO;
				err = -EINVAL;
				goto out;
			}
			break;
		case VCHAN_TRANSPORT_PACKET_TYPE_CONNECTED:
			sk->sk_state = SS_CONNECTED;
			sk->sk_socket->state = SS_CONNECTED;
			vsock_insert_connected(vsk);
			sk->sk_state_change(sk);
			break;
		default:
			err = -EINVAL;
			skerr = EPROTO;
			goto out;
	}
	return 0;
out:
	sk->sk_state = SS_UNCONNECTED;
	sk->sk_err = skerr;
	sk->sk_error_report(sk);
	return err;
}

static int vchan_transport_recv_connected(struct vsock_sock *vsk,struct vchan_pkt_header pkt_header)
{
	int err;
	int skerr;
	struct perport_channel *ppchannel;
	struct sock *sk = sk_vsock(vsk);

	ppchannel = vchan_trans(vsk)->ppchannel;

	switch(pkt_header.type) {
		case VCHAN_TRANSPORT_PACKET_TYPE_DATA:
			sk->sk_data_ready(sk);
			break;
		case VCHAN_TRANSPORT_PACKET_TYPE_SHUTDOWN:
			if (pkt_header.mode) {
				vsk->peer_shutdown |= pkt_header.mode;
				sk->sk_state_change(sk);
			}
			break;
		case VCHAN_TRANSPORT_PACKET_TYPE_CONNECTED:
			break;
		default:
			if (handle_fast_packet(vsk,pkt_header.type) == 0)
				return 0;
			err = -EINVAL;
			skerr = EPROTO;
			goto out;
			break;
	}
	return 0;
out:
	sk->sk_state = SS_UNCONNECTED;
	sk->sk_err = skerr;
	sk->sk_error_report(sk);
	return err;
}


static bool xenbus_is_peer_online(struct vsock_sock *vsk)
{
	const char *xenstore_path, *remote_id;
	int err;
	xenstore_path = kasprintf(GFP_KERNEL,"%s/vchan",PATH);
	remote_id = kasprintf(GFP_KERNEL,"%d",vsk->remote_addr.svm_cid);
	err = xenbus_exists(XBT_NIL,xenstore_path,remote_id);
	kfree(xenstore_path);
	kfree(remote_id);
	if (err==1)
		return true;
	return false;
}


static int xenbus_dir_online_watch(u32 local_id)
{
	const char *xenstore_path;
	const char *local_id_str;
	int err;
	int rc;

	rc=0;
	xenstore_path = kasprintf(GFP_KERNEL,"%s/vchan",PATH);
	local_id_str = kasprintf(GFP_KERNEL,"%d",local_id);
	err = xenbus_exists(XBT_NIL,xenstore_path,local_id_str);
	if (err==1) {
		rc = 0;
		goto out;
	}
	err = xenbus_mkdir(XBT_NIL,xenstore_path,local_id_str);
	if (err<0)
		rc=-1;
	watch.node = kasprintf(GFP_KERNEL,"%s/vchan/%d",PATH,local_id);
	watch.callback = xenbus_watcher_callback;
	err = register_xenbus_watch(&watch);
	if (err<0) 
		rc=-1;
out:
	kfree(xenstore_path);
	kfree(local_id_str);
	return rc;
}

static int xenbus_dir_offline_watch(u32 local_id)
{
	const char *xenstore_path;
	const char *local_id_str;
	int err;
	int rc;

	rc=0;
	xenstore_path = kasprintf(GFP_KERNEL,"%s/vchan",PATH);
	local_id_str = kasprintf(GFP_KERNEL,"%d",local_id);
	err = xenbus_exists(XBT_NIL,xenstore_path,local_id_str);
	if (err!=1) {
		rc=-1;
		goto out;
	}
	unregister_xenbus_watch(&watch);
	kfree(watch.node);
	watch.node = NULL;
	err = xenbus_rm(XBT_NIL,xenstore_path,local_id_str);
	if (err<0)
		rc=-1;
out:
	kfree(xenstore_path);
	kfree(local_id_str);
	return rc;
}

static struct vchan_bus *vchan_bus_from_channel(struct channel_t *channel)
{
	struct vchan_bus *bus = (struct vchan_bus *) channel->addr;
	return bus;
}

static struct vchan_bus *vchan_rx_from_ppchannel(struct perport_channel *ppchannel)
{
	return vchan_bus_from_channel(&ppchannel->duplex.rxq);
}

static struct vchan_bus *vchan_tx_from_ppchannel(struct perport_channel *ppchannel)
{
	return vchan_bus_from_channel(&ppchannel->duplex.txq);
}

static u64 vchan_compute_max_data_buffer_size(void)
{
	size_t size = offsetof(struct vchan_bus, data);
	return ((u64) (RING_SIZE - size - 10));
}

static void vchan_queue_idx_init(struct channel_t *channel)
{
	u64 size;
	struct vchan_bus *bus = vchan_bus_from_channel(channel);
	size = vchan_compute_max_data_buffer_size();

	atomic64_set(&bus->queue_idx.size, size);
	atomic64_set(&bus->queue_idx.prod ,0);
	atomic64_set(&bus->queue_idx.cons ,0);
}

static void vchan_pktq_idx_init(struct channel_t *channel)
{
	u64 size;
	struct vchan_bus *bus = vchan_bus_from_channel(channel);
	size = ARRAY_SIZE(bus->pkt_header);

	atomic64_set(&bus->pktq_idx.size, size);
	atomic64_set(&bus->pktq_idx.prod ,0);
	atomic64_set(&bus->pktq_idx.cons ,0);
}

static void duplex_headers_init(struct perport_channel *ppchannel)
{
	vchan_pktq_idx_init(&ppchannel->duplex.txq);
	vchan_pktq_idx_init(&ppchannel->duplex.rxq);
	vchan_queue_idx_init(&ppchannel->duplex.txq);
	vchan_queue_idx_init(&ppchannel->duplex.rxq);
	return;
}

struct perport_channel *__perport_channel_create(int local_id, int local_port, int remote_id, int remote_port, int count, bool isHost, struct duplex_params params)
{
	int err;
	struct perport_channel *ppchannel = kmalloc(sizeof(*ppchannel),GFP_KERNEL);
	if (!ppchannel)
		return NULL;
	err = __channel_create(&ppchannel->duplex.txq, local_id, remote_id, count, isHost,
		       	params.tx_grefs, params.tx_evtchn_port,vchan_perport_handler_tx, &ppchannel->duplex.txq);
	if (err < 0)
		goto out_free;
	err = __channel_create(&ppchannel->duplex.rxq, local_id, remote_id, count, isHost,
		       	params.rx_grefs, params.rx_evtchn_port, vchan_perport_handler_rx, &ppchannel->duplex.rxq);
	if (err < 0)
		goto out_free_tx;
	tasklet_init(&ppchannel->duplex.rxq.tasklet, bh_perport_handler_rx, (unsigned long) ppchannel->duplex.rxq.addr);
	
	/*Control messages will be sent to approriate queue for each domain. TX for host of connection, RX for guest connection*/
	ppchannel->local_port = local_port;
	ppchannel->remote_port = remote_port;
	mutex_init(&ppchannel->duplex.txq.mutex);
	mutex_init(&ppchannel->duplex.rxq.mutex);
	duplex_headers_init(ppchannel);
	if (!isHost) {
		err = perport_notify_guest_mapped(ppchannel);
		if (err < 0)
			goto out_free;
	}
	return ppchannel;
out_free_tx:
	/* TODO */
	;

out_free:
	kfree(ppchannel);
	return NULL;
}

static void vchan_transport_evtchn_notify(struct perport_channel *ppchannel)
{
	struct vchan_bus *bus;
	int port = ppchannel->duplex.txq.evtchn_port;
	bus = (struct vchan_bus *) (ppchannel->duplex.txq.addr);

	notify_remote_via_evtchn(port);
	return;
}

static int vchan_transport_pktq_enqueue_packet(struct vchan_bus *bus, int type, int size, int lid, int lport, int rid, int rport, int mode)
{
	struct vchan_pkt_header *pkt_header;
	int i;

	if (!bus)
		return -1;

       	i = atomic64_read(&bus->pktq_idx.prod);
	pkt_header = &bus->pkt_header[i];
	pkt_header->type = type;
	pkt_header->size = size;
	pkt_header->src = lid;
	pkt_header->src_port = lport;
	pkt_header->dst = rid;
	pkt_header->dst_port = rport;
	if (mode>0)
		pkt_header->mode = mode;
	pktq_update_producer_unlocked(bus, 1);
	return 0;
}

static int memcpy_toring(struct channel_t *channel, size_t offset, struct iovec *iov, size_t size)
{
	void *base;
	int page, page_offset;
	size_t copy;
	int err;
	size_t data_offset = offsetof(struct vchan_bus, data);

	while (size > 0) {
		page = (data_offset + offset) / PAGE_SIZE;
		base = page_address(channel->pages[page]);
		if (page == 0)
			page_offset = data_offset + offset;
		else
			page_offset = (offset + data_offset) % PAGE_SIZE;
		copy = min_t(size_t, size, PAGE_SIZE - page_offset);
		err = memcpy_fromiovec(base + page_offset, iov, copy);
		if (err != 0) {
			pr_err("memcpy_from_iovec %d bytes could not be copied EFAULT\n", err);
			return -EFAULT;
		}
		size -= copy;
		offset += copy;
	}
	return 0;
}

static int memcpy_fromring(struct channel_t *channel, size_t offset, struct iovec *iov, size_t size)
{
	void *base;
	int page, page_offset;
	size_t copy;
	int err;
	size_t data_offset = offsetof(struct vchan_bus, data);

	while (size > 0) {
		page = (data_offset + offset) / PAGE_SIZE;
		base = page_address(channel->pages[page]);
		if (page == 0)
			page_offset = data_offset + offset;
		else
			page_offset = (offset + data_offset) % PAGE_SIZE;
		copy = min_t(size_t, size, PAGE_SIZE - page_offset);
		err = memcpy_toiovec(iov, base + page_offset, copy);
		if (err != 0) {
			pr_err("memcpy_to_iovec %d bytes could not be copied EFAULT\n", err);
			return -EFAULT;
		}
		size -= copy;
		offset += copy;
	}
	return 0;
}


static int vchan_transport_send_pkt(struct vsock_sock *vsk,enum vchan_packet_type type,
		void *data, size_t size, size_t offset, int mode)
{
	struct vchan_bus *bus;
	int err;
	bool hasSpace;

	bus = (struct vchan_bus *) (vchan_trans(vsk)->ppchannel->duplex.txq.addr);
	if (!bus)
		return -EPIPE;

	vchan_transport_evtchn_notify(vchan_trans(vsk)->ppchannel);
	hasSpace = vchan_transport_pktq_has_space(bus);
	if (!hasSpace) 
		return -EAGAIN;

	vchan_transport_pktq_enqueue_packet(bus, type, size,
			vsk->local_addr.svm_cid, vsk->local_addr.svm_port,
			vsk->remote_addr.svm_cid,vsk->remote_addr.svm_port,
			mode);

	/* Because I'm using producer/consumer ring buffer, I don't need locking mechanism
	 * for copying actual data in data buffer */
	if (data) {
		struct iovec *iov = (struct iovec *)data;
		if (vchan_trans(vsk)->ppchannel->duplex.txq.isHost) {
			err = memcpy_fromiovec(bus->data + offset, iov, size);
			if (err != 0) {
				pr_err("memcpy_from_iovec %d bytes could not be copied EFAULT\n", err);
				return -EFAULT;
			}
		}
		else {
			err = memcpy_toring(&vchan_trans(vsk)->ppchannel->duplex.txq, offset, iov, size);
			if (err < 0)
				return err;
		}
		channel_lock(&vchan_trans(vsk)->ppchannel->duplex.txq);
		queue_update_producer_unlocked(bus,size);
		channel_unlock(&vchan_trans(vsk)->ppchannel->duplex.txq);
	}

	vchan_transport_evtchn_notify(vchan_trans(vsk)->ppchannel);
	return 0;
}

static int perport_send_ctrl_pkt(struct perport_channel *ppchannel,enum vchan_packet_type type)
{	
	struct channel_t *channel = &ppchannel->duplex.txq;
	struct vchan_bus *bus = vchan_bus_from_channel(channel);
	bool hasSpace;

	if (!bus)
		return -EHOSTDOWN;

	vchan_transport_evtchn_notify(ppchannel);
	hasSpace = vchan_transport_pktq_has_space(bus);
	if (!hasSpace) {
		return -EAGAIN;
	}

	vchan_transport_pktq_enqueue_packet(bus, type, 0,
			channel->local_id, ppchannel->local_port,
			channel->remote_id, ppchannel->remote_port, 0);

	vchan_transport_evtchn_notify(ppchannel);
	return 0;
}


static int perport_notify_guest_mapped(struct perport_channel *ppchannel)
{
	int ret;
	int resends = 0;
	do {
		ret = perport_send_ctrl_pkt(ppchannel,VCHAN_TRANSPORT_PACKET_TYPE_GUEST_MAPPED);
	} while (resends++ < MAX_RESENDS && ret == -EAGAIN);
	if (resends >= MAX_RESENDS)
		ret = -ECOMM;
	return ret;
}

static int perport_notify_remote_detach(struct perport_channel *ppchannel)
{
	int ret;
	int resends = 0;
	do {
		ret = perport_send_ctrl_pkt(ppchannel,VCHAN_TRANSPORT_PACKET_TYPE_DETACH);
	} while (resends++ < MAX_RESENDS && ret == -EAGAIN);
	if (resends >= MAX_RESENDS)
		ret = -ECOMM;
	return ret;
}

static int vchan_transport_send_connection_ok(struct vsock_sock *vsk)
{
	int ret;
	int resends = 0;
	do {
		ret = vchan_transport_send_pkt(vsk,VCHAN_TRANSPORT_PACKET_TYPE_CONNECTED,NULL,0,0,0);
	} while (resends++ < MAX_RESENDS && ret == -EAGAIN);
	if (resends >= MAX_RESENDS)
		ret = -ECOMM;
	return ret;
}

static int vchan_transport_send_waiting_write(struct vsock_sock *vsk)
{
	int ret;
	int resends = 0;
	do {
		ret = vchan_transport_send_pkt(vsk,VCHAN_TRANSPORT_FAST_PACKET_TYPE_NOTIFY_WAITING_WRITE, NULL, 0, 0, 0);
	} while (resends++ < MAX_RESENDS && ret == -EAGAIN);
	if (resends >= MAX_RESENDS)
		ret = -ECOMM;
	return ret;
}

static int vchan_transport_send_waiting_read(struct vsock_sock *vsk)
{
	int ret;
	int resends = 0;
	do {
		ret = vchan_transport_send_pkt(vsk,VCHAN_TRANSPORT_FAST_PACKET_TYPE_NOTIFY_WAITING_READ, NULL, 0, 0, 0);
	} while (resends++ < MAX_RESENDS && ret == -EAGAIN);
	if (resends >= MAX_RESENDS)
		ret = -ECOMM;
	return ret;
}

static int vchan_transport_send_wrote(struct vsock_sock *vsk)
{
	int ret;
	int resends = 0;
	do {
		ret = vchan_transport_send_pkt(vsk,VCHAN_TRANSPORT_FAST_PACKET_TYPE_NOTIFY_WRITE,NULL,0,0,0);
	} while (resends++ < MAX_RESENDS && ret == -EAGAIN);
	if (resends >= MAX_RESENDS)
		ret = -ECOMM;
	return ret;
}

static int vchan_transport_send_read(struct vsock_sock *vsk)
{
	int ret;
	int resends = 0;
	do {
		ret = vchan_transport_send_pkt(vsk,VCHAN_TRANSPORT_FAST_PACKET_TYPE_NOTIFY_READ,NULL,0,0,0);
	} while (resends++ < MAX_RESENDS && ret == -EAGAIN);
	if (resends >= MAX_RESENDS)
		ret = -ECOMM;
	return ret;
}

static int vchan_transport_send_shutdown(struct vsock_sock *vsk,int mode)
{
	int ret;
	int resends = 0;
	do {
		ret = vchan_transport_send_pkt(vsk,VCHAN_TRANSPORT_PACKET_TYPE_SHUTDOWN,NULL,0,0,mode);
	} while (resends++ < MAX_RESENDS && ret == -EAGAIN);
	if (resends >= MAX_RESENDS)
		ret = -ECOMM;
	return ret;
}

static int vchan_transport_send_negotiate(struct vsock_sock *vsk)
{
	int ret;
	int resends = 0;
	do {
		ret = vchan_transport_send_pkt(vsk,VCHAN_TRANSPORT_PACKET_TYPE_NEGOTIATE,NULL, 0 ,0, 0);
	} while (resends++ < MAX_RESENDS && ret == -EAGAIN);
	if (resends >= MAX_RESENDS)
		ret = -ECOMM;
	return ret;
}

static int vchan_transport_send_client_ok(struct vsock_sock *vsk)
{
	int ret;
	int resends = 0;
	do {
		ret = vchan_transport_send_pkt(vsk,VCHAN_TRANSPORT_PACKET_TYPE_CLIENT_OK,NULL, 0 ,0, 0);
	} while (resends++ < MAX_RESENDS && ret == -EAGAIN);
	if (resends >= MAX_RESENDS)
		ret = -ECOMM;
	return ret;
}

static int vchan_transport_send_raw_data(struct vsock_sock *vsk,void *data,size_t len, u32 offset)
{
	int ret;
	u32 max = vchan_trans(vsk)->queue_pair_size;
	const size_t page_offset = offset % max;
	int resends = 0;

	do {
		ret = vchan_transport_send_pkt(vsk,VCHAN_TRANSPORT_PACKET_TYPE_DATA,data,len,page_offset,0);
	} while (resends++ < MAX_RESENDS && ret == -EAGAIN);
	if (resends >= MAX_RESENDS)
		ret = -ECOMM;
	return ret;
}


static void vchan_transport_init_vsock_data(struct vsock_sock *child,struct vsock_sock *parent)
{
	vchan_trans(child)->ppchannel = vchan_trans(parent)->ppchannel;
}

static int vchan_transport_socket_init(struct vsock_sock *vsk,struct vsock_sock *psk)
{
	u64 qp_size;
	vsk->trans = kmalloc(sizeof(struct vchanlike_transport),GFP_KERNEL);
	if (!vsk->trans)
		return -ENOMEM;
	if (psk) {
		vchan_transport_init_vsock_data(vsk,psk);
		vchan_trans(vsk)->child = true;
		vchan_trans(vsk)->queue_pair_size = vchan_trans(psk)->queue_pair_size;
		vchan_trans(vsk)->queue_pair_min_size = vchan_trans(psk)->queue_pair_min_size;
		vchan_trans(vsk)->queue_pair_max_size = vchan_trans(psk)->queue_pair_max_size;
	}
	else {
		qp_size = vchan_compute_max_data_buffer_size();
		vchan_trans(vsk)->child = false;
		vchan_trans(vsk)->ppchannel = NULL;
		vchan_trans(vsk)->queue_pair_size = qp_size;
		vchan_trans(vsk)->queue_pair_max_size = qp_size;
		vchan_trans(vsk)->queue_pair_min_size = qp_size;
	}
	vchan_trans(vsk)->notify.peer_waiting_read = false;
	vchan_trans(vsk)->notify.peer_waiting_write = false;
	vchan_trans(vsk)->notify.sent_waiting_read = false;
	vchan_trans(vsk)->notify.sent_waiting_write = false;
	return 0;
}

static int vchan_transport_connect(struct vsock_sock *vsk)
{
	struct sock *sk = &vsk->sk;
	int err = 0;
	
	struct cchannel *cc;
	struct perport_channel *ppchannel;
	struct duplex_params params;
	memset(&params,0,sizeof(params));

	vsk->local_addr.svm_cid = vchan_transport_get_local_cid();

	if (!xenbus_is_peer_online(vsk)) {
		pr_err("Peer not there\n");
		return -EHOSTUNREACH;
	}

	cc = cc_channel_bound(vsk->remote_addr.svm_cid);
	if (!cc) {
		cc = __cc_channel_create(vsk->local_addr.svm_cid, vsk->remote_addr.svm_cid, HOSTDOM, NULL, 0);
		if (!cc) {
			pr_err("Error creating channel\n");
			return -EFAULT;
		}
		cc_channel_add(cc);

		err = xenbus_transmit_cc_params(cc);
		if (err < 0)
			return -EFAULT;
		err = channel_wait_ready(&cc->g_channel);
		if (err < 0) {
			return -ETIMEDOUT;
		}
	}

	//inc_get(inc);
	//err = __inc_destroy(inc, true /*I leave, so notify remote */);

	ppchannel = __perport_channel_create(vsk->local_addr.svm_cid,vsk->local_addr.svm_port,
						vsk->remote_addr.svm_cid,vsk->remote_addr.svm_port, NR_PAGES, HOSTDOM, params /*for hosts this is 0*/);
	if (!ppchannel)
		goto out_err;
	ppchannel->vsk = vsk;
	vchan_trans(vsk)->ppchannel = ppchannel;
	err = cc_send_perport_request(cc,ppchannel);
	if (err < 0)
		goto out_err;

	/* Now we now we have an endpoint of communication. We send our connection request*/
	return 0;
out_err:
	sk->sk_state = SS_UNCONNECTED;
	return err;
}

static void queue_update_producer_unlocked(struct vchan_bus *bus,size_t len)
{
	u64 MAX = atomic64_read(&bus->queue_idx.size);
	u64 new_val = atomic64_read(&bus->queue_idx.prod);
	if (new_val >= MAX - len)
		new_val -= MAX;
	new_val += len;
	atomic64_set(&bus->queue_idx.prod, new_val);
}

static void queue_update_consumer_unlocked(struct vchan_bus *bus,size_t len)
{
	u32 MAX = atomic64_read(&bus->queue_idx.size);
	u64 new_val = atomic64_read(&bus->queue_idx.cons);
	if (new_val >= MAX - len)
		new_val -= MAX;
	new_val += len;
	atomic64_set(&bus->queue_idx.cons, new_val);
}

static void queue_get_ring_indices(struct channel_t *channel, u64 *prod, u64 *cons) 
{
	struct vchan_bus *bus = vchan_bus_from_channel(channel);
	*prod = atomic64_read(&bus->queue_idx.prod);
	*cons = atomic64_read(&bus->queue_idx.cons);
}

static u64 queue_produce_buf_ready(struct vsock_sock *vsk)
{
	u64 buf_ready;
	u64 size, head, tail;
	struct vchan_bus *bus = vchan_tx_from_ppchannel(vchan_trans(vsk)->ppchannel);
	size = atomic64_read(&bus->queue_idx.size);
	head = atomic64_read(&bus->queue_idx.prod);
	tail = atomic64_read(&bus->queue_idx.cons);

	if (tail>= size || head >= size) {
		return -EINVAL;
	}
	/*
	* Deduct 1 to avoid tail becoming equal to head which causes
	* ambiguity. If head and tail are equal it means that the
	* queue is empty.
	*/

	if (head >= tail)
		buf_ready = head-tail;
	else
		buf_ready = size - (tail-head);
	return buf_ready;
}

static u64 queue_consume_free_space(struct vsock_sock *vsk) 
{
	u64 free_space;
	u64 size, head, tail;

	struct vchan_bus *bus = vchan_rx_from_ppchannel(vchan_trans(vsk)->ppchannel);
	size = atomic64_read(&bus->queue_idx.size);
	tail = atomic64_read(&bus->queue_idx.prod);
	head = atomic64_read(&bus->queue_idx.cons);

	if (tail>= size || head >= size) {
		return -EINVAL;
	}
	/*
	* Deduct 1 to avoid tail becoming equal to head which causes
	* ambiguity. If head and tail are equal it means that the
	* queue is empty.
	*/

	if (tail >= head)
		free_space = size - (tail-head) - 1;
	else
		free_space = head-tail - 1;
	return free_space;
}


static int vchan_transport_memcpy_from_queue(struct channel_t *channel,void *dst,size_t len, u32 offset)
{
	int err;
	struct vchan_bus *bus = vchan_bus_from_channel(channel);
	u32 max = atomic64_read(&bus->queue_idx.size);
	const size_t page_offset = offset % max;
	struct iovec *iov = (struct iovec *)dst;

	if (channel->isHost) {
		err = memcpy_toiovec(iov, bus->data + page_offset, len);
		if (err > 0) {
			pr_err("memcpy_to_iovec %d bytes were not written EFAULT\n", err);
			return -EFAULT;
		}
	}
	else {
		err = memcpy_fromring(channel, page_offset, iov, len);
		if (err < 0)
			return err;
	}

	channel_lock(channel);
	queue_update_consumer_unlocked(bus, len);
	channel_unlock(channel);
	return 0;
}

static int vchan_transport_dgram_bind(struct vsock_sock *vsk,struct sockaddr_vm *addr)
{
	pr_err("DGRAM Operations not yet implemented\n");
	return -ENOSYS;
}

static int vchan_transport_dgram_enqueue(struct vsock_sock *vsk,
					struct sockaddr_vm *remote_addr,
					struct iovec *iov,
					size_t len)
{
	pr_err("DGRAM Operations not yet implemented\n");
	return -ENOSYS;
}

static int vchan_transport_dgram_dequeue(struct kiocb *kiocb,
					struct vsock_sock *vsk,
					struct msghdr *msg, size_t len,
					int flags)
{
	pr_err("DGRAM Operations not yet implemented\n");
	return -ENOSYS;
}


static bool vchan_transport_dgram_allow(u32 cid,u32 port)
{
	/* DGRAM operations not yet implemented */
	return false;
}


static ssize_t vchan_transport_stream_dequeue(struct vsock_sock *vsk,struct iovec *iov,size_t len,int flags)
{
	u32 buf_ready;
	u32 head;
	u32 size;
	size_t read;
	ssize_t result = 0;
	size_t tmp = 0;
	struct vchan_bus *bus = vchan_rx_from_ppchannel(vchan_trans(vsk)->ppchannel);
	u32 fake;

	if (flags & MSG_PEEK) {
		/*TODO What happens if MSG_PEEK */;
	}
	else {
		buf_ready = (u32) vchan_transport_stream_has_data(vsk);
		if (buf_ready <= 0)
			return -EINVAL;

		read = (size_t) (buf_ready > len ? len : buf_ready);

		head = atomic64_read(&bus->queue_idx.cons);
		fake = atomic64_read(&bus->queue_idx.prod);
		size = atomic64_read(&bus->queue_idx.size);

		if (head + read < size) {
			result = vchan_transport_memcpy_from_queue(&(vchan_trans(vsk)->ppchannel->duplex.rxq), iov, read, head);
		}
		else {
			tmp = (size_t) size-head;
			result = vchan_transport_memcpy_from_queue(&(vchan_trans(vsk)->ppchannel->duplex.rxq), iov, tmp, head);
			if (result == 0)
				result = vchan_transport_memcpy_from_queue(&(vchan_trans(vsk)->ppchannel->duplex.rxq), iov, read-tmp, 0);
		}
		if (result < 0) 
			read = result;

		return read;
	}
	return 0;
}

static ssize_t vchan_transport_stream_enqueue(struct vsock_sock *vsk,struct iovec *iov,size_t len)
{
	u32 free_space;
	u32 tail;
	u32 size;
	size_t written;
	ssize_t result = 0;
	size_t tmp = 0;
	struct vchan_bus *bus = vchan_tx_from_ppchannel(vchan_trans(vsk)->ppchannel);
	u32 fake;

	free_space = (u32) vchan_transport_stream_has_space(vsk);

	if (free_space <= 0)
		return -EINVAL;


	written = (size_t) (free_space > len ? len : free_space);

	tail = atomic64_read(&bus->queue_idx.prod);
	fake = atomic64_read(&bus->queue_idx.cons);
	size = atomic64_read(&bus->queue_idx.size);


	if (tail + written < size) {
		result = vchan_transport_send_raw_data(vsk, iov, written, tail);
	}
	else {
		tmp = (size_t) (size - tail);
		result = vchan_transport_send_raw_data(vsk, iov, tmp, tail);
		if (result == 0)
			result = vchan_transport_send_raw_data(vsk, iov, written-tmp, 0);
	}
	if (result != 0) 
		written = -1;

	return written;
}

static s64 vchan_transport_stream_has_data(struct vsock_sock *vsk) 
{
	u64 buf_ready;
	u64 size, head, tail;
	struct vchan_bus *bus = vchan_rx_from_ppchannel(vchan_trans(vsk)->ppchannel);
	size = atomic64_read(&bus->queue_idx.size);
	head = atomic64_read(&bus->queue_idx.prod);
	tail = atomic64_read(&bus->queue_idx.cons);

	if (tail>= size || head >= size) {
		return -EINVAL;
	}
	/*
	* Deduct 1 to avoid tail becoming equal to head which causes
	* ambiguity. If head and tail are equal it means that the
	* queue is empty.
	*/

	if (head >= tail)
		buf_ready = head-tail;
	else
		buf_ready = size - (tail-head);
	return buf_ready;
}

static s64 vchan_transport_stream_has_space(struct vsock_sock *vsk)
{
	u64 free_space;
	u64 size, head, tail;

	struct vchan_bus *bus = vchan_tx_from_ppchannel(vchan_trans(vsk)->ppchannel);

	/*First check if I can send packet headers */
	if (!vchan_transport_pktq_has_space(bus))
		return 0;

	size = atomic64_read(&bus->queue_idx.size);
	tail = atomic64_read(&bus->queue_idx.prod);
	head = atomic64_read(&bus->queue_idx.cons);

	if (tail>= size || head >= size) {
		return -EINVAL;
	}
	/*
	* Deduct 1 to avoid tail becoming equal to head which causes
	* ambiguity. If head and tail are equal it means that the
	* queue is empty.
	*/

	if (tail >= head)
		free_space = size - (tail-head) - 1;
	else
		free_space = head-tail - 1;
	return free_space;
}


static u64 vchan_transport_stream_rcvhiwat(struct vsock_sock *vsk)
{
	return (u64) atomic64_read(&(vchan_rx_from_ppchannel(vchan_trans(vsk)->ppchannel)->queue_idx.size));
}

static bool vchan_transport_stream_is_active(struct vsock_sock *vsk)
{
	if (vchan_trans(vsk)->ppchannel)
		return true;
	return false;
}

static u64 vchan_transport_get_buffer_size(struct vsock_sock *vsk)
{
	return vchan_trans(vsk)->queue_pair_size;
}

static u64 vchan_transport_get_min_buffer_size(struct vsock_sock *vsk)
{	
	return vchan_trans(vsk)->queue_pair_min_size;
}
	 
static u64 vchan_transport_get_max_buffer_size(struct vsock_sock *vsk)
{
        return vchan_trans(vsk)->queue_pair_max_size;
}

static void vchan_transport_set_buffer_size(struct vsock_sock *vsk, u64 val)
{
	if (val < vchan_trans(vsk)->queue_pair_min_size)
                vchan_trans(vsk)->queue_pair_min_size = val;
	if (val > vchan_trans(vsk)->queue_pair_max_size)
                vchan_trans(vsk)->queue_pair_max_size = val;
	vchan_trans(vsk)->queue_pair_size = val;
}

static void vchan_transport_set_min_buffer_size(struct vsock_sock *vsk, u64 val)
{
	if (val > vchan_trans(vsk)->queue_pair_size)
                vchan_trans(vsk)->queue_pair_size = val;
	vchan_trans(vsk)->queue_pair_min_size = val;
}

static void vchan_transport_set_max_buffer_size(struct vsock_sock *vsk, u64 val)
{
        if (val < vchan_trans(vsk)->queue_pair_size)
		vchan_trans(vsk)->queue_pair_size = val;
        vchan_trans(vsk)->queue_pair_max_size = val;
}

static int vchan_transport_notify_recv_init(struct vsock_sock *vsk,size_t target, struct vsock_transport_recv_notify_data *data)
{
	struct vchan_transport_recv_notify_data *vchan_data = (struct vchan_transport_recv_notify_data *) data;
	vchan_data->consumer = 0;
	vchan_data->producer = 0;
	return 0;
}

static int vchan_transport_notify_recv_pre_block(struct vsock_sock *vsk, size_t target, struct vsock_transport_recv_notify_data *data)
{
	vchan_transport_evtchn_notify(vchan_trans(vsk)->ppchannel);
	if (vchan_trans(vsk)->notify.sent_waiting_read)
		return 0;
	if (vchan_transport_send_waiting_read(vsk) < 0)
		return -EHOSTUNREACH;
	vchan_trans(vsk)->notify.sent_waiting_read = true;

	return 0;
}


static int vchan_transport_notify_recv_pre_dequeue(struct vsock_sock *vsk,size_t target,struct vsock_transport_recv_notify_data *data)
{
	struct vchan_transport_recv_notify_data *vchan_data = (struct vchan_transport_recv_notify_data *) data;
	queue_get_ring_indices(&(vchan_trans(vsk)->ppchannel->duplex.rxq),&vchan_data->producer, &vchan_data->consumer);
	return 0;
}

static int vchan_transport_notify_recv_post_dequeue(struct vsock_sock *vsk,size_t target,ssize_t copied,
		bool data_read, struct vsock_transport_recv_notify_data *data)
{
	int err = 0;
	if (data_read) {
		err = vchan_transport_send_read(vsk);
		if (err < 0)
			return -1;
	}
	return 0;
}

static int vchan_transport_notify_send_init(struct vsock_sock *vsk,struct vsock_transport_send_notify_data *data)
{
	struct vchan_transport_send_notify_data *vchan_data = (struct vchan_transport_send_notify_data *) data;
	vchan_data->consumer = 0;
	vchan_data->producer = 0;
	return 0;
}

static int vchan_transport_notify_send_pre_block(struct vsock_sock *vsk,struct vsock_transport_send_notify_data *data)
{
	vchan_transport_evtchn_notify(vchan_trans(vsk)->ppchannel);
	if (vchan_trans(vsk)->notify.sent_waiting_write)
		return 0;
	if (vchan_transport_send_waiting_write(vsk) < 0)
		return -EHOSTUNREACH;

	vchan_trans(vsk)->notify.sent_waiting_write = true;
	return 0;
}

static int vchan_transport_notify_send_pre_enqueue(struct vsock_sock *vsk,struct vsock_transport_send_notify_data *data)
{
	struct vchan_transport_send_notify_data *vchan_data = (struct vchan_transport_send_notify_data *) data;
	queue_get_ring_indices(&(vchan_trans(vsk)->ppchannel->duplex.txq),&vchan_data->producer, &vchan_data->consumer);
	return 0;
}

static int vchan_transport_notify_send_post_enqueue(struct vsock_sock *vsk,ssize_t written, struct vsock_transport_send_notify_data *data)
{
	int err = 0;
	u32 buf_ready;

	if (!(vchan_trans(vsk)->notify.peer_waiting_read))
		return 0;

	buf_ready = queue_produce_buf_ready(vsk);
	if (buf_ready > 0) {
		err = vchan_transport_send_wrote(vsk);
		if (err < 0)
			return -1;
		vchan_trans(vsk)->notify.peer_waiting_read = false;
	}
	return 0;
}

static int vchan_transport_shutdown(struct vsock_sock *vsk, int mode)
{
	return vchan_transport_send_shutdown(vsk,mode);
}

/*TODO Handler when detaching 
	 * vmci_transport.c#L832
	 */

static int __ppchannel_destruct(struct perport_channel *ppchannel)
{
	int err = 0;
	
	if (!ppchannel)
		return -1;

	err = perport_notify_remote_detach(ppchannel);
	err = channel_destruct(&ppchannel->duplex.txq);
	err = channel_destruct(&ppchannel->duplex.rxq);

	kfree(ppchannel);
	return 0;
}

static void vchan_transport_destruct(struct vsock_sock *vsk)
{
	/* In here I must release everything. TODO sock_hold, sock_put 
	 * Send conn shutdown */

	struct perport_channel *ppchannel;
	int err;

	if ((!vchan_trans(vsk)->ppchannel) || vchan_trans(vsk)->child)
		return;
	ppchannel = vchan_trans(vsk)->ppchannel;

	ppchannel->vsk = NULL;
	err = __ppchannel_destruct(ppchannel);
	if (err < 0)
		pr_err("Error releasing ppchannel\n");

	vchan_trans(vsk)->ppchannel = NULL;

	kfree(vsk->trans);
	vsk->trans=NULL;
	return;

}

static void vchan_transport_release(struct vsock_sock *vsk)
{
	return;
}

static bool vchan_transport_stream_allow(u32 domid,u32 port) 
{
	        return true;
}

static int vchan_transport_notify_poll_in(struct vsock_sock *vsk, size_t target, bool *data_ready_now)
{
	if (vsock_stream_has_data(vsk)) 
		*data_ready_now = true;
	else 
		*data_ready_now = false;
	return 0;
}

static int vchan_transport_notify_poll_out(struct vsock_sock *vsk, size_t target, bool *space_avail_now)
{
	s64 produce_q_free_space;

	produce_q_free_space = vsock_stream_has_space(vsk);
	if (produce_q_free_space > 0) {
		*space_avail_now = true;
	}
	else if (produce_q_free_space == 0) {
		*space_avail_now = false;
	}
	return 0;
}

u32 vchan_transport_get_local_cid(void)
{
	return LOCAL_ID;
}

static struct vsock_transport vchan_transport = {
	.init = vchan_transport_socket_init,
	.destruct = vchan_transport_destruct,
	.release = vchan_transport_release,
	.connect = vchan_transport_connect,
	.dgram_bind = vchan_transport_dgram_bind,
	.dgram_dequeue = vchan_transport_dgram_dequeue,
	.dgram_enqueue = vchan_transport_dgram_enqueue,
	.dgram_allow = vchan_transport_dgram_allow,
	.stream_dequeue = vchan_transport_stream_dequeue,
	.stream_enqueue = vchan_transport_stream_enqueue,
	.stream_has_data = vchan_transport_stream_has_data,
	.stream_has_space = vchan_transport_stream_has_space,
	.stream_rcvhiwat = vchan_transport_stream_rcvhiwat,
	.stream_is_active = vchan_transport_stream_is_active,
	.stream_allow = vchan_transport_stream_allow,
	.notify_poll_in = vchan_transport_notify_poll_in,
	.notify_poll_out = vchan_transport_notify_poll_out,
	.notify_recv_init = vchan_transport_notify_recv_init,
	.notify_recv_pre_block = vchan_transport_notify_recv_pre_block,
	.notify_recv_pre_dequeue = vchan_transport_notify_recv_pre_dequeue,
	.notify_recv_post_dequeue = vchan_transport_notify_recv_post_dequeue,
	.notify_send_init = vchan_transport_notify_send_init,
	.notify_send_pre_block = vchan_transport_notify_send_pre_block,
	.notify_send_pre_enqueue = vchan_transport_notify_send_pre_enqueue,
	.notify_send_post_enqueue = vchan_transport_notify_send_post_enqueue,
	.shutdown = vchan_transport_shutdown,
	.set_buffer_size = vchan_transport_set_buffer_size,
	.set_min_buffer_size = vchan_transport_set_min_buffer_size,
	.set_max_buffer_size = vchan_transport_set_max_buffer_size,
	.get_buffer_size =     vchan_transport_get_buffer_size,
	.get_min_buffer_size = vchan_transport_get_min_buffer_size,
	.get_max_buffer_size = vchan_transport_get_max_buffer_size,
	.get_local_cid = vchan_transport_get_local_cid,
};


static int __init vchan_transport_init(void)
{
	int err;
	int i;
	u32 local_id;

	/*
	 * If set, translation between the guest's 'pseudo-physical' address space
	 * and the host's machine address space are handled by the hypervisor. In this
	 * mode the guest does not need to perform phys-to/from-machine translations
	 * when performing page table operations.
	 */
	if (xen_feature(XENFEAT_auto_translated_physmap)) { /*HVM Guest */
		hvm = true;
		pr_err("Vchan transport is not yet supported for HVM Guests\n");
		return -EPERM;
	}
	else { /*PV Guest */
		hvm = false;
	}
	err = vsock_core_init(&vchan_transport);
	if (err < 0) {
		pr_err("Error loading vsock_core_init\n");
		return err;
	}
	
	local_id = vchan_transport_get_local_cid();
	err = xenbus_dir_online_watch(local_id);
	if (err<0) {
		pr_err("Error in xenbus_dir_online_watch\n");
		vsock_core_exit();
		return -EACCES;
	}
	for (i=0; i<ARRAY_SIZE(cc_table) ; i++)
		INIT_LIST_HEAD(&cc_table[i]);
	return 0;
}
module_init(vchan_transport_init);

static void __exit vchan_transport_exit(void)
{
	int err = 0;
	u32 local_id;
	local_id = vchan_transport_get_local_cid();
	xenbus_dir_offline_watch(local_id);

	vsock_core_exit();

	err = cc_destroy_channels();
	if (err < 0)
		pr_err("Error destroying channels\n");
}
module_exit(vchan_transport_exit);

MODULE_AUTHOR("M.R Diploma");
MODULE_DESCRIPTION("VCHANlike transport for Virtual Sockets");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("vchanlike_vsock");
MODULE_ALIAS_NETPROTO(PF_VSOCK);
