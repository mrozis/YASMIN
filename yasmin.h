#ifndef __VSOCK_VCHAN_H__
#define __VSOCK_VCHAN_H__

#include <xen/events.h>
#include <xen/xenbus.h>
#include "mechanics.h"

#define vchan_trans(_vsk) ((struct vchanlike_transport *) ((_vsk)->trans))

#define SS_LISTEN 255

#define PATH "/local/domain/0/data"	/*Must have proper privillage to work*/
#define HOSTDOM true
#define GUESTDOM false
#define PACKET_WINDOW 64	/* This ring_size will be used as packet buffer */
#define MAX_RESENDS 32

enum vchan_packet_type {
	VCHAN_TRANSPORT_PACKET_TYPE_DATA = 0,
	VCHAN_TRANSPORT_PACKET_TYPE_REQUEST,
	VCHAN_TRANSPORT_PACKET_TYPE_NEGOTIATE,
	VCHAN_TRANSPORT_PACKET_TYPE_CLIENT_OK,
	VCHAN_TRANSPORT_PACKET_TYPE_CONNECTED,
	VCHAN_TRANSPORT_PACKET_TYPE_SHUTDOWN,
	VCHAN_TRANSPORT_PACKET_TYPE_DETACH,
	VCHAN_TRANSPORT_PACKET_TYPE_GUEST_MAPPED,
	/* Following packet types refer to processing done only in top-half. Need to be fast. */
	VCHAN_TRANSPORT_FAST_PACKET_TYPE_NOTIFY_WRITE,
	VCHAN_TRANSPORT_FAST_PACKET_TYPE_NOTIFY_READ,
	VCHAN_TRANSPORT_FAST_PACKET_TYPE_NOTIFY_WAITING_READ,
	VCHAN_TRANSPORT_FAST_PACKET_TYPE_NOTIFY_WAITING_WRITE,
};

struct vchan_transport_send_notify_data {
	u64 consumer;
	u64 producer;
};

struct vchan_transport_recv_notify_data {
	u64 consumer;
	u64 producer;
};

extern const char *packet_type_strings[];

struct duplex_params {
	int tx_count;
	int rx_count;
	int *tx_grefs;
	int *rx_grefs;
	int tx_evtchn_port;
	int rx_evtchn_port;
};

struct perport_channel {
	struct duplex_t duplex;
	int local_port;
	int remote_port;
	struct vsock_sock *vsk;
};

struct vchan_pktq_idx {
	atomic64_t prod;
	atomic64_t cons;
	atomic64_t size;
};

struct vchan_queue_idx {
	atomic64_t prod;
	atomic64_t cons;
	atomic64_t size;
};

struct vchan_pkt_header {
	enum vchan_packet_type type;
	int src,dst;
	int src_port,dst_port;
	size_t size;	/*Size of data */
	/* Mode filed is needed for shutdown */
	int mode;
};

struct vchan_bus {
	/* "Global" variables
	 * @lock :used for spinlocking
	 * */
	struct vchan_pktq_idx pktq_idx;
	struct vchan_queue_idx queue_idx;

	struct vchan_pkt_header pkt_header[PACKET_WINDOW];

	u8 data[];
};

struct vchan_recv_pkt_info {
	struct work_struct work;
	struct sock *sk;
	struct vchan_pkt_header *pkt_header;
};	

struct vchan_notify_stuff {
	bool peer_waiting_read;
	bool peer_waiting_write;
	bool sent_waiting_read;
	bool sent_waiting_write;
};

struct vchanlike_transport {
	struct perport_channel *ppchannel;
	u64 queue_pair_size;
	u64 queue_pair_max_size;
	u64 queue_pair_min_size;

	bool child;
	struct vchan_notify_stuff notify;
};

u32 vchan_transport_get_local_cid(void);
void bh_perport_handler_rx(unsigned long data);
int vchan_transport_recv_listen(struct vsock_sock *vsk,struct vchan_pkt_header pkt_header);
struct perport_channel *__perport_channel_create(int local_id, int local_port, int remote_id, int remote_port, int count, bool isHost, struct duplex_params params);

#endif
