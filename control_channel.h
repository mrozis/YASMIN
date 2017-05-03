#ifndef _INTERDOMAIN_CHANNEL_H_
#define _INTERDOMAIN_CHANNEL_H_

#include "yasmin.h"
#include "mechanics.h"
/*Interdomain Negotiation Channel stuff */
#define VCHAN_HASH_SIZE 30
#define VCHAN_HASH(src,dst) (((src) ^ (dst)) % VCHAN_HASH_SIZE)
extern struct list_head cc_table[VCHAN_HASH_SIZE];
extern spinlock_t cc_table_lock;

extern struct xenbus_watch watch;
extern const char *packet_type_istrings[];

/*Channel used only for control init requests */
struct cchannel {
	struct channel_t g_channel;
	struct list_head table;
	atomic_t refcnt;
};

enum cc_packet_type {
	INC_PACKET_TYPE_REQUEST = 0,
	INC_PACKET_TYPE_CONN_OK,
	INC_PACKET_TYPE_REMOTE_DC,
};

struct cc_packet_header {
	enum cc_packet_type type;
	int src,dst;
	/* following variables > 0 only when TYPE = REQUEST */
	int src_port;
	int dst_port;
	int evtchn_port;
	int evtchn_port_2;	/*full duplex channel. txq */
	int count_1;
	int count_2;
	int gref_ids[];		/*full duplex channel. txq */
};

struct cc_bus {
	spinlock_t lock;
	struct cc_packet_header pkt_header;
};

struct cc_recv_pkt_info {
	struct work_struct work;
	struct cchannel *cc;
	struct cc_packet_header pkt_header;
};	

void xenbus_watcher_callback(struct xenbus_watch *watch,const char **vec,unsigned int len);
int xenbus_transmit_cc_params(struct cchannel *cc);

struct cchannel *cc_channel_bound(int remote_id);
int cc_destroy_channels(void);
int cc_send_perport_request(struct cchannel *cc, struct perport_channel *ppchannel);
struct cchannel *__cc_channel_create(int local_id, int remote_id, bool isHost, int *ring_refs,int remote_evtchn_port);
void cc_channel_add(struct cchannel *cc);
int __cc_destruct(struct cchannel *cc, bool notify_remote);


#endif
