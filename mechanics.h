#ifndef __MECHANICS_H__
#define __MECHANICS_H__

#define RING_ORDER 7
#define NR_PAGES (RING_ORDER == 0 ? 1 : (1U << RING_ORDER))
#define RING_SIZE (PAGE_SIZE << RING_ORDER)

struct channel_t {
	int local_id;
	int remote_id;

	int evtchn_port;
	int nr_pages;
	int *gref_ids;
	struct page **pages;


	bool isHost;
	void *addr;

	struct gnttab_map_grant_ref *map;
	struct gnttab_unmap_grant_ref *unmap;

	wait_queue_head_t wait;
	struct mutex mutex;
	struct tasklet_struct tasklet;
};

struct duplex_t {
	struct channel_t txq;
	struct channel_t rxq;
};

void channel_lock(struct channel_t *channel);
void channel_unlock(struct channel_t *channel);
void * __gntalloc_init(int remote_dom,int *gref_ids,struct page **pages, int count);
int __map_channel(int remote_dom,int *gref_ids, struct channel_t *channel, int count);
int __channel_unmap(struct channel_t *channel);
int __channel_dealloc(struct channel_t *channel);
int channel_destruct(struct channel_t *channel);
int channel_wait_ready(struct channel_t *channel);
int __channel_wait_remote_unmap(struct channel_t *channel);
int __evtchn_bind_interdomain(int remote_dom,int remote_port, irq_handler_t handler,void *data);
int __evtchn_alloc(int remote_dom,irq_handler_t handler,void *data);
int __evtchn_check_status(int port);
int __channel_create(struct channel_t *channel, int local_id, int remote_id, int count, bool isHost, int *ring_refs, int remote_evtchn_port, irq_handler_t handler, void *data);

#endif
