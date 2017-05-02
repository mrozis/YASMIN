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
#include <xen/balloon.h>
#include <xen/grant_table.h>
#include <xen/gntalloc.h>
#include <asm/xen/hypervisor.h>
#include <asm/xen/hypercall.h>
#include <asm/xen/page.h>
#include <asm/bitops.h>

#include "control_channel.h"
#include "vintra.h"
#include "debug.h"
#include "mechanics.h"

static int __evtchn_unbind(int port);

void channel_lock(struct channel_t *channel)
{
	mutex_lock(&channel->mutex);
}

void channel_unlock(struct channel_t *channel)
{
	mutex_unlock(&channel->mutex);
}

static int logFunc(int x) 
{ 
	int log = -1; 
	while(x) { 
		log++; 
		x >>= 1; 
	} 
	return log; 
} 

void * __gntalloc_init(int remote_dom,int *gref_ids,struct page **pages, int count)
{
	struct ioctl_gntalloc_alloc_gref op;
	int rc, readonly;
	struct page *page;
	void *va;
	int i;

	op.count = 1;
	op.domid = remote_dom;
	readonly = !GNTALLOC_FLAG_WRITABLE;
	va = NULL;

	page = alloc_pages(GFP_KERNEL|__GFP_ZERO, logFunc(count));
	if (!page)
		return NULL;
	for (i=0; i< count; i++) 
		pages[i] = page++;

	va = page_address(pages[0]);
	if (!va)
		goto out_free;

	for (i=0; i< count; i++) {
		rc = gnttab_grant_foreign_access(op.domid,pfn_to_mfn(page_to_pfn(pages[i])),readonly);
		if (rc<0) {
			pr_err("grant_foreign_access failed\n");
			goto out_free;
		}
		gref_ids[i] = rc;
	}
	return va;
out_free:
	__free_pages(pages[0], logFunc(count));
	return NULL;
}


int __map_channel(int remote_dom,int *gref_ids, struct channel_t *channel, int count)
{
#ifdef DEBUG
	char *error_messages[] = GNTTABOP_error_msgs;
#endif
	phys_addr_t phys_addr;
	int i;
	uint32_t flags;

	if (channel->map == NULL || channel->unmap == NULL)
		return -1;

	if (alloc_xenballooned_pages(count, channel->pages, false) < 0)
		return -1;

	flags = GNTMAP_host_map;
	for (i = 0; i< count; i++) {
		phys_addr = ((unsigned long) pfn_to_kaddr(page_to_pfn(channel->pages[i])));
		gnttab_set_map_op(&channel->map[i],phys_addr,flags, gref_ids[i], remote_dom);
		gnttab_set_unmap_op(&channel->unmap[i],phys_addr,flags,-1 /*handle */);
	}

	gnttab_batch_map(channel->map,count);
	
	if (channel->map[0].status != GNTST_okay)  {
		DEBUG_PRINT_LOW("Error in ops status: %s\n",error_messages[-(channel->map[0].status)]);
		goto out_err;
	}
	
	for (i = 0; i< count; i++) 
		channel->unmap[i].handle = channel->map[i].handle;
	channel->addr = page_address(channel->pages[0]);
	return 0;
out_err:
	free_xenballooned_pages(count, channel->pages);
	return -1;
}

int __channel_unmap(struct channel_t *channel)
{
#ifdef DEBUG
	char *error_messages[] = GNTTABOP_error_msgs;
#endif
	int ret;
	int i;

	if (!channel->pages)
		return -1;
	if ((channel->isHost) || (channel->map == NULL) || (channel->unmap == NULL)) {
		ret = -1;
		goto out;
	}
	for (i=0 ;i<channel->nr_pages; i++) {
		if (channel->unmap[i].handle < 0) {
			ret = -1;
			goto out;
		}
	}
	if (HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, channel->unmap, channel->nr_pages)) {
		pr_err("unmap err\n");
		ret = -1;
		goto out;
	}
	ret = 0;
	for (i = 0; i< channel->nr_pages; i++) {
		DEBUG_PRINT_LOW("Ops status %s\n",error_messages[-(channel->unmap[i].status)]);
	}
	if (channel->unmap[0].status != GNTST_okay) {
		DEBUG_PRINT_LOW("Error in ops status: %s\n",error_messages[-(channel->unmap[0].status)]);
		ret = -1;
	}
out:
	kfree(channel->map);
	kfree(channel->unmap);
	return ret;
}

int __channel_dealloc(struct channel_t *channel)
{
	int err;
	int i;
	if (!channel->isHost)	
		return -1;

	for (i=0; i<channel->nr_pages; i++) {
		if (channel->gref_ids[i] > 0) {
			err = __channel_wait_remote_unmap(channel);
			if (err < 0) {
				pr_err("Unmapping unsuccessfull %d\n",err);
				return -1;
			}
			if(!gnttab_end_foreign_access_ref(channel->gref_ids[i],0)) 
				return -1;
			gnttab_free_grant_reference(channel->gref_ids[i]);
		}
	}
	return 0;
}

int channel_destruct(struct channel_t *channel)
{
	int err = 0;
	int ret = 0;
	
	err = __evtchn_unbind(channel->evtchn_port);
	if (channel->gref_ids == NULL)
		return -1;
	if (channel->isHost) {
		err = __channel_dealloc(channel);
		if (err < 0) {
			ret = -1;
			goto out;
		}
	}
	else {
		err = __channel_unmap(channel);
		if (err < 0) {
			ret = -1;
			goto out;
		}
	}
	ret = 0;
out:
	if (channel->pages)
		free_xenballooned_pages(channel->nr_pages, channel->pages);
	tasklet_kill(&channel->tasklet);
	kfree(channel->gref_ids);
	channel->addr = NULL;
	return ret;
}

int channel_wait_ready(struct channel_t *channel)
{
	DEFINE_WAIT(wait);
	long timeout = HZ;
	int err = 0;
	prepare_to_wait(&channel->wait,&wait,TASK_INTERRUPTIBLE);
	if ((err = __evtchn_check_status(channel->evtchn_port))==0)
		return 0;
	else {
		timeout = schedule_timeout(timeout);
		finish_wait(&channel->wait,&wait);

		if (signal_pending(current)) {
		        err = -ECOMM;
		        goto out_wait_error;
		} else if (timeout == 0) {
			if ((err = __evtchn_check_status(channel->evtchn_port))==0)
				return 0;
			err = -ETIMEDOUT;
			goto out_wait_error;
		}
	}
out_wait_error:
	return err;
}

/* Because remote domain is unmapping in batch mode,
 * we only need to wait for the first grant reference id.
 * If this is unmapped, then all are unmapped */
int __channel_wait_remote_unmap(struct channel_t *channel)
{
	DEFINE_WAIT(wait);
	long timeout = HZ;
	int err = 0;
	prepare_to_wait(&channel->wait,&wait,TASK_INTERRUPTIBLE);
	if (!gnttab_query_foreign_access(channel->gref_ids[0])) 
		return 0;
	else {
		timeout = schedule_timeout(timeout);

		finish_wait(&channel->wait,&wait);
		if (signal_pending(current)) {
		        err = -ECOMM;
		        goto out_wait_error;
		} else if (timeout == 0) {
			if (!gnttab_query_foreign_access(channel->gref_ids[0])) 
				return 0;
			err = -ETIMEDOUT;
		}
	}
out_wait_error:
	return err;
}

int __evtchn_bind_interdomain(int remote_dom,int remote_port, irq_handler_t handler,void *data)
{
	struct evtchn_bind_interdomain bind_interdomain;
	struct evtchn_close close;
	int rc;
	const char *name;
	int local_port;


	bind_interdomain.remote_dom = remote_dom;
	bind_interdomain.remote_port = remote_port;
	rc = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain, &bind_interdomain);
	if (rc !=0) {
		pr_err("Error in hypercall bind_interdomain\n");
		goto out;
	}
	local_port = bind_interdomain.local_port;


	name = kasprintf(GFP_KERNEL,"evtchn_bind-%d",local_port);
	if (!name) 
		goto out_close;
	/*TODO Instead of NULL must think of something to send to handler*/
	rc = bind_evtchn_to_irqhandler(bind_interdomain.local_port,handler, 0, name, data);
	if (rc<0) {
		pr_err("Could not register irqhandler\n");
		goto out_close;
	}
	rc = evtchn_make_refcounted(bind_interdomain.local_port);
	if (rc <0 )
		pr_err("error in evtchn_make_refcounted\n");
	return local_port;
out_close:
	close.port = bind_interdomain.local_port;
	rc = HYPERVISOR_event_channel_op(EVTCHNOP_close,&close);
	rc = -1;
out:
	return rc;
}

static int __evtchn_unbind(int port)
{
	int irq;
	if (port <= 0)
		return -1;
	irq = irq_from_evtchn(port);
	if (irq < 0)  {
		pr_err("Error. evtchn not irq\n");
		return -1;
	}
	else 
		evtchn_put(port);
	return 0;
}

int __evtchn_alloc(int remote_dom,irq_handler_t handler,void *data)
{
	struct evtchn_alloc_unbound alloc_unbound;
	struct evtchn_close close;
	int rc;
	const char *name;
	alloc_unbound.dom = DOMID_SELF;
	alloc_unbound.remote_dom = remote_dom;
	rc = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &alloc_unbound);
	if (rc != 0) {
		pr_err("hypercall_event_op error\n");
		goto out_err;
	}
	name = kasprintf(GFP_KERNEL,"%d_evtchn_alloc_%s",alloc_unbound.port, current->comm);
	if (!name) {
		rc = -ENOMEM;
		goto out_err;
	}
	rc = bind_evtchn_to_irqhandler(alloc_unbound.port,handler,0,name,data);
	if (rc<0) {
		pr_err("Could not register irqhandler\n");
		goto out_close;
	}
	rc = evtchn_make_refcounted(alloc_unbound.port);
	if (rc <0 )
		pr_err("error in evtchn_make_refcounted\n");
	return alloc_unbound.port;
out_close:
	close.port = alloc_unbound.port;
	rc = HYPERVISOR_event_channel_op(EVTCHNOP_close,&close);
	rc = -1;
out_err:
	return rc;
}

int __evtchn_check_status(int port)
{
	struct evtchn_status status;
	int err=0;
	memset(&status,0,sizeof(status));
	status.dom = DOMID_SELF;
	status.port = port;
	err = HYPERVISOR_event_channel_op(EVTCHNOP_status,&status);
	if (err < 0)
		goto out_err;
	if (status.status == EVTCHNSTAT_unbound)
		return 1;
	else if (status.status == EVTCHNSTAT_interdomain) 
		return 0;
out_err:
	return -1;
}

int __channel_create(struct channel_t *channel, int local_id, int remote_id, int count, bool isHost, int *ring_refs, int remote_evtchn_port, irq_handler_t handler, void *data)
{
	int i;
	int rc;
	void *addr = NULL;

	memset(channel,0,sizeof(*channel));
	channel->gref_ids = kcalloc(count, sizeof(channel->gref_ids[0]), GFP_KERNEL);
	channel->pages = kcalloc(count, sizeof(channel->pages[0]),GFP_KERNEL);
	if (channel->gref_ids == NULL || channel->pages == NULL)
		goto out_err;
	if (!isHost) {
		channel->map = kcalloc(count, sizeof(channel->map[0]), GFP_KERNEL);
		channel->unmap = kcalloc(count, sizeof(channel->unmap[0]), GFP_KERNEL);
	    	if (channel->map == NULL || channel->unmap == NULL)
		goto out_err;
	}

	channel->nr_pages = count;
	init_waitqueue_head(&channel->wait);
	mutex_init(&channel->mutex);
	channel->evtchn_port = -1;
	for (i=0; i<count; i++)
		channel->gref_ids[i] = -1;

	channel->local_id = local_id;
	channel->remote_id = remote_id;
	channel->isHost = isHost;
	if (isHost) {
		addr = __gntalloc_init(remote_id, channel->gref_ids, channel->pages, channel->nr_pages);
		if (!addr) {
			pr_err("Error kmap\n");
			goto out_err;
		}
		channel->addr = addr;
		rc = __evtchn_alloc(remote_id, handler, data);
		if (rc <= 0)
			goto out_undo;
		channel->evtchn_port = rc;
	}
	else {
		for (i=0; i<count; i++) 
			channel->gref_ids[i] = ring_refs[i];
		rc = __map_channel(remote_id, channel->gref_ids, channel, channel->nr_pages);            
		if (rc < 0) 
			goto out_undo;
		rc = __evtchn_bind_interdomain(remote_id,remote_evtchn_port, handler, data);
		if (rc<0)
			goto out_undo;
		channel->evtchn_port = rc;
	}
	if (evtchn_get(channel->evtchn_port))
		goto out_undo;
	return 0;
out_undo:
	channel_destruct(channel);
out_err:
	/* Probably kfree for these pointer has already happened,
	 * but since it's so cheap, we prefer not to leak */
	kfree(channel->pages);
	kfree(channel->gref_ids);
	kfree(channel->map);
	kfree(channel->unmap);
	return -1;
}

