// raw0reset - standalone root-hub port reset for a wedged DFU device.
//
// The kernel's usb_reset_device() deadlocks against a held knife-edge
// transfer: it fires the port reset fine (the device re-enters DFU with
// its heap intact), then hangs waiting for a post-reset descriptor read
// that khubd never completes, and the logical disconnect it leaves
// behind never produces a fresh connect event - the re-entered device
// sits invisible at address 0.
//
// This module pokes PORTSC directly over PCI MMIO: no hooks, no xHCI
// structs, no locks. Asserting PR generates the change event khubd
// needs, the kernel re-enumerates the fresh DFU device, and the raw0
// hook captures the new slot. The on-chip heap is untouched by all this.
//
// Modes (module param "mode"):
//   0 = scan only: print PORTSC of every port, reset nothing
//   1 = scan + auto-reset the single CCS+full-speed port (or "port=")
// Params:
//   bdf  = PCI BDF of the xHC, e.g. "0000:04:00.4" (default; = bus 3/4)
//   port = 1-based xHC MMIO port number; -1 = auto-pick the only
//          connected full-speed port

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/io.h>
#include <linux/delay.h>

static char *bdf = "0000:04:00.4";
static int port = -1;
static int mode = 1;
module_param(bdf, charp, 0444);
module_param(port, int, 0444);
module_param(mode, int, 0444);

static void __iomem *mmio;
static struct pci_dev *pdev;

static const char *decode_speed(u32 v)
{
	switch ((v >> 10) & 0xf) {
	case 1: return "full";
	case 2: return "low";
	case 3: return "high";
	case 4: return "super";
	case 5: return "super+";
	default: return "?";
	}
}

static int __init r0r_init(void)
{
	unsigned int dom, b, s, f;
	u32 cap, caplen, hcs1;
	int maxports, i, target = -1;
	void __iomem *ps;
	u32 v;

	if (sscanf(bdf, "%x:%x:%x.%x", &dom, &b, &s, &f) != 4) {
		pr_err("r0r: bad bdf '%s'\n", bdf);
		return -EINVAL;
	}
	pdev = pci_get_domain_bus_and_slot(dom, b, PCI_DEVFN(s, f));
	if (!pdev) {
		pr_err("r0r: no such pci device %s\n", bdf);
		return -ENODEV;
	}
	mmio = pci_ioremap_bar(pdev, 0);
	if (!mmio) {
		pci_dev_put(pdev);
		pr_err("r0r: ioremap failed\n");
		return -ENOMEM;
	}

	cap = readl(mmio);
	caplen = cap & 0xff;
	hcs1 = readl(mmio + 0x04);
	maxports = (hcs1 >> 24) & 0xff;
	pr_info("r0r: %s caplen=%u maxports=%d mode=%d port=%d\n",
		bdf, caplen, maxports, mode, port);

	for (i = 1; i <= maxports; i++) {
		ps = mmio + caplen + 0x400 + 4 * (i - 1);
		v = readl(ps);
		pr_info("r0r: port %d PORTSC %08x ccs=%u csc=%u ped=%u pr=%u speed=%s\n",
			i, v, v & 1, (v >> 1) & 1, (v >> 2) & 1,
			(v >> 4) & 1, decode_speed(v));
		if ((v & 1) && (((v >> 10) & 0xf) == 1) && port == -1) {
			if (target == -1)
				target = i;
			else
				target = -2;	/* ambiguous: more than one */
		}
	}
	if (port > 0)
		target = port;

	if (mode == 0 || target < 1) {
		pr_info("r0r: scan done (target=%d)\n", target);
		return 0;
	}

	ps = mmio + caplen + 0x400 + 4 * (target - 1);
	v = readl(ps);
	pr_info("r0r: resetting port %d (PORTSC %08x)\n", target, v);
	writel(v | (1u << 4), ps);
	{
		int k;
		for (k = 0; k < 250; k++) {
			msleep(2);
			v = readl(ps);
			if (!(v & (1u << 4)))
				break;
		}
		for (k = 0; k < 150; k++) {
			v = readl(ps);
			if (v & 1)
				break;
			msleep(2);
		}
	}
	pr_info("r0r: port %d final PORTSC %08x ccs=%u ped=%u speed=%s\n",
		target, v, v & 1, (v >> 2) & 1, decode_speed(v));
	return 0;
}

static void __exit r0r_exit(void)
{
	if (mmio)
		iounmap(mmio);
	if (pdev)
		pci_dev_put(pdev);
	pr_info("r0r: unloaded\n");
}

module_init(r0r_init);
module_exit(r0r_exit);
MODULE_LICENSE("GPL");
