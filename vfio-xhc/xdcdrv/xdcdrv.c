// xdcdrv: minimal ring-provider for the AMD FCH xDC (04:00.4) while driverless.
// Borrows the orphan PCI device's DMA domain for coherent ring memory.
// No IRQ, no binding, no hotplug. rmmod to remove.
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/stddef.h>
#include <linux/pci.h>

#define DRV_NAME "xdcdrv"

#define XDC_BUS 0x04
#define XDC_DEVFN 0x00  // 04:00.4 -> devfn = (4<<3) = 0x20 relative? use dev=0,fn=4 => 0x04? devfn = (0<<3)|4 = 4

struct xdc_req { u32 off; u32 val; };
struct xdc_dma_req { u32 off; u32 len; u32 val[64]; };

#define XDC_MAGIC 0xd6
#define XDC_REG_READ   _IOWR(XDC_MAGIC, 1, struct xdc_req)
#define XDC_REG_WRITE  _IOW(XDC_MAGIC, 2, struct xdc_req)
#define XDC_MEM_READ   _IOWR(XDC_MAGIC, 3, struct xdc_dma_req)
#define XDC_MEM_WRITE  _IOW(XDC_MAGIC, 4, struct xdc_dma_req)
#define XDC_IRQ_SETUP  _IO(XDC_MAGIC, 5)
#define XDC_IRQ_COUNT  _IO(XDC_MAGIC, 6)

#define DMA_POOL_SIZE (512 * 1024)

static void __iomem *regs;
static int major;
static struct pci_dev *pdev;
static void *dma_virt;
static dma_addr_t dma_phys;
static size_t dma_size = DMA_POOL_SIZE;
static int irq_count = 0;
static int irq_num = -1;
static irqreturn_t xdc_isr(int irq, void *d) { irq_count++; return IRQ_HANDLED; }

static struct xdc_req xr;
static struct xdc_dma_req x;

static long xdc_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case XDC_REG_READ:
        if (copy_from_user(&xr, (void __user *)arg, sizeof(xr))) return -EFAULT;
        if (xr.off > 0x100000 - 4) return -EINVAL;
        xr.val = readl(regs + xr.off);
        if (copy_to_user((void __user *)arg, &xr, sizeof(xr))) return -EFAULT;
        return 0;
    case XDC_REG_WRITE:
        if (copy_from_user(&xr, (void __user *)arg, sizeof(xr))) return -EFAULT;
        if (xr.off > 0x100000 - 4) return -EINVAL;
        writel(xr.val, regs + xr.off);
        return 0;
    case XDC_MEM_READ:
        if (copy_from_user(&x, (void __user *)arg, sizeof(x))) return -EFAULT;
        if ((u64)x.off + x.len > dma_size) return -EINVAL;
        {
            u32 words = (x.len + 3) / 4;
            if (words > 64) return -EINVAL;
            if (copy_to_user((void __user *)arg, &x, offsetof(struct xdc_dma_req, val))) return -EFAULT;
            if (copy_to_user(((void __user *)arg) + offsetof(struct xdc_dma_req, val),
                             dma_virt + x.off, words * 4)) return -EFAULT;
        }
        return 0;
    case XDC_MEM_WRITE:
        if (copy_from_user(&x, (void __user *)arg, sizeof(x))) return -EFAULT;
        if ((u64)x.off + x.len > dma_size) return -EINVAL;
        {
            u32 words = (x.len + 3) / 4;
            if (words > 64) return -EINVAL;
            memcpy(dma_virt + x.off, x.val, words * 4);
        }
        return 0;
    case XDC_IRQ_SETUP: {
        int n;
        if (irq_num >= 0) return 0;
        n = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_MSIX | PCI_IRQ_MSI);
        if (n < 1) { pr_warn("xdcdrv: alloc_irq_vectors failed %d\n", n); return -EIO; }
        irq_num = pci_irq_vector(pdev, 0);
        {
            int err = request_irq(irq_num, xdc_isr, 0, DRV_NAME, NULL);
            if (err) { pr_warn("xdcdrv: request_irq %d failed %d\n", irq_num, err); pci_free_irq_vectors(pdev); irq_num = -1; return err; }
        }
        pr_info("xdcdrv: irq %d armed\n", irq_num);
        return 0;
    }
    case XDC_IRQ_COUNT:
        return irq_count;
    }
    return -ENOTTY;
}

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = xdc_ioctl,
};

static int __init xdc_init(void)
{
    pdev = pci_get_domain_bus_and_slot(0, XDC_BUS, PCI_DEVFN(0, 4));
    if (!pdev)
        pdev = pci_get_device(0x1022, 0x1639, NULL); // fallback: first match
    if (!pdev) return -ENODEV;
    if (pdev->devfn != PCI_DEVFN(0, 4)) { // want 04:00.4 specifically
        // walk for the .4 variant
        struct pci_dev *it = pdev;
        while (it) {
            if (it->bus->number == 4 && it->devfn == PCI_DEVFN(0, 4)) { pdev = it; break; }
            it = pci_get_device(0x1022, 0x1639, it);
        }
    }
    pr_info("xdcdrv: using %04x:%02x:%02x.%d (%s)\n",
            pci_domain_nr(pdev->bus), pdev->bus->number,
            PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn),
            pdev->driver ? pci_name(pdev) : "driverless");
    if (pdev->driver) { pr_warn("xdcdrv: device has a driver!\n"); return -EBUSY; }
    regs = ioremap(pci_resource_start(pdev, 0), pci_resource_len(pdev, 0));
    if (!regs) return -ENOMEM;
    if (pci_enable_device_mem(pdev)) { iounmap(regs); return -EIO; }
    pci_set_master(pdev);
    dma_virt = dma_alloc_coherent(&pdev->dev, dma_size, &dma_phys, GFP_KERNEL);
    if (!dma_virt) { iounmap(regs); return -ENOMEM; }
    dev_info(&pdev->dev, "xdcdrv: regs=%p fhys=%pad size=%zx\n", regs, &dma_phys, dma_size);
    major = register_chrdev(0, DRV_NAME, &fops);
    if (major < 0) { dma_free_coherent(&pdev->dev, dma_size, dma_virt, dma_phys);
                     pci_clear_master(pdev); iounmap(regs); return major; }
    pr_info("xdcdrv: major=%d, DMA@%pad (%zuK)\n", major, &dma_phys, dma_size / 1024);
    return 0;
}

static void __exit xdc_exit(void)
{
    if (irq_num >= 0) { free_irq(irq_num, NULL); pci_free_irq_vectors(pdev); }
    if (dma_virt) { struct pci_dev *p = pdev; dma_free_coherent(&p->dev, dma_size, dma_virt, dma_phys); }
    unregister_chrdev(major, DRV_NAME);
    pci_clear_master(pdev);
    iounmap(regs);
    pr_info("xdcdrv: unloaded\n");
}

module_init(xdc_init);
module_exit(xdc_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("davis/mistral");
MODULE_DESCRIPTION("ring/relay provider for orphaned AMD FCH xDC");
