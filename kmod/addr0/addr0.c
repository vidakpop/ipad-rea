// addr0 - live ftrace hook that keeps every newly addressed USB device at
// address 0 on the wire (the checkm8 precondition, achieved through the
// kernel's own xHCI datapath).
//
// Mechanism: xhci_queue_address_device(xhci, cmd, in_ctx, slot_id, setup)
// receives `setup` in argument 5 = r8. Forcing it to SETUP_CONTEXT_ONLY (0)
// sets TRB_BSR on the Address Device command: per xHCI spec 4.6.5, the xHC
// shall NOT issue SET_ADDRESS to the device, the slot stays in Default state,
// and the device address in the slot context remains 0 - so every transfer
// token this slot ever generates carries USB address 0.
//
// The usb core (hub.c hub_set_address) never inspects the wire or the slot
// context address; it trusts the command's return value and updates its own
// software numbers. Kernel keeps working normally; the wire never sees a
// SET_ADDRESS. Remove with rmmod to restore normal behavior.
//
// Load it before the device enumerates; it only affects Address Device
// commands issued while it is loaded.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/version.h>

static unsigned long target_addr;
static struct ftrace_ops a0_ops;

static void notrace a0_hook(unsigned long ip, unsigned long parent_ip,
                            struct ftrace_ops *op, struct ftrace_regs *fregs)
{
    struct pt_regs *regs;

    if (!fregs)
        return;
    regs = ftrace_get_regs(fregs);
    if (!regs)
        return;
    /*
     * arg5: enum xhci_setup_dev setup (SETUP_CONTEXT_ONLY == 0).
     * Rewriting a register argument at function entry needs an ops that
     * participates in IPMODIFY management.
     */
    regs->r8 = 0;
}

static int __init addr0_init(void)
{
    /* resolve xhci_queue_address_device without exported kallsyms */
    struct kprobe kp = { .symbol_name = "xhci_queue_address_device" };
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("addr0: kprobe resolve failed: %d\n", ret);
        return ret;
    }
    target_addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    if (!target_addr) {
        pr_err("addr0: could not resolve xhci_queue_address_device\n");
        return -ENOENT;
    }
    pr_info("addr0: hooking xhci_queue_address_device at %px\n",
            (void *)target_addr);

    a0_ops.func = a0_hook;
    a0_ops.flags = FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED |
                   FTRACE_OPS_FL_IPMODIFY;
    ret = ftrace_set_filter_ip(&a0_ops, target_addr, 0, 0);
    if (ret) {
        pr_err("addr0: ftrace_set_filter_ip failed: %d\n", ret);
        return ret;
    }
    ret = register_ftrace_function(&a0_ops);
    if (ret) {
        pr_err("addr0: register_ftrace_function failed: %d\n", ret);
        return ret;
    }
    pr_info("addr0: active - all Address Device commands now BSR=1 "
            "(wire stays address 0, no SET_ADDRESS is ever sent)\n");
    return 0;
}

static void __exit addr0_exit(void)
{
    unregister_ftrace_function(&a0_ops);
    pr_info("addr0: released - xHCI addressing back to normal\n");
}

module_init(addr0_init);
module_exit(addr0_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Force xHCI Address Device BSR=1 - devices live at USB address 0");
