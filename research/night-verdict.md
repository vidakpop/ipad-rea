# Night verdict: BSR lie + full-stack harness, one wall remains (measured from all sides)

## What now works end-to-end (all committed)
- raw0.ko ftrace hook at xhci_setup_device: forces phase-2 to
  SETUP_CONTEXT_ONLY, which hits the kernel's own "slot already in
  default state" early-return. SET_ADDRESS never appears on the wire;
  the iPad enumerates fully with every token at address 0 - the
  pristine-heap condition the checkm8 sketch runs under.
- Capture fires when an enabled kprobe co-instruments the hooked
  symbol during fresh enumeration (PCI unbind/bind of 04:00.3).
- AMD PORTSC secret: registers stride 0x10, port 2 = 0x430 (BAR0 +
  0x20 op). VBUS cuts/restores work from software (PP bit) - a
  replug emulator.
- usbfs ABI of this kernel: usbdevfs_urb = 56 bytes (setup lives in
  buffer head, no embedded field), SUBMITURB size 56, REAPURBNDELAY
  nr 13. URB buffers are truncated to wLength on submit - the
  overshoot is usbfs-impossible.

## The measured wall: no statusless control stacking on this host
- Raw dangling TDs (module TRB pusher): the AMD xHC parks forever
  inside the first statusless TD; later TDs are parsed (their staging
  IOVAs get IOMMU-checked) but never reach the wire. STALL on the
  first EP0 halt (the seed CLEAR_FEATURE) also wedges it.
- Userspace cancels (nanosleep): ~350us effective latency vs a
  ~30-40us full control sequence - 700 sprays, every request
  completed, zero leaks, ROM survived fine.
- SCHED_FIFO busy-wait cancels at 5-35us: kills land mid-flight and
  the ROM's service loop (or the lie-slot ring) wedges after ~5
  requests. Dead probe confirmed repeatedly.
- Completing the odd-sized wLength 0x81 feng-shui request kills the
  ROM's EP0 service by itself (the sketch leaves it dangling for a
  reason).

## Architecture verdict
The checkm8 A5 sketch requires a transaction-level raw host: the
Arduino's MAX3421 simply declines to send the status phase, and
stacks 620 such transactions. The xHCI + Linux USB stack structurally
interposes a TD state machine and cancel machinery that cannot
express that act on this silicon. Every software path on the laptop
xHCI has now been measured; the wall is real.

## Routes forward
1. The sketch's own verified environment: Arduino UNO + USB Host
   Shield (~$10) - build/src/checkm8-a5 + patches in this repo are
   ready to flash.
2. Raw host from the laptop itself: bind 04:00.3 to vfio-pci (the
   handoff mechanics are proven tonight) and drive the xHC from
   userspace with our own EP0 token sequencer - no kernel USB stack
   in between, wire-exact dangling semantics, same freedom as the
   MAX3421 but on the laptop's silicon. This is the software-only
   breakthrough path; it is hours of focused work, not nights.
