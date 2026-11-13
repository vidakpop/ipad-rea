# Ledger - failures and successes (running)

## Successes (proven, committed)
- BSR lie via ftrace at xhci_setup_device: SET_ADDRESS never on the
  wire, device enumerates fully at address 0. THE core primitive.
- Capture harness (kprobe co-instrumentation recipe + PCI cycle).
- AMD PORTSC layout (0x10 stride, port2 @ 0x430): software VBUS cut.
- This kernel's usbfs ABI documented (urb 56B, setup-in-buffer,
  REAPND 13).
- usbfs spray path is freeze-proof (every mechanism bounded).
- The feng shui's completion-path behavior mapped: completed
  requests are harmless (700 OK) except the 0x81 odd-size completion
  which kills the ROM's EP0 service.
- Kernel source layouts: xhci_setup_device 2-phase enum semantics.

## Failures (tabulated, do not re-try blindly)
1. Raw dangling TDs by the dozen: AMD xHC parks/halts at the first
   statusless control TD; later TDs parsed, not wire'd. The "pump"
   (a normal URB queued behind) times out. => DEAD as a stacking
   strategy - BUT see the recovery insight below.
2. Userspace nanosleep cancels: ~350us latency vs ~40us wire: all
   complete, zero leaks.
3. SCHED_FIFO busy-wait cancels 5-35us: kills mid-flight; ROM service
   loop wedges after ~5 requests. DEAD.
4. Kernel-internal hrtimer cancels: TWO BOX FREEZES (uninitialized
   hrtimer cancel at rmmod; usb_unlink_urb from hardirq). Fixed in
   code but RETIRED.
5. Completing the 0x81 request: ROM EP0 service death. Never let it
   complete; always leave it dangling in the real run.

## Open: the halt-recovery loophole (the crack in the wall)
The "park" re-diagnosed: per xHCI spec 4.12.2, a Setup TRB landing
while a control transfer is incomplete = SEQUENCE ERROR + endpoint
HALTED. That is NOT a park-forever state: a Halted endpoint is
recovered by the standard command pair (Stop Endpoint / Reset
Endpoint + Set TR Dequeue), which the kernel itself runs for its own
stalls. The kernel does NOT recover OUR halts (td_list mismatch ->
WARN, no recovery) - therefore the module can and must issue the
recovery itself after EVERY dangling TD:
  push dangling TD -> wire setup+data (ROM leaks) -> poll EP0 ctx for
  Halted -> Stop Endpoint cmd -> Set TR Dequeue to next-cycle start
  -> EP Running -> next dangling TD.
~2 xHC commands per wire-leak, ~100-400us/cycle, 620 cycles ~ 1-2
minutes - slower than the sketch but spec-clean, software-only, and
kernel-native command completions (my commands ride the cmd_list and
the kernel's own handlers update the ring state).

## Rules of engagement (learned the hard way)
- Every xHC command issued from process context only.
- Never call kernel functions on zero-initialized kernel objects.
- Small test first (1 cycle), telemetry before volume.
- No new freeze may cost more than a 60s timeout.

## 2025-XX-XX RINGDUMP era: FIRST confirmed wire execution of a module push
- Added RAW0_IOC_RINGDUMP (nr 6): dumps EP0 ring first 48 TRBs + enq/deq/cycle state.
- Baseline (post-PCI-cycle, fresh DFU enum): 12 kernel control TDs at TRB 0-35
  (SETUP w/ IDT + DATA + STATUS), all cycle=1, cycle_state=1, enq=36.
- Type-table correction: transfer-ring TRB types are 1=Normal..4=Status,6=Link,7=Event Data
  (earlier labels used the command-ring table - the "LINK" rows are SETUP TRBs, IDT-carrying).
- PUSHED ONE COMPLETE TD (GET_DESCRIPTOR device 18B IN + status) via raw0_ioctl:
    TRB36 = setup inline (IDT+CHAIN+cycle), TRB37 = staging IOVA data 0x12,
    TRB38 = status IOC. RESULT: enq advanced 36->39 AND
    "xhci_hcd 0000:04:00.3: Event TRB for slot 4 ep 0 with no TDs queued" in dmesg
    = TRANSFER EVENT EMITTED = THE FIRST EVER WIRE PROOF of a module push.
  The push primitive, doorbell, staging DMA, cycle-bit placement all WORK.
- Post-mortem of prior silent failures: pushes before this had never executed
  (no events, follow-up kernel URBs -110 behind a stalled fetch). Root diff vs today:
  today's builder emits IDT (bit6) on SETUP. Missing IDT = xHC DMAs "setup" from
  garbage pointer => IOMMU-fault-era signature + silent stall. LEDGER UPDATES its
  verdict: the push primitive is now proven; prior CYC halt-detection readings were
  garbage (pushes never executed => no halts ever happened). Redo halt-ladder tests
  on the live primitive.
- Next ladder: (1) READBACK of staged IN data to verify data-phase correctness,
  (2) dangling push (has_status=0) + ep_state==2 halt check,
  (3) single CYC cycle (halt + SET-TR-DEQ resume) validation,
  (4) scale to the 620-request feng-shui, (5) stage 2/3 overwrite/payload pushes.
