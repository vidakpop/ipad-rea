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

## RINGDUMP-era VERDICT (the false positive corrected + the real root cause)
CORRECTION of the earlier "confirmed wire execution" entry: FALSE POSITIVE.
The "Event TRB ... no TDs queued" WARNs correlated with OTHER devices'
re-enumeration cycles on the same controller, not with module pushes.
Decisive negative proof (READBACK ioctl, staging buffer): pushes of complete
GET_DESCRIPTOR TDs NEVER put ROM data into staging - zero bytes every time,
including multiple attempts fired DURING the enum window. No module push has
ever executed a wire transaction.

Actual root-cause knowledge (out_ctx forensics, ctx now dumped in RINGDUMP):
- The device out_ctx slot context shows ADDRESS FIELD = 4 (nonzero) with
  EP0 running. The BSR lie ("address stays 0 on the wire") does NOT hold:
  post-enum, every token the xHC emits for this slot is addressed to the
  kernel-chosen devnum, while the DFU ROM (never SET_ADDRESSed) only
  answers its enum flow. Hence: enum strings read fine every cycle
  (kernel-driven, during the enum state machine), while every usbfs read
  after that returns a zero-length instant completion (~238ms) and every
  module push parks silently - the ROM is deaf to both.
- Doorbell experiments: even ringing the CORRECT bell (doorbell[0] for
  slot 1, value 0x10000 = EP0) does not make parked TRBs fetch.
- The ~238ms zero-byte "successful" usbfs reads: instant-looking
  completions with no data - xHC closing TDs against a device that never
  answers at that address.
- 0x13 = COMP_CONTEXT_STATE_ERROR fires during enum because high-speed
  double port reset calls xhci_setup_device twice; the module's hijack
  forces CONTEXT_ONLY both times; the second Address Device errors.
IMPLICATION FOR THE EXPLOIT: the module's "capture then push later" model
is architecturally wrong in this AMD host - the only wire-live window is
the enum itself, driven by the kernel. Any checkm8 spray must either
(a) ride the enum (intercept and serve/inject inside xhci_setup_device's
    window with the port in the enum state), or
(b) make the ROM hear post-enum traffic, which requires the slot context
    address field to be 0 - i.e. patch the slot context (a context write,
    not just token-level) OR stop the kernel from writing the address.
(c) Alternative: use the LEAK ioctl's kernel-internal URB path (the kernel
    queues + cancels real URBs) - this produced the old-era 128-byte served
    behavior per the 1840s evidence only when reads actually served; with
    the address-4 deafness, kernel-internal URBs suffer the same fate.
NEXT: the module hook could also rewrite the slot context address field to
0 via its command-ring access (SET_CONTEXT/p_queue_command with an input
context) right after capture - making post-enum tokens wire-address 0 -
then the parked-TD/spray model revives. This is the top candidate for the
 reboot.
Host hygiene: an increasing number of syscall paths (dmesg/journalctl/
kmsg reads, rmmod, insmod, unbind) enter multi-ten-second transient wedges
- the host needs a reboot soon; /tmp build dirs get wiped, rebuild from
kmod/raw0 after boot.
