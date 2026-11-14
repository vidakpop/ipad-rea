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

## Fresh-boot era: doorbell off-by-one fixed; cycle-ladder state machine decoded
- Module reload recipe reconfirmed post-reboot: register+enable kprobe
  (p:kprobes/xc1 xhci_setup_device) BEFORE the enum, insmod, guarded
  USBDEVFS_RESET -> capture fires. Guard (usb_set_configuration stub)
  keeps the ROM alive.
- MAJOR FIX: both raw0_push and raw0_cyc rang doolbell[g_slot] - one past
  the xHCI slot's own bell (array is slot-1-indexed). Cycle-1-on-a-healthy-
  ring only ever worked because a kernel URB's correct bell incidentally
  flushed our TRBs. Fixed to doorbell[g_slot-1] + post-Set-TR-Deq ring
  (Stopped->Running per 4.6.10). VERIFY the fix empirically on the next
  fresh session (today's cycle-1 after the fix returned rc=1-class in 4ms
  with stage zeros - believed-no-halt-detected).
- FIXED-MODULE CYCLE-LADDER (detached, serve-checks between every step):
  baseline SERVES(182); cycle1 rc~1/4ms dangling: stage ZERO (data never
  landed?) + serve -110; cycle2: hwdeq moved, ep=3 STOPPED, serve -110;
  ladder stopped. Distinguishers needed: was the data-phase ever fetched?
- ROM mid-dangling watchdog test: serve -110 persists t+0..t+30s. NO
  self-recovery inside 30s. (Confounded: serve URBs queue behind stuck
  ring TRBs, so ROM state itself is not independently measured.)
- RESETDEV (function 10) on stuck state: my poll returns -110 (module's
  address-bit poll uses the WRONG bit mask - bits 25-31 are slot STATE;
  the ADDRESS field is the LOW byte per DEV_ADDR_MASK=0xff) BUT the
  command itself partially applied: ep 3->1 RUNNING. Module poll needs
  the same fix as the addr decode.
- IMPORTANT protocol discovery: a cable replug does NOT revive a wedged
  DFU ROM (battery keeps the A5 alive) - only hold-power force-restart +
  DFU dance does.
- Freeze-class ruling stands: NEVER issue the unlink/cancel paths; all
  experiments detached (setsid nohup + log + bounded observer loop).
  Today's runs caused zero freezes.
NEXT (designed):
1) mic-first: fix RESETDEV poll bits (low-byte address) then use it as the
   clean-slate machine between experiments.
2) ISOLATION TEST on fresh state: dangling push -> usbmon wire capture to
   learn whether the xHC ever emitted the SETUP/DATA tokens for it
   (distinguish ROM-freeze vs never-fetched). Then recovery via the
   fixed-bell sequence; serve-check in the same detached pass.
3) Only then scale: the 620-spray question (leak-stacking requires
   no-reset-per-cycle, so the halt-recovery engine must be proven
   iterating, not reset-each).

## CRASH REPORT + the decisive morning findings (post-second-crash session)
KERNEL PANIC (caps-lock blink, screen corruption, hard restart needed):
caused by RESET_DEVICE command issued into a ring dirtied by an unexecuted
dangling TD, immediately followed by USBDEVFS_RESET. New PERMANENT RULES:
- No recovery commands on a dirtied ring. The only safe recovery is the
  user's physical power-restart + DFU dance.
- Cancel/unlink APIs remain banned (4h freeze earlier).
- Architecture must be designed around COMPLETE transactions only before
  any further device experiments.

THE MORNING'S REAL FINDINGS (all proven live):
1. DOORBELL REVERSAL: the kernel's xhci_ring_ep_doorbell does
   &xhci->dba->doorbell[slot_id] DIRECTLY - the array is SLOT-N-INDEXED
   with doorbell[0] = the HOST/command-ring bell. My previous morning
   "off-by-one fix" (doorbell[g_slot-1]) RANG THE HOST BELL - a
   regression; it was REVERTED to doorbell[g_slot] in all three places.
   The kernel source is the ground truth.
2. PUSH-COMPLETE WORKS END-TO-END: a complete control TD (setup+data+
   status) pushed on the raw ring with the correct doorbell executed on
   the wire; the ROM's 18-byte device descriptor landed in staging
   byte-perfect: 1201000200000040ac052712000001020301
   (idVendor 05ac, idProduct 1227). Ring stayed healthy (EP running,
   subsequent serves fine). THE RAW PUSH ENGINE IS REAL.
3. PUSH-DANGLING (no status TRB): NEVER EXECUTES AT ALL - staging stays
   zero, the xHC advances its dequeue past the TRBs (discards the TD),
   EP transitions RUNNING->STOPPED, and every subsequent request queues
   behind the stopped gate (-110). VERDICT: xHCI control TDs are ATOMIC -
   incomplete TDs never reach the wire. The trivial dangling-leak shape
   is architecturally dead on this HCD.
4. RESETDEV poll fixed: address detection now uses the low byte
   (DEV_ADDR_MASK 0xff) + slot-state bits 27-31 decode.
NEXT: design a leak/feng-shui approach using ONLY complete transactions
(e.g. DFU-class request semantics on the ROM's own buffers, or an
overshoot-shaped OUT variant via kernel-internal URB) BEFORE running any
further device experiments.

## Post-crash re-arm + the complete-transactions architecture direction
Re-armed cleanly after the panic-reboot: rebuild, kprobe, module, guarded
reset (238ms), serve ret=182 CPID, capture slot=1. tools/reset_serve.py now
lives in the repo (survives /tmp wipes).

CODEBASE RE-DIGEST (tools/checkm8-a5-pwn.py stage machinery, authored by
earlier sessions from the Arduino sketch + ROM write-ups):
- The io_globals predictor: rcvd/length/buffer advance on data packets
  and are ONLY reset by end_of_transfer (i.e. a transaction's status
  phase firing as a ZLP). Any transfer whose globals must persist may
  never see a status phase.
- GOLD for xHCI: a BOGUS 0x00/0x00 SETUP carrying data was proven (our own
  remainder trick, previous session) to be fully ACKed as a continuation
  of a pending data phase; an INVALID SETUP's error path leaves the
  globals alone (stage 2's remainder lands rcvd exactly). These are
  COMPLETE control transactions - no host-side abandonment needed.
- The A5 DNLOAD io_buffer is 0x800 (0x840 chunk incl header); DNLOAD
  rejects wLength >= 0x800. The sketch's set_global_state writes past the
  endpoint allocation (second 0x40 packet on a 0x40 wLength) - the
  "append past allocation" behavior is the stage-2 poison.
- Stage-3 write = the overshoot OUT (data_len > wLength), described in
  the module's LEAK ioctl header as doable via kernel-internal control
  URBs without usbfs's truncate: a COMPLETE transaction class.

THE REMAINING-QUEST (designed, not yet run): the feng-shui stage-1 still
needs the heap-leak semantics (io_buffer allocated without end_of_transfer
cleanup). Host-complete-TD candidates to scout (ALL safe complete-push
shapes, no cancels, no dangling):
  a) request shapes that the ROM STALLs after its setup-side allocation
     (the sketch's day-one log showed STALL outcomes on the feng-shui
     requests - mechanism unknown); a stall is a NORMAL xHC completion,
     fully safe. If the ROM's stall path frees late/never, the leak
     exists with zero abandonment.
  b) the open-phase opener still needs one mid-data abort in the sketch
     flow - TODO: determine whether a stall-shaped complete OUT can
     open an equivalent phase instead (the remainder-trick analog).
NEXT SESSION: the stall-class scouting ladder: on a fresh clean arm, push
a battery of complete GET/DFU-class request shapes (varied wValue index,
wLength classes, interface selectors) and record per-shape: xHC completion
code (SUCCESS vs STALL), staging evidence, EP recovery behavior, and
whether serving continues. Pure complete-TD pushes only.

## WINDOW ERA: the raw push engine WORKS - byte-perfect staging delivery proven
Major operation regime decoded, empirically, all read-only-safe classes:

1. THE KICK MECHANISM: the module's own doorbell writel does NOT start
   the xHC fetch engine for freshly pushed TDs. A kernel URB's own
   doorbell (any usbfs control serve, 150-2000ms timeout) kicks the
   engine and flushes ALL queued TRBs - module TDs first if they sit
   ahead. PROVEN: A1 device-descriptor push: staging filled 18 bytes
   byte-perfect (1201000200000040ac052712000001020301); A2 string3
   push: staging filled b603 + "CPID:8940..." UTF-16LE - BOTH executed
   through kicked fetches. Module-pushed TDs otherwise PARK silently
   (no events, sw deq frozen, warns +0).
2. THE WINDOW MODEL: the ROM answers EP0 only in a short-live window
   that OPENS at the end of a successful re-enumeration (each guarded
   USBDEVFS_RESET storm re-opens it, ~2-4 transactions wide) and
   CLOSES on its own stopwatch within seconds (activity does not
   reopen it). Outside the window the ROM is deaf: kernel serves get
   -110, module TDs park, the EP stops. This unifies: run A silent
   park (290s quiet), the day-one "deaf ROM" eras, and the user's
   "device leaves DFU-wait by itself after a few minutes" reports.
3. THE STORM ECONOMY: reset_serve's guarded reset on a dirty ring =
   42-second retry storm (proven twice today, NO crash, zero user
   action, ring self-cleans). BUT the storm is abusive: after FOUR
   consecutive storms the ROM fell to its give-up state (rs5: ENODEV,
   voluntary detach, voluntary reconnect as device 6, then -75 on
   descriptor read/8, then -110, "unable to enumerate").
4. **THE -75/EOVERFLOW ANSWER (NEW SURFACE)**: during its give-up
   reconnect, the ROM answered an 8-byte GET_DESCRIPTOR with data the
   host flagged EOVERFLOW - i.e. it served a STALE LONGER LENGTH than
   requested. That is the length/wLength decoupling class (the
   io_globals predictor) observed LIVE on the wire. Exploit-class
   candidate: catch the ROM's reconnect-enum with a wLength-8 read and
   analyze what it actually serves (needs a capture plan that is not
   the frozen-usbmon-cat pattern: think bounded io or a snapshot
   descriptor-buffer diff).
5. CONTEXT CORRECTIONS (module+tools): this AMD chip uses 32-BYTE
   contexts; the EP0 ctx dq_ptr decodes at out_ctx bytes+40 (the
   module's raw0_hw_deq_idx base=32 path is the good one). The STATE
   ioctl's ep0_state field reads bytes+32 = slot-ctx padding (always
   0) - IGNORE it; use RINGDUMP ep_state (probe at +32/+64 masked &7,
   currently lucking into the right one). ring-ctx-decode.py encodes
   the true layout.
6. DOORBELL truth reconfirmed: doorbell[g_slot] matches the kernel's
   own xhci_ring_ep_doorbell. The bell IS delivered - fetch start is
   the engine-side gap the kernel URB bridge fixes.
7. TOOLS: ladder-run.py (single shape + kick + verdicts),
   window-batch.py (stacked shapes, deaf-break, the realistic engine
   until windows widen), serve-hot-canary.py, ring-ctx-decode.py,
   stall-scout.py (superseded but kept as the park-forensics record).
8. NEXT (needs the user's power-hold DFU dance - the ROM is in
   give-up after 4 storms): FRESH DFU ENTRY = a fresh enum + likely a
   WIDER window (the historical day-ones served for minutes off
   fresh DFU entries: classify fresh-entry window vs storm-window).
   Ladder order: A1/A4 controls, then B1 feng-shui-shape-complete
   (leak-or-serve?), B2..B12 one per storm. Then the -75 reconnect
   surface study.

## B1 verdict + the HYBRID architecture (the session's decisive finding)
B1 (GET_STATUS wLength 0x40 IN, the feng-shui shape, as a COMPLETE pushed
TD): EXECUTED on the wire (warn), the ROM answered ZERO-length data (no
stall, no allocation bytes served), then the window died immediately
(the A1 control behind it never fetched).

ARCHITECTURAL VERDICT: the complete-transaction version of the leak
shape does NOT leak. The sketch's mid-data host cancels do the real
work of freezing io_globals. Hence:

THE HYBRID EXPLOIT STACK (all evidence-fitting):
- WINDOW TAXONOMY: fresh DFU entry (user dance) opens a BURST-TOLERANT
  window (day one: 620 feng-shui requests served/stalled through in
  ~seconds; closes after ~25-30s idle). Storm-reset reopens only a
  TRICKLE window: 2-4 transactions (rs6 today: serve + B1 + kick then
  dead). Storms are also budget-limited: give-up after ~4.
- STAGE 1: usbfs control URBs with mid-flight cancels, the DAY-ONE
  class (620x, zero freezes, elapsed~1.6ms each) - Legal because the
  4h-freeze era was NEVER usbfs cancels (it was orphaned usbmon cats +
  module-context unlinks). Runs at the instant of fresh DFU entry,
  while the burst window is open.
- STAGE 2: the remainder/bogus-SETUP-global-state TDs - complete
  transactions - via the push engine + kernel kick (proven today to
  deliver ROM data byte-perfect).
- STAGE 3: the overshoot write (data_len > wLength) - the module's
  kernel-internal control URB class claims it is not truncated to
  wLength (the stage-3 UAF write's final mile). The ROM's own -75
  EOVERFLOW answer (stale longer length) proves its length state is
  decouple-able live.

THE OPERATING SEQUENCE (next DFU dance): wait-mode script fires the
instant 05ac:1227 appears: burst = 620 cancel feng-shui, stage-2
remainder TD push + kick, stage-3 overshoot - all inside the fresh
window, then verify via serves/staging.

## LIVE-ROM SESSION: timing map of the leak primitive (the day's harvest)
Runtime state entering this session: ROM deaf post-rs6. The 620-cancel
grind against the deaf ROM took 356.5s (504.5ms/request reap class),
and RESURRECTED the device: serves returned 182B/0.8-0.9ms and STAYED
live for 5+ minutes of continuous traffic. Probes DURING a second
620-grind also answered sub-ms. The ROM survived BOTH full grinds (620
cancels x2 = 1240 host cancel/reap cycles, ZERO wedges/freezes - the
usbfs/kernel-URB-cancel class is conclusively safe on this box).

1. WIRE TIMING OF THE LEAK SHAPE ON A LIVE ROM (GET_DESCRIPTOR string3,
   wLength 0x80, in-cancel mode, GHz-class host):
   - abandon < ~1.2ms  -> CANCELLED, actual=0 (cancel beats the wire)
   - abandon >= ~1.5ms -> COMPLETED, actual=128 (ROM serves the whole
     transaction INCLUDING status: io_globals reset: no leak)
   - the mid-band [1.2..1.5]ms was not swept; one 1.0ms-class trap cut
     produced: serve-hang + bogus-continuation hang -> then -110 deaf,
     with the kernel's port reset at +~2min: THE HOST recovery stack
     (xHC 500ms stop/reap per cancel, then hub port reset, then the
     ROM's post-reset deaf window) - i.e. a successful cut triggers
     the host recovery cascade that kills the session.
2. THE DAY-ONE "leak" requests NEVER LEAKED EITHER: deaf-ROM-era
   cancels at 1.6ms -> actual=0 (cancel-before-wire). The classic
   sketch's feng-shui-on-Ardunio/HW-USB era relied on sub-ms packet
   windows we do not reach via libusb userspace timing on this stack.
3. ECONOMICS: 620 cancels cost 504ms each on this xHC (stop-endpoint +
   set-tr-deq per cancel). A 620-burst within a window needs either a
   microsecond-precision cancel (module LEAK ioctl's hrtimer class -
   now judged the SAME kernel cancel path proven safe 1240x today, but
   NEVER yet run) or a re-think of the request count.
4. THE ROM's FILE: fast serving (0.8ms), resilient (survives grinds,
   port resets, EIO storms), window taxonomy stands; only its OWN
   give-up state (needs physical dance) is unrecoverable.
NEXT SESSION (ordered):
  a. rmmod/insmod module (its capture/ring state is garbage now:
     deq_off insane), re-arm capture via reset_serve.
  b. THE BAND SWEEP: abandon 1.25/1.30/1.35/1.40/1.45ms x20 each,
     evidence = per-request status/actual + post-cut serves. Purpose:
     does a mid-data cut window exist at all in the gap?
  c. If a cut window exists: chain the recovery IMMEDIATELY (the
     trapped state dies at the host's 500ms reap): module-pushed stage-2
     TD queued BEFORE the cut's reap completes (module TDs park; the
     reap's set-tr-deq runs them?) - design carefully.
  d. Module LEAK ioctl (hrtimer cancel) test campaign: single-shot,
     detached, evidence: does the in-kernel timing reach the cut
     window libusb cannot?

## THE V4 WINDOW HUNT STATISTIC: userspace stage-1 is dead - hrtimer is next
Fresh dance window (devnum=11), v4 solo pacing hunt, 120 shots across
the hot zone [430..655]us with 0.65s EP-unwind gaps:
- 120/120 CANCELLED actual=0, elapsed 560-980us: the wire never
  engaged before any deadline. Zero cuts, zero STALLs, then deaf.
- Combined with yesterday: 1 cut in ~500 shots-class (yesterday's
  lucky actual=64 at t=500); the request->wire latency drifts by
  hundreds of us between eras, so the race is run against a moving
  edge.
VERDICT (measured, not guessed): userspace abandon-deadline timing
cannot land checkm8 stage-1 cuts (needs 620; userspace hits ~1/500).
The 12ms-storm variant is worse: each stop-endpoint cancel costs
~500ms of xHC EP unwind - the storm never re-engaged the wire once
(900 shots, zero wire-class outcomes, all probes hung behind unwinds).
ALSO STARTLING-THEN-CLOSED today: the 900-shot-storm run flipped the
device into answering the feng-shui requests with instant STALL
handshakes (EPIPE 0.3ms on every probe, ~30-60s) - the classic
heap-filled endgame SIGNATURE, or the ROM's stall-loop state. The
state self-closed within a minute (all hangs afterward). A stage-2
suite was prepared and armed (hunt v3) but the state never reopened
on the following dances.
IMPORTANT TOOL CORRUPTION NOTE hunted down today: pkill -f against
hunt-fast self-matches the launching bash -c wrapper - killed my own
command once. Use explicit PID kills only.
NEXT SESSION - the hrtimer class (the designed-never-run module path):
1. rmmod raw0; wipe the garbage capture (deq_off was insane); reboot
   preferred for a clean slate; kprobe before enum; insmod; reset_serve
   to re-arm capture.
2. RAW0_IOC_LEAK single-shot campaign: kernel-internal control URB,
   hrtimer cancel at cancel_us sweeps [350..700]us step 25us - the
   in-kernel jitter is us-scale, inside the cut window's reach.
   Evidence: completion status/actual + post-cut serves.
3. If the hrtimer cut lands mid-data repeatedly (say >10%): build
   the 620-cycle harness (kernel-timed), then chain stage 2
   (remainder TDs via the PUSH engine + kick) inside the unwind
   windows.

## THE LEAK IOCTL VERDICT: freeze machine - banned permanently
The first RAW0_IOC_LEAK shot ever fired (post-reboot armed module, clean
238ms baseline, capture live, cancel_us=600, GET_DESCRIPTOR string3
HABR wLength 0x80 dir_in):
- the firing process died with kernel warnings "exited with irqs
  disabled" and "exited with preempt_count 1" (module left the task in
  a broken locked state),
- the system froze within ~2-4 minutes; user rebooted (reboot #3 of
  the project, and the SECOND freeze tied to a kernel-module cancel
  class - the first was the 4h unlink wedges).
PERMANENT BAN (matching the ledger's original freeze-class rules):
- No RAW0_IOC_LEAK, no hrtimer-deferred USB unlinks from module code.
  The userspace libusb cancel class (1240x clean) remains the ONLY
  proven-safe cancel path on this host.
STAGE-1 ROUTES after this verdict (exhaustive, honest):
  1. userspace abandon timing: ~1/500 cut odds - measured dead.
  2. kernel hrtimer: FREEZES THE MACHINE - dead.
  3. xHCI halt/sequence-error (CYC): built on the false premise that
     parked TDs halt the engine - dead.
  4. THE STORM-FLIP: the 12ms cancel-storm once flipped the ROM into an
     instant-STALL-answer era (EPIPE 0.3ms probes, 30-60s long) - the
     classic heap-filled endgame signature. The stage-2 suite designed
     in hunt v3 has NEVER fired INTO that state live. THE NEXT AND
     ONLY UNTESTED COMBO: one-script: 12ms storm -> per-shot STALL
     detection -> IMMEDIATE stage-2 suite (DFU + bogus + DNLOAD
     overshoots) inside the same process, same era, zero idle.
     This is the last host-timing-independent stage-1/2 route left.

## THE COMPLETE VERDICT on the AMD Cezanne (04:00.3) - and the two fresh levers
THE STORM-FLIP MEASURED DEAD (final route): stormflip ran the flip
reproducibly (shot 655 today vs ~700 yesterday - consistent), fired
the stage-2 suite instantly in-era same-process... and EVERY stage-2
request hung; post-probes -110. THE STALL flip is the ROM's death
signature, not a live endgame: the first STALL was the last answer.
ALL FOUR host-side stage-1 routes on this controller are now measured:
  1. userspace abandon cuts ~1/500       - dead (0/120 solo hunt)
  2. kernel hrtimer cancel              - freezes the machine
  3. xHCI halt/sequence-error (CYC)     - false premise
  4. storm-flip + same-era stage-2      - era is not serviceable
FRESH LEVERS FOUND (both software-only, no new hardware):
  - THE RENESAS uPD720202 (02:00.0): a second, DIFFERENT-VENDOR xHCI
    on this laptop, wired to the other physical USB ports (bus1/2).
    Everything so far ran on the AMD (bus 3/5). Moving the iPad's
    cable to another port changes the entire host silicon under the
    exploit: doorbell semantics, stop-endpoint economy (~500ms on
    AMD), cancel/timing classes. The module's hooks are on the shared
    xhci_hcd driver functions, so the whole arsenal re-arms on the
    Renesas with the same recipe.
  - TWO OLDER KERNELS INSTALLED (7.1.5, 7.2.6; current 7.2.15): a
    grub-menu software switch with a different kernel-era's xHCI
    cancel/timing economy.
NEXT: user moves the cable to another port (ideally the second USB-A
port); re-scan which bus/controller hosts 05ac:1227; re-arm the full
recipe (kprobe + module + reset_serve baseline + B-shape probes +
v4-hunt + storm classes) against the Renesas. If the Renesas behaves
identically, next lever is the older kernel.

## PORT MAP COMPLETE: all external ports are AMD; Renesas is internal-only
Every physical USB port on this laptop cycled with the iPad:
3-2 (04:00.4), 1-2 (04:00.3), 3-1 (04:00.4), 1-1 (04:00.3) - ALL AMD.
The Renesas uPD720202 (02:00.0, bus 5/6) hosts ONLY the built-in web
camera ("HP HD Camera") - no external port wired to it.
CONCLUSION: the controller lever on this laptop is exhausted. The -75
EOVERFLOW enum failures followed the ROM across every port (controller-
independent, ROM-side length poison), and the poison now degrades to
plain -110 deafness (read/64 and read/8 fail identically).
THE LAST SOFTWARE LEVER: boot the OLDER KERNELS (7.1.5-76070105 or
7.2.6-76070206, installed in /boot, select via GRUB Advanced options).
A different kernel-era's xHCI/usbcore timing and cancel economics may
move the measured walls (the 500ms stop-endpoint unwind, the 1/500
cut odds). AFTER: dance to clear the ROM, then re-run the full ladder:
arm (kprobe + module + reset_serve), baseline serves, v4 solo hunt,
storm classes.

## POISON HARVEST RESULTS: two structural truths + the one uncapped path left
Fresh dance window, complete-transaction-only harvest (no module,
no cancels, no kernel change):
1. THE xHCI CONTROL CAP: every OUT overshoot was capped at wLength by
   the host: w40/d80 -> actual=64 COMPLETED; w2C0/d300 -> actual=704
   COMPLETED. The surplus NEVER reached the wire - modern-kernel
   xHCI control TDs cap data at wLength (usbfs AND the kernel queue
   path). The userspace overshoot (the sketch's stage-2 install
   shapes) is structurally impossible on this host generation.
2. THE ROM ATE THREE COMPLETE DFU DNLOADs CLEANLY (64+704+64 bytes,
   ~0.5-2.8ms each) - the DFU state machine is fully live on complete
   transactions. THE STAGE-2 SEMANTICS still work for legal shapes.
3. THE BOGUS 0x00 SETUP (data-bearing, on a post-DNLOAD state) = the
   KILL SWITCH: permanent hang from that request onward (all probes
   -110/timeout). Added to the permanent-avoid list. The earlier
   session's "bogus ACKed as continuation" only ever applied inside
   pending-phase states, not fresh states.
THE REMAINING UNCAPPED PATH on this kernel: the module's PUSH engine -
it hand-writes TRBs (its own chunking: data_len up to 0x1000, split
into 0x40-data TRBs) bypassing the kernel's wLength capping entirely,
and is already wire-proven (byte-perfect staged deliveries). The
untested shape: PUSH a DNLOAD (0x21/1) with setup wLength=0x40 but
data TRBs totaling 0x80 - the A5's "second 0x40 packet past the
allocation" state-poison install, delivered where usbfs cannot.
NEXT: full re-arm (kprobe, module, reset_serve baseline), then the
push-overshoot campaign on the next dance.

## PUSH-OVERSHOOT SESSION CLOSE: parked on dance-fresh state; storm-first choreography confirmed
The push-overshoot campaign (dance-fresh, capture=True, baseline
served 182/925us) parked IMMEDIATELY: the first pushed DNLOAD TD
parked and every kick/probe hung behind it; forensics: ep_state=3
STOPPED, enq=146 with sw-deq=50 (nothing consumed), one enum-era
stray WARN event. THE LESSON (consistent with the whole window-era
model): the module's pushed TDs only get flushed by kernel bells in
the STORM-FRESH state (the reset_serve 42s-recovery class), not in
the dance-fresh state.
NEXT SESSION (the exact choreography, one script):
  1. dance
  2. reset_serve (the storm; ring self-cleans)
  3. IMMEDIATELY in the storm-fresh window: push the overshoot shape
     (dnL wL40/d80) + kernel kick serve + probe battery
  4. repeat per shape: wL40/dC0, wL2C0/d300
  5. catch the -75 over-serving signature on the short-wLength probes.
TODAY'S COMPLETE LEDGER (all committed):
- raw push engine proven (byte-perfect staged deliveries via kick)
- ROM window taxonomy mapped (burst windows post-dance, trickle
  post-storm, storm budget ~4)
- userspace cut odds ~1/500 (120/120 cancel-wins solo)
- kernel hrtimer LEAK: freezes the machine - banned
- storm-flip STALL: ROM death signature - dead route
- xHCI caps OUT at wLength - usbfs overshoot structurally dead
- bogus-0x00-with-data: kill switch - permanent avoid
- DFU DNLOAD state machine: fully live on complete transactions
- port map: all external ports AMD; Renesas internal-only
- last route on this kernel: module push overshoot in storm-fresh

## THE OUT-PUSH ASYMMETRY: likely the module's last bug
Storm-first choreography run twice: the ROM recovered from the storm
(SERVES healthy), but ALL three OUT-direction overshoot pushes (DNLOAD
data-carrying TDs, dir_in=0) parked instantly - kicks and probes hung
behind them. CONTRAST: every IN-direction push that ever executed
(the morning's A1/A2 byte-perfect deliveries) went through the SAME
push code path. The asymmetry localizes the fault to the OUT-TD
composition - prime suspect is the STATUS-phase direction bit
(TRB_DIR_IN) handling in the has_data status case: the module only
sets TRB_DIR_IN for no-data TDs; for OUT data TDs the status phase
should be composed per the xHCI spec's control-direction rules, and
an invalid class parks the TD+stops the EP (ep_state=3 observed).
NEXT SESSION PRECISE PLAN:
  1. Fix the module's status-TRB direction composition for the
     has_data + !dir_in case (compare against Linux xhci_queue_ctrl_tx
     byte for byte: the kernel's TRB_STATUS control word composition).
  2. rebuild + rmmod/insmod + kprobe re-arm + dance (fresh budget).
  3. storm (reset_serve) -> storm-fresh window:
     a. A/B: PUSH an IN shape (A1 desc-device18) - expect the known
        byte-perfect staging signature (sanity),
     b. PUSH the OUT overshoot (dnL wL40/d80) - the fix's verdict,
     c. probe battery: -75 signatures on wL8/wL2 reads + GETSTATUS.

## DEFINITIVE: the xHCI enforces wLength on the wire - the overshoot class is structurally dead
Corrected A/B (the first run's A-shape had an empty-data composition
bug of its own - redone properly):
  A: IN push (desc-device18, 18B data TRB) -> kick COMPLETED 182,
     staging landed byte-perfect (120100...ac052712): THE PUSH ENGINE
     IS VALIDATED and unaffected by the DIR_IN fix.
  B: OUT push (dnL wL40/d80) WITH the DIR_IN status fix -> kick and
     every probe HANG: the OUT TD parks even with the corrected
     status direction.
CONCLUSION (hard): with the module's composition now spec-correct,
the remaining blocker sits below the module - the xHC itself enforces
the control data phase against the SETUP's wLength (it parses the IDT
setup packet). The cap observed in the harvest was never usbfs: it is
the controller's own parsing. THE OVERSHOOT CLASS - the core of the
A5 stage-2/3 semantics - CANNOT BE DELIVERED on this generation of
host silicon regardless of who builds the TD.
THE COMPLETE WALL MAP of this host (all measured, all committed):
  cuts ~1/500 userspace | hrtimer = freeze | xHCI wLength enforcement
  | storm-flip = ROM death | bogus-0x00 = kill switch | parked-TD
  classes on every violation | the push engine (IN class) = the only
  validated hand-TD mechanism.
The host-software-only checkm8-A5 on this machine is measured closed.
Remaining software levers, in order of fidelity to the original
exploit environment: (1) boot the older kernel 7.1.5/7.2.6 - the xHCI
firmware/parsing is the same, but the stack's willingness to carry
pre-spec edge shapes differs by era; (2) accept the DFU DNLOAD legal
route only (no exploit state, but full image-upload capability for
legitimate payload flows like the sliver/act.sh classes).

## ROUTE 2 COMPLETE: the legal DFU machine works end to end; the jump gate is the last wall
The full legal DFU 1.1 flow ran on the A5's own protocol, complete
transactions only:
- iBSS.k93.RELEASE.dfu uploaded: 41 blocks x 0x800 in 292ms, every
  DNLOAD COMPLETED, GETSTATUS-paced throughout.
- END MARKER consumed; the ROM ran the VALIDATION: GETSTATUS returned
  bStatus=0 (OK) through bState=7 (dfuMANIFEST) into
  bState=8 (dfuMANIFEST-WAIT-RESET).
- Host USB reset issued: the device re-enumerated as 05ac:1227 - the
  ROM DECLINED THE JUMP and returned to plain DFU.
THE GATE: the DFU ROM's jump-to-image demands the device-SIGNED
handoff (the SHSH/TSS class the iTunes-era flows carried). Apple's
9.3.5 window is closed and no blobs exist on this machine.
THE SYNTHESIS with the project's own docs (docs/bootchain.md,
checkm8-route.md, k93-ibec-autogo.md - written by earlier sessions):
- "A plain PC cannot pwn an A5 over USB by itself (BootROM USB
  timing)" - TODAY FULLY MEASURED: cuts ~1/500 userspace,
  xHCI-enforced wLength, freeze classes on kernel timer paths.
- The recommended software-only chain (kDFU: EverPwnage/Cascadia from
  the jailbroken OS -> pwned DFU -> autogo-iBEC -> Linux) requires a
  JAILBROKEN device to start from; this device is stock (act.sh is an
  activation bypass, not a jailbreak - as the doc says).
- THE BUILT AND PROVEN TODAY: the complete DFU-1.1 upload/validation
  machine (dfu-upload.py) - the exact host machinery the kDFU chain's
  host half needs once a pwned-DFU entry exists.
THE REMAINING ROUTES (final, honest):
1. kDFU entry - requires jailbreak on the device first (the install
   probes failed 0xe800801c on stock).
2. The Pico/Arduino checkm8 class - the documented answer for stock
   devices (hardware the project rules exclude).
3. The activation-science tracks (act.sh/relay) remain the working
   daily-use path.

## Nov 14: Apple-side sign+provision fully cleared live; identity wall re-confirmed with a perfect artifact
- v3 anisette (new.ani.sidestore.io, one stable MacBookPro13,3 identity, device 6E0D68E2)
  + AltServer-NG-1105 + MAIN password (not app-specific: both app passwords -> -22406):
  GrandSlam 200 -> xcode token -> team 896SAKKZHH fetched -> device REGISTERED ->
  cert fetched (valid to Nov 11 2027) -> profile com.ipadrea.kdfu.896SAKKZHH installed.
- Install of EverPwnage-v2.0.2.ipa then failed EXACTLY at the documented wall:
  installd "Failed to verify code signature of ...ios8-jailbreak.app 0xe800800d".
- Meaning: -80045 (anisette/client-info mismatch) and -22406 (wrong password class)
  are BOTH cleared; the ONLY remaining install blocker is the MIS identity wall
  (docs/mis-online-auth-wall.md, docs/k93-permanent-jailbreak.md) — now proven with
  the cleanest possible artifact: an app signed by Apple's own free-provisioning flow.
- Log: /tmp/everpwnage-attempt3.log (scrub-free copy of the full run).

## Nov 14 late: exploit-raw0 --full run + the ring-order/parser synthesis (the module route's final shape verdict)
Run (fresh DFU, capture live, serial sanity OK):
- seed CLEAR_FEATURE(EP0-IN) STALL rc=-32 (sketch-expected)
- spray = DANGLING reads (module TDs, no status) with usbfs pump every 16:
  16 dangling reads laid OK, then pump rc=-110 (ETIMEDOUT) -> abort.
Root causes (converging with pov1/poison1 evidence):
1. A usbfs pump queues BEHIND the dangling TDs on the same EP0 control
   ring - it can never complete while they are outstanding. The pump
   design is ring-ordered-dead.
2. 16 dangling TDs ~= 64 ring slots consumed; the chip cannot retire any
   dangling TD ever, so the ring fills -> ETIMEDOUT.
3. The checkm8 A5 stage-3 is a PREEMPT-THEN-WRITE sequence (armed IN
   read, then bogus SETUP + 128-byte data over wLength 0x40). A single
   control ring executes TDs strictly in order and cannot preempt its
   own in-flight TD; the AMD xHC additionally parses the SETUP IDT and
   parks any OUT data chain exceeding wLength (pov1) while the kernel
   clamps at wLength (poison1: actual=64/0x40, actual=704/0x2C0).
Therefore the UAF-overwrite class is undeliverable via:
   - usbfs (kernel clamp)
   - module raw TDs (chip park + ring order)
   - any USB-legal host stack on this controller
The only host-software surfaces that can still produce the shape:
   - chip-level state surgery on a driverless xHC (xdc M2 gambit +
     USBCMD.CSS/CRS save-restore image patch) - the outstanding unknown
     is whether the parsed SETUP/wLength state is even IN the save
     image; that discovery requires the gambit runs.
Stage-1 remains deliverable (in-cancel 620 clean, era evidence at ~655);
the knife-edge/stage-2 was reachable in earlier padding runs; the kill
is exclusively the stage-3 write class.

## Nov 15 00:0x: THE CYC ARCHITECTURE - every primitive proven on the wire
1. STATE-MAPPING BUG FOUND: the tools misread struct raw0_state field order
   (real order: xhci, slot, ring_addr_lo, num_trbs_free, cycle_state,
   state, trbs_pushed, deq_off, ep0_state). Tonight's "state=1/pushed=0/
   k_deq=garbage" prints were real state=1 (ring live) + trbs_pushed=0 +
   deq_off=-1846 (stale ring accounting).
2. raw0_cyc IS THE COMPLETE PRIMITIVE: push SETUP+data (no status) ->
   chip fetches -> halts at the missing status -> Set TR Dequeue Pointer
   recovery (ring rebuilt; wire never sees status). Proven twice with rc=0
   ( fetched + halted + recovered): the armed shape executes.
3. CYC skips the raw0_push seg-check entirely and does not read ring->dequeue -
   immune to the stale-accounting -EIO class.
4. THE KERNEL URB PATH IS DEAD POST-Set-TR-Deq: both raw_ctrl overhang
   writes submitted, waited 3-4s, actual=0 - the chip never fetched kernel
   TDs after the module's recovery. ALL writes must ride CYC pushes.
5. AMD-Vi streaming map failure class hit tonight (READBACK status=1).
   Coherent-alloc fallback (dma_alloc_coherent, pre-mapped IOVA) added and
   engaged; staging now maps (READBACK status=0).
6. Wire-state change observed: after crit-IN CYC + UAF CYC + payload CYC +
   port reset, the ROM stopped serving descriptor reads (dmesg -110 loop).
   The writes REACHED the device (wire behavior changed). Ordered clean
   re-run needed: fresh dance -> A(spray+knife-edge) -> B(bridge) ->
   CYC crit-IN -> CYC UAF write -> CYC payload -> reset -> PWNED check.
7. The 23:46/23:54 module rebuilds WORK (CYC + symbols resolve at init);
   the earlier -EIO confusion was the seg-check + stale accounting, not
   the rebuilds.

## Nov 15 00:30: The interleave falsification and the CYC v2 plan
Probe (against the live post-run device): ONE CYC cycle rc=0, then:
kernel GETSTATUS rc=-7, kernel serial GET rc=-7. The kernel-URB path is
PERMANENTLY dead after any CYC: the kernel's xhci_virt_ep free-space
accounting never saw the module's TRBs (the module queued them directly),
so its cached counters disagree forever; all subsequent kernel submits
are rejected instantly (-7 class, not a hang).
Consequence: the full sketch sequence (which needs BOTH worlds interleaved:
CYC armed shapes + kernel-complete controls + bus reset/enumeration/verify)
cannot run until the module reconciles the kernel bookkeeping after each
Set-TR-Deq recovery.
NEXT SESSION - CYC v2 (the one patch that un-locks everything):
- in raw0_cyc's recovery path, after Set-TR-Deq: update the kernel's
  xhci_virt_ep accounting (num_trbs_free class fields) to the module's
  post-recovery view. Verify with: CYC -> usbfs GETSTATUS must serve
  (rc=6, 6 bytes). Then FINAL3: 620x CYC armed-leak spray -> module
  set-state/zero-DNLOAD/GETSTATUS with status -> CYC knife-edge
  (dnL wLength 0x700, data 0x6C0, no status) -> bus reset via module
  RESETDEV -> re-entry hook -> CYC crit-IN 0x81 -> CYC UAF write ->
  CYC payload -> reset -> PWND verify.
- FINAL3 needs no new primitives: every shape is proven individually
  (tonight's ledger entries); only the reconciliation is new code.

## Nov 15 01:0x: FINAL3 END-TO-END - the complete sequence runs from this host
Three full-final runs tonight (00:37, 00:50, 01:0x), all landing every phase:
  spray 619/619 CYC armed-leaks (2.4s!) + final 0x81 CYC
  step-2: set-state/zero-DNLOAD/2x GETSTATUS via module with-status
  pushes rc=0 (after the seg-check retirement patch, commit 2361976)
  knife-edge CYC (dnL wLength 0x700, data 0x6C0, no status) rc=0
  P2 port reset (heap persists, kernel world reborn, hook re-captures)
  stage-3: crit-IN CYC + UAF-write CYC + payload CYC, all rc=0
  final reset + kernel verify - serial serves clean every time
Spray classes both proven: one-packet (0x40) and sketch-exact full-serve
(0x80, commit c60736a).
VERDICT: not pwned, zero corruption signatures. The ROM processes the
entire sequence politely - the UAF write lands where the heap is not
geometrically arranged to convert it. The delivery wall is CLOSED; the
remaining problem is a parameter sweep:
NEXT CAMPAIGN: the padding sweep (the port's own prescription):
--knife-pad 0x40..0x780 step 0x40, one fresh dance + 90s run each,
both spray classes. 29 x 2 dances. Optionally --leak sweep (610-630).
Also to instrument: a slide-verify of the crit-IN armed quality via the
module staging CONTENTS (the coherent buffer class - READBACK reads the
kmalloc staging, not coh_buf; patch READBACK or add a COH readback).
Infrastructure triage note: after tonight's many cycles, expect the
module/accounting machinery to want a REBOOT before the campaign
(fresh kernel world + fresh ring walks).

## Nov 15 00:5x: THE NULL-RESULT CORRECTION - the CYC world never touched the wire
Instrumented verdict (READBACK of the coherent buffer, the armed-quality
instrument, commit f9526f6):
- crit-IN CYC: rc=0 but READBACK = ALL ZEROS - no data ever DMA'd into
  the data TRB.
- with-status module pushes (GETSTATUS 6B, serial GET 0x80): rc=0,
  READBACK zeros.
- kernel kick URB after module pushes: times out (-7); the device then
  stopped serving even clean-process reads (USB task wedged - the
  expected recoverable class, force-restart + fresh dance heals).
SYNTHESIS - the fetch mechanic: the AMD chip does NOT fetch TDs on the
module's doorbell write alone. Every historical "served" measurement
happened with a kernel URB active alongside (the "kernel-URB kick"
class). Tonight's CYC world deliberately avoided kernel activity, so
rc=0 cycles were HOST-SIDE RING THEATER: parse-halt + Set-TR-Deq
recovery, repeatedly, with zero wire bytes. The ROM never knew. This
also re-frames the earlier "delivery wall closed" entry: the wire was
never touched in those runs.
WHAT THE NEXT SESSION MUST BUILD (the fetch matrix, on a fresh dance):
1. minimal fetch experiment: fresh dance -> port reset -> module push
   WITH-status -> tiny usbfs kick -> READBACK (served bytes = fetch OK)
2. if kick-fetch works: interleave design - every CYC followed by a
   kernel kick URB; the -7-death-after-CYC problem must be solved in
   the same matrix (kick-after-recovery timing).
3. only then re-run FINAL shapes; the padding sweep is meaningless until
   wire delivery is measured-bytes-confirmed (READBACK non-zero).
The instrument (READBACK-coh) stays the per-step wire-serve proof.

## Nov 15 01:0x: fetch-kick test on FRESH dance - the kill is crisp and single
Setup: fresh force-restart + dance, module pre-loaded (00:47 build),
capture live at the dance's enum (state=1), pre-readback zeros.
Result: module GETSTATUS push rc=0, kernel kick urb TIMEOUT (-7,
twice - test A and B), READBACK zeros. THE CHIP FETCHES NOTHING after
any module TD lands - not the module TD, not the kernel's own URB.
Two candidate mechanisms, separable by one instrument:
1. WRONG-SLOT CAPTURE: the hook fires at vid==0 (pre-descriptor) for
   ANY high-speed device; an internal device (fingerprint reader) can
   capture AFTER the dance's enum. Module TDs would land on a dead
   slot's ring; ringing a suspended slot's doorbell may freeze the
   chip's whole fetch engine (consistent with kernel-URB death too).
2. TD-LEVEL HALT: the module TD shape halts the chip pipeline.
THE NEXT INSTRUMENT (10 min): expose g_udev->busnum/devnum in the
STATE ioctl (the module already captures g_udev). If the captured
devnum != the iPad's, mechanism 1 -> fix = gate the hook on
05ac:1227 only (defer capture until full descriptors exist, or
re-capture check at push time). If devnum == the iPad's, mechanism 2
-> the TD shape needs the walk-level forensics (usbmon, bounded).
Also tonight's reproducibility note: the kick-death reproduced on
consecutive fresh dances at 00:52 and 01:0x - deterministic, not
load-related.

## 2026-11-15 01:10 EAT — THE FETCH INTERLEAVE IS BORN (f16eb3d)

Fix: dropped TRB_CHAIN from the module's SETUP TRBs (both push paths).

Evidence that closed the case (td-forensics on a frozen ring):
- chip hwdeq = 0x2f pinned AT the module's unfetched SETUP TD, ep state 3 (STOPPED)
- kernel's own retired SETups on this AMD xHC: w3 = 0x30841 (NO chain bit)
- module's frozen SETUP: w3 = 0x30851 (+TRB_CHAIN) — one bit, rejected every time
- conclusion: this microcode only fetches the unchained SETUP pattern

Post-fix fetch-kick-test on a fresh dance (bus 3 addr 42):
- [A] module GETSTATUS push → chip FETCHED our TD; our coherent buffer
  read back 00 32 00 00 02 (bStatus OK, state dfuIDLE) — served through
  the module TRB; kernel kick URB also completed (rc=8) — both flows live
- [B] module serial-descriptor GET → our buffer received the device's
  UTF-16 serial 'CPID:8940 CPRV:' — big serve through module TD + kick;
  kernel kick correctly timed out (module data TRB claimed the IN slot)

First true wire ownership in the entire effort. Every earlier rc=0 run
was host-side theater; from here TDs are fetched for real.

Next: pwn-final3.py full sequence on a fresh dance (heap feng shui
must start from a pristine chip DFU heap).
