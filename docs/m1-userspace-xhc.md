# M1: userspace xHCI driver on the AMD FCH xDC (04:00.4) — REAL, with a frozen-core caveat

## What works (verified tonight, Nov ~12 03:00)
- **kernel/xdcdrv module**: driverless-PCI 04:00.4 + `ioremap` MMIO regs + 512K `dma_alloc_coherent`
  pool at 0xcc780000 (kernel-managed DMA domain — the ONLY DMA path that ever worked; the
  vfio/iommufd route was abandoned — the chip's fetches through those IOAS mappings never happened).
- **tools/xdc.py**: python xHCI driver: register r/w, pool mem r/w (chunked), HCRST/halt/run,
  interrupter programming, scratchpad array, ring building, event-ring retire + poll.
- **The chip EXECUTES our TRBs**: command-completion events with real params
  (`param=0xcc780000+0x10...`), real completion codes: cc=5 (TRB error), cc=9 (No Slot Available),
  cc=11, port-status-change floods (type 34, param=0x2000000 = port 2 = the iPad).
- **Event ring pipeline fully live**: chip writes events INTO OUR event-ring page obediently.
- **Port machinery live from userspace**: PORTSC port-reset on the iPad's port worked (PRC dance).

## The frozen core (the current M2 blocker)
The chip has internal state HCRST/D3hot/FLR/CRCR-DCBAAP-CONFIG-writes **cannot alter**:
- Its internal command-ring pointer is pinned at pool+0 (0xcc780000): every doorbell walks whatever
  TRBs we lay there (we ride it: real commands DO execute and complete).
- Its "slots available" is stuck at none: ENABLE_SLOT returns cc=9 regardless of CONFIG writes at
  op+0x20/0x24/0x28/0x2C (the op-window registers CONFIG/CRCR/DCBAAP read-as-lies on this chip —
  reads return stale/0 values even for the kernel; writes may land in a shadow the core ignores).
-	cc codes observed on safe-spin NOPs after ENABLE_SLOT: cc=11 (Slot Not Enabled) — the chip's
  internal slot-bitmap/MaxSlotsEn relic from the kernel era persists.

## Key insights / gotchas (hard-won)
- The iPad is on **04:00.4 port 2** (bus 3), NOT 04:00.3 (which hosts fingerprint-internal stuff).
  lsusb -t with .3 vfio-bound proves it: only .4's buses exist.
- MMIO "RAZ/WI" drama tonight was mostly a **python reader bug**: the module's MEM_READ smeared
  the header into data — every "read" lost its first 8 bytes. Fixed via offsetof copy_to_user.
- The NOP "consumed" verdicts earlier tonight were false positives of that reader bug.
- scratch=64 → SP array of 64 pool pages required BEFORE the chip will do anything (512K pool needed).
- Doorbell works w/ or w/o MSI armed; IMAN.IP gets set by the chip (legacy-ish pending).

## Next moves (ordered)
0. **THE remove+rescan gambit (NEW, top priority)**: `echo 1 > .../0000:04:00.4/remove; echo 1 > .../rescan`
   refreshed the function at PCI level and the kernel's probe then initialized it INSTANTLY.
   Conjecture: each PCI enumeration opens a fresh "init window"; the kernel driver has been
   consuming it every time. NEXT SESSION: keep 04:00.4 DRIVERLESS right after remove+rescan
   (no xhci_hcd bind!), load xdcdrv, bring up rings — our CRCR/DCBAAP/CONFIG writes may be
   accepted cleanly for the first time. (System restored to normal at session end: both
   controllers on xhci_hcd, iPad visible in DFU on bus 3.)
1. **xHCI Save/Restore state attack**: USBCMD.CSS (bit 8) saves the ENTIRE internal state into
   the scratchpad buffers (well-defined format!) → READ the save image from our SP pages →
   DISCOVER the frozen internals (cmd-ring ptr, slot bitmap, MaxSlotsEn) → patch → USBCMD.CRS
   to restore. This is the surgical tool for the frozen core.
2. FCH XHCI_PM ACPIMMIO block at **0xFED81C00** via a module ioremap — the AMD side-door where
   the real init/reset/lock knobs live (coreboot acpimmio_map.h). Check for an MMIO-filter/lock bit.
3. If neither works: ACPI S3 cycle (the only true xDC power reset) then re-run M1 bring-up quickly.
4. When ENABLE_SLOT finally succeeds → port-reset port 2 → ADDRESS_DEVICE (input contexts!) →
   EP0 control TDs → port the checkm8-a5 sequence (arduino sketch = wire spec) onto xHCI TDs —
   the overhang is NATIVE in xHCI (SETUP TRB wLen=0x40 + TWO OUT TRBs — the xHC never checks
   wLength; it DMAs exactly the TD chain — the kernel's usbfs was the only thing that blocked it).

---
## Session addendum (Nov 12, ~05:30) — checkm8-over-kernel runs + frozen core survives PCI rescan

### checkm8 host-port status (through the NORMAL kernel stack — no module needed!)
- **sketch mode**: stage 0 ✓; feng-shui runs (in-cancel = stall-after-3 pattern; setup-only = clean
  620 CANCELLED); stage 2 lands **EXACTLY** `rcvd=0x6C0 of length=0x700` (0x100 on wire + 0x5C0
  remainder) — the Arduino-identical heap-poised state; stage 3: crit-IN + overwrite OUT times
  out (device stops ACKing at the overwrite).
- **native mode (`--mode native --skip-req-stall`)**: phase 1 = **620/620 sync leaks COMPLETED,
  0 rejected** (only on a real fresh cable attach — a software re-enumeration is NOT equivalent:
  leaks hang "leak 0 timed out"); phase 2 async-0x800-DNLOAD-cancel ✓ + DFU_ABORT ✓;
  phase 3 req_leak ✓ COMPLETED (0x80→128B); overwrite = TIMEOUT.
- The missing axi0mX **"advance buffer offset"** transfer was discovered missing in the port
  (original: `libusb1_no_error_ctrl_transfer(device, 0, 0, 0, 0, 'A'*overwrite_offset, 10)`
  between the DNLOAD-cancel and the DFU_ABORT) — RESTORED in our port (commit b47e64f+), but on
  this 838.3 it times out too. Reference: build/src/matthewpierson-ipwndfu/checkm8.py lines ~517-545.
- **838.3 quirk confirmed twice**: after a `req_stall` (0x02/3/0/0x80), ep0 hangs forever
  (leak requests time out; needs physical replug). Hence --skip-req-stall is MANDATORY on 838.3.
- Temporary state notes: plain string GET (0x80/6/0x0303/0x040A, wLen 0x80) completes in ~900µs
  with 128B; DFU GETSTATUS healthy dfuIDLE. No_leak (wLen 0x81) completes 129B ~900-917µs —
  the "receive data then abandon" window is therefore sub-100µs on a complete-transfer host:
  the crit-IN cancel deadline must be tuned (~850µs? between last-packet and status-ZLP) —
  the sketch (MAX3421) stops issuing IN tokens after exactly one 0x40 packet; a kernel stack
  cannot do that, and my patched cancel_at=0x40 completions trip the ZLP guard.

### Frozen core — STILL frozen
After tonight's PCI remove+rescan cycles (fresh kernel init of the chip through 1000s of
transfers!) the module path STILL shows: chip walks pool+0 (its eternal internal ring ptr)
with cc=5, ignores CRCR/DCBAAP/CONFIG writes; ENABLE_SLOT never gets cc=1. The xDC's internal
state machine does NOT reset on PCI function-level re-enumeration. Only ACPI S3 (or full power
off) remains as the true reset for the module path.

### Ranked next moves for the pwn session
1. **Crit-IN cancel-deadline sweep** on sketch mode (`abandon_timeout_ms` around 700-1000µs in
   ~25µs steps — the measured wire RTT of a complete 0x81 descriptor GET is ~900µs; the window
   between last data packet and status-ZLP is sub-100µs) — a handful of DFU re-entries.
2. **`--padding` sweep on sketch mode** (0x40..0x780 step 0x40) — the port's own prescribed
   fallback; stage 2 is already exact; each attempt needs a fresh DFU entry.
3. **ACPI S3** (or battery-out power cycle) → immediately `rmmod`/driverless .4 + `xdcdrv`
   → test ENABLE_SLOT for the frozen-core clear → if cc=1: the module gives TRUE packet-level
   host (sketch-exact wire behavior incl. receive-then-stop).
4. Long-shot: patch xhci_hcd's control-transfer TD builder is unnecessary — the kernel ACCEPTS
   overhang SETups via USBDEVFS_SUBMITURB raw (verified: wLen=0x40 + 0x80 data flows, device
   ACKs) — the blocker is stage-3 handshake semantics, not emission.
