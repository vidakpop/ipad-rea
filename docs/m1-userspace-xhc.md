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
