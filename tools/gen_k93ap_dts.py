#!/usr/bin/env python3
"""
Phase 2 (ipad-rea port): map the parsed Apple ADT onto Linux device-tree
bindings for the iPad 2 (iPad2,1 / K93AP / S5L8942, Apple A5 rev A).

ADAPTED FROM iBSSloader's scripts/gen_p105ap_dts.py (iPad mini 1, P105AP) --
https://github.com/teutekeune/iBSSloader -- (GPL-2.0). The upstream generator
is fully ADT-driven; this port changes the board constants, the template
header, and adds glue the upstream template lacks (gpio-keys generated from
the ADT /device-tree/buttons node, a pmu-timer node, g_cdc bootargs).

Reads the k93ap ADT JSON (from parse_apple_dt.py) and emits dts/ipad2-k93ap.dts.
Every register address and interrupt number is looked up from the ADT at
generation time. Values not in the static ADT (framebuffer base, initrd
extents, DRAM size) are clearly-marked placeholders/TODOs.

Run with --report to print the extracted hardware facts instead of a DTS.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

# --------------------------------------------------------------------------
# Values that are NOT derivable from the static ADT.
#
# The firmware copy of the device tree has these zeroed; iBoot fills them in
# at runtime from the live memory map.  We emit conservative placeholders and
# rely on scripts/pongo-boot.md's fixup step.  Documented in DECISIONS.md.
# --------------------------------------------------------------------------

# S5L894x maps DRAM at 0x80000000.  iPad 2 populates 512 MiB.
# TODO(ipad-rea): the static ADT /memory node is zeroed -- confirm size at
# runtime (iOS hw.memsize stops at vram). Value carried from p105ap.
DRAM_BASE = 0x80000000
DRAM_SIZE = 0x1F6FC000

# TODO(ipad-rea): iPad 2 panel is 1024x768 (non-retina), 32bpp.  The
# framebuffer base/stride must be read from the k93 iBEC (upstream:
# scripts/analyze-ibec-display.py) or live iOS ioreg -- the static ADT /vram
# is zeroed.  p105ap values kept as placeholders until measured.
FB_WIDTH = 768
FB_HEIGHT = 1024
FB_BPP = 4
FB_STRIDE = 3072
FB_SIZE = 0x00400000  # 3 MiB rounded up to 4 MiB, section-aligned

# Placeholder carried from P105AP.  TODO(ipad-rea): measure k93ap vram base.
FB_BASE = 0x9F6FC000

# Where the loader is expected to drop things.  Kept well clear of the kernel's
# own load address and of the framebuffer at the top of DRAM.
INITRD_BASE = 0x88000000
INITRD_SIZE = 0x08000000  # 128 MiB budget for the compressed Alpine cpio

# Cortex-A9 PERIPHCLK, used by the global timer and TWD.  It is CPU/2 on A9;
# the A5 in iPad2,5 runs at 1.0 GHz.  Only affects timekeeping accuracy.
A9_PERIPHCLK_HZ = 500000000

# Measured on P105AP Recovery via CBAR (mrc p15,4). ADT pl310@0x3fd00000 was wrong.
# TODO(ipad-rea): re-measure CBAR on k93ap (same SoC family, expected same).
CBAR_PERIPHBASE = 0x3E100000


class AdtView:
    """Path-addressed view over the parser's JSON with bus translation."""

    def __init__(self, doc: dict[str, Any]) -> None:
        self.doc = doc
        self.by_path: dict[str, dict[str, Any]] = {}
        self._index(doc["root"])
        self.ranges: dict[str, list[tuple[int, int, int]]] = {}
        for entry in doc["address_map"]:
            self.ranges[entry["path"]] = [
                (r["child"], r["parent"], r["size"]) for r in entry["ranges"]
            ]

    def _index(self, node: dict[str, Any]) -> None:
        self.by_path[node["path"]] = node
        for child in node["children"]:
            self._index(child)

    def node(self, path: str) -> dict[str, Any]:
        try:
            return self.by_path[path]
        except KeyError:
            raise SystemExit(f"ADT node not found: {path}")

    def find_child(self, parent_path: str, compatible: str) -> dict[str, Any]:
        """Locate a child by its ADT 'compatible' string.

        Several P105AP nodes have FourCC-mangled names (the AIC is 'Aic', the
        watchdog is a packed integer), so compatible is the stable key.
        """
        parent = self.node(parent_path)
        for child in parent["children"]:
            strings = child["props"].get("compatible", {}).get("strings", [])
            if compatible in strings:
                return child
        raise SystemExit(f"no child of {parent_path} with compatible {compatible!r}")

    def prop_cells(self, node: dict[str, Any], name: str) -> list[int]:
        return node["props"].get(name, {}).get("cells", [])

    def regs(self, node: dict[str, Any]) -> list[tuple[int, int]]:
        """Decode a 1-address/1-size 'reg' into (addr, size) pairs."""
        cells = self.prop_cells(node, "reg")
        return [(cells[i], cells[i + 1]) for i in range(0, len(cells) - 1, 2)]

    def translate(self, addr: int, bus_path: str) -> int:
        """Apply one bus's 'ranges' to a child-local address."""
        for child, parent, size in self.ranges.get(bus_path, []):
            if child <= addr < child + size:
                return parent + (addr - child)
        return addr

    def irqs(self, node: dict[str, Any]) -> list[int]:
        return self.prop_cells(node, "interrupts")


def collect_facts(adt: AdtView) -> dict[str, Any]:
    """Pull every number the template needs out of the ADT."""
    DT = "/device-tree"
    IO = f"{DT}/arm-io"

    arm_io = adt.node(IO)
    io_ranges = adt.ranges[IO]
    if len(io_ranges) != 1:
        raise SystemExit(f"expected one arm-io range, got {io_ranges}")
    io_child, io_parent, io_size = io_ranges[0]

    def io_node(compatible: str) -> dict[str, Any]:
        return adt.find_child(IO, compatible)

    def first_reg(node: dict[str, Any]) -> tuple[int, int]:
        regs = adt.regs(node)
        if not regs:
            raise SystemExit(f"{node['path']} has no reg")
        return regs[0]

    aic = io_node("aic,1")
    gpio = io_node("gpio,s5l8940x")
    pmgr = io_node("pmgr,s5l8940x")
    pl310 = io_node("pl310,s5l8940x")
    clcd = io_node("clcd,s5l8940x")
    dsim = io_node("mipi-dsim-1,samsung")
    usbc = io_node("usb-complex,s5l8940x")
    otgphy = adt.node(f"{IO}/otgphyctrl")
    uart0 = adt.node(f"{IO}/uart0")
    spi1 = adt.node(f"{IO}/spi1")
    mt = adt.node(f"{IO}/spi1/multi-touch")

    # The watchdog's ADT node name is a packed integer, so match on compatible.
    wdt = io_node("wdt,s5l8940x")

    # usb-complex is a second bus level: its children's reg values are relative
    # to usb-complex's own ranges, which are themselves arm-io-local.
    usbc_path = usbc["path"]
    ehci = next(c for c in usbc["children"] if c["name"] == "usb-ehci")
    ohci0 = next(c for c in usbc["children"] if c["name"] == "usb-ohci0")
    ohci1 = next(c for c in usbc["children"] if c["name"] == "usb-ohci1")

    def usb_reg(node: dict[str, Any]) -> tuple[int, int]:
        addr, size = first_reg(node)
        return adt.translate(addr, usbc_path), size

    aic_reg = first_reg(aic)
    gpio_reg = first_reg(gpio)
    pmgr_reg = first_reg(pmgr)
    wdt_reg = first_reg(wdt)
    uart_reg = first_reg(uart0)
    spi1_reg = first_reg(spi1)
    clcd_regs = adt.regs(clcd)
    dsim_regs = adt.regs(dsim)
    pl310_regs = adt.regs(pl310)
    otg_reg = first_reg(otgphy)
    usbc_reg = first_reg(usbc)

    ehci_reg = usb_reg(ehci)
    ohci0_reg = usb_reg(ohci0)
    ohci1_reg = usb_reg(ohci1)

    # Wi-Fi on iPad2,1 is a Broadcom part on the SDIO bus: the ADT sdio node
    # carries all the wlan.*/bcom.* properties.  Unlike p105 (BCM4334 on
    # HSIC/EHCI) there is no wlan child in the static ADT.  The Wi-Fi reset
    # line is only present as an Apple "function-device_reset" descriptor
    # whose encoding is not a plain gpio number -- left for a live ioreg dump.
    sdio = io_node("sdio,s5l8940x")
    sdio_reg = first_reg(sdio)

    # multi-touch hangs off gpio for its attention line: <pin flags>.
    mt_irq = adt.irqs(mt)

    # The multi-touch "reg" is not a Linux-style reg at all.  On P105AP it is
    #   <0 124 0x08010000 5000 10000 0 0 0>
    # i.e. chip-select 0 followed by Apple's SPI timing parameters.  The last
    # two non-zero cells are clock rates in kHz (5 MHz / 10 MHz); we take the
    # lower as spi-max-frequency because it is the one iBoot uses.
    mt_reg = adt.prop_cells(mt, "reg")

    # cpu0's ADT "interrupts" is <ipi_self, timer, ipi_other>; the middle entry
    # is the AIC line that carries this core's private timer.
    cpu0_irqs = adt.prop_cells(adt.node(f"{DT}/cpus/cpu0"), "interrupts")

    facts = {
        "soc_base": io_parent,
        "soc_size": io_size,
        "soc_child": io_child,
        "aic": {"reg": aic_reg, "phys": io_parent + aic_reg[0],
                "ncells": adt.prop_cells(aic, "#interrupt-cells")[0],
                "main_cpus": adt.prop_cells(aic, "#main-cpus")[0]},
        "gpio": {"reg": gpio_reg, "phys": io_parent + gpio_reg[0],
                 "irq": adt.irqs(gpio)[0],
                 "ports": adt.prop_cells(gpio, "#gpio-ports")[0],
                 "groups": adt.prop_cells(gpio, "#interrupt-groups")[0]},
        "pmgr": {"reg": pmgr_reg, "phys": io_parent + pmgr_reg[0],
                 "all": [(io_parent + a, s) for a, s in adt.regs(pmgr)]},
        "wdt": {"reg": wdt_reg, "phys": io_parent + wdt_reg[0],
                "irq": adt.irqs(wdt)[0]},
        "uart0": {"reg": uart_reg, "phys": io_parent + uart_reg[0],
                  "irq": adt.irqs(uart0)[0]},
        "spi1": {"reg": spi1_reg, "phys": io_parent + spi1_reg[0],
                 "irq": adt.irqs(spi1)[0]},
        "multitouch": {"irq_pin": mt_irq[0] if mt_irq else 0,
                       "irq_flags": mt_irq[1] if len(mt_irq) > 1 else 0,
                       "reg_cells": mt_reg,
                       "max_khz": min(c for c in mt_reg[3:5] if c) if len(mt_reg) > 4
                       else 5000},
        "cpu0_irqs": cpu0_irqs,
        "usb_bus_base": adt.ranges[usbc_path][0][1] if adt.ranges.get(usbc_path) else 0,
        "clcd": {"regs": [(io_parent + a, s) for a, s in clcd_regs],
                 "irqs": adt.irqs(clcd)},
        "dsim": {"regs": [(io_parent + a, s) for a, s in dsim_regs],
                 "irqs": adt.irqs(dsim)},
        "pl310": {"regs": [(io_parent + a, s) for a, s in pl310_regs]},
        "usb_complex": {"phys": io_parent + usbc_reg[0], "size": usbc_reg[1]},
        "otgphyctrl": {"phys": io_parent + otg_reg[0], "size": otg_reg[1]},
        "ehci": {"local": ehci_reg[0], "size": ehci_reg[1],
                 "phys": io_parent + ehci_reg[0], "irq": adt.irqs(ehci)[0]},
        "ohci0": {"local": ohci0_reg[0], "size": ohci0_reg[1],
                  "phys": io_parent + ohci0_reg[0], "irq": adt.irqs(ohci0)[0]},
        "ohci1": {"local": ohci1_reg[0], "size": ohci1_reg[1],
                  "phys": io_parent + ohci1_reg[0], "irq": adt.irqs(ohci1)[0]},
        "sdio": {"reg": sdio_reg, "phys": io_parent + sdio_reg[0],
                 "irq": adt.irqs(sdio)[0],
                 "width": adt.prop_cells(sdio, "sdio.card.width")[0],
                 "clock_hz": adt.prop_cells(sdio, "sdio.card.clock-rate")[0]},
    }
    # Physical buttons, from the ADT /device-tree/buttons node.  The ADT lists
    # button-names in order and a matching "interrupts" cell list of
    # (linux_gpio, flags) pairs; the first cell of each pair is the Linux gpio
    # specifier for the s5l8940x gpio controller.  Verified against p105's
    # known-good gpio-keys (home=0, hold=1, volup=2, voldown=3, side=4).
    # "halleffect" is the Smart Cover hall sensor, not a key -- skipped.
    buttons = adt.node(f"{DT}/buttons")
    btn_names = buttons["props"].get("button-names", {}).get("strings", [])
    btn_irqs = adt.prop_cells(buttons, "interrupts")
    btn_pairs = [(btn_irqs[i], btn_irqs[i + 1])
                 for i in range(0, len(btn_irqs) - 1, 2)]
    key_map = {  # ADT button name -> (label, linux,code, input-type or None)
        "menu":     ("Home",        172, None),
        "hold":     ("Hold",        116, None),
        "volup":    ("Volume Up",   115, None),
        "voldown":  ("Volume Down", 114, None),
        "ringerab": ("Side Switch", 14,  5),
    }
    keys = []
    for name, (pin, _flags) in zip(btn_names, btn_pairs):
        if name not in key_map:
            continue
        label, code, input_type = key_map[name]
        keys.append({"name": name, "label": label, "pin": pin,
                     "code": code, "input_type": input_type})

    facts["buttons"] = keys
    return facts


# --------------------------------------------------------------------------
# DTS template.  {field} slots are filled from the ADT-derived facts above.
# --------------------------------------------------------------------------

TEMPLATE = r"""// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Apple iPad 2, WiFi -- iPad2,1 / K93AP / S5L8942 (Apple A5, rev A).
 *
 * GENERATED FILE.  Do not edit by hand; edit tools/gen_k93ap_dts.py and
 * re-run scripts/gen-dts.sh.  Every reg/interrupt below was read out of the
 * iBoot Apple Device Tree extracted from the iPad2,1 9.3.5 (13G36) IPSW
 * (DeviceTree.k93ap), not transcribed from a datasheet.
 *
 * Port of iBSSloader's p105ap generator (iPad mini 1) to the iPad 2.
 *
 * Scope: the minimum needed to bring Alpine + LXDE up on the glass, per
 * alpine-lxde-ramdisk-buildplan.md -- UART console, interrupt controller,
 * timer, simple-framebuffer, and an SPI transport for the touch controller.
 * NAND, GPU, ISP, audio, cameras and the sensor I2C buses are deliberately
 * absent; see DECISIONS.md.
 *
 * Address model
 * -------------
 * The ADT's "arm-io" node is a bus whose children use bus-local addresses:
 *   ranges = <{soc_child:#x} {soc_base:#x} {soc_size:#x}>
 * We keep that structure as /soc so unit addresses match the ADT one-for-one
 * and cross-checking against a fresh dump stays trivial.  usb-complex is a
 * second, nested bus; its children are flattened into /soc here because
 * nothing in Linux needs the extra level.
 *
 * Boot protocol (32-bit ARM):
 *   r0 = 0, r1 = ~0 (DT-only boot, no machine ID), r2 = <dtb physical address>
 */

/dts-v1/;

/ {{
	compatible = "apple,k93ap", "apple,s5l8942", "apple,s5l8940x", "apple,arm";
	model = "Apple iPad 2 (iPad2,1)";
	#address-cells = <1>;
	#size-cells = <1>;
	interrupt-parent = <&aic>;

	aliases {{
		serial0 = &uart0;
	}};

	chosen {{
		/*
		 * earlycon uses the Samsung s3c6400 driver: the S5L UART is a
		 * Samsung derivative with an identical register file (ULCON 0x00,
		 * UCON 0x04, UFCON 0x08, UTRSTAT 0x10, UTXH 0x20, URXH 0x24,
		 * UBRDIV 0x28).  See DECISIONS.md #3.
		 *
		 * No baud rate is given to earlycon on purpose: that tells it to
		 * keep whatever divisor iBoot already programmed.
		 *
		 * console=tty0 only.  Do NOT set stdout-path to serial0 — OF
		 * would still prefer ttySAC0 on probe (legacy console enabled)
		 * and /dev/console open fails for init.  UART still probes for
		 * /dev/ttySAC0; earlycon+keep_bootcon covers pre-fbcon printk.
		 *
		 * g_cdc.dev_addr / g_cdc.host_addr pin the two ends of the USB
		 * CDC-ECM link.  Without them u_ether picks a fresh random MAC on
		 * every boot, so the host-side interface has to be reconfigured
		 * every time.  Both are locally-administered unicast (low nibble
		 * of the first octet is 2), so they cannot collide with a real
		 * vendor OUI: ...:01 = host side, ...:02 = device side (usb0).
		 */
		bootargs = "earlycon=s3c6400,{uart_phys:#x} keep_bootcon console=tty0 lpj=5000000 root=/dev/ram0 rw rootwait panic=10 loglevel=8 g_cdc.host_addr=02:10:5a:05:00:01 g_cdc.dev_addr=02:10:5a:05:00:02";

		/*
		 * Placeholders.  The loader MUST overwrite both before jumping;
		 * scripts/fdt_fixup.py and the pongoOS module in pongo/ do this.
		 * Leaving them equal means "no initrd", which is a safe default.
		 */
		linux,initrd-start = <{initrd_base:#x}>;
		linux,initrd-end   = <{initrd_base:#x}>;
	}};

	/*
	 * S5L894x maps DRAM at 0x80000000; iPad2,1 populates 512 MiB.
	 * The static ADT /memory node is zeroed (iBoot fills it at runtime),
	 * so this is a fixed constant rather than an extracted value.
	 */
	memory@{dram_base:x} {{
		device_type = "memory";
		reg = <{dram_base:#x} {dram_size:#x}>;
	}};

	reserved-memory {{
		#address-cells = <1>;
		#size-cells = <1>;
		ranges;

		/*
		 * iBoot's scanout buffer.  Must be no-map so the kernel never
		 * hands these pages to the allocator while the CLCD is still
		 * DMA-ing out of them.  Base is patched at boot together with
		 * the framebuffer node below.
		 */
		fb_region: framebuffer@{fb_base:x} {{
			reg = <{fb_base:#x} {fb_size:#x}>;
			no-map;
		}};
	}};

	/*
	 * simple-framebuffer over iBoot's already-running CLCD scanout.
	 *
	 * The static ADT's /vram node has reg = <0 0>: the base is assigned by
	 * iBoot at runtime.  The loader reads the LIVE ADT's /vram (pongoOS
	 * keeps iBoot's device tree in memory) and patches reg[0] here plus
	 * fb_region above.  Portrait Recovery scanout: 768x1024, stride 3072.
	 *
	 * TODO: confirm the pixel order on hardware.  a8r8g8b8 is what iBoot
	 * uses on every other A5-era device, but if the display comes up with
	 * red and blue swapped, change this to "x8b8g8r8" -- it is the only
	 * value here that cannot be checked without looking at the panel.
	 */
	framebuffer0: framebuffer@{fb_base:x} {{
		compatible = "simple-framebuffer";
		reg = <{fb_base:#x} {fb_size:#x}>;
		width = <{fb_width}>;
		height = <{fb_height}>;
		stride = <{fb_stride}>;
		format = "a8r8g8b8";
		memory-region = <&fb_region>;
		status = "okay";
	}};

	cpus {{
		#address-cells = <1>;
		#size-cells = <0>;

		cpu0: cpu@0 {{
			device_type = "cpu";
			compatible = "arm,cortex-a9";
			reg = <0>;
			enable-method = "apple,pmgr-core";
		}};

		/*
		 * Dual-core A5: cpu1 brought up via PMGR function-enable_core
		 * ("Core", arg 2) + AIC IPI_SEND.  See docs/p105-smp-bringup.md.
		 */
		cpu1: cpu@1 {{
			device_type = "cpu";
			compatible = "arm,cortex-a9";
			reg = <1>;
			enable-method = "apple,pmgr-core";
		}};
	}};

	/*
	 * Cortex-A9 private memory region (SCU + global timer + private timers).
	 *
	 * PERIPHBASE is NOT in the ADT.  The candidate below is the second reg
	 * entry of the ADT "pl310" node -- 0x2000 long, which is exactly the
	 * size of the A9 private memory map, so it is almost certainly right.
	 * It is still a guess, so every consumer is disabled by default.
	 *
	 * Do not trust this file for it: Cortex-A9 exposes PERIPHBASE in the
	 * CBAR register (mrc p15, 4, rX, c15, c0, 0).  docs/read-cbar.md shows
	 * how to print it from a pongoOS shell; once confirmed, flip the three
	 * nodes below to "okay" (or let the loader do it).
	 *
	 * The interrupt numbers are equally provisional: {cpu0_timer_irq} is the middle
	 * cell of the ADT cpu0 "interrupts" tuple <{cpu0_irq_str}>, which by Apple
	 * convention is <ipi-self, timer, ipi-other>.  That the A9 private timer
	 * output is what reaches the AIC on that line is an inference, not a fact.
	 */
	scu@{periphbase:x} {{
		compatible = "arm,cortex-a9-scu";
		reg = <{periphbase:#x} 0x100>;
		status = "{a9_status}";
	}};

	global_timer: timer@{gtimer:x} {{
		compatible = "arm,cortex-a9-global-timer";
		reg = <{gtimer:#x} 0x20>;
		interrupts = <{cpu0_timer_irq}>;
		clock-frequency = <{a9_periph_clk}>;
		/* Counter + udelay only. Comparator IRQ is not routed like a GIC PPI. */
		clocksource-only;
		status = "{a9_status}";
	}};

	twd_timer: timer@{twd:x} {{
		compatible = "arm,cortex-a9-twd-timer";
		reg = <{twd:#x} 0x20>;
		interrupts = <{cpu0_timer_irq}>;
		clock-frequency = <{a9_periph_clk}>;
		status = "disabled";
	}};

	l2: cache-controller@{pl310_phys:x} {{
		compatible = "arm,pl310-cache";
		reg = <{pl310_phys:#x} {pl310_size:#x}>;
		cache-unified;
		cache-level = <2>;
		/*
		 * iBoot already enabled PL310. Linux outer_cache with SCTLR.C=0
		 * hangs in slab init — keep hardware on, do not bind the driver.
		 */
		status = "disabled";
	}};

	/*
	 * Placeholder UART clock for samsung_tty probe (no PMGR yet).
	 * Rate is invented; glass console uses tty0 and does not need it.
	 */
	uart_clk: clock-24000000 {{
		compatible = "fixed-clock";
		#clock-cells = <0>;
		clock-frequency = <24000000>;
	}};

	/*
	 * System tick from the Cortex-A9 PMU overflow interrupt (the middle entry
	 * of cpu0's ADT "interrupts").  Disabled: the AIC timer is the tick; the
	 * A9 architected timer is not yet proven on this SoC.
	 */
	pmu_timer: pmu-timer {{
		compatible = "apple,s5l8940x-pmu-timer";
		interrupts = <{pmu_irq}>;
		status = "disabled";
	}};

	/*
	 * Physical buttons, generated from the ADT /device-tree/buttons node
	 * (button-names + interrupts pairs).  GPIO numbers are Linux specifiers
	 * for the s5l8940x gpio controller.  Flags: 1 = GPIO_ACTIVE_LOW.
	 */
	gpio-keys {{
		compatible = "gpio-keys";
		#address-cells = <1>;
		#size-cells = <0>;
{buttons_children}
	}};

	soc: soc@{soc_base:x} {{
		compatible = "simple-bus";
		#address-cells = <1>;
		#size-cells = <1>;
		ranges = <{soc_child:#x} {soc_base:#x} {soc_size:#x}>;

		/*
		 * Apple Interrupt Controller revision 1 ("aic,1"), per ADT.
		 * Custom driver: drivers/irqchip/irq-apple-aic1.c
		 */
		aic: interrupt-controller@{aic_local:x} {{
			compatible = "aic,1";
			reg = <{aic_local:#x} {aic_size:#x}>;
			interrupt-controller;
			#interrupt-cells = <{aic_ncells}>;
			apple,main-cpus = <{aic_main_cpus}>;
		}};

		/*
		 * GPIO block.  {gpio_ports} ports, {gpio_groups} interrupt groups
		 * multiplexed onto a single AIC line.  Needed here only because
		 * the touch controller's attention line hangs off it.
		 *
		 * TODO: no upstream driver binds apple,s5l8940x-gpio.  Until one
		 * exists the touchscreen child below cannot get a real interrupt
		 * and the userspace daemon must poll.  Kept in the DT so the
		 * wiring is recorded.
		 */
		gpio: gpio@{gpio_local:x} {{
			compatible = "apple,s5l8940x-gpio";
			reg = <{gpio_local:#x} {gpio_size:#x}>;
			interrupts = <{gpio_irq}>;
			gpio-controller;
			#gpio-cells = <2>;
			interrupt-controller;
			#interrupt-cells = <2>;
			apple,gpio-ports = <{gpio_ports}>;
			apple,interrupt-groups = <{gpio_groups}>;
			status = "disabled";
		}};

		/*
		 * Boot console.  The ADT marks this node "boot-console" and gives
		 * it a "debug-console" child, so iBoot has already configured the
		 * pin muxing, the clock gate and 115200 8N1 -- we only have to
		 * keep using it.  compatible lists the Samsung part second so the
		 * stock samsung_tty driver binds even without our patch.
		 *
		 * clocks: samsung_tty requires clk_get("uart") + baud clk.
		 * PMGR is unmodelled; a fixed 24 MHz placeholder lets the port
		 * probe.  Baud may be wrong for USB-TTL until the real rate is
		 * known — on-glass console=tty0 does not depend on it.
		 */
		uart0: serial@{uart_local:x} {{
			compatible = "apple,s5l-uart", "samsung,s3c6400-uart";
			reg = <{uart_local:#x} {uart_size:#x}>;
			interrupts = <{uart_irq}>;
			clocks = <&uart_clk>, <&uart_clk>;
			clock-names = "uart", "clk_uart_baud0";
			status = "okay";
		}};

		/*
		 * SPI1 -- transport for the multi-touch controller.
		 *
		 * Exposed as spidev on purpose.  Per the build plan, v1 drives the
		 * panel from a userspace daemon that speaks Apple's Z2 protocol
		 * and injects events via uinput; writing a kernel multitouch
		 * driver is explicitly out of scope for "LXDE on glass".
		 *
		 * TODO: no upstream driver binds apple,s5l8940x-spi either, so
		 * this is disabled until patches/ grows one.  The ADT records DMA
		 * channels 11/12 on the cdma controller if we ever want them.
		 */
		spi1: spi@{spi1_local:x} {{
			compatible = "apple,s5l8940x-spi";
			reg = <{spi1_local:#x} {spi1_size:#x}>;
			interrupts = <{spi1_irq}>;
			#address-cells = <1>;
			#size-cells = <0>;
			status = "disabled";

			touchscreen@0 {{
				compatible = "apple,z2-multitouch", "linux,spidev";
				reg = <0>;
				/*
				 * The ADT multi-touch "reg" is Apple-specific:
				 *   <{mt_reg_str}>
				 * chip-select 0, then timing parameters.  The two
				 * rate-looking cells are 5000 and 10000 kHz; we take
				 * the lower as the conservative ceiling.
				 */
				spi-max-frequency = <{mt_max_hz}>;
				interrupt-parent = <&gpio>;
				interrupts = <{mt_pin} {mt_flags}>;
			}};
		}};

		/*
		 * Watchdog.  Disabled: nothing pets it, and an armed watchdog
		 * during a long kernel bring-up just resets the device mid-debug.
		 */
		wdt: watchdog@{wdt_local:x} {{
			compatible = "apple,s5l8940x-wdt";
			reg = <{wdt_local:#x} {wdt_size:#x}>;
			interrupts = <{wdt_irq}>;
			status = "disabled";
		}};

		/*
		 * Power/clock manager.  Modelled only so the address space is
		 * documented -- we rely entirely on iBoot having left every clock
		 * we use already ungated.  Enabling this without a driver that
		 * understands the ADT device-clocks table would gate the UART.
		 */
		pmgr: power-management@{pmgr_local:x} {{
			compatible = "apple,s5l8940x-pmgr", "syscon";
			reg = <{pmgr_local:#x} {pmgr_size:#x}>;
			status = "disabled";
		}};

		/*
		 * Display pipeline, recorded but unused.  simplefb above reuses
		 * the output of these blocks rather than reprogramming them; a
		 * real CLCD + MIPI-DSI driver for S5L8940X does not exist and is
		 * not needed to get a desktop on screen.
		 */
		clcd: display-controller@{clcd_local:x} {{
			compatible = "apple,s5l8940x-clcd";
			reg = <{clcd_local:#x} {clcd_size:#x}>;
			interrupts = <{clcd_irq0} {clcd_irq1}>;
			status = "disabled";
		}};

		dsim: dsi@{dsim_local:x} {{
			compatible = "apple,s5l8940x-mipi-dsim", "samsung,mipi-dsim-1";
			reg = <{dsim_local:#x} {dsim_size:#x}>;
			interrupts = <{dsim_irq}>;
			#address-cells = <1>;
			#size-cells = <0>;
			apple,lanes = <{dsim_lanes}>;
			status = "disabled";

			panel@0 {{
				compatible = "apple,lcd-pinot";
				reg = <0>;
				status = "disabled";
			}};
		}};

		/*
		 * USB host (dock connector).  NOT Wi-Fi: on iPad2,1 the wireless
		 * part is a Broadcom chip on SDIO (see the sdio node below), so
		 * brcmfmac will bind through an SDIO host driver, not USB.  The
		 * usb-device child in the ADT is the iPad itself in peripheral
		 * mode (g_cdc gadget), served by these same controllers.
		 *
		 * Kept disabled for now: the OTG PHY needs bringing up first and
		 * USB is not on the critical path to a desktop.
		 *
		 * Addresses are flattened through the usb-complex bus, whose own
		 * ranges map child 0 to {usbc_bus:#x} within arm-io; EHCI's ADT reg of
		 * 0x300000 therefore lands at {ehci_local:#x} here, {ehci_phys:#x} physical.
		 */
		otgphy: phy@{otgphy_local:x} {{
			compatible = "apple,s5l8940x-otgphy";
			reg = <{otgphy_local:#x} {otgphy_size:#x}>;
			#phy-cells = <0>;
			status = "disabled";
		}};

		ehci: usb@{ehci_local:x} {{
			compatible = "apple,s5l8940x-ehci", "generic-ehci";
			reg = <{ehci_local:#x} {ehci_size:#x}>;
			interrupts = <{ehci_irq}>;
			status = "disabled";
		}};

		ohci0: usb@{ohci0_local:x} {{
			compatible = "apple,s5l8940x-ohci", "generic-ohci";
			reg = <{ohci0_local:#x} {ohci0_size:#x}>;
			interrupts = <{ohci0_irq}>;
			status = "disabled";
		}};

		ohci1: usb@{ohci1_local:x} {{
			compatible = "apple,s5l8940x-ohci", "generic-ohci";
			reg = <{ohci1_local:#x} {ohci1_size:#x}>;
			interrupts = <{ohci1_irq}>;
			status = "disabled";
		}};

		/*
		 * SDIO host -- the Wi-Fi bus on this board.  The ADT sdio node
		 * carries the wlan.*/bcom.* properties (Broadcom BCM4330, 4-bit
		 * bus at 51.3 MHz, AIC interrupt {sdio_irq}) plus a
		 * function-device_reset descriptor whose gpio line still needs
		 * confirming from a live ioreg dump on the running iPad.
		 *
		 * Disabled: no upstream driver binds "sdio,s5l8940x" yet.  This
		 * is new work relative to the p105 port (whose BCM4334 sat on
		 * USB); the Wi-Fi roadmap is a small s5l8940x SDIO host driver +
		 * brcmfmac.  The node is kept so the wiring is recorded and the
		 * BCM4330 firmware load can be tested against it.
		 */
		sdio: sdio@{sdio_local:x} {{
			compatible = "sdio,s5l8940x";
			reg = <{sdio_local:#x} {sdio_size:#x}>;
			interrupts = <{sdio_irq}>;
			bus-width = <{sdio_width}>;
			max-frequency = <{sdio_clock_hz}>;
			status = "disabled";
		}};
	}};
}};
"""


def render(facts: dict[str, Any], a9_timers: bool = False) -> str:
    pl310_main = facts["pl310"]["regs"][0]
    periph = CBAR_PERIPHBASE

    # Build the gpio-keys child nodes from the ADT /device-tree/buttons facts.
    key_lines = []
    for k in facts["buttons"]:
        it = ""
        if k["input_type"] is not None:
            it = f'\t\t\tlinux,input-type = <{k["input_type"]}>;\n'
        key_lines.append(
            f'\t\t{k["name"]} {{\n'
            f'\t\t\tlabel = "{k["label"]}";\n'
            f'\t\t\tgpios = <&gpio {k["pin"]} 1>;\n'
            f'{it}'
            f'\t\t\tlinux,code = <{k["code"]}>;\n'
            f'\t\t\tdebounce-interval = <20>;\n'
            f'\t\t}};'
        )
    buttons_children = "\n".join(key_lines)

    fields = {
        "soc_base": facts["soc_base"],
        "soc_size": facts["soc_size"],
        "soc_child": facts["soc_child"],
        "dram_base": DRAM_BASE,
        "dram_size": DRAM_SIZE,
        "fb_base": FB_BASE,
        "fb_size": FB_SIZE,
        "fb_width": FB_WIDTH,
        "fb_height": FB_HEIGHT,
        "fb_stride": FB_STRIDE,
        "initrd_base": INITRD_BASE,
        "periphbase": periph,
        "gtimer": periph + 0x200,
        "twd": periph + 0x600,
        "cpu0_timer_irq": facts["cpu0_irqs"][1] if len(facts["cpu0_irqs"]) > 1 else 0,
        "cpu0_irq_str": " ".join(f"{c:#x}" for c in facts["cpu0_irqs"]),
        "a9_status": "okay" if a9_timers else "disabled",
        # A9 peripheral clock is CPU/2.  iBoot runs the A5 in this iPad at
        # 1.0 GHz, so 500 MHz.  Wrong here only costs a wrong-rate clocksource,
        # not a hang, and the global timer driver will use it as-is.
        "a9_periph_clk": A9_PERIPHCLK_HZ,
        "pl310_phys": pl310_main[0],
        "pl310_size": pl310_main[1],
        "pl310_tag": 272,
        "pl310_data": 288,
        "aic_local": facts["aic"]["reg"][0],
        "aic_size": facts["aic"]["reg"][1],
        "aic_ncells": facts["aic"]["ncells"],
        "aic_main_cpus": facts["aic"]["main_cpus"],
        "gpio_local": facts["gpio"]["reg"][0],
        "gpio_size": facts["gpio"]["reg"][1],
        "gpio_irq": facts["gpio"]["irq"],
        "gpio_ports": facts["gpio"]["ports"],
        "gpio_groups": facts["gpio"]["groups"],
        "uart_local": facts["uart0"]["reg"][0],
        "uart_size": facts["uart0"]["reg"][1],
        "uart_irq": facts["uart0"]["irq"],
        "uart_phys": facts["uart0"]["phys"],
        "spi1_local": facts["spi1"]["reg"][0],
        "spi1_size": facts["spi1"]["reg"][1],
        "spi1_irq": facts["spi1"]["irq"],
        "mt_pin": facts["multitouch"]["irq_pin"],
        "mt_flags": facts["multitouch"]["irq_flags"],
        "mt_max_hz": facts["multitouch"]["max_khz"] * 1000,
        "mt_reg_str": " ".join(f"{c:#x}" for c in facts["multitouch"]["reg_cells"]),
        "wdt_local": facts["wdt"]["reg"][0],
        "wdt_size": facts["wdt"]["reg"][1],
        "wdt_irq": facts["wdt"]["irq"],
        "pmgr_local": facts["pmgr"]["reg"][0],
        "pmgr_size": facts["pmgr"]["reg"][1],
        "clcd_local": facts["clcd"]["regs"][0][0] - facts["soc_base"],
        "clcd_size": facts["clcd"]["regs"][0][1],
        "clcd_irq0": facts["clcd"]["irqs"][0],
        "clcd_irq1": facts["clcd"]["irqs"][1],
        "dsim_local": facts["dsim"]["regs"][0][0] - facts["soc_base"],
        "dsim_size": facts["dsim"]["regs"][0][1],
        "dsim_irq": facts["dsim"]["irqs"][0],
        "dsim_lanes": 4,
        "otgphy_local": facts["otgphyctrl"]["phys"] - facts["soc_base"],
        "otgphy_size": facts["otgphyctrl"]["size"],
        "usbc_bus": facts["usb_bus_base"],
        "ehci_local": facts["ehci"]["local"],
        "ehci_size": facts["ehci"]["size"],
        "ehci_irq": facts["ehci"]["irq"],
        "ehci_phys": facts["ehci"]["phys"],
        "ohci0_local": facts["ohci0"]["local"],
        "ohci0_size": facts["ohci0"]["size"],
        "ohci0_irq": facts["ohci0"]["irq"],
        "ohci1_local": facts["ohci1"]["local"],
        "ohci1_size": facts["ohci1"]["size"],
        "ohci1_irq": facts["ohci1"]["irq"],
        "sdio_local": facts["sdio"]["reg"][0],
        "sdio_size": facts["sdio"]["reg"][1],
        "sdio_irq": facts["sdio"]["irq"],
        "sdio_width": facts["sdio"]["width"],
        "sdio_clock_hz": facts["sdio"]["clock_hz"],
        "pmu_irq": facts["cpu0_irqs"][1],
        "buttons_children": buttons_children,
    }

    return TEMPLATE.format(**fields)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate ipad2-k93ap.dts from parsed ADT (ipad-rea)")
    ap.add_argument("input", help="apple-k93ap-raw.json from parse_apple_dt.py")
    ap.add_argument("-o", "--output", help="DTS output path (default: stdout)")
    ap.add_argument("--report", action="store_true",
                    help="print extracted hardware facts as JSON and exit")
    ap.add_argument("--a9-timers", action="store_true",
                    help="enable the Cortex-A9 SCU and global timer at the "
                         "candidate PERIPHBASE (only once CBAR confirms it)")
    args = ap.parse_args()

    with open(args.input, encoding="utf-8") as fh:
        doc = json.load(fh)

    adt = AdtView(doc)
    facts = collect_facts(adt)

    if args.report:
        json.dump(facts, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    text = render(facts, a9_timers=args.a9_timers)
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
