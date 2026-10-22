# UART console on the iPad 2

The iPad 2 has a 30-pin dock connector, and the A5's UART0 is routed straight
to it — unlike the iPad mini 1 (Lightning), which needs a DCSD cable. So a
cheap dock-connector breakout + a 3.3 V USB-TTL adapter is enough.

## Wiring (commonly cited for the 30-pin dock — verify before soldering)

| Dock pin | Signal | USB-TTL adapter |
|---|---|---|
| 12 / 13 | UART pair (one TX, one RX) | cross: dock TX → adapter RX, dock RX → adapter TX (swap if you see no output) |
| 1, 2, 15, 16, 29, 30 | GND | GND |

- Reference pinout: [The Apple Wiki — 30-pin Connector](https://theapplewiki.com/wiki/30-pin_Connector)
- The accessory-detect pin (21) may need a resistor to enable the accessory
  UART on some devices/firmwares — if you get nothing, check this.
- **Use a 3.3 V adapter** (FT232R / CP2102 / PL2303 set to 3.3 V logic).
  Do not feed 5 V into the dock.

## What to expect

- The A5 UART is a **Samsung s3c6400 derivative** (identical register file:
  ULCON 0x00, UCON 0x04, UFCON 0x08, UTRSTAT 0x10, UTXH 0x20, URXH 0x24,
  UBRDIV 0x28). The kernel uses the Samsung serial driver
  (`earlycon=s3c6400,<base>`, `ttySAC0`).
- `earlycon` is given **no baud rate on purpose** — it keeps whatever divisor
  iBoot programmed, so you see output before any clock driver exists.
- Once Linux is up: 115200 8N1 on `/dev/ttySAC0`.

## TODO (ipad-rea)

- Confirm the **k93ap UART0 MMIO base** from the k93 ADT — the p105ap DTS uses
  `0x32500000`; the iPad 2's base may differ. Update `chosen/bootargs`
  (`earlycon=s3c6400,0x...`) and the uart node in `dts/ipad2-k93ap.dts`.
- The on-glass console (`console=tty0` via simplefb) does not depend on the
  UART — the cable is a debugging nicety, not a blocker (same as Cascadia).
