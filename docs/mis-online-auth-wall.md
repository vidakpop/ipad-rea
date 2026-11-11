# MIS online-auth wall — binary-level root cause (Nov 11)

This closes the loop on why **every** sideloaded app fails with
`0xe800800d` on this hacktivated iPad 2, no matter who signs it
(zsign, Sideloader, AltServer-NG, iloader all produce the same
terminal error).

## How this was established

1. Full 9.3.5 rootfs decrypted with `readencrcdsa.py`
   (nlitsme/encrypteddmg) using the wiki RootFSKey:
   `f17d6a73913dfb7ca9df505d6b2a829e25797a89a9dba446d5cfef671c0b500fb201958b`
   (72 hex = 16-byte AES key + 20-byte HMAC, `-K` flag).
   - input  `058-49123-036.dmg` (extracted from `/tmp/fw935/ipad2.ipsw`)
   - output `/tmp/fw935/058-49123-036-decrypted.dmg` (koly trailer intact)
   - decrypt log `/tmp/rootfs-decrypt.log`, ~90 s runtime
2. `libmis.dylib` does **not** exist as a file — installd links
   `/usr/lib/libmis.dylib` from the dyld shared cache
   (`System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7`).
   Carved at vm `0x23099000..0x230B4000` (file off `0x3099000`, 108 KiB)
   with `tools/dsc-parse-libmis.py`. blacktop/ipsw 3.1.745 cannot
   extract iOS 9 caches (LC_DYLD_CHAINED_FIXUPS required).
3. libmis has **zero** local symbols in the cache (local-symbols entry
   `nlistCount == 0`), so strings + flow reconstruction only.

## The chain, proven from device syslog + libmis strings

```
installd  ->  libmis checkTrustAndAuthorization()
           ->  xpc com.apple.online-auth-agent.xpc
online-auth-agent:
    SecItemCopyMatching(com.apple.lockdown.identity.activation
                        kSecClassIdentity, system keychain)
    -> errSecItemNotFound (-25300)   <-- hacktivated device has no identity
    -> "MIS: Could not find device identity"
    -> "MIS: Could not perform authorization."
installd:
    -> "MIS: Auth agent contact failure (entitlement status 0)"
mobile_installation_proxy:
    -> 0xe800800d Application verification failed
```

## Key strings from libmis (carve: /tmp/dsc/libmis_carved.bin)

```
MIS: Auth agent contact failure (entitlement status %lld)
com.apple.online-auth-agent.xpc
MIS: validation failed because of failing online authorization (%d)
MIS: validation failed because of missing trust and/or authorization (%x)
RespectUppTrustAndAuthorization / ValidateSignatureOnly
ValidatedByProfile / ValidatedByLocalProfile / ValidatedByUniversalProfile
/private/var/db/MobileIdentityData/AuthListReadyCdHashes.plist
/private/var/db/MobileIdentityData/AuthListBannedCdHashes.plist
/private/var/db/MobileIdentityData/UserTrustedUpps.plist
/private/var/db/MobileIdentityData/UserOverriddenCdHashes.plist
/private/var/db/MobileIdentityData/Indeterminates.plist
MIS: Profile not in banned auth list, proceeding.
```

## What this proves

- The device-side verdict pipeline is: local MobileIdentityData lists
  first; only ``indeterminate`` apps hit the online agent
  (`online-auth-agent`, launchd XPC `com.apple.online-auth-agent.xpc`).
- The agent needs the **activation identity**
  (`com.apple.lockdown.identity.activation`, kSecClassIdentity in the
  **system keychain**). That identity is created *by the device itself*
  during a genuine activation handshake (device generates the keypair,
  sends the CSR — the same `DeviceCertRequest` blob act.sh sends — and
  imports the returned cert into the system keychain).
- Sliver/act.sh hacktivation writes plists only
  (`/var/root/Library/Lockdown/…`). A host-side tool **can never**
  create the keychain identity: the system keychain is root-only.
- Therefore **no host-side signing variation can ever pass** the app
  verify stage on this device. zsign / Sideloader / AltServer / iloader
  results are all the same wall with different cosmetic error codes
  (0xe800800d "communication with device", 0xe8008019 for the
  cryptographically-broken zsign CMS).

## Falsified bypasses for this wall (all need root, which we don't have)

| idea | why it fails |
|------|--------------|
| write cdhash into `AuthListReadyCdHashes.plist` | file is root-only (`/private/var/db/MobileIdentityData`) |
| Settings → “Trust” button | shown for enterprise/MDM profiles only; free-dev profiles never reach install so no profile entry exists |
| MITM gsp-ssl.gs.apple.com | TLS trust store root-only; agent pins Apple CAs |
| plant identity via backup restore | keychain items not restorable host-side; idevicebackup2 restore blocked by FMI (err 211) |
| quota/-80045 retries | quota was never the real blocker; verify stage fails on identity regardless |

## Remaining software-only routes (ranked)

1. **checkm8 A5 host-port sweep** — existing `tools/checkm8-a5-pwn.py`,
   needs fresh DFU per attempt; Linux USB stack makes the race
   unreliable (documented) but each run is free.
2. Real activation (needs the previous owner's Apple ID — user cannot).
3. Anything else hits the wall above.

## Artifacts on this machine

- `/tmp/fw935/ipad2.ipsw` — full signed 9.3.5 IPSW (1.4 GB)
- `/tmp/fw935/058-49123-036-decrypted.dmg` — decrypted rootfs UDIF (1.3 GB, 63k files)
- `/tmp/fw935/mis/…` — extracted installd, misagent, online-auth-agent,
  mobile_installation_proxy, MobileInstallation XPC service, dyld cache
- `/tmp/dsc/libmis_carved.bin` — libmis __TEXT carve with all MIS strings
- `/tmp/parse_dsc.py`, `tools/dsc-parse-libmis.py` — cache parsers
