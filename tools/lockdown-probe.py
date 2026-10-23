#!/usr/bin/env python3
"""
lockdown-probe.py — enumerate which lockdown services the iPad will start.

For each candidate service name we ask lockdownd to start it and report the
result.  A service that starts is a channel we can talk to from the host with
no jailbreak, no ssh and no Cydia; this is how we map the toolbox before
picking a way to run kloader (see docs/k93-boot-linux.md).

    python3 tools/lockdown-probe.py [udid]
"""
import ctypes
import sys

UDID = "ae85db46b1dd7faa563fc6eb53780515a67dfcc7"
LIB = "/usr/lib/x86_64-linux-gnu/libimobiledevice-1.0.so.6"

# lockdownd error codes we care about (include/libimobiledevice/lockdown.h)
ERR_NAMES = {
    0: "SUCCESS",
    -26: "MISSING_SERVICE (unknown to device)",
    -27: "INVALID_SERVICE",
    -34: "SERVICE_PROHIBITED",
    -35: "ESCROW_LOCKED",
    -37: "FMIP_PROTECTED",
    -38: "MC_PROTECTED",
    -39: "MC_CHALLENGE_REQUIRED",
}

SERVICES = [
    # file access
    "com.apple.afc",                    # jailed AFC (known to work)
    "com.apple.afc2",                   # needs the Cydia AFC2 tweak
    "com.apple.streaming_zip_conduit",  # zip extraction onto the device
    "com.apple.mobile.file_relay",      # diagnostic file pull (runs as root)
    "com.apple.mobile.house_arrest",    # app container access
    # exec / debug
    "com.apple.debugserver",            # needs Developer Disk Image mounted
    # app management
    "com.apple.mobile.installation_proxy",
    # backup
    "com.apple.mobile.mobilebackup2",
    "com.apple.mobilebackup",
    # device control
    "com.apple.mobile.diagnostics_relay",
    "com.apple.syslog_relay",
    "com.apple.mobile.mobile_image_mounter",
    "com.apple.misagent",
    "com.apple.pcapd",
    "com.apple.crashreportcopymobile",
    "com.apple.dt.fetchsymbols",
    "com.apple.ostrace",
    "com.apple.mobile.obliteration",
    "com.apple.insecure_notification_proxy",
    "com.apple.mobile.wireless_lockdown",
]


class ServiceDescriptor(ctypes.Structure):
    _fields_ = [
        ("port", ctypes.c_uint16),        # offset 0
        ("ssl_enabled", ctypes.c_uint8),  # offset 2
        ("_pad", ctypes.c_uint8 * 5),     # pad to 8
        ("identifier", ctypes.c_char_p),  # offset 8
    ]


def main():
    udid = sys.argv[1] if len(sys.argv) > 1 else UDID
    lib = ctypes.CDLL(LIB)
    c_void_p_p = ctypes.POINTER(ctypes.c_void_p)

    lib.idevice_new.argtypes = [c_void_p_p, ctypes.c_char_p]
    lib.idevice_new.restype = ctypes.c_int
    lib.idevice_free.argtypes = [ctypes.c_void_p]
    lib.idevice_free.restype = None
    lib.lockdownd_client_new_with_handshake.argtypes = [ctypes.c_void_p, c_void_p_p, ctypes.c_char_p]
    lib.lockdownd_client_new_with_handshake.restype = ctypes.c_int
    lib.lockdownd_client_free.argtypes = [ctypes.c_void_p]
    lib.lockdownd_client_free.restype = None
    # NOTE: lockdownd_start_service() allocates the descriptor and returns it
    # as an out-pointer (lockdownd_service_descriptor_t*), so we pass a void**.
    lib.lockdownd_start_service.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                            ctypes.POINTER(ctypes.c_void_p)]
    lib.lockdownd_start_service.restype = ctypes.c_int
    lib.lockdownd_service_descriptor_free.argtypes = [ctypes.c_void_p]
    lib.lockdownd_service_descriptor_free.restype = None
    lib.service_client_new.argtypes = [ctypes.c_void_p, ctypes.c_void_p, c_void_p_p]
    lib.service_client_new.restype = ctypes.c_int
    lib.service_client_free.argtypes = [ctypes.c_void_p]
    lib.service_client_free.restype = None

    device = ctypes.c_void_p()
    r = lib.idevice_new(ctypes.byref(device), udid.encode())
    if r != 0:
        sys.exit(f"error: idevice_new -> {r} (device not connected?)")

    client = ctypes.c_void_p()
    r = lib.lockdownd_client_new_with_handshake(device, ctypes.byref(client), b"ipad-rea")
    if r != 0:
        sys.exit(f"error: lockdownd handshake -> {r} (not paired?)")

    print(f"{'service':45s} {'start':4s} {'connect':8s} port  ssl  detail")
    for name in SERVICES:
        desc_p = ctypes.c_void_p()
        r = lib.lockdownd_start_service(client, name.encode(), ctypes.byref(desc_p))
        if r != 0:
            print(f"{name:45s} {'NO':4s} {'-':8s} {'':5s} {'':4s} {ERR_NAMES.get(r, r)}")
            continue
        desc = ctypes.cast(desc_p, ctypes.POINTER(ServiceDescriptor)).contents
        sc = ctypes.c_void_p()
        rc = lib.service_client_new(device, desc_p, ctypes.byref(sc))
        connect = "ok" if rc == 0 else f"rc={rc}"
        if rc == 0:
            lib.service_client_free(sc)
        print(f"{name:45s} {'YES':4s} {connect:8s} {desc.port:<5d} {desc.ssl_enabled:<4d} "
              f"{desc.identifier.decode() if desc.identifier else ''}")
        lib.lockdownd_service_descriptor_free(desc_p)

    lib.lockdownd_client_free(client)
    lib.idevice_free(device)


main()
