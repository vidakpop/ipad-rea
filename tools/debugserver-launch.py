#!/usr/bin/env python3
"""
debugserver-launch.py — launch a program as root on the iPad via com.apple.debugserver.

Uses the installed libimobiledevice through ctypes — no compilation, no sudo, no
ssh on the device.  This is the same launch flow `idevicedebug run` uses (see
libimobiledevice's tools/idevicedebug.c), except the target is an arbitrary
executable path instead of an installed app's bundle id:

    python3 tools/debugserver-launch.py /bin/sh /var/mobile/Media/kdfu/payload.sh

debugserver is a lockdown service, so the launched process runs as root.  After
qLaunchSuccess the client detaches ("D"), so the process keeps running after
this script exits.

Requires: device paired and connected over USB (usbmuxd).  Anything the
launched program needs kernel access for (e.g. kloader) additionally requires
the device to be jailbroken.
"""
import ctypes
import sys

UDID = "ae85db46b1dd7faa563fc6eb53780515a67dfcc7"
LIB = "/usr/lib/x86_64-linux-gnu/libimobiledevice-1.0.so.6"

lib = ctypes.CDLL(LIB)

c_int_p = ctypes.POINTER(ctypes.c_int)
c_char_p_p = ctypes.POINTER(ctypes.c_char_p)
c_void_p_p = ctypes.POINTER(ctypes.c_void_p)

lib.idevice_new.argtypes = [c_void_p_p, ctypes.c_char_p]
lib.idevice_new.restype = ctypes.c_int
lib.idevice_free.argtypes = [ctypes.c_void_p]
lib.idevice_free.restype = None
lib.debugserver_client_start_service.argtypes = [ctypes.c_void_p, c_void_p_p, ctypes.c_char_p]
lib.debugserver_client_start_service.restype = ctypes.c_int
lib.debugserver_client_free.argtypes = [ctypes.c_void_p]
lib.debugserver_client_free.restype = None
lib.debugserver_client_set_argv.argtypes = [ctypes.c_void_p, ctypes.c_int, c_char_p_p, c_char_p_p]
lib.debugserver_client_set_argv.restype = ctypes.c_int
lib.debugserver_command_new.argtypes = [ctypes.c_char_p, ctypes.c_int, c_char_p_p, c_void_p_p]
lib.debugserver_command_new.restype = ctypes.c_int
lib.debugserver_command_free.argtypes = [ctypes.c_void_p]
lib.debugserver_command_free.restype = None
lib.debugserver_client_send_command.argtypes = [ctypes.c_void_p, ctypes.c_void_p, c_char_p_p, c_int_p]
lib.debugserver_client_send_command.restype = ctypes.c_int

def send_command(client, name, args=None):
    cmd = ctypes.c_void_p()
    argv = None
    argc = 0
    if args:
        argc = len(args)
        argv = (ctypes.c_char_p * (argc + 1))(*[a.encode() for a in args], None)
    r = lib.debugserver_command_new(name.encode(), argc, argv, ctypes.byref(cmd))
    if r != 0:
        raise RuntimeError(f"debugserver_command_new({name!r}) -> {r}")
    resp = ctypes.c_char_p()
    status = ctypes.c_int(-1)
    r = lib.debugserver_client_send_command(client, cmd, ctypes.byref(resp), ctypes.byref(status))
    out = resp.value.decode("utf-8", "replace") if resp.value else None
    lib.debugserver_command_free(cmd)
    return r, out, status.value


def main():
    if len(sys.argv) < 2:
        sys.exit(f"usage: {sys.argv[0]} <executable> [args...]")
    target = sys.argv[1:]

    device = ctypes.c_void_p()
    r = lib.idevice_new(ctypes.byref(device), UDID.encode())
    if r != 0:
        sys.exit(f"error: idevice_new -> {r} (device not connected?)")

    client = ctypes.c_void_p()
    r = lib.debugserver_client_start_service(device, ctypes.byref(client), b"ipad-rea")
    if r != 0:
        sys.exit(f"error: could not start com.apple.debugserver (rc={r})")

    print("QSetMaxPacketSize:", send_command(client, "QSetMaxPacketSize:", ["1024"])[1])
    print("QSetWorkingDir:   ", send_command(client, "QSetWorkingDir:", ["/"])[1])

    argc = len(target)
    argv = (ctypes.c_char_p * argc)(*[a.encode() for a in target])
    r = lib.debugserver_client_set_argv(client, argc, argv, None)
    print(f"set_argv:         rc={r} argv={target}")

    r, resp, status = send_command(client, "qLaunchSuccess")
    print(f"qLaunchSuccess:   rc={r} resp={resp!r} exit_status={status}")
    if resp != "OK":
        sys.exit("error: launch refused by debugserver (is the device jailbroken?)")

    r, resp, _ = send_command(client, "D")
    print(f"detach (D):       rc={r} resp={resp!r}")

    lib.debugserver_client_free(client)
    lib.idevice_free(device)
    print("launched and detached; the process keeps running as root on the device")


main()
