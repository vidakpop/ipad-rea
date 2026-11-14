#!/usr/bin/env python3
"""whoami.py - WHO instrument: which usb_device does the module's capture hold?"""
import fcntl, os, struct, sys
IOC_WHO = (2 << 30) | (16 << 16) | (ord('R') << 8) | 11
fd = os.open('/dev/raw0', os.O_RDWR)
buf = bytearray(16)
fcntl.ioctl(fd, IOC_WHO, buf, True)
busnum, devnum, vid, pid = struct.unpack('<4I', bytes(buf))
print('captured device: bus %d addr %d  (vid %04x pid %04x)' % (busnum, devnum, vid, pid))
if devnum == 0xFFFFFFFF:
    print('NO CAPTURE (module loaded after last enumeration)')
else:
    import subprocess
    out = subprocess.check_output(['lsusb'], text=True)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) > 3 and parts[1] == '%03d' % busnum and parts[3].rstrip(':') == '%03d' % devnum:
            print('identity:', ' '.join(parts[3:]))
