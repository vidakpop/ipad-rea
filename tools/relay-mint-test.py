import asyncio, hashlib, re, urllib.request, uuid, plistlib

async def get_info():
    from pymobiledevice3.lockdown import create_using_usbmux
    ld = await create_using_usbmux(serial="ae85db46b1dd7faa563fc6eb53780515a67dfcc7")
    return await ld.get_value(key="ActivationInfo")

def post_relay(serial, info_bytes):
    b = uuid.uuid4().hex
    fields = [("InStoreActivation","false"),("AppleSerialNumber",serial),("activation-info",info_bytes.decode(errors="replace"))]
    body = ""
    for name, val in fields:
        body += f'--------------------------{b}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{val}\r\n'
    body += f"--------------------------{b}--\r\n"
    req = urllib.request.Request("http://cengdealajr.gearhostpreview.com/sliver.php",
        data=body.encode(),
        headers={"Content-Type": f"multipart/form-data; boundary=------------------------{b}",
                 "User-Agent": "iOS Device Activator (MobileActivation-592.103.2)"})
    with urllib.request.urlopen(req, timeout=40) as r:
        return r.read()

def fingerprint(resp):
    t = resp.decode(errors="replace")
    out = []
    for key in ("FairPlayKeyData","AccountToken","DeviceCertificate","AccountTokenCertificate"):
        m = re.search(rf"<key>{key}</key>\s*<data>\s*(.*?)\s*</data>", t, re.S)
        out.append(f"{key[:4]}:{hashlib.sha1(m.group(1).encode()).hexdigest()[:10]}" if m else f"{key[:4]}:-")
    return " ".join(out)

async def main():
    info = await get_info()
    print("raw info type:", type(info).__name__)
    if isinstance(info, (bytes, bytearray)):
        info_bytes = bytes(info)
    elif isinstance(info, dict) and "ActivationInfoXML" in info or isinstance(info, dict):
        info_bytes = plistlib.dumps(info)
    else:
        info_bytes = str(info).encode()
    print("info bytes len:", len(info_bytes), " head:", info_bytes[:60])
    open("/tmp/fresh-info.plist","wb").write(info_bytes)
    for label, serial in [("real-serial", "F6QTF059DFHW"), ("shifted-1", "F6QTF059DFHX"), ("fictional", "C02QWERTYUIOP")]:
        try:
            resp = post_relay(serial, info_bytes)
            t = resp.decode(errors="replace")
            isrec = "FairPlayKeyData" in t
            print(f"{label:12} -> {len(resp)}B record:{isrec} {fingerprint(resp) if isrec else t[:90]}")
        except Exception as e:
            print(f"{label:12} -> EXC {type(e).__name__}: {str(e)[:70]}")

asyncio.run(main())
