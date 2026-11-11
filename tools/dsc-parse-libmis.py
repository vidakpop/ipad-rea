import struct, sys

CACHE='/tmp/fw935/mis/Genoa13G36.K93OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7'
f=open(CACHE,'rb')
hdr=f.read(0x400)
print('magic',hdr[:16])
mappingOffset,mappingCount=struct.unpack_from('<II',hdr,0x10)
f.seek(mappingOffset)
maps=[]
for i in range(mappingCount):
    m=f.read(40)
    addr,size,foff,fsize,maxp,initp=struct.unpack('<QQQQii',m)
    maps.append((addr,size,foff,fsize))
    print('map addr 0x%X size 0x%X fileoff 0x%X filesize 0x%X'%(addr,size,foff,fsize))

imgsOff,imgsCnt=struct.unpack_from('<II',hdr,0x18)
dyldBase,=struct.unpack_from('<Q',hdr,0x20)
print('imagesOffset 0x%X count %d dyldBase 0x%X'%(imgsOff,imgsCnt,dyldBase))
localSymbolsOff,localSymbolsSize=struct.unpack_from('<II',hdr,0x50)
print('localSymbols off 0x%X size 0x%X'%(localSymbolsOff,localSymbolsSize))
f.seek(localSymbolsOff)
nlistOffset,nlistCount,symstrOffset,symstrSize=struct.unpack('<IIII',f.read(16))
print('nlist off 0x%X count %d stroff 0x%X size 0x%X'%(nlistOffset,nlistCount,symstrOffset,symstrSize))

def path_for(pfo):
    f.seek(pfo); s=f.read(300); return s.split(b'\0')[0].decode(errors='replace')

f.seek(imgsOff)
imgs=[]
for i in range(imgsCnt):
    e=f.read(32)
    addr,mtime,inode,pfo,pad=struct.unpack('<QQQII',e)
    imgs.append((addr,pfo))

mis=[(a,po) for (a,po) in imgs if 'libmis' in path_for(po)]
print('libmis images:',[(hex(a),path_for(po)) for a,po in mis])
if not mis: sys.exit(0)

# sort images by address to find the end of libmis
sv=sorted(imgs)
misaddr,mispfo=mis[0]
end=None
for i,(a,po) in enumerate(sv):
    if a==misaddr and i+1<len(sv):
        end=sv[i+1][0]; break
print('libmis vm 0x%X .. 0x%X (next %s)'%(misaddr,end,path_for(dict(sv)[end]) if end else '?'))

def vaddr_to_off(v):
    for (a,s,fo,fs) in maps:
        if a<=v<a+s and fo!=0xFFFFFFFF:
            return v-a+fo
    return None

start=vaddr_to_off(misaddr)
print('libmis file offset 0x%X'%start)
f.seek(start)
mh=f.read(0x400)
magic_,cputype,cpusubtype,ft,len_=struct.unpack_from('<IIIIII',mh,0)[:2]+ (0,0,0,0)
magic_,cputype,cpusubtype,filetype,ncmds,sizeofcmds=struct.unpack_from('<IIIIII',mh,0)
print('magic 0x%X ncmds %d sizeofcmds 0x%X'%(magic_,ncmds,sizeofcmds))
# read segments to find size needed for carve (in-cache)
seg=[]
o=32
for i in range(ncmds):
    f.seek(start+o)
    lc=f.read(8); cmd,cmdsize=struct.unpack('<II',lc)
    if cmd==1: # LC_SEGMENT
        b=f.read(cmdsize-8)
        segname=b[0:16].rstrip(b'\0').decode()
        vmaddr,vmsize,fo,fsz,maxp,initp,nsects,flags=struct.unpack('<QQQQIIII',b[16:])
        seg.append((segname,vmaddr,vmsize,fo,fsz))
    o+=cmdsize
print('segments:')
totend=0
for s in seg: print('  %s vm 0x%X..0x%X fileoff 0x%X fsz 0x%X'%s)

carve_end=max(vmsize for (_,_,vmsize,_,_) in seg)
endoff=vaddr_to_off(misaddr+carve_end) or end and vaddr_to_off(end)
outlen=(endoff-start) if endoff else carve_end
print('carve len 0x%X'%outlen)
f.seek(start)
data=f.read(outlen)
open('/tmp/dsc/libmis_carved.bin','wb').write(data)
print('written /tmp/dsc/libmis_carved.bin')

# extract local symbols within libmis range
import mmap
mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
strbase=localSymbolsOff
def read_str(off):
    o=strbase+symstrOffset+off
    e=mm.find(b'\0',o)
    return mm[o:e].decode(errors='replace')
syms=[]
for i in range(min(nlistCount,10**9)):
    o=localSymbolsOff+nlistOffset+i*16
    if o+16>len(mm): break
    n_strx,n_type,n_sect,n_desc,n_value=struct.unpack_from('<IBBHII',mm,o)
    if misaddr<=n_value< misaddr+carve_end:
        syms.append((n_value,read_str(n_strx)))
print('symbols in range:',len(syms))
with open('/tmp/dsc/libmis_symbols.txt','w') as out:
    for a,n in sorted(syms): out.write('0x%X %s\n'%(a,n))
print('sample:', [n for _,n in syms[:20]])
