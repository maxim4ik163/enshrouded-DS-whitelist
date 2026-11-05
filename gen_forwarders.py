#!/usr/bin/env python3
# Regenerate forwarders.h (MSVC /EXPORT pragmas) from a (new) steam_api64.dll.
# Usage:  python3 gen_forwarders.py  path\to\steam_api64.dll  > forwarders.h
# Run only if a Steam update changes steam_api64.dll and the MSVC build fails
# with a missing/duplicate export. (For the MinGW build, regen steam_api64.def
# with gen_def.py instead.)
import sys, struct
HOOK='SteamInternal_FindOrCreateGameServerInterface'; REAL='steam_api64_org'
d=open(sys.argv[1],'rb').read()
pe=struct.unpack_from('<I',d,0x3C)[0]; coff=pe+4
nsec=struct.unpack_from('<H',d,coff+2)[0]; szopt=struct.unpack_from('<H',d,coff+16)[0]; opt=coff+20
exp_rva=struct.unpack_from('<I',d,opt+112)[0]
sect=opt+szopt; secs=[]
for i in range(nsec):
    o=sect+i*40; va=struct.unpack_from('<I',d,o+12)[0]; rptr=struct.unpack_from('<I',d,o+20)[0]
    vsz=struct.unpack_from('<I',d,o+8)[0]; rsz=struct.unpack_from('<I',d,o+16)[0]; secs.append((va,vsz,rptr,rsz))
def r2f(r):
    for va,vsz,rptr,rsz in secs:
        if va<=r<va+max(vsz,rsz): return rptr+(r-va)
eo=r2f(exp_rva); nname=struct.unpack_from('<I',d,eo+24)[0]
names=r2f(struct.unpack_from('<I',d,eo+32)[0])
nm=[]
for i in range(nname):
    nfo=r2f(struct.unpack_from('<I',d,names+4*i)[0]); e=d.find(b'\0',nfo); nm.append(d[nfo:e].decode('latin1'))
nm.sort()
print('#pragma once'); print('#ifdef _MSC_VER')
for n in nm:
    if n==HOOK: print('#pragma comment(linker, "/export:%s=My_FindOrCreateGameServerInterface")'%n)
    elif n=='g_pSteamClientGameServer': print('#pragma comment(linker, "/export:%s=%s.%s,DATA")'%(n,REAL,n))
    else: print('#pragma comment(linker, "/export:%s=%s.%s")'%(n,REAL,n))
print('#endif')
