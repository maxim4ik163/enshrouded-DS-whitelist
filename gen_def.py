#!/usr/bin/env python3
# Regenerate steam_api64.def from a (new) original steam_api64.dll.
# Usage:  python3 gen_def.py  path\to\original\steam_api64.dll  > steam_api64.def
# Run this only if a Steam update changes steam_api64.dll and the server
# fails to start with a "missing export" error.
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
eo=r2f(exp_rva); ordbase=struct.unpack_from('<I',d,eo+16)[0]
nname=struct.unpack_from('<I',d,eo+24)[0]
funcs=r2f(struct.unpack_from('<I',d,eo+28)[0]); names=r2f(struct.unpack_from('<I',d,eo+32)[0]); ords=r2f(struct.unpack_from('<I',d,eo+36)[0])
rows=[]
for i in range(nname):
    nfo=r2f(struct.unpack_from('<I',d,names+4*i)[0]); e=d.find(b'\0',nfo); nm=d[nfo:e].decode('latin1')
    rows.append((ordbase+struct.unpack_from('<H',d,ords+2*i)[0], nm))
rows.sort()
print('LIBRARY steam_api64'); print('EXPORTS')
for o,n in rows:
    if n==HOOK:                       print('    %s=My_FindOrCreateGameServerInterface'%n)
    elif n=='g_pSteamClientGameServer': print('    %s=%s.%s DATA'%(n,REAL,n))
    else:                             print('    %s=%s.%s'%(n,REAL,n))
