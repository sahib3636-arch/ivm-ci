#!/usr/bin/env python3
"""s43 kernel trap PCs, resolved at run time from the guest kernelcache (no hardcoded symbols).

usage: kernel-trap-pcs.py <kernelcache(IM4P)> <outdir>
stdout: shell exports  IVM_KTRACE / IVM_KTRACE_SAVE / IVM_KTRACE_NOSS / IVM_KTRACE_N
outdir: ksyms-pick.txt (resolved name -> VA) and kernel-raw.bin is NOT kept.
Kernel symtab VAs are used as-is (kaslr-off), checked against known values (_handle_breakpoint 0xfffffff007b57de4)."""
import sys, os, struct, lzfse

def read_len(d, p):
    l = d[p]; p += 1
    if l & 0x80:
        n = l & 0x7f; l = int.from_bytes(d[p:p+n], 'big'); p += n
    return l, p

def im4p_payload(path):
    d = open(path, 'rb').read()
    assert d[0] == 0x30, 'not an IM4P SEQUENCE'
    top, p = read_len(d, 1)
    els, off, end = [], p, p + top
    while off < end:
        tag = d[off]; l, q = read_len(d, off + 1); els.append((tag, q, l)); off = q + l
    assert d[els[0][1]:els[0][1]+4] == b'IM4P'
    tag, q, l = els[3]
    assert tag == 0x04, 'payload not OCTET STRING'
    return d[q:q+l]

def symbols(k):
    ncmds = struct.unpack('<I', k[16:20])[0]; off = 32; out = {}
    for _ in range(ncmds):
        cmd, cs = struct.unpack('<II', k[off:off+8])
        if cmd == 0x2:
            symoff, nsyms, stroff, _ = struct.unpack('<IIII', k[off+8:off+24])
            for i in range(nsyms):
                n_strx, n_type, _s, _d, n_value = struct.unpack('<IBBHQ', k[symoff+i*16:symoff+i*16+16])
                if n_value and (n_type & 0x0e):
                    name = k[stroff+n_strx:k.index(b'\0', stroff+n_strx)].decode('utf8', 'replace')
                    out.setdefault(name, n_value)
            break
        off += cs
    return out

def main():
    src, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    payload = im4p_payload(src)
    if payload[:4] not in (b'bvx2', b'bvx1', b'bvxn'):
        sys.exit('kernel payload not LZFSE (magic %r)' % payload[:4])
    k = lzfse.decompress(payload)
    syms = symbols(k)
    want = {'_sleh_synchronous': 0xfffffff007b569a0, '_handle_breakpoint': 0xfffffff007b57de4,
            '_exception_triage': 0xfffffff007a2c850, '_psignal_internal': None,
            '_memorystatus_do_kill': None, '_exit1': None}
    pick = {}
    for n in want:
        pick[n] = syms.get(n)
    if pick['_handle_breakpoint'] != want['_handle_breakpoint']:
        sys.exit('symtab check failed: _handle_breakpoint %r' % pick['_handle_breakpoint'])
    with open(os.path.join(outdir, 'ksyms-pick.txt'), 'w') as f:
        for n, v in pick.items():
            f.write('%s %s\n' % (n, hex(v) if v else 'MISSING'))
    # data abort call site inside handle_user_abort (s42) + the three hooks; signal/exit/memorystatus print regs only
    pcs = [pick['_sleh_synchronous'], 0xfffffff007b57734, pick['_handle_breakpoint'], pick['_exception_triage'],
           pick['_psignal_internal'], pick['_memorystatus_do_kill'], pick['_exit1']]
    pcs = [p for p in pcs if p]
    noss = [pick[n] for n in ('_psignal_internal', '_memorystatus_do_kill', '_exit1') if pick[n]]
    print('export IVM_KTRACE=%s' % ','.join('%x' % p for p in pcs))
    print('export IVM_KTRACE_SAVE=%x' % pick['_sleh_synchronous'])
    print('export IVM_KTRACE_SS=1')
    print('export IVM_KTRACE_NOSS=%s' % ','.join('%x' % p for p in noss))
    print('export IVM_KTRACE_N=20000')

if __name__ == '__main__':
    main()
