#!/usr/bin/env python3
"""photos_db_dump.py <root raw image> <container offset> <out dir>
Reads Photos.sqlite (+ -wal/-shm) from the iVM Data volume with pyfsapfs (no mount), then checks
CoreData key counters (Z_PRIMARYKEY.Z_MAX vs MAX(Z_PK)) and lists UNIQUE indexes."""
import os, sqlite3, sys
import pyfsapfs


class F:
    def __init__(s, p, o):
        s.f = open(p, 'rb'); s.o = o; s.f.seek(0, 2); s.sz = s.f.tell() - o; s.f.seek(o)
    def read(s, n=-1): return s.f.read(n if n >= 0 else s.sz - s.tell())
    def seek(s, p, w=0):
        if w == 0: s.f.seek(p + s.o)
        elif w == 1: s.f.seek(p, 1)
        else: s.f.seek(s.sz + p + s.o)
    def tell(s): return s.f.tell() - s.o
    def get_size(s): return s.sz


img, off, out = sys.argv[1], int(sys.argv[2], 0), sys.argv[3]
os.makedirs(out, exist_ok=True)
c = pyfsapfs.container(); c.open_file_object(F(img, off))
base = '/private/var/mobile/Media/PhotoData/'
found = None
for vi in range(c.get_number_of_volumes()):
    v = c.get_volume(vi)
    try:
        e = v.get_file_entry_by_path(base + 'Photos.sqlite')
    except Exception:
        e = None
    if e is not None:
        found = vi
        break
print('volumes', c.get_number_of_volumes(), 'Photos.sqlite volume', found)
if found is None:
    sys.exit(3)
v = c.get_volume(found)
for name in ('Photos.sqlite', 'Photos.sqlite-wal', 'Photos.sqlite-shm'):
    try:
        e = v.get_file_entry_by_path(base + name)
    except Exception:
        e = None
    if e is None:
        print('absent', name); continue
    data = e.read_buffer(e.get_size())
    open(os.path.join(out, name), 'wb').write(data)
    print('copied', name, len(data))
db = os.path.join(out, 'Photos.sqlite')
con = sqlite3.connect(db)
rep = open(os.path.join(out, 'report.txt'), 'w')
def w(*a): print(*a); print(*a, file=rep)
w('integrity:', con.execute('PRAGMA integrity_check').fetchall()[:5])
pk = {ent: (name, zmax) for ent, name, zmax in con.execute('SELECT Z_ENT, Z_NAME, Z_MAX FROM Z_PRIMARYKEY')}
w('Z_PRIMARYKEY:', sorted(pk.items()))
for t in sorted(r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Z%'")):
    cols = [r[1] for r in con.execute(f'PRAGMA table_info("{t}")')]
    if 'Z_PK' not in cols or 'Z_ENT' not in cols:
        continue
    n, mx = con.execute(f'SELECT COUNT(*), MAX(Z_PK) FROM "{t}"').fetchone()
    for (e,) in con.execute(f'SELECT DISTINCT Z_ENT FROM "{t}"').fetchall():
        zmax = pk.get(e, ('?', None))[1]
        bad = zmax is not None and mx is not None and zmax < mx
        w(f'{t} ent={e} rows={n} maxZ_PK={mx} Z_MAX={zmax} {"MISMATCH" if bad else "ok"}')
w('unique indexes:')
for row in con.execute("SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index' AND sql LIKE '%UNIQUE%'"):
    w(' ', row)
rep.close()
