#!/usr/bin/env python3
"""sqlite_check.py <CoreData store file (Z_PRIMARYKEY based)>. Read-only report on a copy: integrity, Z_MAX vs real
max Z_PK per entity, rows per entity, and duplicate keys under every UNIQUE index (the constraint a CoreData save
hits with 'Constraint unique violation')."""
import os
import sqlite3
import sys

db = sys.argv[1]
con = sqlite3.connect('file:' + db + '?mode=rw', uri=True)
print('file:', db, os.path.getsize(db))
print('integrity:', con.execute('PRAGMA integrity_check').fetchone()[0])
try:
    pk = {e: (n, m) for e, n, m in con.execute('SELECT Z_ENT, Z_NAME, Z_MAX FROM Z_PRIMARYKEY')}
    print('Z_PRIMARYKEY entities:', len(pk))
except Exception as ex:
    pk = {}
    print('no Z_PRIMARYKEY:', ex)
for t in sorted(r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Z%'")):
    cols = [r[1] for r in con.execute(f'PRAGMA table_info("{t}")')]
    if 'Z_PK' not in cols or 'Z_ENT' not in cols:
        continue
    for e, c, mx in con.execute(f'SELECT Z_ENT, COUNT(*), MAX(Z_PK) FROM "{t}" GROUP BY Z_ENT').fetchall():
        name, zmax = pk.get(e, ('?', None))
        flag = 'MISMATCH' if zmax is not None and mx is not None and zmax < mx else 'ok'
        print(f'{t} ent={e}({name}) rows={c} maxZ_PK={mx} Z_MAX={zmax} {flag}')
for name, tbl, sql in con.execute("SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index' AND sql LIKE '%UNIQUE%'").fetchall():
    cols = [r[2] for r in con.execute(f'PRAGMA index_info("{name}")')]
    if not cols or None in cols:
        print('UNIQUE', name, 'expression index, skipped')
        continue
    cl = ', '.join(f'"{c}"' for c in cols)
    try:
        dup = con.execute(f'SELECT {cl}, COUNT(*) FROM "{tbl}" GROUP BY {cl} HAVING COUNT(*)>1 LIMIT 5').fetchall()
    except Exception as ex:
        dup = 'ERR %s' % ex
    print(f'UNIQUE {name} on {tbl}{tuple(cols)} dups={dup}')
