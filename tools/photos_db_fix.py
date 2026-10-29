#!/usr/bin/env python3
"""photos_db_fix.py <Photos.sqlite on a READ-WRITE mount>
CoreData hands out Z_PK = Z_PRIMARYKEY.Z_MAX + 1. In the setupdone base image three entities
(GenericAlbum, Z_ENT 26/31/32) have Z_MAX = 0 while their table already holds Z_PK up to 38, so the
next insert collides ("Constraint unique violation" -> optimistic locking failure).
Fix: raise Z_MAX to the real max Z_PK of each entity's table (only where it is behind)."""
import sqlite3, sys

db = sys.argv[1]
con = sqlite3.connect(db)
con.execute('PRAGMA journal_mode=WAL')
fixed = []
pk = {ent: zmax for ent, zmax in con.execute('SELECT Z_ENT, Z_MAX FROM Z_PRIMARYKEY')}
tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Z%'")]
for t in sorted(tables):
    cols = [r[1] for r in con.execute(f'PRAGMA table_info("{t}")')]
    if 'Z_PK' not in cols or 'Z_ENT' not in cols:
        continue
    mx = con.execute(f'SELECT MAX(Z_PK) FROM "{t}"').fetchone()[0]
    if mx is None:
        continue
    for (e,) in con.execute(f'SELECT DISTINCT Z_ENT FROM "{t}"').fetchall():
        if pk.get(e, 0) < mx:
            con.execute('UPDATE Z_PRIMARYKEY SET Z_MAX=? WHERE Z_ENT=?', (mx, e))
            fixed.append((t, e, pk.get(e), mx))
con.commit()
con.execute('PRAGMA wal_checkpoint(TRUNCATE)')
print('integrity:', con.execute('PRAGMA integrity_check').fetchone()[0])
print('fixed:', fixed if fixed else 'nothing to fix')
con.close()
