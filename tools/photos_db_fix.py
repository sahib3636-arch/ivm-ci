#!/usr/bin/env python3
"""photos_db_fix.py <Photos.sqlite on a READ-WRITE mount>

CoreData hands out Z_PK = Z_PRIMARYKEY.Z_MAX + 1 per entity. Several entities share one table
(GenericAlbum hierarchy: ZGENERICALBUM holds Z_ENT 26, 31, 32 rows), and in the setupdone base image
their Z_MAX counters are 0 while the table already holds Z_PK up to 38 -> the next insert collides
("Constraint unique violation" -> optimistic locking failure).

Fix, raise-only (safe to run more than once):
  * every entity that stores rows in a shared table gets its own disjoint Z_PK range:
    entity k (sorted by Z_ENT) gets Z_MAX >= (k+1) * 1_000_000, so sibling inserts can never collide.
  * any entity whose counter is behind the table's max Z_PK is raised to that max.
"""
import sqlite3
import sys

RANGE = 1_000_000
db = sys.argv[1]
con = sqlite3.connect(db)
con.execute('PRAGMA journal_mode=WAL')
pk = {ent: zmax for ent, zmax in con.execute('SELECT Z_ENT, Z_MAX FROM Z_PRIMARYKEY')}
tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Z%'")]
changes = []


def raise_to(ent, val):
    cur = pk.get(ent, 0)
    if cur < val:
        con.execute('UPDATE Z_PRIMARYKEY SET Z_MAX=? WHERE Z_ENT=?', (val, ent))
        changes.append((ent, cur, val))
        pk[ent] = val


for t in sorted(tables):
    cols = [r[1] for r in con.execute(f'PRAGMA table_info("{t}")')]
    if 'Z_PK' not in cols or 'Z_ENT' not in cols:
        continue
    mx = con.execute(f'SELECT MAX(Z_PK) FROM "{t}"').fetchone()[0]
    if mx is None:
        continue
    ents = sorted(e for (e,) in con.execute(f'SELECT DISTINCT Z_ENT FROM "{t}"').fetchall())
    for k, e in enumerate(ents):
        base = (k + 1) * RANGE if len(ents) > 1 else 0
        raise_to(e, max(mx, base))
con.commit()
con.execute('PRAGMA wal_checkpoint(TRUNCATE)')
print('integrity:', con.execute('PRAGMA integrity_check').fetchone()[0])
print('changes (ent, old, new):', changes if changes else 'nothing to change')
con.close()
