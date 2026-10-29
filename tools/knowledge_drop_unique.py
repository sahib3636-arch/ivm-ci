#!/usr/bin/env python3
"""knowledge_drop_unique.py <knowledgeC.db>: drop every UNIQUE index in the CoreDuet knowledge store (Option 1 test 2).
Rows stay; CoreData's unique-constraint updates then no longer raise 'Constraint unique violation'."""
import sqlite3
import sys

c = sqlite3.connect(sys.argv[1])
idx = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='index' AND sql LIKE '%UNIQUE%'")]
for i in idx:
    c.execute('DROP INDEX IF EXISTS "%s"' % i)
c.commit()
print('dropped unique indexes:', idx)
print('remaining indexes:', [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='index'")])
print('integrity:', c.execute('PRAGMA integrity_check').fetchone()[0])
