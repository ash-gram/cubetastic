"""Online SQLite snapshot with integrity check; keep 14 server-local copies."""
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

os.umask(0o077)
source = Path('/var/lib/cubetastic/cubetastic.sqlite3')
folder = Path('/var/backups/cubetastic')
folder.mkdir(mode=0o700, parents=True, exist_ok=True)
destination = folder / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.sqlite3')
with sqlite3.connect(f'file:{source}?mode=ro', uri=True) as src, sqlite3.connect(destination) as backup:
    src.backup(backup)
    assert backup.execute('PRAGMA integrity_check').fetchone()[0] == 'ok', 'Backup integrity check failed'
    backup.execute('SELECT count(*) FROM users').fetchone()
    backup.execute('SELECT count(*) FROM solves').fetchone()
for old in sorted(folder.glob('*.sqlite3'), reverse=True)[14:]:
    old.unlink()
print('Verified backup:', destination.name)
