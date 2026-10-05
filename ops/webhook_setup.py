"""Create the webhook secret on Oracle; print only when explicitly registering GitHub."""
import os
from pathlib import Path
import secrets
import sys
if os.geteuid() != 0:
    raise SystemExit('Run on the server as root.')
os.umask(0o077)
path = Path('/etc/cubetastic/webhook.env')
if not path.exists():
    path.write_text('GITHUB_WEBHOOK_SECRET=' + secrets.token_hex(32) + '\n')
    path.chmod(0o600)
if '--register' in sys.argv:
    print(path.read_text().strip().split('=', 1)[1])
else:
    print('Server-owned webhook secret ready.')
