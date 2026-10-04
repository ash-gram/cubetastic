# Standalone Cubetastic

Fork of [cubetastic33/cubetastic](https://github.com/cubetastic33/cubetastic), retaining the MIT license and original timer, scrambles, statistics, themes and browser-only mode.

Website: https://cubetastic.duckdns.org

## Accounts and data

Flask + Gunicorn + SQLite, with no Firebase project or cloud database. Passwords use Werkzeug scrypt hashes. Account recovery uses a one-time recovery code shown at signup; no mail provider is required. Recovery revokes old sessions and rotates the code. Password changes and logout revoke server-side sessions. Cookies are Secure, HttpOnly and SameSite=Lax, writes require CSRF tokens, and APIs scope every solve to the signed-in account. Login, signup, recovery and feedback are rate limited in SQLite across workers.

Guest solves stay in the browser's IndexedDB. Signed-in solves and saved settings sync through the server (10-second polling, plus refresh after writes). Guest solves are not silently uploaded at login. Existing import/export features remain available. Session names and current view preferences are device-local and partitioned by account. Profile pictures use the default avatar; external social login and push messaging were removed. Emails are account identifiers and are not verified.

## Local development

Use Python 3.12+, create a virtual environment, and install `requirements.lock`. Set a random `SECRET_KEY` and `COOKIE_SECURE=0` for localhost development, then run `flask --app app:create_app run`. Tests: `python -m unittest discover -s tests -v`.

## Deployment

The app is separate from other sites on the Oracle VM. Runtime user `cubetastic`; loopback port 8033; source `/opt/cubetastic/source`; versioned releases `/opt/cubetastic/releases`; persistent SQLite `/var/lib/cubetastic/cubetastic.sqlite3`; protected configuration `/etc/cubetastic/app.env`.

All source travels **PC → GitHub → server**. Never use SCP/SFTP/rsync or send local scripts through SSH stdin. SSH only invokes control commands. On the server, clone `https://github.com/ash-gram/cubetastic.git` into `/opt/cubetastic/source`, then run `sudo bash ops/bootstrap.sh` from that clone. nginx, certbot, Python 3 with venv, git, and node must already be installed. The bootstrap creates its own Linux users, database directory, random secret, nginx host, certificate and services. It does not modify other apps' configuration.

## Updates

GitHub Actions checks upstream hourly at minute 23 (schedules may be delayed by GitHub). It merges `cubetastic33/cubetastic:master`, runs isolation/auth/persistence tests and syntax checks, and pushes only a passing merge to this fork. Conflicts or failing tests stop the workflow for review; they never overwrite the standalone changes. Check the repository Actions tab for failures. Enable Actions in the fork and allow its workflow token to write contents. GitHub may disable schedules after 60 days of repository inactivity; re-enable the workflow in Actions if this happens.

The independent server timer checks this fork every five minutes. Each new revision builds in its own release, runs tests as an unprivileged build user, backs up the database, and activates only after checks pass. The health check verifies the exact revision and rolls back the application symlink on startup failure. Database schema rollback is not automatic; future migrations must remain backward-compatible. Failed revisions are recorded and skipped until a new commit or an explicit `sudo env FORCE=1 /usr/local/sbin/cubetastic-deploy` retry.

Commands: `systemctl status cubetastic cubetastic-deploy.timer`; `journalctl -u cubetastic-deploy`; `sudo systemctl start cubetastic-deploy`; `curl https://cubetastic.duckdns.org/healthz`.

## Backups and recovery

The server takes an online SQLite backup before releases and nightly, checks its integrity and table readability, and keeps 14 copies in root-only `/var/backups/cubetastic`. These copies stay on the same VM. To restore, stop `cubetastic`, preserve the current database plus WAL/SHM files, restore a verified snapshot with owner `cubetastic`, remove only the old WAL/SHM files after preserving them, and restart. Preserve `/etc/cubetastic/app.env` for session signing; database passwords remain usable if that secret is rotated (existing cookies are invalidated).

DNS: point `cubetastic.duckdns.org` to the Oracle public IP. TLS renews through the existing certbot timer and the independent ACME webroot. No workstation needs to stay running for serving, backups or updates.

## Bundled dependencies

Frontend JavaScript/CSS dependencies are served locally. Added versions: jQuery 3.7.1 (MIT), Material Components Web 14.0.0 (MIT), animate.css 3.5.2 (MIT), noUiSlider 11.1.0 (MIT), video.js CSS 7.1.0 (Apache-2.0). Their original copyright/license headers are retained. The original repository's bundled timer libraries and their license headers remain. Fonts and Material Icons are bundled locally; account and solve API calls are same-origin only. The inherited TNoodle engine requires CSP unsafe-eval and the legacy timer uses inline scripts; external scripts and cross-origin API calls are blocked. The original author's analytics and Firebase endpoints are removed.
