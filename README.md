# Standalone Cubetastic

Fork of [cubetastic33/cubetastic](https://github.com/cubetastic33/cubetastic), retaining the MIT license and original timer, scrambles, statistics, themes and browser-only mode.

Website: https://cubetastic.duckdns.org

## Accounts and data

Flask + Gunicorn + SQLite, with no Firebase project or cloud database. Passwords use Werkzeug scrypt hashes. Account recovery uses a one-time recovery code shown at signup; no mail provider is required. Recovery revokes old sessions and rotates the code. Password changes and logout revoke server-side sessions. Cookies are Secure, HttpOnly and SameSite=Lax, writes require CSRF tokens, and APIs scope every solve to the signed-in account. Login, signup, recovery and feedback are rate limited in SQLite across workers.

Guest solves stay in the browser's IndexedDB. Signed-in solves and saved settings sync through the server (10-second polling, plus refresh after writes). Guest solves are not silently uploaded at login. Existing import/export features remain available. Session names and current view preferences are device-local and partitioned by account. Google sign-in is optional. Google profiles show their avatar and verified email; password accounts can explicitly connect a matching Google account from their profile. Push messaging was removed. Password-account email addresses are account identifiers and are not verified until Google is connected.

## Local development

Use Python 3.12+, create a virtual environment, and install `requirements.lock`. Set a random `SECRET_KEY` and `COOKIE_SECURE=0` for localhost development, then run `flask --app app:create_app run`. Tests: `python -m unittest discover -s tests -v`.

## Deployment

The app is separate from other sites on the Oracle VM. Runtime user `cubetastic`; loopback port 8033; source `/opt/cubetastic/source`; versioned releases `/opt/cubetastic/releases`; persistent SQLite `/var/lib/cubetastic/cubetastic.sqlite3`; protected configuration `/etc/cubetastic/app.env`.

All source travels **PC → GitHub → server**. Never use SCP/SFTP/rsync or send local scripts through SSH stdin. SSH only invokes control commands. On the server, clone `https://github.com/ash-gram/cubetastic.git` into `/opt/cubetastic/source`, then run `sudo bash ops/bootstrap.sh` from that clone. nginx, certbot, Python 3 with venv, git, and node must already be installed. The bootstrap creates its own Linux users, database directory, random secret, nginx host, certificate and services. It does not modify other apps' configuration.

## Updates

GitHub Actions checks upstream hourly at minute 23 (schedules may be delayed by GitHub). It merges `cubetastic33/cubetastic:master`, runs isolation/auth/persistence tests, browser regression checks and syntax checks, and pushes only a passing merge to this fork. Conflicts or failing tests stop the workflow for review; they never overwrite the standalone changes. Check the repository Actions tab for failures. The specific workflow requests write access to this repository's contents. After 30 quiet days, a passing run makes an empty maintenance commit to keep the public fork active; GitHub can otherwise disable schedules after 60 days of inactivity. If a workflow remains broken or is disabled, resolve the failure and re-enable it in Actions.

The independent server timer checks this fork every five minutes. Each new revision builds in its own release, runs tests as an unprivileged build user, backs up the database, and activates only after checks pass. The health check verifies the exact revision and rolls back the application symlink on startup failure. Database schema rollback is not automatic; future migrations must remain backward-compatible. Failed revisions are recorded and skipped until a new commit or an explicit `sudo env FORCE=1 /usr/local/sbin/cubetastic-deploy` retry.

Commands: `systemctl status cubetastic cubetastic-deploy.timer`; `journalctl -u cubetastic-deploy`; `sudo systemctl start cubetastic-deploy`; `curl https://cubetastic.duckdns.org/healthz`.

Live account/persistence check: `sudo python3 /opt/cubetastic/current/ops/smoke.py`. It generates temporary credentials on the server, tests signup/login/solve persistence/logout over HTTPS, and removes only its own test account. Local browser check: install Playwright, run the development server, then `node tests/browser-check.cjs` (set `BROWSER_CHANNEL=chromium` for bundled Chromium). `READ_ONLY=1 BASE_URL=https://cubetastic.duckdns.org` tests the live guest timer without creating an account.

## Backups and recovery

The server takes an online SQLite backup before releases and nightly, checks its integrity and table readability, and keeps 14 copies in root-only `/var/backups/cubetastic`. These copies stay on the same VM. To restore, stop `cubetastic`, preserve the current database plus WAL/SHM files, restore a verified snapshot with owner `cubetastic`, remove only the old WAL/SHM files after preserving them, and restart. Preserve `/etc/cubetastic/app.env` for session signing; database passwords remain usable if that secret is rotated (existing cookies are invalidated).

DNS: point `cubetastic.duckdns.org` to the Oracle public IP. TLS renews through the existing certbot timer and the independent ACME webroot. No workstation needs to stay running for serving, backups or updates.

## Bundled dependencies

Frontend JavaScript/CSS dependencies are served locally. Added versions: jQuery 3.7.1 (MIT), Material Components Web 14.0.0 (MIT), animate.css 3.5.2 (MIT), noUiSlider 11.1.0 (MIT), video.js CSS 7.1.0 (Apache-2.0). Their original copyright/license headers are retained. The original repository's bundled timer libraries and their license headers remain. Fonts and Material Icons are bundled locally; account and solve API calls are same-origin only. The inherited TNoodle engine requires CSP unsafe-eval and the legacy timer uses inline scripts; external scripts and cross-origin API calls are blocked. The original author's analytics and Firebase endpoints are removed.

## Google sign-in

Use a separate **Web application** OAuth client for Cubetastic:

- Authorized JavaScript origin: `https://cubetastic.duckdns.org`
- Authorized redirect URI: `https://cubetastic.duckdns.org/auth/google/callback`
- Homepage: `https://cubetastic.duckdns.org`

Only `openid email profile` scopes are requested. Authlib validates state, nonce, PKCE and the signed Google identity token. Provider access/refresh tokens are not persisted. The database records Google's stable subject identifier; an email match alone never links an existing account. Existing password users sign in first and choose **Connect Google** in their profile. Google-only users manage password/recovery in Google, and cannot disconnect their only sign-in method. Password users must confirm their current password to disconnect Google. All existing solves remain scoped to the same internal account ID.

Client credentials live only in root-readable `/etc/cubetastic/google.env`, loaded by systemd. The configured callback is fixed, independent of incoming Host headers. OAuth query strings are omitted from both nginx and Gunicorn access logs.

Provisioning follows PC → GitHub → Oracle, with **no direct workstation file transfer**:

1. Commit the provisioning utility. On Oracle run `sudo python3 /opt/cubetastic/source/ops/google_setup.py key`. The private 4096-bit RSA key remains on Oracle; retrieve only its public key.
2. On the PC, read the downloaded Google JSON in memory and encrypt just client ID/secret using RSA-OAEP-SHA256 for that public key. Commit only the resulting `ops/google-client.sealed.json` ciphertext and recipient fingerprint to GitHub. Never commit the plaintext JSON or server private key.
3. Oracle pulls that commit from GitHub and runs `sudo python3 /opt/cubetastic/source/ops/google_setup.py apply`, which writes the protected server environment. Install the service/nginx definitions from the same GitHub checkout and restart Cubetastic.
4. After checking the Google authorization redirect, run the utility's `destroy-key` action on Oracle and remove the delivery ciphertext in a follow-up Git commit. The original downloaded JSON remains on the PC. For rotation, generate a new one-time key and repeat.

Google Cloud consent-screen audience/test-user settings are controlled by the Google project owner. Test-mode clients permit only configured test users. An actual Google account consent/login must be completed by its owner; automated tests exercise callback validation and account linking without signing in as a real person.
