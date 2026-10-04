#!/usr/bin/env bash
# Run as root from a GitHub clone. Never accepts a workstation archive.
set -euo pipefail
[[ $(id -u) == 0 ]]
[[ $(git remote get-url origin) == https://github.com/ash-gram/cubetastic.git ]]
for name in cubetastic cubetastic-build; do
  id "$name" >/dev/null 2>&1 || useradd --system --home-dir "/var/lib/$name" --create-home --shell /usr/sbin/nologin "$name"
done
install -d -m 750 -o cubetastic -g cubetastic /var/lib/cubetastic
install -d -m 700 /etc/cubetastic /var/backups/cubetastic
install -d -m 755 /opt/cubetastic/releases /var/www/cubetastic-acme
if [[ ! -s /etc/cubetastic/app.env ]]; then
  (umask 077
  python3 -c 'import secrets; print("SECRET_KEY="+secrets.token_urlsafe(48)); print("DATABASE_PATH=/var/lib/cubetastic/cubetastic.sqlite3\nCOOKIE_SECURE=1\nTRUST_PROXY=1")' > /etc/cubetastic/app.env
  )
fi
install -m 644 ops/cubetastic.service /etc/systemd/system/cubetastic.service
install -m 644 ops/cubetastic-deploy.service ops/cubetastic-deploy.timer ops/cubetastic-backup.service ops/cubetastic-backup.timer /etc/systemd/system/
install -m 755 ops/deploy.sh /usr/local/sbin/cubetastic-deploy
systemctl daemon-reload
/usr/local/sbin/cubetastic-deploy
# Issue a certificate using a separate nginx virtual host and ACME webroot.
if [[ ! -s /etc/letsencrypt/live/cubetastic.duckdns.org/fullchain.pem ]]; then
  install -m 644 ops/nginx-http.conf /etc/nginx/sites-available/cubetastic
  ln -sfn /etc/nginx/sites-available/cubetastic /etc/nginx/sites-enabled/cubetastic
  nginx -t
  systemctl reload nginx
  certbot certonly --webroot -w /var/www/cubetastic-acme -d cubetastic.duckdns.org --non-interactive --agree-tos --register-unsafely-without-email
fi
install -m 644 ops/nginx.conf /etc/nginx/sites-available/cubetastic
ln -sfn /etc/nginx/sites-available/cubetastic /etc/nginx/sites-enabled/cubetastic
nginx -t
systemctl reload nginx
systemctl enable --now cubetastic cubetastic-deploy.timer cubetastic-backup.timer
systemctl start cubetastic-backup.service
curl --fail --silent --show-error https://cubetastic.duckdns.org/healthz
