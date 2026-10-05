#!/usr/bin/env bash
set -euo pipefail
umask 022
exec 9>/run/lock/cubetastic-deploy.lock
flock -n 9 || exit 0
rm -f /var/lib/cubetastic/deploy-request
source_dir=/opt/cubetastic/source
cd "$source_dir"
[[ $(git remote get-url origin) == https://github.com/ash-gram/cubetastic.git ]]
git fetch --quiet origin main
revision=$(git rev-parse origin/main)
[[ $revision =~ ^[a-f0-9]{40}$ ]]
previous=''
if [[ -L /opt/cubetastic/current ]]; then previous=$(readlink -f /opt/cubetastic/current); fi
if [[ -f /opt/cubetastic/current/REVISION && $(cat /opt/cubetastic/current/REVISION) == "$revision" ]]; then exit 0; fi
if [[ ${FORCE:-0} != 1 && -f /opt/cubetastic/failed_revision && $(cat /opt/cubetastic/failed_revision) == "$revision" ]]; then echo "Revision $revision previously failed; push a fix or retry with FORCE=1" >&2; exit 1; fi
release="/opt/cubetastic/releases/$revision"
activated=0
failed() {
  code=$?
  trap - ERR
  printf '%s\n' "$revision" > /opt/cubetastic/failed_revision
  if [[ $activated == 1 ]]; then
    if [[ -n $previous && -d $previous ]]; then
      ln -sfn "$previous" /opt/cubetastic/next
      mv -Tf /opt/cubetastic/next /opt/cubetastic/current
      install -m 644 "$previous/ops/cubetastic.service" /etc/systemd/system/cubetastic.service
      systemctl daemon-reload
      systemctl restart cubetastic || true
    else systemctl stop cubetastic || true; fi
  fi
  exit "$code"
}
trap failed ERR
install -d -m 755 "$release"
git archive "$revision" | tar -x -C "$release"
printf '%s\n' "$revision" > "$release/REVISION"
printf 'RELEASE_SHA=%s\n' "$revision" > "$release/release.env"
# Dependency installation and application checks never run as root.
chown -R cubetastic-build:cubetastic-build "$release"
runuser -u cubetastic-build -- python3 -m venv "$release/.venv"
runuser -u cubetastic-build -- "$release/.venv/bin/pip" install --disable-pip-version-check -r "$release/requirements.lock"
(cd "$release" && runuser -u cubetastic-build -- .venv/bin/python -m unittest discover -s tests -v)
for script in main profile loggedStatus timer; do node --check "$release/js/$script.js"; done
bash -n "$release/ops/deploy.sh" "$release/ops/bootstrap.sh"
runuser -u cubetastic-build -- "$release/.venv/bin/python" "$release/ops/build_assets.py"
chown -R root:root "$release"
chmod -R go-w "$release"
runuser -u cubetastic -- "$release/.venv/bin/gunicorn" --version
if [[ -f /var/lib/cubetastic/cubetastic.sqlite3 ]]; then python3 "$release/ops/backup.py"; fi
ln -sfn "$release" /opt/cubetastic/next
mv -Tf /opt/cubetastic/next /opt/cubetastic/current
activated=1
install -m 644 "$release/ops/cubetastic.service" /etc/systemd/system/cubetastic.service
systemctl daemon-reload
systemctl restart cubetastic
healthy=0
for attempt in $(seq 1 30); do
  if [[ $(curl --fail --silent http://127.0.0.1:8033/healthz/revision || true) == "$revision" ]]; then healthy=1; break; fi
  sleep 1
done
[[ $healthy == 1 ]]
# Advance operations only after the candidate has passed all release checks.
git merge --ff-only "$revision"
install -m 755 "$release/ops/deploy.sh" /usr/local/sbin/cubetastic-deploy
rm -f /opt/cubetastic/failed_revision
trap - ERR
echo "Cubetastic activated $revision"
