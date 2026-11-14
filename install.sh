#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

[[ ${EUID} -eq 0 ]] || { echo 'Run with sudo bash install.sh'; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'Ubuntu/Debian with systemd is required.'; exit 1; }
. /etc/os-release
[[ ${ID} == ubuntu || ${ID} == debian ]] || { echo 'Ubuntu or Debian is required.'; exit 1; }
case "$(uname -m)" in
  x86_64) ARCH=amd64; SHA=699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968 ;;
  aarch64|arm64) ARCH=arm64; SHA=436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26 ;;
  *) echo 'AMD64 or ARM64 is required.'; exit 1 ;;
esac
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates python3 tar util-linux
install -d -m 755 /opt/tailscale-proxy
exec 9>/run/lock/tailscale-proxy-install.lock
flock -n 9 || { echo 'Another installation is running.'; exit 1; }
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

# Resolve main once; all downloaded source files use that immutable commit.
REPO=https://api.github.com/repos/waqaarhussain/tailscale-proxy
curl -fsSL --retry 3 "$REPO/commits/main" -o "$STAGE/commit.json"
REV=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha"])' "$STAGE/commit.json")
[[ $REV =~ ^[0-9a-f]{40}$ ]] || { echo 'Invalid source revision.'; exit 1; }
for FILE in manager.py tailscale-proxy@.service README.md install.sh; do
  curl -fsSL --retry 3 "https://raw.githubusercontent.com/waqaarhussain/tailscale-proxy/$REV/$FILE" -o "$STAGE/$FILE"
done
bash -n "$STAGE/install.sh"
python3 -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "$STAGE/manager.py"
VERSION=1.14.4
curl -fsSL --retry 3 "https://github.com/SagerNet/sing-box/releases/download/v$VERSION/sing-box-$VERSION-linux-$ARCH.tar.gz" -o "$STAGE/sing-box.tar.gz"
printf '%s  %s\n' "$SHA" "$STAGE/sing-box.tar.gz" | sha256sum -c -
tar -xzf "$STAGE/sing-box.tar.gz" -C "$STAGE"
ENGINE="$STAGE/sing-box-$VERSION-linux-$ARCH/sing-box"
"$ENGINE" version | grep -q with_tailscale || { echo 'Engine is missing Tailscale support.'; exit 1; }
getent group tailscale-proxy >/dev/null || groupadd --system tailscale-proxy
id tailscale-proxy >/dev/null 2>&1 || useradd --system --gid tailscale-proxy --home-dir /var/lib/tailscale-proxy --shell /usr/sbin/nologin tailscale-proxy
install -d -m 750 -o root -g tailscale-proxy /etc/tailscale-proxy /etc/tailscale-proxy/exits
install -d -m 750 -o root -g tailscale-proxy /var/lib/tailscale-proxy /var/lib/tailscale-proxy/nodes
for CONFIG in /etc/tailscale-proxy/exits/*.json; do
  [[ -f $CONFIG ]] || continue
  "$ENGINE" check -c "$CONFIG"
done
install -m 755 "$ENGINE" /opt/tailscale-proxy/sing-box.new
mv /opt/tailscale-proxy/sing-box.new /opt/tailscale-proxy/sing-box
install -m 755 "$STAGE/manager.py" /opt/tailscale-proxy/manager.py
install -m 644 "$STAGE/README.md" /opt/tailscale-proxy/README.md
install -m 644 "$STAGE/tailscale-proxy@.service" /etc/systemd/system/tailscale-proxy@.service
printf '%s\n' "$REV" > /opt/tailscale-proxy/REVISION
cat > /usr/local/bin/tailscale-proxy <<'WRAPPER'
#!/usr/bin/env bash
exec python3 /opt/tailscale-proxy/manager.py "$@"
WRAPPER
chmod 755 /usr/local/bin/tailscale-proxy
for CMD in add manage bench check; do
  # Never take over helpers belonging to an existing installation.
  if [[ ! -e /usr/local/bin/$CMD && ! -L /usr/local/bin/$CMD ]]; then
    printf '#!/usr/bin/env bash\nexec /usr/local/bin/tailscale-proxy %s "$@"\n' "$CMD" > "/usr/local/bin/$CMD"
    chmod 755 "/usr/local/bin/$CMD"
  fi
done
systemctl daemon-reload
/usr/local/bin/tailscale-proxy restart-all
echo
echo 'Tailscale Proxy installed. One VPS, one Tailscale exit node per proxy.'
echo '45.88.89.23 bypass: DIRECT through the VPS.'
echo 'Commands: add | manage | bench | check'
echo
if [[ ${1:-} == --no-add ]]; then
  echo 'Run: sudo tailscale-proxy add'
elif [[ -r /dev/tty && -w /dev/tty ]]; then
  read -r -p 'Add a proxy exit now? [Y/n]: ' ANSWER < /dev/tty || ANSWER=n
  if [[ ${ANSWER,,} != n && ${ANSWER,,} != no ]]; then
    /usr/local/bin/tailscale-proxy add < /dev/tty
  fi
else
  echo 'Run: sudo tailscale-proxy add'
fi
