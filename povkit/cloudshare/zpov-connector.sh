#!/bin/bash
# Zscaler POV Kit: a ZPA App Connector on a CloudShare (or any) Rocky Linux / RHEL 9 machine.
#
# Two steps, so the machine can be saved as a CloudShare blueprint in between with no customer values in it:
#   prepare             once, when building the blueprint: Zscaler's package source and the zpa-connector package
#   enroll KEY [IP]     per POV, on each connector: the POV's provisioning key (from the POV console), and the test
#                       app's address so pov-app.zpov.internal resolves on this connector
#
#   curl -fsSL https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/zpov-connector.sh | sudo bash -s -- prepare
#
# The steps are Zscaler's (App Connector Deployment Guide for Linux): the EL9 repository yum.private.zscaler.com,
# signed with Zscaler's key (fingerprint a6fe 2422 fce7 e8ac 672e 9e51 644e a315 8765 e1dd, checked below), then the
# provisioning key in /opt/zscaler/var/provision_key and the zpa-connector service. Nothing here touches the tenant.
set -euo pipefail
FPR="A6FE2422FCE7E8AC672E9E51644EA3158765E1DD"
say() { printf '  %s\n' "$*"; }
fail() { printf '\n  %s\n\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail "Run it with sudo."
cmd="${1:-}"; shift || true

case "$cmd" in
prepare)
  . /etc/os-release
  case "${VERSION_ID%%.*}" in 9) EL=el9 ;; 8) EL=el8 ;; *) fail "Zscaler's App Connector packages are for RHEL / Rocky 8 or 9 (this is ${PRETTY_NAME:-unknown})." ;; esac
  cat > /etc/yum.repos.d/zscaler.repo <<EOF
[zscaler]
name=Zscaler Private Access Repository
baseurl=https://yum.private.zscaler.com/yum/$EL
enabled=1
gpgcheck=1
gpgkey=https://yum.private.zscaler.com/yum/$EL/gpg
EOF
  curl -fsSL "https://yum.private.zscaler.com/yum/$EL/gpg" -o /tmp/zscaler.gpg
  GOT="$(gpg --with-colons --import-options show-only --import --fingerprint /tmp/zscaler.gpg 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')"
  [ "$GOT" = "$FPR" ] || fail "Zscaler's package key has fingerprint '$GOT', not the one in Zscaler's guide. Nothing installed."
  rpm --import /tmp/zscaler.gpg
  say "Zscaler's package key checked ($FPR)"
  dnf -y -q install zpa-connector
  systemctl disable --now zpa-connector 2>/dev/null || true
  rm -f /opt/zscaler/var/*     # empty, as Zscaler's guide asks, so each copy of the blueprint enrolls on its own
  say "zpa-connector installed and not enrolled. Save the machine (or the CloudShare blueprint) now."
  ;;
enroll)
  KEY="${1:-}"; APP_IP="${2:-}"
  [ ${#KEY} -ge 20 ] || fail "Give the POV's provisioning key: POV console > Get ready to test > ZPA App Connectors > Show the key."
  rpm -q zpa-connector >/dev/null || fail "Run 'prepare' first."
  systemctl stop zpa-connector 2>/dev/null || true
  rm -f /opt/zscaler/var/*
  install -m 644 /dev/null /opt/zscaler/var/provision_key
  printf '%s\n' "$KEY" > /opt/zscaler/var/provision_key
  if [ -n "$APP_IP" ]; then
    [[ "$APP_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || fail "The test app's address is an IPv4 address (zpov-test-app.sh shows it)."
    sed -i '/pov-app\.zpov\.internal/d' /etc/hosts
    echo "$APP_IP pov-app.zpov.internal" >> /etc/hosts
    say "pov-app.zpov.internal -> $APP_IP on this connector"
  fi
  systemctl enable --now zpa-connector
  say "Enrolling with the POV's key. It shows in the POV's connector group within about 10 minutes."
  ;;
*)
  fail "Use: zpov-connector.sh prepare | enroll KEY [TEST_APP_IP]"
  ;;
esac
