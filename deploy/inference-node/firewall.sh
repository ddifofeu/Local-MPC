#!/usr/bin/env bash
# Allow the mTLS gateway (8443) ONLY from the orchestrator host.
# Docker-published ports are DNAT'ed before INPUT, so ufw/INPUT rules do not apply:
# the DOCKER-USER chain is the supported place to filter them.
# Usage: sudo ORCH_IP=<orchestrator LAN IP> ./firewall.sh
set -euo pipefail
: "${ORCH_IP:?set ORCH_IP to the orchestrator host LAN address}"

iptables -N DOCKER-USER 2>/dev/null || true
# idempotent: remove previous copies of our rules
while iptables -D DOCKER-USER -p tcp -m conntrack --ctorigdstport 8443 ! -s "$ORCH_IP" -j DROP 2>/dev/null; do :; done
while iptables -D DOCKER-USER -p tcp -m conntrack --ctorigdstport 8443 ! -s "$ORCH_IP" -j LOG --log-prefix "M-NODE-DENY " 2>/dev/null; do :; done
iptables -I DOCKER-USER 1 -p tcp -m conntrack --ctorigdstport 8443 ! -s "$ORCH_IP" -j DROP
iptables -I DOCKER-USER 1 -p tcp -m conntrack --ctorigdstport 8443 ! -s "$ORCH_IP" -j LOG --log-prefix "M-NODE-DENY "

# Legacy exposure: make sure nothing answers on the old plaintext ports.
for p in 8000 8001 11434; do
  if ss -ltnH "sport = :$p" | grep -q .; then
    echo "WARNING: something is still listening on :$p — stop it (old Ollama?)" >&2
  fi
done
iptables -S DOCKER-USER
