#!/bin/bash
set -e

# Unified CoreDNS configuration script.
#
# Usage: coredns.sh <apply|reset|break-node-b>
#
# Modes:
#   apply         — Apply working .kels rewrite rules and restart CoreDNS
#   reset         — Remove .kels rewrite rules (idempotent, skips if absent)
#   break-node-b  — Redirect node-b .kels DNS to a non-existent name
#
# Environment:
#   DNS_CACHE_TTL — CoreDNS cache and record TTL in seconds (default: 30).
#                   Set low (e.g. 2) during test-federation so node-level
#                   DNS caches expire quickly after break/repair transitions.

MODE="${1:?Usage: coredns.sh <apply|reset|break-node-b>}"
TTL="${DNS_CACHE_TTL:-30}"

# Idempotency check for reset
case "$MODE" in
  reset)
    if ! kubectl get configmap coredns -n kube-system -o json | jq .data.Corefile | jq -r . | grep -q "registry-"; then
      echo "CoreDNS does not have .kels rewrite rules"
      exit 0
    fi
    ;;
  apply|break-node-b)
    ;;
  *)
    echo "Unknown mode: $MODE"
    echo "Usage: coredns.sh <apply|reset|break-node-b>"
    exit 1
    ;;
esac

# Build rewrite rules
REWRITE_RULES=""
if [ "$MODE" != "reset" ]; then
  REWRITE_RULES="        rewrite name regex (.*)\.registry-(.)\.kels {1}.kels-registry-{2}.svc.cluster.local answer auto
"
  if [ "$MODE" = "break-node-b" ]; then
    REWRITE_RULES="${REWRITE_RULES}        rewrite name regex (.*)\.node-(b)\.kels {1}.kels-node-broken.svc.cluster.local answer auto
"
  fi
  REWRITE_RULES="${REWRITE_RULES}        rewrite name regex (.*)\.node-(.)\.kels {1}.kels-node-{2}.svc.cluster.local answer auto
"
fi

# Apply CoreDNS ConfigMap
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
        errors
        health {
           lameduck 5s
        }
        ready
        kubernetes cluster.local in-addr.arpa ip6.arpa {
           pods insecure
           fallthrough in-addr.arpa ip6.arpa
           ttl ${TTL}
        }
${REWRITE_RULES}        prometheus :9153
        forward . /etc/resolv.conf {
           max_concurrent 1000
        }
        cache ${TTL}
        loop
        reload
        loadbalance
    }
EOF

# Kubernetes rejects rollout restart within 1s of the previous one.
# Wait for any in-progress rollout to finish before triggering a new one.
kubectl rollout status -n kube-system deploy/coredns 2>/dev/null || true
sleep 1
kubectl rollout restart -n kube-system deploy/coredns
kubectl rollout status -n kube-system deploy/coredns

case "$MODE" in
  apply)        echo "CoreDNS restarted with .kels rewrite rules" ;;
  reset)        echo "CoreDNS .kels rewrite rules removed and restarted" ;;
  break-node-b) echo "CoreDNS restarted — node-b DNS broken" ;;
esac
