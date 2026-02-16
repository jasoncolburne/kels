#!/bin/bash
set -e

# Unified CoreDNS configuration script.
#
# Usage: coredns.sh <configure|unconfigure|break-node-b|repair-node-b>
#
# Modes:
#   configure     — Add .kels rewrite rules (idempotent, skips if present)
#   unconfigure   — Remove .kels rewrite rules (idempotent, skips if absent)
#   break-node-b  — Redirect node-b .kels DNS to a non-existent name
#   repair-node-b — Restore working .kels DNS (not idempotent)
#
# Environment:
#   DNS_CACHE_TTL — CoreDNS cache and record TTL in seconds (default: 30).
#                   Set low (e.g. 2) during test-comprehensive so node-level
#                   DNS caches expire quickly after break/repair transitions.

MODE="${1:?Usage: coredns.sh <configure|unconfigure|break-node-b|repair-node-b>}"
TTL="${DNS_CACHE_TTL:-30}"

# Idempotency checks for configure/unconfigure
case "$MODE" in
  configure)
    if kubectl get configmap coredns -n kube-system -o json | jq .data.Corefile | jq -r . | grep -q "kels-registry"; then
      echo "CoreDNS already configured for .kels domains"
      exit 0
    fi
    ;;
  unconfigure)
    if ! kubectl get configmap coredns -n kube-system -o json | jq .data.Corefile | jq -r . | grep -q "kels-registry"; then
      echo "CoreDNS does not have .kels rewrite rules"
      exit 0
    fi
    ;;
  break-node-b|repair-node-b)
    ;;
  *)
    echo "Unknown mode: $MODE"
    echo "Usage: coredns.sh <configure|unconfigure|break-node-b|repair-node-b>"
    exit 1
    ;;
esac

# Build rewrite rules
REWRITE_RULES=""
if [ "$MODE" != "unconfigure" ]; then
  REWRITE_RULES="        rewrite name regex (.*)\.kels-registry-(.)\.kels {1}.kels-registry-{2}.svc.cluster.local answer auto
"
  if [ "$MODE" = "break-node-b" ]; then
    REWRITE_RULES="${REWRITE_RULES}        rewrite name regex (.*)\.kels-node-(b)\.kels {1}.kels-node-broken.svc.cluster.local answer auto
"
  fi
  REWRITE_RULES="${REWRITE_RULES}        rewrite name regex (.*)\.kels-node-(.)\.kels {1}.kels-node-{2}.svc.cluster.local answer auto
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

kubectl rollout restart -n kube-system deploy/coredns
kubectl rollout status -n kube-system deploy/coredns

case "$MODE" in
  configure)     echo "CoreDNS configured and restarted" ;;
  unconfigure)   echo "CoreDNS .kels rewrite rules removed and restarted" ;;
  break-node-b)  echo "CoreDNS restarted — node-b DNS broken" ;;
  repair-node-b) echo "CoreDNS restarted — node-b DNS repaired" ;;
esac
