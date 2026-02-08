#!/bin/bash
set -e

# Check if rewrite rules already exist
if kubectl get configmap coredns -n kube-system -o json | jq .data.Corefile | jq -r . | grep -q "kels-registry"; then
  echo "CoreDNS already configured for .kels domains"
  exit 0
fi

# Apply the new CoreDNS ConfigMap
kubectl apply -f - <<'EOF'
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
           ttl 30
        }
        rewrite name regex (.*)\.kels-registry-(.)\.kels {1}.kels-registry-{2}.svc.cluster.local answer auto
        rewrite name regex (.*)\.kels-node-(.)\.kels {1}.kels-node-{2}.svc.cluster.local answer auto
        prometheus :9153
        forward . /etc/resolv.conf {
           max_concurrent 1000
        }
        cache 30
        loop
        reload
        loadbalance
    }
EOF

# Restart CoreDNS to pick up changes
kubectl rollout restart -n kube-system deploy/coredns
kubectl rollout status -n kube-system deploy/coredns
echo "CoreDNS configured and restarted"
