#!/bin/bash
set -e

# Apply CoreDNS config with node-b rewritten to a non-existent namespace.
# Existing libp2p TCP connections survive (gossipsub announcements still flow)
# but HTTP fetches to http://kels.kels-node-b.kels fail with DNS errors.

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
        rewrite name regex (.*)\.kels-node-(b)\.kels {1}.kels-node-broken.svc.cluster.local answer auto
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

kubectl rollout restart -n kube-system deploy/coredns
kubectl rollout status -n kube-system deploy/coredns
echo "CoreDNS restarted — node-b DNS broken"
