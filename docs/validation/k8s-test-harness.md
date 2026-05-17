# Kubernetes Test Harness

This document describes the in-repo Kubernetes test harness for the kels gossip mesh — the configuration the project's automated tests use to stand up a federation in a single cluster.

> **This is not a production deployment recipe.** The harness colocates federation nodes in one Kubernetes cluster with cross-namespace routing via CoreDNS rewrites. Production deployments must address transport reachability between peer networks/clusters on their own terms; see [../design/infrastructure/gossip.md §Transport reachability](../design/infrastructure/gossip.md#transport-reachability) for the design-level requirement.

## Cross-namespace communication

Gossip nodes in different namespaces connect directly over TCP using the advertised gossip addresses each peer publishes in its address SEL. CoreDNS rewrites (below) translate `.kels` domains into in-cluster service names so the same URLs work for both internal services and external clients.

## Services

Each namespace has:

- `gossip` — ClusterIP service for gossip TCP connections.

## CoreDNS configuration for `.kels` domains

Nodes advertise URLs using `.kels` domains (e.g., `http://kels.node-a.kels`) so that the same URLs work for both:

- **External clients** (iOS, CLI) — resolved via `/etc/hosts` or local DNS.
- **Internal services** — resolved via CoreDNS inside the cluster.

To enable internal resolution, CoreDNS must be configured with rewrite rules:

```bash
scripts/coredns.sh apply
```

This applies rewrite rules that translate `.kels` domains to `.svc.cluster.kels`:

```
rewrite name regex (.*)\.node-(.)\.kels {1}.node-{2}.svc.cluster.kels
```

### Platform-specific notes

| Platform | Notes |
|---|---|
| Docker Desktop | Works as-is with the provided script. |
| minikube | May need to edit the `coredns` ConfigMap in `kube-system` namespace manually. |
| kind | CoreDNS config is in `coredns` ConfigMap; may need cluster recreation to apply. |
| EKS/GKE/AKS | Use cluster-specific DNS customization (e.g., CoreDNS ConfigMap or NodeLocal DNSCache). |
| k3s | Uses CoreDNS by default; same ConfigMap approach works. |

If your Kubernetes distribution uses a different DNS provider or configuration method, adapt the rewrite rules accordingly. The key requirement is that `*.node-X.kels` resolves to `*.node-X.svc.cluster.kels` inside the cluster.
