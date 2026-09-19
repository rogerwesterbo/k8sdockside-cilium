# Cilium for K8s Dockside

A plugin for [K8s Dockside](https://github.com/k8sdockside/k8sdockside) that shows
[Cilium](https://cilium.io) as what it manages: endpoints, identities and the
policies between them. Plain HTML and script, no build step. Needs K8s Dockside
0.0.15 or newer (0.0.17 for the *Isolate* button); Prometheus is optional.

## What it shows

- **Overview**: a verdict, how much of the cluster is under enforced policy (a
  ring), the datapath from `cilium-config` (routing, kube-proxy replacement,
  encryption, Hubble, IPAM, BGP, L2 and more), agent → operator → endpoints →
  identities → policies as stages, every node with its agent, what needs
  attention, recent events and Cilium's metrics.
- **Endpoint map**: namespaces as islands, endpoints as hexagons coloured by
  policy enforcement, identity, node or state. Click one for its identity,
  labels and the policies selecting it.
- **Policy map**: every CiliumNetworkPolicy, cluster-wide policy and Kubernetes
  NetworkPolicy, drawn as a flow (from → selected → to) and said in plain words.
- **Nodes & addresses**: nodes with agent, addresses and IPAM usage; LB IPAM
  pools, L2 announcements, BGP sessions and egress gateways where served.
- **Panels** on Pods, Nodes and every kind of network policy, and **tables**
  for every Cilium CRD and Cilium's own pods.

Enforcement per endpoint is worked out from the policies that select it (and
`enable-policy`): Cilium does not publish it in CiliumEndpoints.

## Installing

**Settings → Plugins → From a repository**, with
`https://github.com/k8sdockside/cilium.git`.

## What it reads, and what it may change

It reads Cilium's kinds (`cilium.io`), Pods, Nodes, Namespaces, Services,
NetworkPolicies, Events, Leases (L2 announcement leaders) and the
`cilium-config` ConfigMap. Never Secrets. It may ask to:

- create a NetworkPolicy `default-deny-ingress` in a namespace (*Isolate*)
- set `spec.disabled` on a CiliumLoadBalancerIPPool

The app shows every change first and makes it only when you say so.

## Layout

```
plugin.json        manifest: kinds, views, cards, charts, panels
ui/model.js        reads everything once per poll and works it out
ui/kit.js          shared drawing: icons, hexagons, chips, tip, grip
ui/flow.js         a policy as a flow diagram and in plain words
ui/cilium.css      one stylesheet, on the app's theme tokens
ui/overview.*      overview          ui/endpoints.*  endpoint map
ui/policies.*      policy map        ui/network.*    nodes & addresses
ui/pod.*  ui/policy.*  ui/node.*     detail panels
```

Checked in CI with `go run github.com/k8sdockside/k8sdockside/cmd/plugincheck@main .`
