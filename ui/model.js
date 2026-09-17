// The Cilium model every page of this plugin draws from: the agents and the
// nodes they run on, every endpoint with its identity and whether policy is
// enforced on it, every policy (Cilium's own and Kubernetes') with what it
// selects, the datapath as cilium-config describes it, and -- where their
// kinds are served -- LB IPAM pools, L2 announcements, BGP and egress
// gateways. Read once per poll through the k8sdockside bridge and worked out
// here, so the pages only have to draw.
//
// Policies are matched against identities, not endpoints: endpoints sharing
// an identity share its labels, and a cluster has far fewer identities than
// endpoints. That keeps a poll cheap with thousands of endpoints.
(function () {
    'use strict';

    var KINDS = {
        cnp: 'crd:ciliumnetworkpolicies.cilium.io',
        ccnp: 'crd:ciliumclusterwidenetworkpolicies.cilium.io',
        endpoints: 'crd:ciliumendpoints.cilium.io',
        ciliumNodes: 'crd:ciliumnodes.cilium.io',
        identities: 'crd:ciliumidentities.cilium.io',
        lbPools: 'crd:ciliumloadbalancerippools.cilium.io',
        l2: 'crd:ciliuml2announcementpolicies.cilium.io',
        bgpCluster: 'crd:ciliumbgpclusterconfigs.cilium.io',
        bgpPeers: 'crd:ciliumbgppeerconfigs.cilium.io',
        bgpAdverts: 'crd:ciliumbgpadvertisements.cilium.io',
        bgpNodes: 'crd:ciliumbgpnodeconfigs.cilium.io',
        bgpOverrides: 'crd:ciliumbgpnodeconfigoverrides.cilium.io',
        bgpLegacy: 'crd:ciliumbgppeeringpolicies.cilium.io',
        egress: 'crd:ciliumegressgatewaypolicies.cilium.io',
        lrp: 'crd:ciliumlocalredirectpolicies.cilium.io',
        podPools: 'crd:ciliumpodippools.cilium.io',
        cidrGroups: 'crd:ciliumcidrgroups.cilium.io',
        knp: 'networkpolicies',
        pods: 'pods',
        nodes: 'nodes',
        services: 'services',
        configmaps: 'configmaps',
        events: 'events',
        namespaces: 'namespaces',
        leases: 'leases',
    };

    // Which pods are Cilium's own, by the labels its Helm chart sets.
    var COMPONENTS = [
        { id: 'agent', label: 'Agent', selector: 'k8s-app=cilium' },
        { id: 'operator', label: 'Operator', selector: 'io.cilium/app=operator' },
        { id: 'envoy', label: 'Envoy', selector: 'k8s-app=cilium-envoy' },
        { id: 'relay', label: 'Hubble Relay', selector: 'k8s-app=hubble-relay' },
        { id: 'hubbleUi', label: 'Hubble UI', selector: 'k8s-app=hubble-ui' },
        { id: 'clustermesh', label: 'Cluster Mesh API server', selector: 'k8s-app=clustermesh-apiserver' },
    ];

    var CONFIG_NAME = 'cilium-config';
    var DEFAULT_NAMESPACE = 'kube-system';

    // Where an endpoint's lifecycle stands, and the tone to draw it in. The
    // agent folds its transient states into "ready" before writing them, so
    // ready, not-ready, waiting-for-identity and invalid are what is seen.
    var STATES = {
        ready: { tone: 'ok', label: 'ready' },
        regenerating: { tone: 'info', label: 'regenerating' },
        'waiting-to-regenerate': { tone: 'info', label: 'waiting to regenerate' },
        restoring: { tone: 'info', label: 'restoring' },
        creating: { tone: 'info', label: 'creating' },
        'waiting-for-identity': { tone: 'warn', label: 'waiting for identity' },
        'not-ready': { tone: 'warn', label: 'not ready' },
        disconnecting: { tone: 'warn', label: 'disconnecting' },
        disconnected: { tone: 'warn', label: 'disconnected' },
        invalid: { tone: 'error', label: 'invalid' },
    };

    var ENTITIES = {
        all: 'everything, inside and outside the cluster',
        world: 'anything outside the cluster',
        cluster: 'anything in the cluster',
        host: 'the node the endpoint runs on',
        'remote-node': 'the other nodes',
        'kube-apiserver': 'the Kubernetes API server',
        health: 'Cilium health checks',
        init: 'endpoints still getting an identity',
        ingress: "Cilium's ingress proxy",
        unmanaged: 'pods Cilium does not manage',
        none: 'nothing at all',
        'cluster-mesh': 'the clusters in the mesh',
        'world-ipv4': 'IPv4 addresses outside the cluster',
        'world-ipv6': 'IPv6 addresses outside the cluster',
    };

    // ----- small readers -----------------------------------------------------

    function dig(obj, path) {
        var at = obj;
        var keys = path.split('.');
        for (var i = 0; i < keys.length; i++) {
            if (at === null || at === undefined) return undefined;
            at = at[keys[i]];
        }
        return at;
    }

    function arr(v) {
        return Array.isArray(v) ? v : [];
    }

    function labelsOf(obj) {
        return (obj && obj.metadata && obj.metadata.labels) || {};
    }

    function keyOf(obj) {
        return (obj.metadata.namespace || '') + '/' + obj.metadata.name;
    }

    function conditionOf(obj, type) {
        var list = arr(dig(obj, 'status.conditions'));
        for (var i = 0; i < list.length; i++) {
            if (list[i] && list[i].type === type) return list[i];
        }
        return null;
    }

    function truthy(v) {
        return v === true || v === 'true' || v === 'True';
    }

    function podReady(pod) {
        var c = conditionOf(pod, 'Ready');
        return dig(pod, 'status.phase') === 'Running' && !!c && c.status === 'True';
    }

    function restarts(pod) {
        return arr(dig(pod, 'status.containerStatuses')).reduce(function (n, c) {
            return n + (c.restartCount || 0);
        }, 0);
    }

    // Why a pod is not running, in the kubelet's words.
    function podTrouble(pod) {
        var list = arr(dig(pod, 'status.containerStatuses'));
        for (var i = 0; i < list.length; i++) {
            var s = list[i].state || {};
            if (s.waiting && s.waiting.reason) return s.waiting.reason;
            if (s.terminated && s.terminated.reason) return s.terminated.reason;
            if (list[i].ready === false && s.running) return 'not ready';
        }
        var phase = dig(pod, 'status.phase');
        if (phase && phase !== 'Running') return phase;
        return podReady(pod) ? '' : 'not ready';
    }

    // "quay.io/cilium/cilium:v1.16.3@sha256:..." -> "1.16.3".
    function versionOf(pod) {
        var containers = arr(dig(pod, 'spec.containers'));
        for (var i = 0; i < containers.length; i++) {
            var image = (containers[i].image || '').split('@')[0];
            var at = image.lastIndexOf(':');
            if (at > image.lastIndexOf('/') && /cilium/.test(image)) return image.slice(at + 1).replace(/^v/, '');
        }
        return '';
    }

    function soft(promise) {
        return promise.then(
            function (items) {
                return { ok: true, items: items || [], error: '' };
            },
            function (err) {
                return { ok: false, items: [], error: (err && err.message) || String(err) };
            },
        );
    }

    function stamp(list) {
        return list
            .map(function (o) {
                return o.metadata ? o.metadata.uid + '@' + o.metadata.resourceVersion : '';
            })
            .join(',');
    }

    function plural(n, one, many) {
        return Number(n).toLocaleString() + ' ' + (n === 1 ? one : many || one + 's');
    }

    function names(list, max) {
        max = max || 3;
        var shown = list.slice(0, max);
        if (list.length > max) shown.push(list.length - max + ' more');
        return shown.join(', ');
    }

    function percent(fraction) {
        if (!isFinite(fraction) || fraction <= 0) return '0%';
        if (fraction < 0.01) return '<1%';
        if (fraction > 0.99 && fraction < 1) return '99%';
        return Math.round(fraction * 100) + '%';
    }

    // ----- labels and selectors ------------------------------------------------

    // Cilium writes an identity's labels as "source:key=value" --
    // "k8s:app=web", "reserved:host". A selector key without a source means
    // any source, as it does in a policy.
    function parseLabel(text) {
        text = String(text || '');
        var eq = text.indexOf('=');
        var head = eq < 0 ? text : text.slice(0, eq);
        var value = eq < 0 ? '' : text.slice(eq + 1);
        var colon = head.indexOf(':');
        var source = colon > 0 ? head.slice(0, colon) : 'any';
        var key = colon > 0 ? head.slice(colon + 1) : head;
        return { source: source, key: key, value: value, text: text };
    }

    function labelSet(list) {
        var set = { list: [], any: {}, full: {}, k8s: {}, namespace: '' };
        arr(list).forEach(function (text) {
            var l = parseLabel(text);
            set.list.push(l);
            set.any[l.key] = l.value;
            set.full[l.source + ':' + l.key] = l.value;
            if (l.source === 'k8s') set.k8s[l.key] = l.value;
        });
        set.namespace = set.k8s['io.kubernetes.pod.namespace'] || '';
        return set;
    }

    function splitKey(key) {
        var colon = String(key).indexOf(':');
        if (colon <= 0) return { source: 'any', key: key };
        var source = key.slice(0, colon);
        return { source: source, key: key.slice(colon + 1) };
    }

    function lookup(set, rawKey) {
        var k = splitKey(rawKey);
        if (k.source === 'any') {
            return Object.prototype.hasOwnProperty.call(set.any, k.key) ? { has: true, value: set.any[k.key] } : { has: false };
        }
        var full = k.source + ':' + k.key;
        return Object.prototype.hasOwnProperty.call(set.full, full) ? { has: true, value: set.full[full] } : { has: false };
    }

    // A label selector against a set of labels, through `get(key)`. An empty
    // selector selects everything, as it does in the API.
    function matchWith(selector, get) {
        if (!selector) return true;
        var match = selector.matchLabels || {};
        for (var key in match) {
            var got = get(key);
            if (!got.has || got.value !== String(match[key])) return false;
        }
        var expressions = arr(selector.matchExpressions);
        for (var i = 0; i < expressions.length; i++) {
            var e = expressions[i];
            var have = get(e.key);
            var values = arr(e.values).map(String);
            switch (e.operator) {
                case 'In':
                    if (!have.has || values.indexOf(have.value) < 0) return false;
                    break;
                case 'NotIn':
                    if (have.has && values.indexOf(have.value) >= 0) return false;
                    break;
                case 'Exists':
                    if (!have.has) return false;
                    break;
                case 'DoesNotExist':
                    if (have.has) return false;
                    break;
                default:
                    return false;
            }
        }
        return true;
    }

    // A Cilium EndpointSelector against an identity's labels.
    function selectsIdentity(selector, set) {
        return matchWith(selector, function (key) {
            return lookup(set, key);
        });
    }

    // A plain Kubernetes selector against plain labels.
    function selectsLabels(selector, labels) {
        labels = labels || {};
        return matchWith(selector, function (key) {
            return Object.prototype.hasOwnProperty.call(labels, key) ? { has: true, value: String(labels[key]) } : { has: false };
        });
    }

    function isEmptySelector(sel) {
        return !sel || (Object.keys(sel.matchLabels || {}).length === 0 && arr(sel.matchExpressions).length === 0);
    }

    // Does a selector name the namespace itself? A namespaced policy's peer
    // selector is otherwise kept to the policy's own namespace.
    function namesNamespace(sel) {
        if (!sel) return false;
        var keys = Object.keys(sel.matchLabels || {}).concat(
            arr(sel.matchExpressions).map(function (e) {
                return e.key;
            }),
        );
        return keys.some(function (k) {
            return splitKey(k).key === 'io.kubernetes.pod.namespace';
        });
    }

    // "app=web, tier in (a, b)", with the "k8s:" prefix left off: it is the
    // source every pod label has.
    function selectorText(sel, emptyText) {
        if (isEmptySelector(sel)) return emptyText === undefined ? 'everything' : emptyText;
        var parts = [];
        Object.keys(sel.matchLabels || {}).forEach(function (k) {
            var v = sel.matchLabels[k];
            parts.push(shortKey(k) + '=' + (v === '' ? '""' : v));
        });
        arr(sel.matchExpressions).forEach(function (e) {
            var k = shortKey(e.key);
            var values = arr(e.values).join(', ');
            if (e.operator === 'In') parts.push(k + ' in (' + values + ')');
            else if (e.operator === 'NotIn') parts.push(k + ' not in (' + values + ')');
            else if (e.operator === 'Exists') parts.push(k);
            else if (e.operator === 'DoesNotExist') parts.push('!' + k);
            else parts.push(k + ' ' + e.operator + ' ' + values);
        });
        return parts.join(', ');
    }

    function shortKey(k) {
        return String(k)
            .replace(/^(k8s|any):/, '')
            .replace(/^io\.kubernetes\.pod\.namespace$/, 'namespace')
            .replace(/^io\.cilium\.k8s\.policy\./, 'policy.');
    }

    // ----- addresses ----------------------------------------------------------

    function parseIPv4(text) {
        var parts = String(text || '').split('.');
        if (parts.length !== 4) return null;
        var n = 0;
        for (var i = 0; i < 4; i++) {
            if (!/^\d{1,3}$/.test(parts[i]) || Number(parts[i]) > 255) return null;
            n = n * 256 + Number(parts[i]);
        }
        return n;
    }

    function formatIPv4(n) {
        return [Math.floor(n / 16777216) % 256, Math.floor(n / 65536) % 256, Math.floor(n / 256) % 256, n % 256].join('.');
    }

    // An IPv4 CIDR or start-stop block as numbers; IPv6 only as a size.
    function parseBlock(block) {
        var out = { text: '', v: 0, start: 0, end: -1, size: 0, huge: '' };
        if (typeof block === 'string') block = { cidr: block };
        block = block || {};
        if (block.cidr) {
            out.text = block.cidr;
            var cut = String(block.cidr).split('/');
            var bits = Number(cut[1]);
            var v4 = parseIPv4(cut[0]);
            if (v4 !== null && bits >= 0 && bits <= 32) {
                var size = Math.pow(2, 32 - bits);
                out.v = 4;
                out.start = v4 - (v4 % size);
                out.end = out.start + size - 1;
                out.size = size;
            } else if (cut[0].indexOf(':') >= 0 && bits >= 0 && bits <= 128) {
                out.v = 6;
                out.huge = 128 - bits > 20 ? '2^' + (128 - bits) : '';
                out.size = 128 - bits > 20 ? Infinity : Math.pow(2, 128 - bits);
            }
        } else if (block.start) {
            var a = parseIPv4(block.start);
            var b = parseIPv4(block.stop || block.start);
            out.text = block.start + (block.stop && block.stop !== block.start ? ' – ' + block.stop : '');
            if (a !== null && b !== null && b >= a) {
                out.v = 4;
                out.start = a;
                out.end = b;
                out.size = b - a + 1;
            } else if (String(block.start).indexOf(':') >= 0) {
                out.v = 6;
            }
        }
        return out;
    }

    function inBlock(block, ip) {
        var n = parseIPv4(ip);
        return block.v === 4 && n !== null && n >= block.start && n <= block.end;
    }

    function cidrSize(cidr) {
        var b = parseBlock(cidr);
        return b.v === 4 ? b.size : 0;
    }

    function count(n) {
        if (n === Infinity) return '≈ ∞';
        if (n >= 1e9) return '≈ 2^' + Math.round(Math.log2(n));
        return Number(n).toLocaleString();
    }

    // ----- loading -------------------------------------------------------------

    // opts.extras reads LB IPAM, L2, BGP, egress gateways and services too:
    // what the overview and the network page need, and the rest do not.
    function load(sdk, opts) {
        opts = opts || {};
        function list(kind, namespace, selector) {
            return soft(sdk.list({ kind: kind, namespace: namespace || '', selector: selector || '' }));
        }
        var core = [
            list(KINDS.endpoints),
            list(KINDS.cnp),
            list(KINDS.ccnp),
            list(KINDS.ciliumNodes),
            list(KINDS.identities),
            list(KINDS.knp),
            list(KINDS.nodes),
            list(KINDS.namespaces),
        ].concat(
            COMPONENTS.map(function (c) {
                return list(KINDS.pods, '', c.selector);
            }),
        );
        var extra = opts.extras
            ? [
                  list(KINDS.lbPools),
                  list(KINDS.l2),
                  list(KINDS.bgpCluster),
                  list(KINDS.bgpPeers),
                  list(KINDS.bgpAdverts),
                  list(KINDS.bgpNodes),
                  list(KINDS.bgpLegacy),
                  list(KINDS.egress),
                  list(KINDS.services),
              ]
            : [];
        return Promise.all(core.concat(extra)).then(function (got) {
            var raw = {
                endpoints: got[0],
                cnp: got[1],
                ccnp: got[2],
                ciliumNodes: got[3],
                identities: got[4],
                knp: got[5],
                nodes: got[6],
                namespaces: got[7],
                pods: {},
            };
            COMPONENTS.forEach(function (c, i) {
                raw.pods[c.id] = got[8 + i];
            });
            var base = 8 + COMPONENTS.length;
            if (opts.extras) {
                ['lbPools', 'l2', 'bgpCluster', 'bgpPeers', 'bgpAdverts', 'bgpNodes', 'bgpLegacy', 'egress', 'services'].forEach(function (k, i) {
                    raw[k] = got[base + i];
                });
            }
            var ns = namespaceOf(raw);
            return Promise.all([
                soft(
                    sdk.get({ kind: KINDS.configmaps, namespace: ns, name: CONFIG_NAME }).then(function (cm) {
                        return [cm];
                    }),
                ),
                // L2 announcements elect their node through a Lease in the
                // agent's namespace.
                opts.extras && raw.l2.ok && raw.l2.items.length ? list(KINDS.leases, ns) : Promise.resolve({ ok: false, items: [], error: '' }),
            ]).then(function (more) {
                raw.config = more[0];
                raw.leases = more[1];
                raw.configNamespace = ns;
                return build(raw, opts);
            });
        });
    }

    function namespaceOf(raw) {
        var ids = ['agent', 'operator', 'envoy', 'relay'];
        for (var i = 0; i < ids.length; i++) {
            var items = raw.pods[ids[i]].items;
            if (items.length) return items[0].metadata.namespace;
        }
        return DEFAULT_NAMESPACE;
    }

    // ----- building ------------------------------------------------------------

    function build(raw, opts) {
        var model = {
            installed: raw.endpoints.ok && raw.cnp.ok,
            missing: raw.endpoints.error || raw.cnp.error,
            served: {},
            extras: !!opts.extras,
            namespace: raw.configNamespace,
            version: '',
            components: {},
            config: { ok: raw.config.ok, error: raw.config.error, data: {}, name: CONFIG_NAME },
            nodes: [],
            nodeByName: {},
            endpoints: [],
            groups: [],
            identityCount: 0,
            policies: [],
            namespaces: [],
            nsLabels: {},
            coverage: { both: 0, ingress: 0, egress: 0, none: 0, total: 0 },
            notReady: [],
            lb: null,
            l2: null,
            bgp: null,
            egress: null,
            services: [],
            findings: [],
            sig: '',
        };
        Object.keys(raw).forEach(function (k) {
            if (raw[k] && typeof raw[k].ok === 'boolean') model.served[k] = raw[k].ok;
        });
        if (raw.config.ok && raw.config.items[0]) model.config.data = raw.config.items[0].data || {};

        var sigParts = [];
        ['endpoints', 'cnp', 'ccnp', 'ciliumNodes', 'knp', 'nodes', 'namespaces', 'lbPools', 'l2', 'bgpCluster', 'bgpPeers', 'bgpAdverts', 'bgpNodes', 'bgpLegacy', 'egress', 'services'].forEach(function (k) {
            if (raw[k]) sigParts.push(k + ':' + stamp(raw[k].items));
        });
        // Identities come and go with every pod; their number is what shows.
        sigParts.push('ids:' + raw.identities.items.length);
        COMPONENTS.forEach(function (c) {
            sigParts.push(c.id + ':' + stamp(raw.pods[c.id].items));
        });
        sigParts.push('cm:' + stamp(raw.config.items));
        // A lease is renewed every few seconds; only who holds it matters.
        if (raw.leases) {
            sigParts.push(
                'leases:' +
                    raw.leases.items
                        .map(function (l) {
                            return l.metadata.name + '=' + dig(l, 'spec.holderIdentity');
                        })
                        .join(','),
            );
        }
        model.sig = sigParts.join('|');

        // ----- Cilium's own pods
        COMPONENTS.forEach(function (c) {
            var pods = raw.pods[c.id].items.slice().sort(function (a, b) {
                return a.metadata.name.localeCompare(b.metadata.name);
            });
            model.components[c.id] = {
                id: c.id,
                label: c.label,
                selector: c.selector,
                pods: pods,
                ready: pods.filter(podReady).length,
                total: pods.length,
                restarts: pods.reduce(function (n, p) {
                    return n + restarts(p);
                }, 0),
            };
        });
        var anchor = model.components.agent.pods[0] || model.components.operator.pods[0];
        if (anchor) model.version = versionOf(anchor);

        raw.namespaces.items.forEach(function (n) {
            model.nsLabels[n.metadata.name] = Object.assign({ 'kubernetes.io/metadata.name': n.metadata.name }, labelsOf(n));
        });

        buildNodes(model, raw);
        buildEndpoints(model, raw);
        buildPolicies(model, raw);
        enforcement(model);
        buildNamespaces(model);
        if (opts.extras) {
            buildServices(model, raw);
            buildLB(model, raw);
            buildL2(model, raw);
            buildBGP(model, raw);
            buildEgress(model, raw);
        }
        model.features = features(model);
        model.findings = findings(model);
        return model;
    }

    // ----- nodes

    function buildNodes(model, raw) {
        var agentOn = {};
        model.components.agent.pods.forEach(function (p) {
            var n = dig(p, 'spec.nodeName');
            if (n) agentOn[n] = p;
        });
        var cnByName = {};
        raw.ciliumNodes.items.forEach(function (cn) {
            cnByName[cn.metadata.name] = cn;
        });
        model.nodeByIP = {};
        var seen = {};
        function add(name, nodeObj, cn) {
            seen[name] = true;
            var labels = labelsOf(nodeObj || cn);
            var addrs = arr(dig(nodeObj, 'status.addresses'));
            var internal = '';
            addrs.forEach(function (a) {
                if (a.type === 'InternalIP' && !internal) internal = a.address;
                if (a.address) model.nodeByIP[a.address] = name;
            });
            var ciliumIPs = [];
            arr(dig(cn, 'spec.addresses')).forEach(function (a) {
                if (a.ip) model.nodeByIP[a.ip] = name;
                if (a.type === 'CiliumInternalIP') ciliumIPs.push(a.ip);
                if (a.type === 'InternalIP' && !internal) internal = a.ip;
            });
            var podCIDRs = arr(dig(cn, 'spec.ipam.podCIDRs'));
            if (!podCIDRs.length) podCIDRs = arr(dig(nodeObj, 'spec.podCIDRs'));
            var pools = arr(dig(cn, 'spec.ipam.pools.allocated'));
            var capacity = 0;
            podCIDRs.forEach(function (c) {
                capacity += cidrSize(c);
            });
            pools.forEach(function (p) {
                arr(p.cidrs).forEach(function (c) {
                    capacity += cidrSize(c);
                });
            });
            var used = dig(cn, 'status.ipam.used');
            var agent = agentOn[name] || null;
            var ready = conditionOf(nodeObj, 'Ready');
            var node = {
                name: name,
                obj: nodeObj || null,
                cn: cn || null,
                labels: labels,
                ready: !nodeObj || (!!ready && ready.status === 'True'),
                zone: labels['topology.kubernetes.io/zone'] || '',
                roles: Object.keys(labels)
                    .filter(function (k) {
                        return k.indexOf('node-role.kubernetes.io/') === 0;
                    })
                    .map(function (k) {
                        return k.slice(24);
                    }),
                internalIP: internal,
                ciliumIPs: ciliumIPs,
                podCIDRs: podCIDRs,
                pools: pools,
                ipamUsed: used && typeof used === 'object' ? Object.keys(used).length : null,
                ipamCapacity: capacity,
                ipamError: dig(cn, 'status.ipam.operator-status.error') || '',
                healthIP: dig(cn, 'spec.health.ipv4') || dig(cn, 'spec.health.ipv6') || '',
                encryptionKey: dig(cn, 'spec.encryption.key'),
                agent: agent,
                agentReady: !!agent && podReady(agent),
                agentRestarts: agent ? restarts(agent) : 0,
                agentTrouble: agent ? podTrouble(agent) : '',
                unschedulable: !!dig(nodeObj, 'spec.unschedulable'),
                endpoints: 0,
                notReady: 0,
            };
            model.nodes.push(node);
            model.nodeByName[name] = node;
        }
        raw.nodes.items.forEach(function (n) {
            add(n.metadata.name, n, cnByName[n.metadata.name]);
        });
        // A CiliumNode without a Node: an external workload, or a node
        // that has since left.
        raw.ciliumNodes.items.forEach(function (cn) {
            if (!seen[cn.metadata.name]) add(cn.metadata.name, null, cn);
        });
        model.nodes.sort(function (a, b) {
            return rankNode(a) - rankNode(b) || a.name.localeCompare(b.name);
        });
        model.agentsKnown = model.components.agent.total > 0;
    }

    function nodeTone(model, n) {
        if (!n.obj) return 'muted';
        if (!n.ready) return 'error';
        if (model.agentsKnown && !n.agent) return 'error';
        if (n.agent && !n.agentReady) return 'error';
        if (n.ipamError) return 'warn';
        if (n.agentRestarts > 5) return 'warn';
        return 'ok';
    }

    function rankNode(n) {
        var cp = n.roles.indexOf('control-plane') >= 0 || n.roles.indexOf('master') >= 0;
        return cp ? 0 : 1;
    }

    // ----- endpoints

    function buildEndpoints(model, raw) {
        var groups = {};
        raw.endpoints.items.forEach(function (obj) {
            var st = obj.status || {};
            var ident = st.identity || {};
            var set = labelSet(ident.labels);
            var ips = [];
            var v4 = '';
            var v6 = '';
            arr(dig(st, 'networking.addressing')).forEach(function (a) {
                if (a.ipv4) {
                    ips.push(a.ipv4);
                    v4 = v4 || a.ipv4;
                }
                if (a.ipv6) {
                    ips.push(a.ipv6);
                    v6 = v6 || a.ipv6;
                }
            });
            var nodeIP = dig(st, 'networking.node') || '';
            var state = st.state || '';
            var owner = arr(obj.metadata.ownerReferences).filter(function (o) {
                return o.kind === 'Pod';
            })[0];
            var ep = {
                key: keyOf(obj),
                uid: obj.metadata.uid,
                name: obj.metadata.name,
                namespace: obj.metadata.namespace || '',
                pod: owner ? owner.name : obj.metadata.name,
                obj: obj,
                index: model.endpoints.length,
                id: st.id,
                identity: ident.id !== undefined && ident.id !== null ? Number(ident.id) : null,
                labels: set,
                ips: ips,
                ipv4: v4,
                ipv6: v6,
                nodeIP: nodeIP,
                node: model.nodeByIP[nodeIP] || '',
                state: state,
                stateTone: (STATES[state] || { tone: state ? 'warn' : 'muted' }).tone,
                ready: state === 'ready',
                // Worked out from the policies that select it, below: the
                // agent does not write status.policy into CiliumEndpoints.
                ingress: false,
                egress: false,
                enforcement: 'none',
                namedPorts: arr(st['named-ports']),
                encryptionKey: dig(st, 'encryption.key'),
                serviceAccount: st['service-account'] || '',
                group: null,
            };
            model.endpoints.push(ep);
            if (!ep.ready) model.notReady.push(ep);
            var node = model.nodeByName[ep.node];
            if (node) {
                node.endpoints++;
                if (!ep.ready) node.notReady++;
            }
            // Endpoints with the same identity -- or, before one is
            // allocated, the same labels -- are matched once.
            if (!set.list.length) return;
            var gk = ep.identity !== null ? 'id:' + ep.identity + '@' + ep.namespace : 'l:' + ep.namespace + ':' + (ident.labels || []).join(',');
            var g = groups[gk];
            if (!g) {
                g = groups[gk] = { key: gk, identity: ep.identity, namespace: ep.namespace, labels: set, endpoints: [], policies: [], ingress: false, egress: false };
                model.groups.push(g);
            }
            g.endpoints.push(ep);
            ep.group = g;
        });
        model.endpoints.sort(function (a, b) {
            return a.namespace.localeCompare(b.namespace) || a.name.localeCompare(b.name);
        });
        model.endpoints.forEach(function (ep, i) {
            ep.index = i;
        });
        var ids = {};
        model.endpoints.forEach(function (ep) {
            if (ep.identity !== null) ids[ep.identity] = (ids[ep.identity] || 0) + 1;
        });
        model.identityUse = ids;
        model.identityCount = raw.identities.ok ? raw.identities.items.length : Object.keys(ids).length;
        model.identitiesServed = raw.identities.ok;
    }

    // ----- policies

    function peersOf(r, dir) {
        var P = dir === 'in' ? 'from' : 'to';
        var peers = [];
        arr(r[P + 'Endpoints']).forEach(function (sel) {
            peers.push({ type: 'endpoints', sel: sel });
        });
        arr(r[P + 'Entities']).forEach(function (e) {
            peers.push({ type: 'entity', value: e });
        });
        arr(r[P + 'CIDR']).forEach(function (c) {
            peers.push({ type: 'cidr', value: c, except: [] });
        });
        arr(r[P + 'CIDRSet']).forEach(function (s) {
            if (s.cidrGroupRef) peers.push({ type: 'cidr', value: s.cidrGroupRef, group: true, except: arr(s.except) });
            else if (s.cidrGroupSelector) peers.push({ type: 'cidr', value: selectorText(s.cidrGroupSelector), group: true, except: arr(s.except) });
            else peers.push({ type: 'cidr', value: s.cidr || '', except: arr(s.except) });
        });
        arr(r[P + 'Nodes']).forEach(function (sel) {
            peers.push({ type: 'nodes', sel: sel });
        });
        arr(r[P + 'Groups']).forEach(function (g) {
            var provider = Object.keys(g || {})[0] || 'cloud';
            peers.push({ type: 'group', value: provider, detail: JSON.stringify(g[provider] || {}) });
        });
        if (dir === 'out') {
            arr(r.toFQDNs).forEach(function (f) {
                peers.push({ type: 'fqdn', value: f.matchName || f.matchPattern || '', pattern: !f.matchName });
            });
            arr(r.toServices).forEach(function (s) {
                if (s.k8sService) {
                    peers.push({ type: 'service', value: (s.k8sService.namespace ? s.k8sService.namespace + '/' : '') + (s.k8sService.serviceName || '') });
                } else if (s.k8sServiceSelector) {
                    var sel = s.k8sServiceSelector;
                    peers.push({ type: 'service', value: (sel.namespace ? sel.namespace + '/' : '') + selectorText(sel.selector, 'any service') });
                }
            });
        }
        return peers;
    }

    function portRulesOf(list) {
        return arr(list).map(function (pr) {
            var rules = pr.rules || {};
            var l7 = [];
            arr(rules.http).forEach(function (h) {
                l7.push({ type: 'http', method: h.method || '', path: h.path || '', host: h.host || '', headers: arr(h.headers).length + arr(h.headerMatches).length });
            });
            arr(rules.dns).forEach(function (d) {
                l7.push({ type: 'dns', value: d.matchName || d.matchPattern || '', pattern: !d.matchName });
            });
            arr(rules.kafka).forEach(function (k) {
                l7.push({ type: 'kafka', value: [k.role || k.apiKey || '', k.topic || ''].filter(Boolean).join(' ') });
            });
            if (rules.l7proto) l7.push({ type: 'l7', value: rules.l7proto });
            return {
                ports: arr(pr.ports).map(function (p) {
                    return { port: p.port === undefined ? '' : String(p.port), end: p.endPort || 0, proto: p.protocol || 'ANY' };
                }),
                l7: l7,
                tls: !!(pr.terminatingTLS || pr.originatingTLS),
                serverNames: arr(pr.serverNames),
                listener: pr.listener ? pr.listener.name || '' : '',
            };
        });
    }

    function section(r, dir, deny) {
        r = r || {};
        var peers = peersOf(r, dir);
        var ports = portRulesOf(r.toPorts);
        var icmps = [];
        arr(r.icmps).forEach(function (i) {
            arr(i.fields).forEach(function (f) {
                icmps.push((f.family || 'IPv4') + ' ' + f.type);
            });
        });
        var P = dir === 'in' ? 'from' : 'to';
        return {
            dir: dir,
            deny: deny,
            peers: peers,
            requires: arr(r[P + 'Requires']),
            ports: ports,
            icmps: icmps,
            auth: dig(r, 'authentication.mode') || '',
            // No peer named: every peer, when ports are; nothing at all
            // when neither is -- the idiom for "default deny, allow none".
            anyPeer: peers.length === 0 && (ports.length > 0 || icmps.length > 0),
            nothing: peers.length === 0 && ports.length === 0 && icmps.length === 0,
        };
    }

    function ciliumRule(rule, policy, index) {
        rule = rule || {};
        var sections = [];
        arr(rule.ingress).forEach(function (r) {
            sections.push(section(r, 'in', false));
        });
        arr(rule.ingressDeny).forEach(function (r) {
            sections.push(section(r, 'in', true));
        });
        arr(rule.egress).forEach(function (r) {
            sections.push(section(r, 'out', false));
        });
        arr(rule.egressDeny).forEach(function (r) {
            sections.push(section(r, 'out', true));
        });
        var dd = rule.enableDefaultDeny || {};
        // An omitted or empty list leaves that direction alone.
        var hasIn = arr(rule.ingress).length > 0 || arr(rule.ingressDeny).length > 0;
        var hasOut = arr(rule.egress).length > 0 || arr(rule.egressDeny).length > 0;
        return {
            index: index,
            k8s: false,
            subject: rule.nodeSelector ? { type: 'nodes', sel: rule.nodeSelector } : { type: 'endpoints', sel: rule.endpointSelector || null },
            sections: sections,
            hasIngress: hasIn,
            hasEgress: hasOut,
            defaultDeny: {
                ingress: hasIn && dd.ingress !== false,
                egress: hasOut && dd.egress !== false,
            },
            denyAllIn: false,
            denyAllOut: false,
            description: rule.description || '',
            selected: [],
            nodes: [],
        };
    }

    function k8sPeer(p) {
        if (p.ipBlock) return { type: 'cidr', value: p.ipBlock.cidr || '', except: arr(p.ipBlock.except) };
        return { type: 'k8s', pod: p.podSelector || null, ns: p.namespaceSelector || null };
    }

    function k8sSection(r, dir) {
        var list = arr(dir === 'in' ? r.from : r.to);
        var ports = arr(r.ports).length
            ? [
                  {
                      ports: arr(r.ports).map(function (p) {
                          return { port: p.port === undefined ? '' : String(p.port), end: p.endPort || 0, proto: p.protocol || 'TCP' };
                      }),
                      l7: [],
                      tls: false,
                      serverNames: [],
                      listener: '',
                  },
              ]
            : [];
        var peers = list.map(k8sPeer);
        return {
            dir: dir,
            deny: false,
            peers: peers,
            requires: [],
            ports: ports,
            icmps: [],
            auth: '',
            // In a NetworkPolicy an empty `from` or `to` is every peer.
            anyPeer: peers.length === 0,
            nothing: false,
        };
    }

    function k8sRule(obj) {
        var spec = obj.spec || {};
        var types = arr(spec.policyTypes);
        if (!types.length) {
            // Kubernetes' own default: Ingress always, Egress when there
            // are egress rules.
            types = ['Ingress'];
            if (arr(spec.egress).length) types.push('Egress');
        }
        var hasIn = types.indexOf('Ingress') >= 0;
        var hasOut = types.indexOf('Egress') >= 0;
        var sections = [];
        if (hasIn) {
            arr(spec.ingress).forEach(function (r) {
                sections.push(k8sSection(r || {}, 'in'));
            });
        }
        if (hasOut) {
            arr(spec.egress).forEach(function (r) {
                sections.push(k8sSection(r || {}, 'out'));
            });
        }
        return {
            index: 0,
            k8s: true,
            subject: { type: 'endpoints', sel: spec.podSelector || {} },
            sections: sections,
            hasIngress: hasIn,
            hasEgress: hasOut,
            defaultDeny: { ingress: hasIn, egress: hasOut },
            denyAllIn: hasIn && arr(spec.ingress).length === 0,
            denyAllOut: hasOut && arr(spec.egress).length === 0,
            description: '',
            selected: [],
            nodes: [],
        };
    }

    var KIND_LABEL = { cnp: 'CiliumNetworkPolicy', ccnp: 'CiliumClusterwideNetworkPolicy', knp: 'NetworkPolicy' };
    var KIND_SHORT = { cnp: 'CNP', ccnp: 'CCNP', knp: 'K8s' };

    function buildPolicy(model, obj, kind) {
        var policy = {
            key: kind + ':' + keyOf(obj),
            id: kind + ':' + keyOf(obj),
            kind: kind,
            appKind: KINDS[kind],
            kindLabel: KIND_LABEL[kind],
            kindShort: KIND_SHORT[kind],
            name: obj.metadata.name,
            namespace: kind === 'ccnp' ? '' : obj.metadata.namespace || '',
            obj: obj,
            rules: [],
            valid: null,
            invalid: '',
            selected: [],
            nodes: [],
            ingress: 0,
            egress: 0,
            deny: false,
            l7: false,
            fqdn: false,
            host: false,
            description: '',
        };
        if (kind === 'knp') {
            policy.rules.push(k8sRule(obj));
        } else {
            if (obj.spec) policy.rules.push(ciliumRule(obj.spec, policy, 0));
            arr(obj.specs).forEach(function (r) {
                policy.rules.push(ciliumRule(r, policy, policy.rules.length));
            });
            var valid = conditionOf(obj, 'Valid');
            if (valid) {
                policy.valid = valid.status === 'True';
                if (!policy.valid) policy.invalid = valid.message || valid.reason || 'Cilium could not import this policy.';
            }
        }
        policy.rules.forEach(function (rule) {
            if (rule.description && !policy.description) policy.description = rule.description;
            if (rule.subject.type === 'nodes') policy.host = true;
            rule.sections.forEach(function (s) {
                if (s.dir === 'in') policy.ingress++;
                else policy.egress++;
                if (s.deny) policy.deny = true;
                s.ports.forEach(function (p) {
                    if (p.l7.length) policy.l7 = true;
                });
                s.peers.forEach(function (p) {
                    if (p.type === 'fqdn') policy.fqdn = true;
                });
            });
        });
        return policy;
    }

    // Which identity groups a rule's subject selects.
    function subjectGroups(model, policy, rule) {
        var sel = rule.subject.sel;
        return model.groups.filter(function (g) {
            if (policy.kind !== 'ccnp' && g.namespace !== policy.namespace) return false;
            if (policy.kind === 'knp') return selectsLabels(sel, g.labels.k8s);
            return selectsIdentity(sel, g.labels);
        });
    }

    function buildPolicies(model, raw) {
        // Cilium enforces Kubernetes NetworkPolicies unless told not to.
        model.k8sPolicies = cfg(model, 'enable-k8s-networkpolicy') !== 'false';
        var list = [];
        raw.cnp.items.forEach(function (o) {
            list.push(buildPolicy(model, o, 'cnp'));
        });
        raw.ccnp.items.forEach(function (o) {
            list.push(buildPolicy(model, o, 'ccnp'));
        });
        raw.knp.items.forEach(function (o) {
            list.push(buildPolicy(model, o, 'knp'));
        });
        list.forEach(function (policy) {
            var seen = {};
            var groupSeen = {};
            policy.rules.forEach(function (rule) {
                if (rule.subject.type === 'nodes') {
                    rule.nodes = model.nodes.filter(function (n) {
                        return selectsLabels(rule.subject.sel, n.labels);
                    });
                    rule.nodes.forEach(function (n) {
                        if (policy.nodes.indexOf(n) < 0) policy.nodes.push(n);
                    });
                    return;
                }
                var counts = policy.kind !== 'knp' || model.k8sPolicies;
                subjectGroups(model, policy, rule).forEach(function (g) {
                    if (counts && policy.valid !== false) {
                        if (rule.defaultDeny.ingress) g.ingress = true;
                        if (rule.defaultDeny.egress) g.egress = true;
                    }
                    g.endpoints.forEach(function (ep) {
                        rule.selected.push(ep);
                        if (!seen[ep.key]) {
                            seen[ep.key] = true;
                            policy.selected.push(ep);
                        }
                    });
                    if (!groupSeen[g.key]) {
                        groupSeen[g.key] = true;
                        g.policies.push(policy);
                    }
                });
            });
        });
        list.sort(function (a, b) {
            return a.namespace.localeCompare(b.namespace) || a.name.localeCompare(b.name) || a.kind.localeCompare(b.kind);
        });
        model.policies = list;
        model.policyByKey = {};
        list.forEach(function (p) {
            model.policyByKey[p.key] = p;
        });
        model.policyCounts = {
            cnp: raw.cnp.items.length,
            ccnp: raw.ccnp.items.length,
            knp: raw.knp.items.length,
            total: list.length,
        };
    }

    // Whether each endpoint is in default deny, per direction. The agent does
    // not publish this in CiliumEndpoints, so it is worked out the way the
    // agent does it: the enforcement mode first, then whether any valid rule
    // selecting the endpoint turns default deny on for that direction.
    function enforcement(model) {
        var mode = cfg(model, 'enable-policy') || 'default';
        model.enforcementMode = mode;
        model.coverage = { both: 0, ingress: 0, egress: 0, none: 0, total: 0 };
        model.endpoints.forEach(function (ep) {
            var ing = false;
            var eg = false;
            if (mode === 'always') {
                ing = eg = true;
            } else if (mode !== 'never' && ep.group) {
                ing = ep.group.ingress;
                eg = ep.group.egress;
            }
            ep.ingress = ing;
            ep.egress = eg;
            ep.enforcement = ing && eg ? 'both' : ing ? 'ingress' : eg ? 'egress' : 'none';
            model.coverage[ep.enforcement]++;
            model.coverage.total++;
        });
    }

    // Every policy selecting an endpoint, from the identity it has.
    function policiesFor(model, ep) {
        return ep.group ? ep.group.policies.slice() : [];
    }

    // What a peer of a rule stands for among the endpoints here.
    function resolvePeer(model, policy, peer) {
        var out = { endpoints: [], namespaces: [], nodes: [], known: true };
        var nsSeen = {};
        function take(g) {
            g.endpoints.forEach(function (ep) {
                out.endpoints.push(ep);
            });
            if (!nsSeen[g.namespace]) {
                nsSeen[g.namespace] = true;
                out.namespaces.push(g.namespace);
            }
        }
        if (peer.type === 'endpoints') {
            var own = policy.kind === 'cnp' && !namesNamespace(peer.sel);
            model.groups.forEach(function (g) {
                if (own && g.namespace !== policy.namespace) return;
                if (selectsIdentity(peer.sel, g.labels)) take(g);
            });
        } else if (peer.type === 'k8s') {
            model.groups.forEach(function (g) {
                if (peer.ns) {
                    var nsl = model.nsLabels[g.namespace] || namespaceLabelsFrom(g.labels);
                    if (!selectsLabels(peer.ns, nsl)) return;
                } else if (g.namespace !== policy.namespace) {
                    return;
                }
                if (peer.pod && !selectsLabels(peer.pod, g.labels.k8s)) return;
                take(g);
            });
        } else if (peer.type === 'nodes') {
            out.nodes = model.nodes.filter(function (n) {
                return selectsLabels(peer.sel, n.labels);
            });
        } else if (peer.type === 'entity') {
            if (peer.value === 'cluster' || peer.value === 'all') {
                model.groups.forEach(take);
                out.nodes = model.nodes.slice();
            } else if (peer.value === 'host' || peer.value === 'remote-node') {
                out.nodes = model.nodes.slice();
            } else {
                out.known = false;
            }
        } else {
            out.known = false;
        }
        out.namespaces.sort();
        return out;
    }

    // The namespace's labels as Cilium copies them into an identity.
    function namespaceLabelsFrom(set) {
        var out = {};
        var prefix = 'io.cilium.k8s.namespace.labels.';
        Object.keys(set.k8s).forEach(function (k) {
            if (k.indexOf(prefix) === 0) out[k.slice(prefix.length)] = set.k8s[k];
        });
        return out;
    }

    // ----- namespaces

    function buildNamespaces(model) {
        var by = {};
        function get(name) {
            if (!by[name]) {
                by[name] = { name: name, endpoints: [], policies: [], both: 0, ingress: 0, egress: 0, none: 0, notReady: 0, labels: model.nsLabels[name] || {} };
            }
            return by[name];
        }
        model.endpoints.forEach(function (ep) {
            var ns = get(ep.namespace);
            ns.endpoints.push(ep);
            ns[ep.enforcement]++;
            if (!ep.ready) ns.notReady++;
        });
        model.policies.forEach(function (p) {
            if (p.kind === 'ccnp') return;
            if (by[p.namespace]) by[p.namespace].policies.push(p);
        });
        model.namespaces = Object.keys(by)
            .map(function (k) {
                var ns = by[k];
                ns.enforced = ns.endpoints.length - ns.none;
                // Nothing selects anything here, and nothing is enforced:
                // every connection is let through.
                ns.open = ns.endpoints.length > 0 && ns.none === ns.endpoints.length && ns.policies.length === 0;
                return ns;
            })
            .sort(function (a, b) {
                return b.endpoints.length - a.endpoints.length || a.name.localeCompare(b.name);
            });
        model.namespaceByName = by;
    }

    // ----- services and LB IPAM

    function buildServices(model, raw) {
        model.services = raw.services.items
            .filter(function (s) {
                return dig(s, 'spec.type') === 'LoadBalancer';
            })
            .map(function (s) {
                var ingress = arr(dig(s, 'status.loadBalancer.ingress'));
                var cond = conditionOf(s, 'cilium.io/IPAMRequestSatisfied');
                return {
                    key: keyOf(s),
                    name: s.metadata.name,
                    namespace: s.metadata.namespace,
                    obj: s,
                    labels: labelsOf(s),
                    lbClass: dig(s, 'spec.loadBalancerClass') || '',
                    ips: ingress
                        .map(function (i) {
                            return i.ip;
                        })
                        .filter(Boolean),
                    satisfied: cond ? cond.status === 'True' : null,
                    reason: cond && cond.status !== 'True' ? cond.message || cond.reason || '' : '',
                };
            });
    }

    // The numbers LB IPAM writes into a pool's conditions, as numbers.
    function conditionNumber(obj, type) {
        var c = conditionOf(obj, type);
        if (!c) return null;
        var n = Number(c.message);
        return isFinite(n) ? n : null;
    }

    function buildLB(model, raw) {
        if (!raw.lbPools.ok) {
            model.lb = null;
            return;
        }
        var pools = raw.lbPools.items.map(function (obj) {
            var spec = obj.spec || {};
            var blocks = arr(spec.blocks).length ? arr(spec.blocks) : arr(spec.cidrs);
            var parsed = blocks.map(parseBlock);
            var capacity = 0;
            parsed.forEach(function (b) {
                capacity += b.size;
            });
            var conflict = conditionOf(obj, 'cilium.io/PoolConflict');
            var pool = {
                name: obj.metadata.name,
                obj: obj,
                labels: labelsOf(obj),
                blocks: parsed,
                disabled: spec.disabled === true,
                serviceSelector: spec.serviceSelector || null,
                allowFirstLast: spec.allowFirstLastIPs === 'Yes' || spec.allowFirstLastIPs === true,
                conflict: conflict && conflict.status === 'True' ? conflict.message || conflict.reason || 'conflicts with another pool' : '',
                total: conditionNumber(obj, 'cilium.io/IPsTotal'),
                available: conditionNumber(obj, 'cilium.io/IPsAvailable'),
                used: conditionNumber(obj, 'cilium.io/IPsUsed'),
                capacity: capacity,
                services: [],
                holders: [],
            };
            return pool;
        });
        model.services.forEach(function (svc) {
            svc.pool = null;
            svc.ips.forEach(function (ip) {
                pools.forEach(function (p) {
                    if (
                        p.blocks.some(function (b) {
                            return inBlock(b, ip);
                        })
                    ) {
                        if (p.services.indexOf(svc) < 0) p.services.push(svc);
                        p.holders.push({ ip: ip, svc: svc });
                        svc.pool = svc.pool || p;
                    }
                });
            });
        });
        pools.forEach(function (p) {
            if (p.used === null) p.used = p.holders.length;
            if (p.total === null) p.total = p.capacity;
            p.fraction = p.total > 0 && isFinite(p.total) ? Math.min(1, p.used / p.total) : 0;
            p.holders.sort(function (a, b) {
                return (parseIPv4(a.ip) || 0) - (parseIPv4(b.ip) || 0);
            });
        });
        pools.sort(function (a, b) {
            return a.name.localeCompare(b.name);
        });
        var cilium = function (svc) {
            return svc.lbClass === '' || svc.lbClass.indexOf('io.cilium') === 0;
        };
        model.lb = {
            pools: pools,
            pending: model.services.filter(function (s) {
                return s.ips.length === 0 && cilium(s) && pools.length > 0;
            }),
        };
    }

    // ----- L2 announcements

    // The Lease a service's L2 announcement is elected through:
    // cilium-l2announce-<namespace>-<name>, or with a dot since 1.21.
    var LEASE_PREFIX = 'cilium-l2announce-';

    function buildL2(model, raw) {
        if (!raw.l2.ok) {
            model.l2 = null;
            return;
        }
        var byLease = {};
        model.services.forEach(function (s) {
            byLease[LEASE_PREFIX + s.namespace + '-' + s.name] = s;
            byLease[LEASE_PREFIX + s.namespace + '.' + s.name] = s;
        });
        arr(raw.leases && raw.leases.items).forEach(function (lease) {
            var svc = byLease[lease.metadata.name];
            if (!svc) return;
            svc.announcer = dig(lease, 'spec.holderIdentity') || '';
            svc.announcedSince = dig(lease, 'spec.acquireTime') || '';
        });
        model.leasesRead = !!(raw.leases && raw.leases.ok);
        model.l2 = raw.l2.items
            .map(function (obj) {
                var spec = obj.spec || {};
                var errors = arr(dig(obj, 'status.conditions'))
                    .filter(function (c) {
                        return /^io\.cilium\/bad-/.test(c.type || '') && c.status === 'True';
                    })
                    .map(function (c) {
                        return c.message || c.type;
                    });
                return {
                    name: obj.metadata.name,
                    obj: obj,
                    errors: errors,
                    interfaces: arr(spec.interfaces),
                    externalIPs: spec.externalIPs === true,
                    loadBalancerIPs: spec.loadBalancerIPs === true,
                    nodeSelector: spec.nodeSelector || null,
                    serviceSelector: spec.serviceSelector || null,
                    nodes: model.nodes.filter(function (n) {
                        return n.obj && selectsLabels(spec.nodeSelector, n.labels);
                    }),
                    services: model.services.filter(function (s) {
                        return selectsLabels(spec.serviceSelector, s.labels);
                    }),
                };
            })
            .sort(function (a, b) {
                return a.name.localeCompare(b.name);
            });
    }

    // ----- BGP

    var SESSION_TONE = { established: 'ok', active: 'error', idle: 'error', connect: 'warn', open_sent: 'warn', open_confirm: 'warn', opensent: 'warn', openconfirm: 'warn', unknown: 'muted' };

    function problems(obj, types) {
        return arr(dig(obj, 'status.conditions'))
            .filter(function (c) {
                return types.indexOf(c.type) >= 0 && c.status === 'True';
            })
            .map(function (c) {
                return c.message || c.reason || c.type;
            });
    }

    function buildBGP(model, raw) {
        var v2 = raw.bgpCluster.ok || raw.bgpNodes.ok;
        var legacy = raw.bgpLegacy.ok && raw.bgpLegacy.items.length > 0;
        if (!v2 && !legacy) {
            model.bgp = null;
            return;
        }
        var bgp = {
            mode: raw.bgpCluster.items.length || raw.bgpNodes.items.length || !legacy ? 'v2' : 'legacy',
            clusterConfigs: [],
            peerConfigs: raw.bgpPeers.items,
            advertisements: raw.bgpAdverts.items,
            sessions: [],
            peers: [],
            legacy: raw.bgpLegacy.items,
        };
        raw.bgpCluster.items.forEach(function (obj) {
            var spec = obj.spec || {};
            bgp.clusterConfigs.push({
                name: obj.metadata.name,
                obj: obj,
                errors: problems(obj, ['cilium.io/NoMatchingNode', 'cilium.io/MissingPeerConfigs', 'cilium.io/ConflictingClusterConfig']),
                nodeSelector: spec.nodeSelector || null,
                instances: arr(spec.bgpInstances),
                nodes: model.nodes.filter(function (n) {
                    return n.obj && selectsLabels(spec.nodeSelector, n.labels);
                }),
            });
        });
        var statusSeen = {};
        bgp.nodeErrors = [];
        raw.bgpNodes.items.forEach(function (obj) {
            var node = obj.metadata.name;
            problems(obj, ['cilium.io/BGPReconcileError']).forEach(function (text) {
                bgp.nodeErrors.push({ node: node, text: text });
            });
            var specInstances = arr(dig(obj, 'spec.bgpInstances'));
            var statusInstances = arr(dig(obj, 'status.bgpInstances'));
            statusInstances.forEach(function (inst) {
                arr(inst.peers).forEach(function (p) {
                    statusSeen[node + '|' + p.peerAddress] = true;
                    // 1.16 wrote routesAdvertised / routesReceived instead
                    // of routeCount.
                    var routes = arr(p.routeCount);
                    if (!routes.length && (p.routesAdvertised !== undefined || p.routesReceived !== undefined)) {
                        routes = [{ afi: '', safi: '', advertised: p.routesAdvertised, received: p.routesReceived }];
                    }
                    bgp.sessions.push({
                        node: node,
                        instance: inst.name || '',
                        localASN: inst.localASN,
                        name: p.name || '',
                        address: p.peerAddress || '',
                        asn: p.peerASN,
                        state: String(p.peeringState || 'unknown').toLowerCase(),
                        since: p.establishedTime || '',
                        uptime: p.uptime || '',
                        routes: routes,
                        source: obj,
                    });
                });
            });
            // A peer configured but not (yet) in the status.
            specInstances.forEach(function (inst) {
                arr(inst.peers).forEach(function (p) {
                    if (statusSeen[node + '|' + p.peerAddress]) return;
                    bgp.sessions.push({ node: node, instance: inst.name || '', localASN: inst.localASN, name: p.name || '', address: p.peerAddress || '', asn: p.peerASN, state: 'unknown', since: '', routes: [], source: obj });
                });
            });
        });
        if (bgp.mode === 'legacy') {
            raw.bgpLegacy.items.forEach(function (obj) {
                var spec = obj.spec || {};
                var nodes = model.nodes.filter(function (n) {
                    return n.obj && selectsLabels(spec.nodeSelector, n.labels);
                });
                arr(spec.virtualRouters).forEach(function (vr) {
                    arr(vr.neighbors).forEach(function (nb) {
                        nodes.forEach(function (n) {
                            bgp.sessions.push({
                                node: n.name,
                                instance: 'AS' + vr.localASN,
                                localASN: vr.localASN,
                                name: '',
                                address: String(nb.peerAddress || '').replace(/\/(32|128)$/, ''),
                                asn: nb.peerASN,
                                state: 'unknown',
                                since: '',
                                routes: [],
                                source: obj,
                            });
                        });
                    });
                });
            });
        }
        var byAddress = {};
        bgp.sessions.forEach(function (s) {
            s.tone = SESSION_TONE[s.state] || 'warn';
            var key = s.address + '|' + s.asn;
            if (!byAddress[key]) {
                byAddress[key] = { key: key, address: s.address, asn: s.asn, name: s.name, sessions: [] };
                bgp.peers.push(byAddress[key]);
            }
            byAddress[key].sessions.push(s);
        });
        bgp.peers.forEach(function (p) {
            p.up = p.sessions.filter(function (s) {
                return s.state === 'established';
            }).length;
            p.down = p.sessions.filter(function (s) {
                return s.tone === 'error';
            }).length;
        });
        bgp.peers.sort(function (a, b) {
            return a.address.localeCompare(b.address);
        });
        bgp.nodes = {};
        bgp.sessions.forEach(function (s) {
            (bgp.nodes[s.node] = bgp.nodes[s.node] || []).push(s);
        });
        bgp.down = bgp.sessions.filter(function (s) {
            return s.tone === 'error';
        });
        bgp.known = bgp.sessions.some(function (s) {
            return s.state !== 'unknown';
        });
        model.bgp = bgp;
    }

    // ----- egress gateways

    function buildEgress(model, raw) {
        if (!raw.egress.ok) {
            model.egress = null;
            return;
        }
        model.egress = raw.egress.items
            .map(function (obj) {
                var spec = obj.spec || {};
                var gateways = arr(spec.egressGateways).length ? arr(spec.egressGateways) : spec.egressGateway ? [spec.egressGateway] : [];
                var selectors = arr(spec.selectors);
                var sources = model.groups.filter(function (g) {
                    return selectors.some(function (s) {
                        if (s.podSelector && !selectsLabels(s.podSelector, g.labels.k8s)) return false;
                        if (s.namespaceSelector && !selectsLabels(s.namespaceSelector, model.nsLabels[g.namespace] || namespaceLabelsFrom(g.labels))) return false;
                        return !!(s.podSelector || s.namespaceSelector);
                    });
                });
                var count = 0;
                sources.forEach(function (g) {
                    count += g.endpoints.length;
                });
                return {
                    name: obj.metadata.name,
                    obj: obj,
                    destinations: arr(spec.destinationCIDRs),
                    excluded: arr(spec.excludedCIDRs),
                    selectors: selectors,
                    sources: count,
                    gateways: gateways.map(function (g) {
                        return {
                            egressIP: g.egressIP || '',
                            iface: g.interface || '',
                            nodeSelector: g.nodeSelector || null,
                            nodes: model.nodes.filter(function (n) {
                                return n.obj && g.nodeSelector && selectsLabels(g.nodeSelector, n.labels);
                            }),
                        };
                    }),
                };
            })
            .sort(function (a, b) {
                return a.name.localeCompare(b.name);
            });
    }

    // ----- the datapath, as cilium-config says --------------------------------

    function cfg(model, key) {
        var v = model.config.data[key];
        return v === undefined ? undefined : String(v).trim();
    }

    function on(v) {
        return v === 'true' || v === 'True' || v === 'enabled';
    }

    var IPAM_NAMES = {
        'cluster-pool': 'Cluster pool',
        kubernetes: 'Kubernetes',
        'multi-pool': 'Multi-pool',
        eni: 'AWS ENI',
        azure: 'Azure',
        'alibabacloud': 'Alibaba Cloud',
        crd: 'CRD',
        delegated: 'Delegated',
    };

    // One tile per datapath feature: { id, label, value, detail, on, icon }.
    // `on` is true, false, or null when it cannot be told.
    function features(model) {
        var have = model.config.ok;
        var out = [];
        function tile(id, label, icon, value, detail, state) {
            out.push({ id: id, label: label, icon: icon, value: value, detail: detail || '', on: state === undefined ? null : state });
        }
        var nodesWithKey = model.nodes.filter(function (n) {
            return n.encryptionKey !== undefined && n.encryptionKey !== null && Number(n.encryptionKey) > 0;
        }).length;
        var relay = model.components.relay;
        var hubbleUi = model.components.hubbleUi;

        if (have) {
            // Routing.
            var mode = cfg(model, 'routing-mode');
            var legacyTunnel = cfg(model, 'tunnel');
            var proto = cfg(model, 'tunnel-protocol') || (legacyTunnel && legacyTunnel !== 'disabled' ? legacyTunnel : '') || 'vxlan';
            var native = mode ? mode === 'native' : legacyTunnel === 'disabled';
            tile(
                'routing',
                'Routing',
                native ? 'route' : 'tunnel',
                native ? 'Native' : 'Tunnel · ' + proto.toUpperCase(),
                native ? (on(cfg(model, 'auto-direct-node-routes')) ? 'direct node routes' : 'routed by the network') : 'encapsulated between nodes',
                true,
            );
            // kube-proxy replacement.
            var kpr = cfg(model, 'kube-proxy-replacement');
            var kprOn = kpr === 'true' || kpr === 'strict';
            var kprPartial = kpr === 'partial' || kpr === 'probe';
            var lbMode = cfg(model, 'bpf-lb-mode');
            tile('kpr', 'Service handling', 'bolt', kprOn ? 'eBPF' : kprPartial ? 'eBPF + kube-proxy' : 'kube-proxy', kprOn ? 'kube-proxy replaced' + (lbMode ? ' · ' + lbMode.toUpperCase() : '') : kprPartial ? 'partly replaced' : 'kube-proxy replacement off', kprOn || (kprPartial ? null : false));
            // Encryption.
            var wg = on(cfg(model, 'enable-wireguard'));
            var ipsec = on(cfg(model, 'enable-ipsec'));
            var nodeEnc = on(cfg(model, 'encrypt-node'));
            tile('encryption', 'Encryption', wg || ipsec ? 'lock' : 'unlock', wg ? 'WireGuard' : ipsec ? 'IPsec' : 'Off', wg || ipsec ? (nodeEnc ? 'pods and nodes' : 'pod to pod') : 'node to node in the clear', wg || ipsec);
            // Hubble.
            var hubble = on(cfg(model, 'enable-hubble'));
            var hubbleDetail = hubble ? (relay.total ? 'relay ' + relay.ready + '/' + relay.total : 'no relay') + (hubbleUi.total ? ' · UI' : '') : 'no flow visibility';
            tile('hubble', 'Hubble', 'eye', hubble ? 'On' : 'Off', hubbleDetail, hubble);
            // IPAM.
            var ipam = cfg(model, 'ipam') || 'cluster-pool';
            var pool = cfg(model, 'cluster-pool-ipv4-cidr');
            tile('ipam', 'IPAM', 'grid', IPAM_NAMES[ipam] || ipam, ipam === 'cluster-pool' && pool ? pool + (cfg(model, 'cluster-pool-ipv4-mask-size') ? ' · /' + cfg(model, 'cluster-pool-ipv4-mask-size') + ' each' : '') : 'pod addresses', true);
            // Policy enforcement.
            var enforce = cfg(model, 'enable-policy') || 'default';
            tile('enforcement', 'Policy enforcement', 'shield', enforce === 'always' ? 'Always' : enforce === 'never' ? 'Never' : 'Default', enforce === 'always' ? 'deny unless allowed' : enforce === 'never' ? 'policies are ignored' : 'where policies select', enforce !== 'never');
            // Audit mode.
            var audit = on(cfg(model, 'policy-audit-mode'));
            tile('audit', 'Policy audit mode', 'eyeOff', audit ? 'On' : 'Off', audit ? 'denials are only logged' : 'denials are dropped', audit ? null : false);
            // Host firewall.
            var hostFw = on(cfg(model, 'enable-host-firewall'));
            tile('hostfw', 'Host firewall', 'wall', hostFw ? 'On' : 'Off', hostFw ? 'host policies apply to nodes' : 'nodes are not policed', hostFw);
            // IP families.
            var v4 = cfg(model, 'enable-ipv4') !== 'false';
            var v6 = on(cfg(model, 'enable-ipv6'));
            tile('families', 'IP families', 'layers', v4 && v6 ? 'Dual stack' : v6 ? 'IPv6' : 'IPv4', [v4 ? 'IPv4' : '', v6 ? 'IPv6' : ''].filter(Boolean).join(' + '), true);
            // BGP.
            var bgpOn = on(cfg(model, 'enable-bgp-control-plane'));
            tile('bgp', 'BGP control plane', 'bgp', bgpOn ? 'On' : 'Off', bgpOn ? (model.bgp ? plural(model.bgp.peers.length, 'peer') : 'announces routes') : 'no route announcements', bgpOn);
            // L2.
            var l2On = on(cfg(model, 'enable-l2-announcements'));
            tile('l2', 'L2 announcements', 'l2', l2On ? 'On' : 'Off', l2On ? (model.l2 ? plural(model.l2.length, 'policy', 'policies') : 'ARP / NDP for services') : 'no ARP / NDP answers', l2On);
            // Gateway API / ingress.
            var gw = on(cfg(model, 'enable-gateway-api'));
            var ing = on(cfg(model, 'enable-ingress-controller'));
            tile('gateway', 'Gateway API · Ingress', 'gateway', gw && ing ? 'Both' : gw ? 'Gateway API' : ing ? 'Ingress' : 'Off', gw || ing ? 'served by Cilium' + (model.components.envoy.total ? "'s Envoy" : '') : 'another controller, or none', gw || ing);
            // Bandwidth.
            var bw = on(cfg(model, 'enable-bandwidth-manager'));
            tile('bandwidth', 'Bandwidth manager', 'gauge', bw ? 'On' : 'Off', bw ? (on(cfg(model, 'enable-bbr')) ? 'with BBR' : 'pod egress rate limits') : 'annotations ignored', bw);
            // Egress gateway.
            // enable-egress-gateway since 1.18, enable-ipv4-egress-gateway before.
            var egw = on(cfg(model, 'enable-egress-gateway')) || on(cfg(model, 'enable-ipv4-egress-gateway'));
            tile('egress', 'Egress gateway', 'exit', egw ? 'On' : 'Off', egw ? (model.egress ? plural(model.egress.length, 'policy', 'policies') : 'fixed egress IPs') : 'pods leave from their node', egw);
            // Cluster mesh.
            var name = cfg(model, 'cluster-name') || '';
            var cid = cfg(model, 'cluster-id') || '';
            var meshed = model.components.clustermesh.total > 0 || (cid !== '' && cid !== '0');
            tile('mesh', 'Cluster Mesh', 'mesh', meshed ? 'On' : 'Off', (name ? name : 'unnamed') + (cid ? ' · id ' + cid : ''), meshed);
            // L7 proxy.
            var l7 = cfg(model, 'enable-l7-proxy');
            tile('l7', 'L7 proxy', 'http', l7 === 'false' ? 'Off' : 'On', l7 === 'false' ? 'HTTP / DNS rules cannot apply' : 'HTTP, DNS and Kafka rules', l7 !== 'false');
            // Datapath mode.
            var dp = cfg(model, 'datapath-mode');
            if (dp) tile('datapath', 'Datapath', 'chip', dp === 'netkit' ? 'netkit' : dp === 'veth' ? 'veth' : dp, on(cfg(model, 'enable-bpf-masquerade')) ? 'eBPF masquerading' : 'iptables masquerading', true);
        } else {
            // What can be told without the ConfigMap.
            tile('encryption', 'Encryption', nodesWithKey ? 'lock' : 'unlock', nodesWithKey ? 'Keys in use' : 'Unknown', nodesWithKey ? 'on ' + plural(nodesWithKey, 'node') : 'no node shows a key', nodesWithKey ? true : null);
            tile('hubble', 'Hubble', 'eye', relay.total ? 'Relay running' : 'Unknown', relay.total ? 'relay ' + relay.ready + '/' + relay.total + (hubbleUi.total ? ' · UI' : '') : 'no relay pods', relay.total ? true : null);
            tile('bgp', 'BGP control plane', 'bgp', model.bgp && model.bgp.sessions.length ? 'In use' : 'Unknown', model.bgp ? plural(model.bgp.peers.length, 'peer') : 'no BGP objects', model.bgp && model.bgp.sessions.length ? true : null);
            tile('l2', 'L2 announcements', 'l2', model.l2 && model.l2.length ? 'In use' : 'Unknown', model.l2 ? plural(model.l2.length, 'policy', 'policies') : 'no L2 policies', model.l2 && model.l2.length ? true : null);
            tile('gateway', 'Envoy', 'gateway', model.components.envoy.total ? 'Running' : 'Unknown', model.components.envoy.total ? plural(model.components.envoy.total, 'pod') : 'no separate Envoy pods', model.components.envoy.total ? true : null);
            tile('mesh', 'Cluster Mesh', 'mesh', model.components.clustermesh.total ? 'On' : 'Unknown', model.components.clustermesh.total ? 'API server running' : 'no API server pods', model.components.clustermesh.total ? true : null);
            tile('enforcement', 'Policy enforcement', 'shield', model.coverage.total ? percent((model.coverage.total - model.coverage.none) / model.coverage.total) : 'Unknown', 'of endpoints enforce policy', null);
        }
        return out;
    }

    // How a node's traffic is encrypted, as far as can be told: WireGuard
    // needs no key index, IPsec shows one on the CiliumNode.
    function nodeEncryption(model, n) {
        if (on(cfg(model, 'enable-wireguard'))) return { text: 'WireGuard', tone: 'ok' };
        var key = Number(n.encryptionKey);
        if (key > 0) return { text: 'IPsec · key ' + key, tone: 'ok' };
        if (on(cfg(model, 'enable-ipsec'))) return { text: 'IPsec · no key yet', tone: 'warn' };
        if (model.config.ok) return { text: 'off', tone: 'muted' };
        return null;
    }

    function feature(model, id) {
        for (var i = 0; i < model.features.length; i++) if (model.features[i].id === id) return model.features[i];
        return null;
    }

    // ----- what needs attention --------------------------------------------------

    function findings(model) {
        var out = [];
        if (!model.installed) return out;
        var agent = model.components.agent;
        var operator = model.components.operator;

        // Agents.
        if (model.agentsKnown) {
            var down = model.nodes.filter(function (n) {
                return n.agent && !n.agentReady;
            });
            if (down.length) {
                out.push({
                    tone: 'error',
                    icon: 'node',
                    title: 'Agent not ready on ' + names(down.map(nodeName)),
                    text: down[0].agentTrouble ? down[0].agentTrouble + (down[0].agentRestarts ? ' · ' + plural(down[0].agentRestarts, 'restart') : '') + '. New pods there get no network, and policy is not updated.' : 'New pods there get no network, and policy is not updated.',
                    ref: { kind: KINDS.pods, namespace: down[0].agent.metadata.namespace, name: down[0].agent.metadata.name },
                    logs: { kind: KINDS.pods, namespace: down[0].agent.metadata.namespace, name: down[0].agent.metadata.name },
                });
            }
            var missing = model.nodes.filter(function (n) {
                return n.obj && !n.agent;
            });
            if (missing.length) {
                out.push({ tone: 'error', icon: 'node', title: 'No Cilium agent on ' + names(missing.map(nodeName)), text: 'Pods scheduled there cannot be networked. Check the DaemonSet’s tolerations and node selector.', ref: { kind: KINDS.nodes, namespace: '', name: missing[0].name } });
            }
            var flappy = model.nodes.filter(function (n) {
                return n.agentReady && n.agentRestarts > 5;
            });
            if (flappy.length) {
                out.push({ tone: 'warn', icon: 'cycle', title: 'Agent restarting on ' + names(flappy.map(nodeName)), text: plural(flappy[0].agentRestarts, 'restart') + ' on ' + flappy[0].name + '. It is ready now; the logs say why it went down.', logs: { kind: KINDS.pods, namespace: flappy[0].agent.metadata.namespace, name: flappy[0].agent.metadata.name } });
            }
        }
        if (operator.total === 0 && model.agentsKnown) {
            out.push({ tone: 'warn', icon: 'operator', title: 'No Cilium operator found', text: 'Looked for pods labelled ' + operator.selector + '. Without the operator, IPAM and garbage collection stop.' });
        } else if (operator.total > 0 && operator.ready === 0) {
            out.push({ tone: 'error', icon: 'operator', title: 'The Cilium operator is not ready', text: podTrouble(operator.pods[0]) + '. IPAM allocations and identity garbage collection wait for it.', ref: podRef(operator.pods[0]), logs: podRef(operator.pods[0]) });
        }
        var relay = model.components.relay;
        if (relay.total > 0 && relay.ready < relay.total) {
            out.push({ tone: 'warn', icon: 'eye', title: 'Hubble Relay is not ready', text: podTrouble(relay.pods[0]) + '. Flow visibility across nodes is unavailable.', ref: podRef(relay.pods[0]), logs: podRef(relay.pods[0]) });
        }
        model.nodes.forEach(function (n) {
            if (n.ipamError) out.push({ tone: 'error', icon: 'grid', title: 'IPAM error on ' + n.name, text: n.ipamError, ref: { kind: KINDS.ciliumNodes, namespace: '', name: n.name } });
            else if (n.ipamUsed !== null && n.ipamCapacity > 0 && n.ipamUsed / n.ipamCapacity >= 0.9) {
                out.push({ tone: 'warn', icon: 'grid', title: 'Pod addresses nearly used up on ' + n.name, text: n.ipamUsed + ' of ' + n.ipamCapacity + ' in use. New pods there will wait for an address.', ref: { kind: KINDS.ciliumNodes, namespace: '', name: n.name } });
            }
        });

        // Endpoints.
        if (model.notReady.length) {
            var byState = {};
            model.notReady.forEach(function (ep) {
                var s = (STATES[ep.state] || { label: ep.state || 'no state' }).label;
                byState[s] = (byState[s] || 0) + 1;
            });
            var worst = model.notReady.some(function (ep) {
                return ep.stateTone === 'warn' || ep.stateTone === 'error';
            });
            out.push({
                tone: worst ? 'warn' : 'info',
                icon: 'hex',
                title: plural(model.notReady.length, 'endpoint is', 'endpoints are') + ' not ready',
                text:
                    Object.keys(byState)
                        .map(function (k) {
                            return byState[k] + ' ' + k;
                        })
                        .join(', ') +
                    ' — ' +
                    names(
                        model.notReady.map(function (ep) {
                            return ep.namespace + '/' + ep.name;
                        }),
                        2,
                    ) +
                    '.',
                view: 'endpoints',
                hash: 'filter=notready',
            });
        }

        // Policies.
        model.policies.forEach(function (p) {
            if (p.valid === false) {
                out.push({ tone: 'error', icon: 'shield', title: p.kindShort + ' ' + (p.namespace ? p.namespace + '/' : '') + p.name + ' is invalid', text: p.invalid, ref: { kind: p.appKind, namespace: p.namespace, name: p.name }, policy: p.key });
            }
        });
        var idle = model.policies.filter(function (p) {
            return p.valid !== false && p.selected.length === 0 && p.nodes.length === 0 && model.endpoints.length > 0;
        });
        if (idle.length === 1) {
            var ip = idle[0];
            out.push({ tone: 'warn', icon: 'shield', title: ip.kindShort + ' ' + (ip.namespace ? ip.namespace + '/' : '') + ip.name + ' selects nothing', text: 'No endpoint matches ' + selectorText(ip.rules[0] ? ip.rules[0].subject.sel : null) + (ip.namespace ? ' in ' + ip.namespace : '') + '. A typo in a label keeps a policy from protecting anything.', policy: ip.key, ref: { kind: ip.appKind, namespace: ip.namespace, name: ip.name } });
        } else if (idle.length > 1) {
            out.push({
                tone: 'warn',
                icon: 'shield',
                title: plural(idle.length, 'policy selects', 'policies select') + ' nothing',
                text:
                    names(
                        idle.map(function (p) {
                            return (p.namespace ? p.namespace + '/' : '') + p.name;
                        }),
                    ) + '. A typo in a label keeps a policy from protecting anything.',
                policy: idle[0].key,
            });
        }
        var open = model.namespaces.filter(function (ns) {
            return ns.open;
        });
        if (open.length) {
            out.push({
                tone: 'warn',
                icon: 'unlock',
                title: plural(open.length, 'namespace has', 'namespaces have') + ' no policy',
                text:
                    names(
                        open.map(function (ns) {
                            return ns.name + ' (' + ns.endpoints.length + ')';
                        }),
                    ) + ' — every connection to and from those pods is allowed.',
                view: 'endpoints',
                hash: 'filter=open',
            });
        }
        var audit = cfg(model, 'policy-audit-mode');
        if (on(audit)) {
            out.push({ tone: 'warn', icon: 'eyeOff', title: 'Policy audit mode is on', text: 'Traffic policies would deny is logged and let through. Nothing is actually blocked.' });
        }
        if (cfg(model, 'enable-policy') === 'never') {
            out.push({ tone: 'warn', icon: 'shield', title: 'Policy enforcement is off', text: 'enable-policy is "never": every policy in the cluster is ignored.' });
        }

        // LB IPAM.
        if (model.lb) {
            model.lb.pools.forEach(function (p) {
                var ref = { kind: KINDS.lbPools, namespace: '', name: p.name };
                if (p.conflict) out.push({ tone: 'error', icon: 'grid', title: 'LB pool ' + p.name + ' conflicts', text: p.conflict, ref: ref });
                else if (!p.disabled && p.total > 0 && p.available === 0) out.push({ tone: 'error', icon: 'grid', title: 'LB pool ' + p.name + ' is exhausted', text: 'All ' + p.total + ' addresses are handed out. The next LoadBalancer service it serves will wait.', ref: ref });
                else if (!p.disabled && p.total > 0 && p.fraction >= 0.85) out.push({ tone: 'warn', icon: 'grid', title: 'LB pool ' + p.name + ' is ' + percent(p.fraction) + ' full', text: p.used + ' of ' + p.total + ' addresses in use.', ref: ref });
            });
            if (model.lb.pending.length) {
                var s0 = model.lb.pending[0];
                out.push({
                    tone: 'warn',
                    icon: 'service',
                    title: plural(model.lb.pending.length, 'service is', 'services are') + ' waiting for an address',
                    text:
                        names(
                            model.lb.pending.map(function (s) {
                                return s.namespace + '/' + s.name;
                            }),
                        ) + (s0.reason ? ' — ' + s0.reason : '.'),
                    ref: { kind: KINDS.services, namespace: s0.namespace, name: s0.name },
                });
            }
        }

        // BGP.
        if (model.bgp && model.bgp.down.length) {
            var d = model.bgp.down;
            out.push({
                tone: 'error',
                icon: 'bgp',
                title: plural(d.length, 'BGP session is', 'BGP sessions are') + ' down',
                text:
                    names(
                        d.map(function (s) {
                            return s.node + ' → ' + s.address + ' (' + s.state + ')';
                        }),
                        2,
                    ) + '. Routes announced over ' + (d.length === 1 ? 'it' : 'them') + ' are withdrawn.',
                view: 'network',
                ref: { kind: KINDS.bgpNodes, namespace: '', name: d[0].node },
            });
        }
        if (model.bgp) {
            model.bgp.clusterConfigs.forEach(function (c) {
                if (c.errors.length) out.push({ tone: 'warn', icon: 'bgp', title: 'BGP cluster config ' + c.name + ' has a problem', text: c.errors.join(' '), ref: { kind: KINDS.bgpCluster, namespace: '', name: c.name }, view: 'network' });
            });
            model.bgp.nodeErrors.slice(0, 2).forEach(function (e) {
                out.push({ tone: 'error', icon: 'bgp', title: 'BGP could not be set up on ' + e.node, text: e.text, ref: { kind: KINDS.bgpNodes, namespace: '', name: e.node } });
            });
        }
        if (model.l2) {
            model.l2.forEach(function (p) {
                if (p.errors.length) out.push({ tone: 'error', icon: 'l2', title: 'L2 announcement policy ' + p.name + ' is broken', text: p.errors.join(' '), ref: { kind: KINDS.l2, namespace: '', name: p.name }, view: 'network' });
            });
        }
        if (!model.k8sPolicies && model.policyCounts.knp) {
            out.push({ tone: 'warn', icon: 'shield', title: 'Kubernetes NetworkPolicies are ignored', text: 'enable-k8s-networkpolicy is false, so the ' + plural(model.policyCounts.knp, 'NetworkPolicy', 'NetworkPolicies') + ' here have no effect.' });
        }
        var rank = { error: 0, warn: 1, info: 2 };
        return out.sort(function (a, b) {
            return rank[a.tone] - rank[b.tone];
        });
    }

    function nodeName(n) {
        return n.name;
    }

    function podRef(pod) {
        return { kind: KINDS.pods, namespace: pod.metadata.namespace, name: pod.metadata.name };
    }

    // ----- events ----------------------------------------------------------------

    var KIND_PREFIX = /^Cilium/;

    function eventWhen(ev) {
        return ev.lastTimestamp || ev.eventTime || (ev.series && ev.series.lastObservedTime) || ev.metadata.creationTimestamp || '';
    }

    // What Cilium and its pods have been doing, newest first: the kubelet on
    // Cilium's own pods, anything about Cilium's objects, and the packet
    // drops Hubble reports as events on the pods they hit (when its drop
    // event emitter is on). Those land in the pods' namespaces, so the
    // busiest namespaces under policy are read too.
    var EVENT_NAMESPACES = 16;

    function loadEvents(sdk, model) {
        var namespaces = [model.namespace];
        if (namespaces.indexOf('default') < 0) namespaces.push('default');
        model.namespaces
            .filter(function (ns) {
                return ns.enforced > 0;
            })
            .slice(0, EVENT_NAMESPACES)
            .forEach(function (ns) {
                if (namespaces.indexOf(ns.name) < 0) namespaces.push(ns.name);
            });
        return Promise.all(
            namespaces.map(function (ns) {
                return sdk.list({ kind: KINDS.events, namespace: ns }).catch(function () {
                    return [];
                });
            }),
        ).then(function (answers) {
            var out = [];
            var seen = {};
            answers.forEach(function (items) {
                items.forEach(function (ev) {
                    if (seen[ev.metadata.uid]) return;
                    seen[ev.metadata.uid] = true;
                    var target = ev.involvedObject || ev.regarding || {};
                    var component = (ev.source && ev.source.component) || ev.reportingController || ev.reportingComponent || '';
                    var ours = KIND_PREFIX.test(target.kind || '') || /cilium|hubble/i.test(component) || ev.reason === 'PacketDrop' || (target.kind === 'Pod' && /^(cilium|hubble|clustermesh)/.test(target.name || ''));
                    if (!ours) return;
                    var appKind = target.kind === 'Pod' ? KINDS.pods : target.kind === 'Node' ? KINDS.nodes : target.kind === 'Service' ? KINDS.services : kindFor(target.kind);
                    out.push({
                        uid: ev.metadata.uid,
                        when: eventWhen(ev),
                        type: ev.type || 'Normal',
                        reason: ev.reason || '',
                        message: ev.message || ev.note || '',
                        count: ev.count || (ev.series && ev.series.count) || 1,
                        kind: target.kind || '',
                        appKind: appKind,
                        namespace: target.namespace || '',
                        name: target.name || '',
                    });
                });
            });
            return out
                .sort(function (a, b) {
                    // Warnings first among the newest.
                    return a.when < b.when ? 1 : a.when > b.when ? -1 : 0;
                })
                .slice(0, 14);
        });
    }

    function kindFor(k8sKind) {
        var map = {
            CiliumNetworkPolicy: KINDS.cnp,
            CiliumClusterwideNetworkPolicy: KINDS.ccnp,
            CiliumEndpoint: KINDS.endpoints,
            CiliumNode: KINDS.ciliumNodes,
            CiliumIdentity: KINDS.identities,
            CiliumLoadBalancerIPPool: KINDS.lbPools,
            CiliumL2AnnouncementPolicy: KINDS.l2,
            CiliumBGPClusterConfig: KINDS.bgpCluster,
            CiliumBGPNodeConfig: KINDS.bgpNodes,
            CiliumEgressGatewayPolicy: KINDS.egress,
            NetworkPolicy: KINDS.knp,
        };
        return map[k8sKind] || '';
    }

    window.Cilium = {
        KINDS: KINDS,
        COMPONENTS: COMPONENTS,
        STATES: STATES,
        ENTITIES: ENTITIES,
        CONFIG_NAME: CONFIG_NAME,
        load: load,
        loadEvents: loadEvents,
        dig: dig,
        arr: arr,
        plural: plural,
        names: names,
        percent: percent,
        count: count,
        podReady: podReady,
        podTrouble: podTrouble,
        restarts: restarts,
        conditionOf: conditionOf,
        parseLabel: parseLabel,
        labelSet: labelSet,
        selectsIdentity: selectsIdentity,
        selectsLabels: selectsLabels,
        selectorText: selectorText,
        shortKey: shortKey,
        isEmptySelector: isEmptySelector,
        namesNamespace: namesNamespace,
        policiesFor: policiesFor,
        resolvePeer: resolvePeer,
        nodeTone: nodeTone,
        feature: feature,
        nodeEncryption: nodeEncryption,
        cfg: cfg,
        on: on,
        parseIPv4: parseIPv4,
        formatIPv4: formatIPv4,
        kindFor: kindFor,
        truthy: truthy,
    };
})();
