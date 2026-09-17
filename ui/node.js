// A Node's Cilium panel: the agent on it, the addresses Cilium gave it, how
// full its pod address range is, its endpoints and how many are under
// policy, and its BGP sessions where there are any.
(function () {
    'use strict';

    var sdk = window.k8sdockside;
    var M = window.Cilium;
    var K = window.CiliumKit;
    var el = K.el;
    var add = K.add;
    var POLL = 5000;

    var state = { ctx: null, sig: '' };

    var $ = function (id) {
        return document.getElementById(id);
    };

    function fail(err) {
        $('error').textContent = (err && err.message) || String(err);
        $('error').hidden = false;
    }

    function open(ref) {
        sdk.open(ref).catch(fail);
    }

    function quiet(text) {
        var root = $('root');
        root.textContent = '';
        var line = el('div', 'plain');
        add(line, K.icon('info'), el('span', '', text));
        root.appendChild(line);
    }

    function draw(model, n) {
        var root = $('root');
        root.textContent = '';

        // The agent.
        var agent = el('div', 'agent-line ' + (n.agent ? (n.agentReady ? 'ok' : 'error') : 'muted'));
        var mark = el('span', 'agent-mark');
        mark.appendChild(K.icon('pod'));
        var words = el('div', 'agent-words');
        if (n.agent) {
            add(
                words,
                el('span', 'agent-title', n.agentReady ? 'Cilium agent ready' : 'Cilium agent not ready'),
                el('span', 'agent-state', [n.agent.metadata.name, n.agentReady ? '' : n.agentTrouble, n.agentRestarts ? M.plural(n.agentRestarts, 'restart') : '', model.version ? 'v' + model.version : ''].filter(Boolean).join(' · ')),
            );
        } else {
            add(words, el('span', 'agent-title', model.agentsKnown ? 'No Cilium agent on this node' : 'No Cilium agent pods found'), el('span', 'agent-state', model.agentsKnown ? 'Pods scheduled here cannot be networked by Cilium.' : 'Looked for pods labelled k8s-app=cilium.'));
        }
        add(agent, mark, words);
        if (n.agent) {
            var tools = el('div', 'agent-tools');
            add(
                tools,
                K.button('Logs', 'ghost small', 'logs', function () {
                    sdk.logs({ kind: M.KINDS.pods, namespace: n.agent.metadata.namespace, name: n.agent.metadata.name }).catch(fail);
                }),
                K.button('Pod', 'ghost small', 'open', function () {
                    open({ kind: M.KINDS.pods, namespace: n.agent.metadata.namespace, name: n.agent.metadata.name });
                }),
            );
            agent.appendChild(tools);
        }
        root.appendChild(agent);

        if (!n.cn) {
            root.appendChild(el('p', 'faint small', 'There is no CiliumNode for this node yet — the agent writes it when it starts.'));
        }

        var grid = el('div', 'node-grid');
        var dl = el('dl', 'facts compact');
        function fact(label, value) {
            add(dl, el('dt', '', label), add(el('dd'), value));
        }
        if (n.internalIP) fact('Node IP', el('code', '', n.internalIP));
        if (n.ciliumIPs.length) fact('Cilium host IP', el('code', '', n.ciliumIPs.join(', ')));
        if (n.healthIP) fact('Health IP', el('code', '', n.healthIP));
        var cidrs = el('span', 'ips');
        n.podCIDRs.forEach(function (c) {
            cidrs.appendChild(el('code', 'ipchip', c));
        });
        n.pools.forEach(function (p) {
            M.arr(p.cidrs).forEach(function (c) {
                cidrs.appendChild(el('code', 'ipchip', c + ' · ' + p.pool));
            });
        });
        if (cidrs.childNodes.length) fact('Pod CIDRs', cidrs);
        var enc = M.nodeEncryption(model, n);
        if (enc) fact('Encryption', K.chip(enc.text, enc.tone, enc.tone === 'ok' ? 'lock' : 'unlock'));
        grid.appendChild(dl);

        var side = el('div', 'node-side');
        if (n.ipamUsed !== null) {
            var frac = n.ipamCapacity ? n.ipamUsed / n.ipamCapacity : 0;
            var line = el('div', 'ipam-line');
            add(line, el('span', 'faint', 'Pod addresses'), el('strong', '', n.ipamUsed + (n.ipamCapacity ? ' / ' + K.num(n.ipamCapacity) : '')), n.ipamCapacity ? el('span', 'pct ' + K.fillTone(frac), M.percent(frac)) : null);
            add(side, line, n.ipamCapacity ? K.meter(frac, K.fillTone(frac)) : null);
        }
        var eps = model.endpoints.filter(function (ep) {
            return ep.node === n.name;
        });
        var counts = { both: 0, ingress: 0, egress: 0, none: 0 };
        eps.forEach(function (ep) {
            counts[ep.enforcement]++;
        });
        var epLine = el('div', 'ipam-line');
        add(epLine, el('span', 'faint', 'Endpoints'), el('strong', '', String(eps.length)), n.notReady ? el('span', 'pct warn', n.notReady + ' not ready') : null);
        side.appendChild(epLine);
        if (eps.length) {
            side.appendChild(
                K.stack([
                    { value: counts.both, cls: 'e-both', label: 'ingress + egress' },
                    { value: counts.ingress, cls: 'e-ingress', label: 'ingress only' },
                    { value: counts.egress, cls: 'e-egress', label: 'egress only' },
                    { value: counts.none, cls: 'e-none', label: 'not enforced' },
                ]),
            );
            side.appendChild(el('div', 'faint small', M.percent((eps.length - counts.none) / eps.length) + ' under enforced policy'));
        }
        grid.appendChild(side);
        root.appendChild(grid);

        if (n.ipamError) {
            var err = el('div', 'why error');
            add(err, K.icon('alert'), el('span', '', 'IPAM: ' + n.ipamError));
            root.appendChild(err);
        }

        var sessions = model.bgp && model.bgp.nodes[n.name];
        if (sessions && sessions.length) {
            var sec = el('div', 'panel-sec');
            sec.appendChild(el('h3', 'mini-title', 'BGP sessions'));
            var list = el('div', 'chips');
            sessions.forEach(function (s) {
                list.appendChild(K.chip(s.address + (s.asn ? ' · AS' + s.asn : '') + ' · ' + s.state.replace('_', ' '), s.tone, 'bgp'));
            });
            sec.appendChild(list);
            root.appendChild(sec);
        }
    }

    function tick() {
        var ref = state.ctx.object;
        M.load(sdk, { extras: true })
            .then(function (model) {
                $('error').hidden = true;
                if (!model.installed) {
                    if (state.sig !== 'absent') {
                        state.sig = 'absent';
                        quiet('Cilium is not installed in this cluster.');
                    }
                    return;
                }
                var n = model.nodeByName[ref.name];
                if (!n) {
                    if (state.sig !== 'missing') {
                        state.sig = 'missing';
                        quiet('Cilium knows nothing about this node yet.');
                    }
                    return;
                }
                if (model.sig === state.sig) return;
                state.sig = model.sig;
                draw(model, n);
            })
            .catch(fail)
            .then(function () {
                setTimeout(tick, POLL);
            });
    }

    sdk.ready()
        .then(function (context) {
            state.ctx = context;
            if (!context.object) {
                fail(new Error('This page is a panel, drawn for one Node.'));
                return;
            }
            tick();
        })
        .catch(fail);
})();
