// A Pod's Cilium panel: its endpoint's state, its security identity, whether
// policy is enforced on it each way, its addresses, and the policies that
// select it. A pod Cilium gives no endpoint -- one on the host network, say --
// gets a quiet line saying why.
(function () {
    'use strict';

    var sdk = window.k8sdockside;
    var M = window.Cilium;
    var K = window.CiliumKit;
    var el = K.el;
    var add = K.add;
    var POLL = 5000;
    var MAX_LABELS = 8;
    var MAX_POLICIES = 6;

    var state = { ctx: null, sig: '' };
    var memory = K.store(sdk);

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

    function quiet(text, iconName) {
        var root = $('root');
        root.textContent = '';
        var line = el('div', 'plain');
        add(line, K.icon(iconName || 'info'), el('span', '', text));
        root.appendChild(line);
    }

    function row(label, body) {
        var r = el('div', 'prow-line');
        add(r, el('span', 'prow-label', label), add(el('div', 'prow-body'), body));
        return r;
    }

    function dirChip(dir, on) {
        var word = dir === 'in' ? 'Ingress' : 'Egress';
        return K.chip(word + (on ? ' enforced' : ' open'), on ? 'ok' : 'warn', on ? 'lock' : 'unlock', on ? 'Only what policies allow gets ' + (dir === 'in' ? 'in' : 'out') : 'No policy restricts ' + word.toLowerCase());
    }

    function draw(model, ep) {
        var root = $('root');
        root.textContent = '';
        var head = el('div', 'panel-head');
        var st = M.STATES[ep.state] || { label: ep.state || 'no state', tone: 'muted' };
        var idChip = el('span', 'idchip');
        var sw = el('i', 'hx c');
        sw.style.setProperty('--hc', K.identityColor(ep.identity));
        add(idChip, sw, el('span', '', ep.identity !== null ? 'identity ' + ep.identity : 'no identity yet'));
        var twins = ep.group ? ep.group.endpoints.length - 1 : 0;
        if (twins) idChip.title = 'Shared with ' + M.plural(twins, 'other endpoint') + ' in ' + ep.namespace;
        add(head, K.chip(st.label, st.tone, st.tone === 'ok' ? 'check' : 'alert'), idChip, dirChip('in', ep.ingress), dirChip('out', ep.egress));
        root.appendChild(head);

        var ips = el('span', 'ips');
        ep.ips.forEach(function (ip) {
            ips.appendChild(el('code', 'ipchip', ip));
        });
        if (!ep.ips.length) ips.appendChild(el('span', 'faint', 'none yet'));
        if (ep.node) {
            ips.appendChild(el('span', 'faint', 'on'));
            ips.appendChild(
                K.link(ep.node, function () {
                    open({ kind: M.KINDS.nodes, namespace: '', name: ep.node });
                }),
            );
        }
        root.appendChild(row('Addresses', ips));

        var labels = el('div', 'lchips');
        var sorted = K.sortLabels(ep.labels.list).filter(function (l) {
            return !/^io\.cilium\.k8s\.(namespace\.labels|policy)\./.test(l.key);
        });
        sorted.slice(0, MAX_LABELS).forEach(function (l) {
            labels.appendChild(K.labelChip(l, l.key === 'io.kubernetes.pod.namespace' ? 'quiet' : ''));
        });
        if (sorted.length > MAX_LABELS) labels.appendChild(el('span', 'faint small', '+' + (sorted.length - MAX_LABELS)));
        if (!sorted.length) labels.appendChild(el('span', 'faint', 'none'));
        root.appendChild(row('Identity labels', labels));

        var pols = M.policiesFor(model, ep);
        var list = el('div', 'plist compact');
        if (!pols.length) {
            list.appendChild(el('span', 'faint', model.enforcementMode === 'always' ? 'None — and enable-policy is always, so all its traffic is dropped.' : 'None — every connection to and from this pod is allowed.'));
        }
        pols.slice(0, MAX_POLICIES).forEach(function (p) {
            var b = K.button('', 'prow-btn', null, function () {
                open({ kind: p.appKind, namespace: p.namespace, name: p.name });
            });
            add(b, el('span', 'kbadge k-' + p.kind, p.kindShort), el('span', 'prow-name', p.name), el('span', 'prow-sub', [p.ingress ? p.ingress + ' in' : '', p.egress ? p.egress + ' out' : ''].filter(Boolean).join(' · ')));
            if (p.deny) b.appendChild(K.chip('deny', 'error'));
            if (p.l7) b.appendChild(K.chip('L7', 'l7'));
            list.appendChild(b);
        });
        if (pols.length > MAX_POLICIES) list.appendChild(el('span', 'faint small', 'and ' + (pols.length - MAX_POLICIES) + ' more'));
        root.appendChild(row('Policies', list));

        var foot = el('div', 'panel-foot');
        foot.appendChild(
            K.button('Show in the endpoint map', 'ghost small', 'map', function () {
                memory.set('endpoints.pick', ep.key);
                sdk.openView('endpoints').catch(fail);
            }),
        );
        root.appendChild(foot);
    }

    function tick() {
        var ref = state.ctx.object;
        Promise.all([sdk.object(), M.load(sdk)])
            .then(function (got) {
                $('error').hidden = true;
                var pod = got[0];
                var model = got[1];
                if (!model.installed) {
                    if (state.sig !== 'absent') {
                        state.sig = 'absent';
                        quiet('Cilium is not installed in this cluster, so it does not network this pod.');
                    }
                    return;
                }
                var ep = null;
                for (var i = 0; i < model.endpoints.length; i++) {
                    var e = model.endpoints[i];
                    if (e.namespace === ref.namespace && (e.pod === ref.name || e.name === ref.name)) {
                        ep = e;
                        break;
                    }
                }
                var sig = model.sig + '|' + (pod.metadata && pod.metadata.resourceVersion);
                if (sig === state.sig) return;
                state.sig = sig;
                if (ep) {
                    draw(model, ep);
                } else if (M.dig(pod, 'spec.hostNetwork')) {
                    quiet('This pod runs on the host network, so Cilium gives it no endpoint of its own: it has the node’s identity, and host policies — not pod policies — apply to it.', 'node');
                } else if (M.dig(pod, 'status.phase') === 'Pending' || !M.dig(pod, 'status.podIP')) {
                    quiet('No CiliumEndpoint yet — Cilium creates one once the pod has been given its network.', 'clock');
                } else if (/^(Succeeded|Failed)$/.test(M.dig(pod, 'status.phase') || '')) {
                    quiet('This pod has finished, so Cilium has released its endpoint.', 'info');
                } else {
                    quiet('This pod has no CiliumEndpoint. Cilium may not manage it — another CNI in a chain, or an agent that has not caught up.', 'info');
                }
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
                fail(new Error('This page is a panel, drawn for one Pod.'));
                return;
            }
            tick();
        })
        .catch(fail);
})();
