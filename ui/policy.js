// A policy's Cilium panel -- on CiliumNetworkPolicies, cluster-wide ones and
// Kubernetes NetworkPolicies alike: whether Cilium accepted it, what it
// selects, and each of its rules in a line, with the endpoints it selects.
(function () {
    'use strict';

    var sdk = window.k8sdockside;
    var M = window.Cilium;
    var K = window.CiliumKit;
    var F = window.CiliumFlow;
    var el = K.el;
    var add = K.add;
    var POLL = 5000;
    var MAX_EPS = 14;

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

    function kindOf(appKind) {
        if (appKind === M.KINDS.cnp) return 'cnp';
        if (appKind === M.KINDS.ccnp) return 'ccnp';
        return 'knp';
    }

    function quiet(text) {
        var root = $('root');
        root.textContent = '';
        var line = el('div', 'plain');
        add(line, K.icon('info'), el('span', '', text));
        root.appendChild(line);
    }

    function draw(model, p) {
        var root = $('root');
        root.textContent = '';

        var head = el('div', 'panel-head');
        if (p.valid === true) head.appendChild(K.chip('valid', 'ok', 'check', 'The Cilium operator validated this policy'));
        else if (p.valid === false) head.appendChild(K.chip('invalid', 'error', 'alert'));
        else if (p.kind !== 'knp') head.appendChild(K.chip('not validated yet', 'muted', null, 'No Valid condition: the operator has not looked at it, or validation is off'));
        if (p.host) head.appendChild(K.chip('host policy · ' + M.plural(p.nodes.length, 'node'), 'info', 'node'));
        else head.appendChild(K.chip(M.plural(p.selected.length, 'endpoint') + ' selected', p.selected.length ? 'accent' : 'warn', 'hex'));
        if (p.deny) head.appendChild(K.chip('deny rules', 'error', 'deny'));
        if (p.l7) head.appendChild(K.chip('L7', 'l7', 'http'));
        if (p.fqdn) head.appendChild(K.chip('DNS names', 'fqdn', 'fqdn'));
        if (p.kind === 'knp' && !model.k8sPolicies) head.appendChild(K.chip('ignored by Cilium', 'warn', 'alert', 'enable-k8s-networkpolicy is false'));
        head.appendChild(
            K.button('Policy map', 'ghost small push', 'shield', function () {
                memory.set('policy-map.pick', p.key);
                sdk.openView('policy-map').catch(fail);
            }),
        );
        root.appendChild(head);

        if (p.valid === false) {
            var bad = el('div', 'why error');
            add(bad, K.icon('alert'), el('span', '', p.invalid));
            root.appendChild(bad);
        }

        root.appendChild(F.compact(model, p));

        if (p.selected.length) {
            var eps = el('div', 'epchips');
            p.selected.slice(0, MAX_EPS).forEach(function (ep) {
                var b = K.button('', 'epchip', null, function () {
                    open({ kind: M.KINDS.pods, namespace: ep.namespace, name: ep.pod });
                });
                add(b, el('i', 'hx e-' + ep.enforcement), el('span', '', (p.kind === 'ccnp' ? ep.namespace + '/' : '') + ep.pod));
                if (!ep.ready) b.classList.add('warn');
                b.title = ep.namespace + '/' + ep.pod + (ep.ips[0] ? ' · ' + ep.ips[0] : '');
                eps.appendChild(b);
            });
            if (p.selected.length > MAX_EPS) eps.appendChild(el('span', 'faint small', '+' + (p.selected.length - MAX_EPS) + ' more'));
            var sec = el('div', 'panel-sec');
            add(sec, el('h3', 'mini-title', 'Selected endpoints'), eps);
            root.appendChild(sec);
        } else if (!p.host) {
            var none = el('div', 'why warn');
            add(none, K.icon('alert'), el('span', '', 'Nothing matches its selector' + (p.namespace ? ' in ' + p.namespace : '') + ', so it has no effect. Check the labels for a typo.'));
            root.appendChild(none);
        }
    }

    function tick() {
        var ref = state.ctx.object;
        M.load(sdk)
            .then(function (model) {
                $('error').hidden = true;
                if (!model.installed) {
                    if (state.sig !== 'absent') {
                        state.sig = 'absent';
                        quiet('Cilium is not installed in this cluster.');
                    }
                    return;
                }
                var kind = kindOf(ref.kind);
                var key = kind + ':' + (kind === 'ccnp' ? '' : ref.namespace || '') + '/' + ref.name;
                var p = model.policyByKey[key];
                if (!p) {
                    if (state.sig !== 'missing') {
                        state.sig = 'missing';
                        quiet('This policy could not be read.');
                    }
                    return;
                }
                if (model.sig === state.sig) return;
                state.sig = model.sig;
                draw(model, p);
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
                fail(new Error('This page is a panel, drawn for one network policy.'));
                return;
            }
            tick();
        })
        .catch(fail);
})();
