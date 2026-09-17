// The policy map: every policy in the cluster -- Cilium's, cluster-wide and
// Kubernetes' own -- down a rail, and the one picked drawn as a flow from the
// peers allowed in, through the endpoints it selects, to where they may go,
// with the same said in plain words underneath.
(function () {
    'use strict';

    var sdk = window.k8sdockside;
    var M = window.Cilium;
    var K = window.CiliumKit;
    var F = window.CiliumFlow;
    var el = K.el;
    var add = K.add;
    var POLL = 5000;
    var MAX_ROWS = 24;

    var KINDS = [
        { id: 'all', label: 'All' },
        { id: 'cnp', label: 'CNP', title: 'CiliumNetworkPolicy' },
        { id: 'ccnp', label: 'CCNP', title: 'CiliumClusterwideNetworkPolicy' },
        { id: 'knp', label: 'K8s', title: 'Kubernetes NetworkPolicy' },
    ];

    var state = {
        ctx: null,
        model: null,
        sig: '',
        error: '',
        selected: '',
        kind: 'all',
        query: '',
        rail: 0,
        diagrams: [],
    };
    var memory = K.store(sdk);

    var $ = function (id) {
        return document.getElementById(id);
    };

    function fail(err) {
        state.error = (err && err.message) || String(err);
        $('error').textContent = state.error;
        $('error').hidden = false;
    }

    function open(ref) {
        sdk.open(ref).catch(fail);
    }

    function refOf(p) {
        return { kind: p.appKind, namespace: p.namespace, name: p.name };
    }

    function readHash() {
        var h = K.readHash();
        if (h.p) state.selected = h.p;
        if (
            KINDS.some(function (k) {
                return k.id === h.kind;
            })
        ) {
            state.kind = h.kind;
        }
        if (h.q) state.query = h.q;
        if (Number(h.rail) > 0) state.rail = Number(h.rail);
        return h;
    }

    function writeHash() {
        K.writeHash({ p: state.selected, kind: state.kind === 'all' ? '' : state.kind, q: state.query.trim(), rail: state.rail });
    }

    // ----- the rail -------------------------------------------------------------

    function visible(model) {
        var q = state.query.trim().toLowerCase();
        return model.policies.filter(function (p) {
            if (state.kind !== 'all' && p.kind !== state.kind) return false;
            if (!q) return true;
            if (p.name.toLowerCase().indexOf(q) >= 0 || p.namespace.toLowerCase().indexOf(q) >= 0) return true;
            return p.rules.some(function (r) {
                return M.selectorText(r.subject.sel).toLowerCase().indexOf(q) >= 0;
            });
        });
    }

    function drawKinds(model) {
        var box = $('kinds');
        box.textContent = '';
        var counts = model.policyCounts;
        box.appendChild(
            K.seg(
                KINDS.map(function (k) {
                    var n = k.id === 'all' ? counts.total : counts[k.id];
                    return { id: k.id, label: k.label + ' ' + n, title: k.title };
                }),
                state.kind,
                function (id) {
                    state.kind = id;
                    memory.set('policy-map.kind', id);
                    writeHash();
                    render();
                },
                'Kind',
            ),
        );
    }

    function drawRail(model) {
        var box = $('rail-list');
        var scroll = box.scrollTop;
        box.textContent = '';
        var list = visible(model);
        if (list.length === 0) {
            box.appendChild(el('p', 'rail-none', model.policies.length ? 'No policy matches.' : 'No policies.'));
            return;
        }
        var groups = [];
        var byName = {};
        list.forEach(function (p) {
            var g = p.kind === 'ccnp' ? '' : p.namespace;
            if (!byName[g]) {
                byName[g] = { name: g, items: [] };
                groups.push(byName[g]);
            }
            byName[g].items.push(p);
        });
        groups.sort(function (a, b) {
            if (!a.name) return -1;
            if (!b.name) return 1;
            return a.name.localeCompare(b.name);
        });
        groups.forEach(function (g) {
            var head = el('div', 'rail-group');
            add(head, K.icon(g.name ? 'layers' : 'world'), el('span', '', g.name || 'Cluster-wide'), el('span', 'rail-n', String(g.items.length)));
            box.appendChild(head);
            g.items.forEach(function (p) {
                box.appendChild(railItem(model, p));
            });
        });
        box.scrollTop = scroll;
    }

    function railItem(model, p) {
        var idle = p.selected.length === 0 && p.nodes.length === 0;
        var b = K.button('', 'pitem' + (p.key === state.selected ? ' on' : '') + (p.valid === false ? ' bad' : idle ? ' idle' : ''), null, null);
        b.dataset.key = p.key;
        var top = el('span', 'pitem-top');
        add(top, el('span', 'kbadge k-' + p.kind, p.kindShort), el('span', 'pitem-name', p.name));
        var count = el('span', 'pitem-count' + (idle ? ' zero' : ''));
        if (p.host) add(count, K.icon('node'), String(p.nodes.length));
        else add(count, K.icon('hex'), String(p.selected.length));
        count.title = p.host ? p.nodes.length + ' nodes selected' : p.selected.length + ' endpoints selected';
        top.appendChild(count);
        b.appendChild(top);
        var meta = el('span', 'pitem-meta');
        if (p.ingress) add(meta, el('span', 'dirn in', '↘ ' + p.ingress));
        if (p.egress) add(meta, el('span', 'dirn out', '↗ ' + p.egress));
        if (!p.ingress && !p.egress) meta.appendChild(el('span', 'faint', p.rules.some(function (r) {
            return r.denyAllIn || r.denyAllOut;
        }) ? 'denies all' : 'no rules'));
        if (p.valid === false) meta.appendChild(K.chip('invalid', 'error', 'alert'));
        if (p.deny) meta.appendChild(K.chip('deny', 'error'));
        if (p.l7) meta.appendChild(K.chip('L7', 'l7'));
        if (p.fqdn) meta.appendChild(K.chip('FQDN', 'fqdn'));
        if (p.host) meta.appendChild(K.chip('host', 'muted'));
        if (idle && p.valid !== false) meta.appendChild(el('span', 'idle-text', 'selects nothing'));
        b.appendChild(meta);
        b.title = p.kindLabel + ' ' + (p.namespace ? p.namespace + '/' : '') + p.name;
        return b;
    }

    // ----- the stage ------------------------------------------------------------

    function current(model) {
        var p = model.policyByKey[state.selected];
        if (p) return p;
        var list = visible(model);
        return list[0] || null;
    }

    function drawStage(model) {
        var box = $('stage');
        box.textContent = '';
        state.diagrams = [];
        var p = current(model);
        if (!p) {
            box.appendChild(model.policies.length ? el('p', 'faint pad', 'Pick a policy on the left.') : noPolicies(model));
            return;
        }
        if (p.key !== state.selected) {
            state.selected = p.key;
            writeHash();
            markRail();
        }

        var head = el('header', 'st-head');
        var tile = el('span', 'st-tile k-' + p.kind);
        tile.appendChild(K.icon(p.host ? 'node' : 'shield'));
        var words = el('div', 'st-words');
        add(words, el('div', 'st-kind', p.kindLabel + (p.namespace ? ' · ' + p.namespace : ' · cluster-wide')), el('h2', 'st-name', p.name));
        var tools = el('div', 'st-tools');
        add(
            tools,
            K.button('Open', 'ghost small', 'open', function () {
                open(refOf(p));
            }),
            K.button('Edit YAML', 'small', 'edit', function () {
                sdk.edit(refOf(p)).catch(fail);
            }),
        );
        add(head, tile, words, tools);
        box.appendChild(head);

        var chips = el('div', 'st-chips');
        if (p.valid === true) chips.appendChild(K.chip('valid', 'ok', 'check', 'The operator validated this policy'));
        if (p.valid === false) chips.appendChild(K.chip('invalid', 'error', 'alert'));
        if (p.host) chips.appendChild(K.chip('host policy · ' + M.plural(p.nodes.length, 'node'), 'info', 'node'));
        else chips.appendChild(K.chip(M.plural(p.selected.length, 'endpoint') + ' selected', p.selected.length ? 'accent' : 'warn', 'hex'));
        if (p.deny) chips.appendChild(K.chip('has deny rules', 'error', 'deny'));
        if (p.l7) chips.appendChild(K.chip('L7 rules', 'l7', 'http', 'HTTP, DNS or Kafka rules — traffic goes through the Envoy proxy'));
        if (p.fqdn) chips.appendChild(K.chip('DNS names', 'fqdn', 'fqdn'));
        if (p.rules.length > 1) chips.appendChild(K.chip(p.rules.length + ' rules', 'muted'));
        if (p.kind === 'knp' && !model.k8sPolicies) chips.appendChild(K.chip('ignored: enable-k8s-networkpolicy is false', 'warn', 'alert'));
        box.appendChild(chips);

        if (p.valid === false) {
            var bad = el('div', 'why error');
            add(bad, K.icon('alert'), el('span', '', p.invalid));
            box.appendChild(bad);
        }

        p.rules.forEach(function (rule, i) {
            var card = el('section', 'flow-card');
            if (p.rules.length > 1) {
                var rh = el('div', 'flow-card-head');
                add(rh, el('span', 'mini-title', 'Rule ' + (i + 1)), rule.description ? el('span', 'faint small', rule.description) : null);
                card.appendChild(rh);
            }
            var d = F.diagram(model, p, rule, {});
            card.appendChild(d.node);
            box.appendChild(card);
            state.diagrams.push(d);
        });

        var words2 = el('section', 'card explain-card');
        var wh = el('div', 'card-head');
        add(wh, K.icon('info'), el('h3', '', 'In plain words'));
        words2.appendChild(wh);
        words2.appendChild(F.explain(model, p));
        box.appendChild(words2);

        if (p.selected.length) box.appendChild(selectedList(model, p));
        requestAnimationFrame(function () {
            state.diagrams.forEach(function (d) {
                d.redraw();
            });
        });
    }

    function selectedList(model, p) {
        var card = el('section', 'card');
        var head = el('div', 'card-head');
        add(head, K.icon('hex'), el('h3', '', 'Selected endpoints'), el('span', 'faint small', String(p.selected.length)));
        card.appendChild(head);
        var table = el('div', 'eplist');
        p.selected.slice(0, MAX_ROWS).forEach(function (ep) {
            var row = K.button('', 'eprow', null, function () {
                open({ kind: M.KINDS.pods, namespace: ep.namespace, name: ep.pod });
            });
            var sw = el('i', 'hx e-' + ep.enforcement);
            sw.title = ep.enforcement === 'none' ? 'not enforced' : ep.enforcement === 'both' ? 'ingress + egress enforced' : ep.enforcement + ' enforced';
            add(row, sw, el('span', 'ep-name', ep.pod), el('span', 'ep-ns', ep.namespace), el('code', 'ep-ip', ep.ips[0] || '—'), el('span', 'ep-id', ep.identity !== null ? '#' + ep.identity : '—'), el('span', 'ep-node', ep.node || ''));
            if (!ep.ready) row.appendChild(K.chip((M.STATES[ep.state] || { label: ep.state }).label, 'warn'));
            table.appendChild(row);
        });
        card.appendChild(table);
        if (p.selected.length > MAX_ROWS) card.appendChild(el('p', 'faint small', 'and ' + (p.selected.length - MAX_ROWS) + ' more — the endpoint map shows them all.'));
        return card;
    }

    function noPolicies(model) {
        var box = el('div', 'getting-started big');
        var art = el('div', 'empty-art');
        art.appendChild(K.icon('shieldOff'));
        add(
            box,
            art,
            el('h2', '', 'No network policies'),
            el(
                'p',
                '',
                'Cilium allows everything until a policy selects an endpoint: then that endpoint is in default deny for the direction the policy covers, and only what some policy allows gets through. With no policies at all, every pod here — ' +
                    M.plural(model.endpoints.length, 'endpoint') +
                    ' — can reach every other, and the world.',
            ),
        );
        var cta = el('div', 'cta-row');
        add(
            cta,
            K.button('Open the endpoint map', 'primary', 'map', function () {
                sdk.openView('endpoints').catch(fail);
            }),
            K.button('Writing a policy', 'ghost', 'open', function () {
                sdk.openUrl('https://docs.cilium.io/en/stable/security/policy/').catch(fail);
            }),
        );
        box.appendChild(cta);
        var pre = el('pre', 'snippet');
        pre.textContent = [
            'apiVersion: cilium.io/v2',
            'kind: CiliumNetworkPolicy',
            'metadata:',
            '  name: allow-frontend-to-api',
            '  namespace: shop',
            'spec:',
            '  endpointSelector:',
            '    matchLabels: { app: api }',
            '  ingress:',
            '    - fromEndpoints:',
            '        - matchLabels: { app: frontend }',
            '      toPorts:',
            '        - ports: [{ port: "8080", protocol: TCP }]',
        ].join('\n');
        box.appendChild(pre);
        return box;
    }

    function markRail() {
        var items = $('rail-list').querySelectorAll('.pitem');
        for (var i = 0; i < items.length; i++) items[i].classList.toggle('on', items[i].dataset.key === state.selected);
    }

    // ----- putting it together --------------------------------------------------

    function drawEmpty(model) {
        var box = $('empty');
        box.hidden = false;
        K.whyAbsent(sdk).then(function (summary) {
            K.absent(box, { sdk: sdk, summary: summary, contextName: state.ctx.contextName, missing: model.missing, fail: fail });
        });
    }

    function render() {
        var model = state.model;
        if (!model) return;
        var where = state.ctx.contextName;
        if (model.version) where += ' · Cilium ' + model.version;
        where += ' · ' + M.plural(model.policyCounts.total, 'policy', 'policies');
        $('where').textContent = where;
        document.body.classList.toggle('absent', !model.installed || model.policies.length === 0);
        if (!model.installed) {
            $('layout').hidden = true;
            drawEmpty(model);
            return;
        }
        $('empty').hidden = true;
        $('layout').hidden = false;
        $('layout').classList.toggle('no-rail', model.policies.length === 0);
        drawKinds(model);
        drawRail(model);
        drawStage(model);
    }

    function tick() {
        M.load(sdk)
            .then(function (model) {
                $('error').hidden = true;
                if (model.sig !== state.sig) {
                    state.model = model;
                    state.sig = model.sig;
                    render();
                }
            })
            .catch(fail)
            .then(function () {
                setTimeout(tick, POLL);
            });
    }

    $('rail-list').addEventListener('click', function (event) {
        var item = event.target.closest && event.target.closest('.pitem');
        if (!item || !state.model) return;
        state.selected = item.dataset.key;
        writeHash();
        markRail();
        drawStage(state.model);
        $('stage').scrollTop = 0;
        window.scrollTo(0, 0);
    });
    $('rail-list').addEventListener('keydown', function (event) {
        if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
        var items = Array.prototype.slice.call($('rail-list').querySelectorAll('.pitem'));
        var at = items.indexOf(document.activeElement);
        if (at < 0) return;
        var next = items[at + (event.key === 'ArrowDown' ? 1 : -1)];
        if (next) {
            event.preventDefault();
            next.focus();
            next.click();
        }
    });
    $('logo').appendChild(K.logo());
    $('search-icon').appendChild(K.icon('search'));
    $('query').addEventListener('input', function () {
        state.query = $('query').value;
        writeHash();
        if (state.model && state.model.installed) {
            drawRail(state.model);
            if (!state.model.policyByKey[state.selected]) drawStage(state.model);
        }
    });
    add(
        $('key'),
        K.chip('allow', 'ok', 'arrow'),
        K.chip('deny', 'error', 'deny'),
        K.chip('L7', 'l7', 'http'),
    );
    $('top-actions').appendChild(
        K.button('Endpoint map', 'ghost', 'map', function () {
            sdk.openView('endpoints').catch(fail);
        }),
    );
    $('top-actions').appendChild(
        K.button('Overview', 'ghost', 'logo', function () {
            sdk.openView('overview').catch(fail);
        }),
    );
    window.addEventListener('resize', function () {
        state.diagrams.forEach(function (d) {
            d.redraw();
        });
    });

    var hash = readHash();
    $('query').value = state.query;
    $('rail').parentNode.insertBefore(
        K.grip({
            panel: $('rail'),
            prop: '--rail-w',
            side: 'left',
            min: 240,
            room: 640,
            initial: state.rail,
            label: 'Resize the policy list',
            onResize: function (px, done) {
                state.diagrams.forEach(function (d) {
                    d.redraw();
                });
                if (!done) return;
                state.rail = px;
                writeHash();
            },
        }),
        $('stage'),
    );

    sdk.ready()
        .then(function (context) {
            state.ctx = context;
            $('where').textContent = context.contextName;
            // A page that sent us here may have left a policy to show.
            return Promise.all([memory.get('policy-map.pick'), hash.kind ? null : memory.get('policy-map.kind')]);
        })
        .then(function (kept) {
            if (kept[0]) {
                state.selected = kept[0];
                memory.set('policy-map.pick', null);
                writeHash();
            }
            if (
                kept[1] &&
                KINDS.some(function (k) {
                    return k.id === kept[1];
                })
            ) {
                state.kind = kept[1];
            }
            tick();
        })
        .catch(fail);
})();
