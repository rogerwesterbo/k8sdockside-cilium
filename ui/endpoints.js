// The endpoint map: every namespace as an island, every CiliumEndpoint in it
// as a hexagon, coloured by the lens picked -- whether policy is enforced on
// it, its identity, its node, or its state. Click one for everything about
// it: addresses, identity and labels, and the policies that select it. A
// namespace no policy touches says so, with a button that isolates it.
(function () {
    'use strict';

    var sdk = window.k8sdockside;
    var M = window.Cilium;
    var K = window.CiliumKit;
    var el = K.el;
    var add = K.add;
    var POLL = 5000;
    var CELL = 18;
    var GAP = 3;
    var PITCH = CELL + GAP;
    var MIN_COLS = 11;
    // A namespace draws at most this many cells; past it, a count.
    var MAX_CELLS = 1500;

    var LENSES = [
        { id: 'policy', label: 'Policy', icon: 'shield', title: 'Colour by whether policy is enforced, per direction' },
        { id: 'identity', label: 'Identity', icon: 'tag', title: 'Colour by security identity' },
        { id: 'node', label: 'Node', icon: 'node', title: 'Colour by the node the endpoint runs on' },
        { id: 'state', label: 'State', icon: 'check', title: 'Colour by endpoint state' },
    ];
    var FILTERS = [
        { id: 'unenforced', label: 'Not enforced', tone: 'warn', test: function (ep) {
            return ep.enforcement === 'none';
        } },
        { id: 'notready', label: 'Not ready', tone: 'error', test: function (ep) {
            return !ep.ready;
        } },
    ];
    var ENFORCEMENT = [
        { id: 'both', label: 'Ingress + egress', text: 'default deny both ways' },
        { id: 'ingress', label: 'Ingress only', text: 'default deny for incoming traffic' },
        { id: 'egress', label: 'Egress only', text: 'default deny for outgoing traffic' },
        { id: 'none', label: 'Not enforced', text: 'every connection is allowed' },
    ];

    var state = {
        ctx: null,
        model: null,
        sig: '',
        error: '',
        lens: 'policy',
        query: '',
        filter: '',
        selected: '',
        width: 0,
        notice: '',
        cols: 0,
    };
    var memory = K.store(sdk);

    var $ = function (id) {
        return document.getElementById(id);
    };

    function fail(err) {
        state.error = (err && err.message) || String(err);
        drawError();
    }

    function drawError() {
        $('error').textContent = state.error;
        $('error').hidden = !state.error;
    }

    function open(ref) {
        sdk.open(ref).catch(fail);
    }

    function podRef(ep) {
        return { kind: M.KINDS.pods, namespace: ep.namespace, name: ep.pod };
    }

    function cepRef(ep) {
        return { kind: M.KINDS.endpoints, namespace: ep.namespace, name: ep.name };
    }

    // ----- the address --------------------------------------------------------

    function readHash() {
        var h = K.readHash();
        if (
            LENSES.some(function (l) {
                return l.id === h.lens;
            })
        ) {
            state.lens = h.lens;
        }
        if (h.filter === 'open') h.filter = 'unenforced';
        if (
            FILTERS.some(function (f) {
                return f.id === h.filter;
            })
        ) {
            state.filter = h.filter;
        }
        if (h.q) state.query = h.q;
        if (h.ep) state.selected = h.ep;
        if (Number(h.width) > 0) state.width = Number(h.width);
        return h;
    }

    function writeHash() {
        K.writeHash({ lens: state.lens === 'policy' ? '' : state.lens, filter: state.filter, q: state.query.trim(), ep: state.selected, width: state.width });
    }

    // ----- matching -------------------------------------------------------------

    function matches(ep, q) {
        if (!q) return true;
        if (ep.name.toLowerCase().indexOf(q) >= 0 || ep.pod.toLowerCase().indexOf(q) >= 0) return true;
        if (ep.namespace.toLowerCase().indexOf(q) >= 0) return true;
        if (ep.node.toLowerCase().indexOf(q) >= 0) return true;
        for (var i = 0; i < ep.ips.length; i++) if (ep.ips[i].indexOf(q) === 0) return true;
        if (ep.identity !== null) {
            var id = String(ep.identity);
            if (id === q || (q.charAt(0) === '#' && id === q.slice(1))) return true;
        }
        var list = ep.labels.list;
        for (var j = 0; j < list.length; j++) {
            var l = list[j];
            if ((l.key + '=' + l.value).toLowerCase().indexOf(q) >= 0) return true;
        }
        return false;
    }

    function passes(ep) {
        if (!state.filter) return true;
        var f = FILTERS.filter(function (x) {
            return x.id === state.filter;
        })[0];
        return !f || f.test(ep);
    }

    function selectedEp(model) {
        if (!state.selected) return null;
        for (var i = 0; i < model.endpoints.length; i++) if (model.endpoints[i].key === state.selected) return model.endpoints[i];
        return null;
    }

    // ----- colours ----------------------------------------------------------------

    var nodeIndex = {};

    function cellClass(ep) {
        switch (state.lens) {
            case 'identity':
                return 'hx c';
            case 'node':
                return 'hx c';
            case 'state':
                return 'hx s-' + ep.stateTone;
            default:
                return 'hx e-' + ep.enforcement;
        }
    }

    function cellColor(ep) {
        if (state.lens === 'identity') return K.identityColor(ep.identity);
        if (state.lens === 'node') return ep.node in nodeIndex ? K.palette(nodeIndex[ep.node]) : 'var(--c-faint)';
        return '';
    }

    // ----- the stats ----------------------------------------------------------------

    function stat(label, big, sub, graphic, tone) {
        var tile = el('div', 'stat' + (tone ? ' ' + tone : ''));
        var words = el('div', 'stat-words');
        add(words, el('div', 'stat-label', label), el('div', 'stat-big', big), sub ? el('div', 'stat-sub', sub) : null);
        add(tile, graphic || null, words);
        return tile;
    }

    function drawStats(model) {
        var box = $('stats');
        box.textContent = '';
        var cov = model.coverage;
        var enforced = cov.total ? (cov.total - cov.none) / cov.total : 0;
        var identities = Object.keys(model.identityUse).length;
        var open = model.namespaces.filter(function (ns) {
            return ns.open;
        }).length;
        add(
            box,
            stat('Endpoints', K.num(cov.total), 'on ' + M.plural(model.nodes.filter(function (n) {
                return n.obj;
            }).length, 'node')),
            stat('Identities', K.num(identities), 'in use · ' + K.num(model.identityCount) + ' allocated'),
            stat('Under policy', cov.total ? M.percent(enforced) : '—', cov.both + ' both ways · ' + (cov.ingress + cov.egress) + ' one way', K.ring(enforced, 46, enforced >= 0.5 ? 'ok' : 'warn'), ''),
            stat('Not ready', K.num(model.notReady.length), model.notReady.length ? M.names(
                model.notReady.map(function (ep) {
                    return ep.name;
                }),
                1,
            ) : 'every endpoint is ready', null, model.notReady.length ? 'warn' : ''),
            stat('Namespaces', K.num(model.namespaces.length), open ? M.plural(open, 'has', 'have') + ' no policy' : 'every one under some policy', null, open ? 'warn' : ''),
        );
    }

    function drawFilters(model) {
        var box = $('filters');
        box.textContent = '';
        FILTERS.forEach(function (f) {
            var n = model.endpoints.filter(f.test).length;
            box.appendChild(
                K.fchip(f.label, n, state.filter === f.id, f.tone, function () {
                    state.filter = state.filter === f.id ? '' : f.id;
                    writeHash();
                    render(true);
                }),
            );
        });
        if (model.enforcementMode !== 'default') {
            box.appendChild(K.chip('enable-policy: ' + model.enforcementMode, model.enforcementMode === 'never' ? 'warn' : 'info', 'shield', model.enforcementMode === 'always' ? 'Every endpoint is in default deny, policy or not' : 'Policies are not enforced at all'));
        }
    }

    function drawLegend(model) {
        var box = $('legend');
        box.textContent = '';
        function key(cls, text, color, title) {
            var k = el('span', 'lkey');
            var sw = el('i', 'hx ' + cls);
            if (color) sw.style.setProperty('--hc', color);
            add(k, sw, el('span', '', text));
            if (title) k.title = title;
            box.appendChild(k);
        }
        if (state.lens === 'policy') {
            ENFORCEMENT.forEach(function (e) {
                key('e-' + e.id, e.label, '', e.text);
            });
            var how = el('span', 'lnote', 'worked out from the policies selecting each endpoint');
            box.appendChild(how);
        } else if (state.lens === 'state') {
            key('s-ok', 'ready');
            key('s-info', 'regenerating');
            key('s-warn', 'not ready');
            key('s-error', 'invalid');
        } else if (state.lens === 'node') {
            var nodes = model.nodes.filter(function (n) {
                return n.endpoints > 0;
            });
            nodes.slice(0, 10).forEach(function (n) {
                key('c', n.name, K.palette(nodeIndex[n.name]));
            });
            if (nodes.length > 10) box.appendChild(el('span', 'lnote', '+' + (nodes.length - 10) + ' nodes'));
        } else {
            var ids = Object.keys(model.identityUse).length;
            box.appendChild(el('span', 'lnote', 'one colour per identity · ' + M.plural(ids, 'identity', 'identities') + ' · endpoints sharing a colour and namespace share an identity'));
        }
    }

    // ----- the islands ----------------------------------------------------------------

    function fitCols(n, width) {
        var usable = Math.max(PITCH * MIN_COLS, width - 36 - PITCH / 2);
        var max = Math.max(MIN_COLS, Math.floor(usable / PITCH));
        var want = Math.ceil(Math.sqrt(n * 2.4));
        return Math.max(MIN_COLS, Math.min(max, want));
    }

    function drawIslands(model) {
        var root = $('islands');
        tip.hidden = true;
        root.textContent = '';
        var q = state.query.trim().toLowerCase();
        var searching = !!q || !!state.filter;
        var width = root.clientWidth || window.innerWidth - 48;
        var sel = selectedEp(model);
        var twinGroup = sel && sel.group ? sel.group : null;
        var hidden = 0;
        var shownCells = 0;

        if (model.endpoints.length === 0) {
            root.appendChild(nothingYet());
            return;
        }

        model.namespaces.forEach(function (ns) {
            var eps = ns.endpoints;
            var hits = searching
                ? eps.filter(function (ep) {
                      return passes(ep) && matches(ep, q);
                  })
                : eps;
            var nsHit = q && ns.name.toLowerCase().indexOf(q) >= 0 && !state.filter;
            if (searching && hits.length === 0 && !nsHit) {
                hidden++;
                return;
            }
            var hitSet = null;
            if (searching && !nsHit) {
                hitSet = {};
                hits.forEach(function (ep) {
                    hitSet[ep.key] = true;
                });
            }
            var cols = fitCols(eps.length, width);
            var card = el('article', 'island' + (ns.open ? ' open' : ''));
            card.dataset.ns = ns.name;
            card.style.setProperty('--cols', String(cols));

            var head = el('header', 'isl-head');
            var title = el('div', 'isl-title');
            add(
                title,
                K.link(ns.name, function () {
                    open({ kind: M.KINDS.namespaces, namespace: '', name: ns.name });
                }, 'Open the namespace'),
                el('span', 'isl-count', K.num(eps.length)),
            );
            head.appendChild(title);
            var meter = el('div', 'isl-meter');
            var enforced = eps.length ? ns.enforced / eps.length : 0;
            add(
                meter,
                K.stack(
                    [
                        { value: ns.both, cls: 'e-both', label: 'ingress + egress' },
                        { value: ns.ingress, cls: 'e-ingress', label: 'ingress only' },
                        { value: ns.egress, cls: 'e-egress', label: 'egress only' },
                        { value: ns.none, cls: 'e-none', label: 'not enforced' },
                    ],
                    'isl-stack',
                ),
                el('span', 'isl-pct' + (enforced === 0 ? ' warn' : ''), M.percent(enforced)),
            );
            meter.title = M.percent(enforced) + ' of ' + ns.name + ' is under enforced policy';
            head.appendChild(meter);
            card.appendChild(head);

            if (ns.open) {
                var warn = el('div', 'isl-warn');
                add(warn, K.icon('unlock'), el('span', '', 'No policy — all traffic allowed'));
                // create() came with K8s Dockside 0.0.17.
                if (state.ctx.write && typeof sdk.create === 'function') {
                    var iso = K.button('Isolate', 'small', 'lock', function () {
                        isolate(ns.name);
                    });
                    iso.title = 'Ask to create a NetworkPolicy "default-deny-ingress" in ' + ns.name + ': incoming traffic to its pods is dropped until a policy allows it.';
                    warn.appendChild(iso);
                }
                card.appendChild(warn);
            }

            var honey = el('div', 'honey');
            var row = null;
            var drawn = eps.slice(0, MAX_CELLS);
            drawn.forEach(function (ep, i) {
                if (i % cols === 0) {
                    row = el('div', 'hrow' + (Math.floor(i / cols) % 2 ? ' odd' : ''));
                    honey.appendChild(row);
                }
                var cell = el('i', cellClass(ep));
                var color = cellColor(ep);
                if (color) cell.style.setProperty('--hc', color);
                cell.dataset.i = String(ep.index);
                if (!ep.ready && state.lens !== 'state') cell.classList.add('nr');
                if (hitSet && !hitSet[ep.key]) cell.classList.add('dim');
                if (ep.key === state.selected) cell.classList.add('sel');
                else if (twinGroup && ep.group === twinGroup) cell.classList.add('twin');
                row.appendChild(cell);
            });
            shownCells += drawn.length;
            card.appendChild(honey);
            if (eps.length > drawn.length) card.appendChild(el('div', 'isl-more', '+' + K.num(eps.length - drawn.length) + ' more — search to find one'));

            var foot = el('footer', 'isl-foot');
            var pol = ns.policies.length;
            add(foot, K.icon('shield'), el('span', '', pol ? M.plural(pol, 'policy', 'policies') + ' here' : 'no policy here'));
            if (ns.notReady) foot.appendChild(K.chip(ns.notReady + ' not ready', 'warn'));
            if (hitSet) foot.appendChild(el('span', 'push faint', hits.length + ' match'));
            card.appendChild(foot);
            root.appendChild(card);
        });

        if (hidden && searching) {
            var none = el('p', 'isl-hidden faint', hidden === model.namespaces.length ? 'Nothing matches.' : M.plural(hidden, 'namespace') + ' with nothing that matches are hidden.');
            root.appendChild(none);
        }
    }

    function nothingYet() {
        var box = el('div', 'getting-started');
        add(box, el('h2', '', 'No endpoints yet'), el('p', '', 'Cilium is installed, but no CiliumEndpoint exists. Every pod Cilium networks gets one — pods on the host network do not. Start a pod and it appears here.'));
        return box;
    }

    // ----- isolate ---------------------------------------------------------------------

    function isolate(ns) {
        var object = {
            apiVersion: 'networking.k8s.io/v1',
            kind: 'NetworkPolicy',
            metadata: { name: 'default-deny-ingress', namespace: ns },
            spec: { podSelector: {}, policyTypes: ['Ingress'] },
        };
        K.create(sdk, { kind: M.KINDS.knp, namespace: ns, object: object })
            .then(function (res) {
                if (!res) return;
                notice('Created ' + (res.name || 'default-deny-ingress') + ' in ' + ns + '. Incoming traffic to its pods is now dropped unless a policy allows it.');
            })
            .catch(fail);
    }

    function notice(text) {
        state.notice = text;
        var box = $('notice');
        box.textContent = '';
        add(box, K.icon('check'), el('span', '', text));
        box.hidden = false;
        setTimeout(function () {
            if (state.notice !== text) return;
            state.notice = '';
            box.hidden = true;
        }, 7000);
    }

    // ----- the inspector ---------------------------------------------------------------

    function pick(key) {
        state.selected = state.selected === key ? '' : key;
        writeHash();
        render(true);
        if (state.selected) $('drawer').scrollTop = 0;
    }

    function dsec(title, body, extra) {
        var node = el('section', 'dsec');
        var head = el('div', 'dsec-head');
        add(head, el('h3', 'mini-title', title), extra || null);
        node.appendChild(head);
        add(node, body);
        return node;
    }

    function fact(dl, label, value) {
        add(dl, el('dt', '', label), add(el('dd'), value));
    }

    function directionTile(dir, on, mode) {
        var tile = el('div', 'dir ' + (on ? 'on' : 'off'));
        var mark = el('span', 'dir-icon');
        mark.appendChild(K.icon(on ? 'lock' : 'unlock'));
        var words = el('div');
        add(words, el('div', 'dir-label', dir === 'in' ? 'Ingress' : 'Egress'), el('div', 'dir-value', on ? 'Enforced' : 'Open'), el('div', 'dir-sub', on ? (mode === 'always' ? 'enable-policy is always' : 'only what policies allow') : dir === 'in' ? 'anyone may connect in' : 'it may connect anywhere'));
        add(tile, mark, words);
        return tile;
    }

    function policyRow(model, p) {
        var row = K.button('', 'prow-btn', null, function () {
            showPolicy(p);
        });
        row.title = 'Show ' + p.name + ' in the policy map';
        var badge = el('span', 'kbadge k-' + p.kind, p.kindShort);
        var words = el('span', 'prow-words');
        add(words, el('span', 'prow-name', p.name), el('span', 'prow-sub', (p.namespace || 'cluster-wide') + ' · ' + [p.ingress ? p.ingress + ' in' : '', p.egress ? p.egress + ' out' : ''].filter(Boolean).join(' · ')));
        add(row, badge, words);
        if (p.deny) row.appendChild(K.chip('deny', 'error'));
        if (p.l7) row.appendChild(K.chip('L7', 'l7'));
        if (p.valid === false) row.appendChild(K.chip('invalid', 'error', 'alert'));
        return row;
    }

    function showPolicy(p) {
        memory.set('policy-map.pick', p.key);
        sdk.openView('policy-map').catch(fail);
    }

    function drawDrawer(model) {
        var box = $('drawer');
        var ep = selectedEp(model);
        document.body.classList.toggle('drawer-open', !!ep);
        if (!ep) {
            box.hidden = true;
            box.textContent = '';
            return;
        }
        var scroll = box.scrollTop;
        box.textContent = '';
        box.hidden = false;

        var top = el('div', 'd-top');
        var st = M.STATES[ep.state] || { label: ep.state || 'no state', tone: 'muted' };
        var tools = el('div', 'd-tools');
        add(
            tools,
            K.button('Pod', 'ghost small', 'pod', function () {
                open(podRef(ep));
            }),
            K.button('Logs', 'ghost small', 'logs', function () {
                sdk.logs(podRef(ep)).catch(fail);
            }),
            K.button('Endpoint', 'ghost small', 'open', function () {
                open(cepRef(ep));
            }),
            K.iconButton('close', 'Close (Esc)', function () {
                pick('');
            }),
        );
        add(top, el('span', 'mini-title', 'Endpoint'), tools);
        box.appendChild(top);

        var title = el('h2', 'd-title', ep.pod);
        box.appendChild(title);
        var sub = el('div', 'd-sub');
        add(sub, K.chip(st.label, st.tone, st.tone === 'ok' ? 'check' : 'alert'), el('span', 'faint', ep.namespace));
        if (ep.node) {
            add(
                sub,
                el('span', 'faint', '·'),
                K.link(ep.node, function () {
                    open({ kind: M.KINDS.nodes, namespace: '', name: ep.node });
                }),
            );
        }
        box.appendChild(sub);

        // Enforcement.
        var dirs = el('div', 'dirs');
        add(dirs, directionTile('in', ep.ingress, model.enforcementMode), directionTile('out', ep.egress, model.enforcementMode));
        box.appendChild(dsec('Policy enforcement', dirs));

        // Policies.
        var pols = M.policiesFor(model, ep);
        var plist = el('div', 'plist');
        if (pols.length === 0) {
            var none = el('div', 'd-empty');
            add(none, K.icon('unlock'), el('span', '', model.enforcementMode === 'always' ? 'No policy selects it, and enable-policy is always: everything to and from it is dropped.' : 'No policy selects this endpoint, so every connection to and from it is allowed.'));
            plist.appendChild(none);
        }
        pols.forEach(function (p) {
            plist.appendChild(policyRow(model, p));
        });
        box.appendChild(dsec('Policies selecting it', plist, pols.length ? el('span', 'faint small', String(pols.length)) : null));

        // Identity.
        var idBox = el('div', 'idbox');
        var idHead = el('div', 'id-head');
        var sw = el('i', 'hx c big');
        sw.style.setProperty('--hc', K.identityColor(ep.identity));
        var twins = ep.group ? ep.group.endpoints.length - 1 : 0;
        var idWords = el('div');
        add(idWords, el('div', 'id-num', ep.identity !== null ? '#' + ep.identity : 'none yet'), el('div', 'faint small', ep.identity === null ? 'waiting for an identity' : twins ? 'shared with ' + M.plural(twins, 'other endpoint') + ' here' : 'no other endpoint here has it'));
        add(idHead, sw, idWords);
        if (twins) {
            idHead.appendChild(
                K.button('Find them', 'ghost small push', 'search', function () {
                    $('query').value = String(ep.identity);
                    state.query = String(ep.identity);
                    writeHash();
                    render(true);
                }),
            );
        }
        idBox.appendChild(idHead);
        var labels = el('div', 'lchips');
        K.sortLabels(ep.labels.list).forEach(function (l) {
            var dim = /^io\.cilium\.k8s\.(namespace\.labels|policy)\./.test(l.key) || l.key === 'io.kubernetes.pod.namespace';
            labels.appendChild(K.labelChip(l, dim ? 'quiet' : ''));
        });
        if (!ep.labels.list.length) labels.appendChild(el('span', 'faint', 'No security labels.'));
        idBox.appendChild(labels);
        box.appendChild(dsec('Security identity', idBox));

        // Addresses.
        var dl = el('dl', 'facts');
        var ipBox = el('span', 'ips');
        ep.ips.forEach(function (ip) {
            ipBox.appendChild(el('code', 'ipchip', ip));
        });
        if (!ep.ips.length) ipBox.appendChild(el('span', 'faint', 'none yet'));
        fact(dl, 'Pod IPs', ipBox);
        if (ep.node || ep.nodeIP) fact(dl, 'Node', [ep.node || '—', ep.nodeIP ? el('span', 'faint', ' · ' + ep.nodeIP) : null]);
        if (ep.namedPorts.length) {
            var ports = el('span', 'ips');
            ep.namedPorts.forEach(function (p) {
                ports.appendChild(el('code', 'ipchip', p.name + ' ' + p.port + '/' + (p.protocol || 'TCP')));
            });
            fact(dl, 'Named ports', ports);
        }
        if (ep.id !== undefined) fact(dl, 'Endpoint ID', String(ep.id));
        if (ep.serviceAccount) fact(dl, 'Service account', ep.serviceAccount);
        if (ep.encryptionKey !== undefined && ep.encryptionKey !== null) fact(dl, 'Encryption key', ep.encryptionKey ? 'index ' + ep.encryptionKey : 'none');
        fact(dl, 'CiliumEndpoint', ep.name);
        box.appendChild(dsec('Details', dl));

        var more = el('div', 'd-actions');
        add(
            more,
            K.button('CiliumEndpoint YAML', 'ghost small', 'edit', function () {
                sdk.edit(cepRef(ep)).catch(fail);
            }),
        );
        box.appendChild(more);
        box.scrollTop = scroll;
    }

    // ----- not installed ----------------------------------------------------------------

    function drawEmpty(model) {
        var box = $('empty');
        box.hidden = false;
        K.whyAbsent(sdk).then(function (summary) {
            K.absent(box, { sdk: sdk, summary: summary, contextName: state.ctx.contextName, missing: model.missing, fail: fail });
        });
    }

    // ----- putting it together -----------------------------------------------------------

    function render() {
        var model = state.model;
        if (!model) return;
        drawError();
        var where = state.ctx.contextName;
        if (model.version) where += ' · Cilium ' + model.version;
        $('where').textContent = where;

        document.body.classList.toggle('absent', !model.installed);
        if (!model.installed) {
            $('board').hidden = true;
            document.body.classList.remove('drawer-open');
            $('drawer').hidden = true;
            drawEmpty(model);
            return;
        }
        $('empty').hidden = true;
        $('board').hidden = false;
        nodeIndex = {};
        model.nodes.forEach(function (n, i) {
            nodeIndex[n.name] = i;
        });
        drawLens();
        drawStats(model);
        drawFilters(model);
        drawLegend(model);
        drawIslands(model);
        drawDrawer(model);
    }

    function drawLens() {
        var box = $('lens');
        box.textContent = '';
        box.appendChild(
            K.seg(
                LENSES,
                state.lens,
                function (id) {
                    state.lens = id;
                    memory.set('endpoints.lens', id);
                    writeHash();
                    render(true);
                },
                'Colour by',
            ),
        );
    }

    function tick() {
        M.load(sdk)
            .then(function (model) {
                if (state.error) {
                    state.error = '';
                    drawError();
                }
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

    function measure() {
        var width = $('islands').clientWidth;
        if (!width || !state.model || !state.model.installed) return;
        var cols = Math.floor(width / PITCH);
        if (cols !== state.cols) {
            state.cols = cols;
            drawIslands(state.model);
        }
    }

    // One tip and one click handler for every cell, however often the map
    // under them is redrawn.
    var tip = K.tooltip($('islands'), '.hx', function (cell, into) {
        var model = state.model;
        var ep = model && model.endpoints[Number(cell.dataset.i)];
        if (!ep) return false;
        add(into, el('div', 'tip-head', ep.pod), el('div', 'tip-sub', ep.namespace + (ep.node ? ' · ' + ep.node : '')));
        var line = el('div', 'tip-line');
        add(line, el('code', '', ep.ips[0] || 'no IP yet'), el('span', 'faint', ep.identity !== null ? ' · identity ' + ep.identity : ' · no identity'));
        into.appendChild(line);
        var enf = ENFORCEMENT.filter(function (e) {
            return e.id === ep.enforcement;
        })[0];
        var pol = el('div', 'tip-line');
        var sw = el('i', 'hx e-' + ep.enforcement);
        add(pol, sw, el('span', '', enf.label + ' — ' + enf.text));
        into.appendChild(pol);
        if (!ep.ready) into.appendChild(el('div', 'tip-line bad', (M.STATES[ep.state] || { label: ep.state || 'no state' }).label));
        into.appendChild(el('div', 'tip-note', 'Click for its identity and policies'));
        return true;
    });
    $('islands').addEventListener('click', function (event) {
        var cell = event.target.closest && event.target.closest('.hx');
        if (!cell || !state.model) return;
        var ep = state.model.endpoints[Number(cell.dataset.i)];
        if (ep) pick(ep.key);
    });

    $('scrim').addEventListener('click', function () {
        pick('');
    });
    $('logo').appendChild(K.logo());
    $('search-icon').appendChild(K.icon('search'));
    var searchTimer = 0;
    $('query').addEventListener('input', function () {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(function () {
            state.query = $('query').value;
            writeHash();
            render(true);
        }, 120);
    });
    $('query').addEventListener('keydown', function (event) {
        if (event.key === 'Escape') {
            $('query').value = '';
            state.query = '';
            writeHash();
            render(true);
        }
    });
    document.addEventListener('keydown', function (event) {
        if (event.key === '/' && (document.activeElement === document.body || !document.activeElement)) {
            event.preventDefault();
            $('query').focus();
        } else if (event.key === 'Escape' && state.selected && document.activeElement !== $('query')) {
            pick('');
        }
    });
    $('top-actions').appendChild(
        K.button('Policy map', 'ghost', 'shield', function () {
            sdk.openView('policy-map').catch(fail);
        }),
    );
    $('top-actions').appendChild(
        K.button('Overview', 'ghost', 'logo', function () {
            sdk.openView('overview').catch(fail);
        }),
    );
    if (typeof ResizeObserver === 'function') new ResizeObserver(measure).observe($('islands'));

    var hash = readHash();
    $('query').value = state.query;
    document.body.appendChild(
        K.grip({
            panel: $('drawer'),
            prop: '--drawer-w',
            className: 'drawer-grip',
            min: 340,
            room: 420,
            initial: state.width,
            label: 'Resize the inspector',
            onResize: function (px, done) {
                if (!done) return;
                state.width = px;
                writeHash();
            },
        }),
    );

    sdk.ready()
        .then(function (context) {
            state.ctx = context;
            $('where').textContent = context.contextName;
            // A panel that sent us here may have left an endpoint to show;
            // the lens picked last time stands when the address says none.
            return Promise.all([memory.get('endpoints.pick'), hash.lens ? null : memory.get('endpoints.lens')]).then(function (kept) {
                if (kept[0]) {
                    state.selected = kept[0];
                    memory.set('endpoints.pick', null);
                    writeHash();
                }
                if (
                    LENSES.some(function (l) {
                        return l.id === kept[1];
                    })
                ) {
                    state.lens = kept[1];
                }
            });
        })
        .then(function () {
            if (state.ctx) tick();
        })
        .catch(fail);
})();
