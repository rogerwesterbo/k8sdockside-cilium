// Nodes & addresses: every node with its agent, its Cilium addresses and how
// full its pod address range is; and, where their kinds are served, the LB
// IPAM pools and who holds their addresses, the L2 announcements and the node
// answering for each service, the BGP sessions from each node to each peer,
// and the egress gateways.
(function () {
    'use strict';

    var sdk = window.k8sdockside;
    var M = window.Cilium;
    var K = window.CiliumKit;
    var el = K.el;
    var add = K.add;
    var POLL = 5000;
    var MAX_HOLDERS = 8;

    var state = { ctx: null, model: null, sig: '', error: '', hover: '', bgpWires: null, notice: '' };

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

    function nodeRef(name) {
        return { kind: M.KINDS.nodes, namespace: '', name: name };
    }

    function secHead(box, iconName, title, note, extra) {
        var head = el('div', 'sec-head');
        var h = el('h2');
        add(h, K.icon(iconName), el('span', '', title));
        add(head, h, note ? el('span', 'sec-note', note) : null, extra || null);
        box.appendChild(head);
    }

    function notice(text) {
        state.notice = text;
        var box = $('notice');
        box.textContent = '';
        add(box, K.icon('check'), el('span', '', text));
        box.hidden = false;
        setTimeout(function () {
            if (state.notice === text) box.hidden = true;
        }, 6000);
    }

    // ----- nodes ------------------------------------------------------------------

    function drawNodes(model) {
        var box = $('nodes');
        box.textContent = '';
        var nodes = model.nodes;
        var healthy = nodes.filter(function (n) {
            return M.nodeTone(model, n) === 'ok';
        }).length;
        secHead(box, 'node', 'Nodes', healthy + ' of ' + nodes.length + ' healthy');
        if (!nodes.length) {
            box.appendChild(el('p', 'faint', 'No nodes could be read.'));
            return;
        }
        var grid = el('div', 'ncards');
        nodes.forEach(function (n) {
            grid.appendChild(nodeCard(model, n));
        });
        box.appendChild(grid);
    }

    function nodeCard(model, n) {
        var tone = M.nodeTone(model, n);
        var card = el('article', 'ncard ' + tone);
        var head = el('header', 'ncard-head');
        var name = K.link(n.name, function () {
            open(nodeRef(n.name));
        });
        name.classList.add('ncard-name');
        add(head, K.dot(tone), name);
        n.roles.forEach(function (r) {
            head.appendChild(K.chip(r, 'muted'));
        });
        if (!n.obj) head.appendChild(K.chip('no Node object', 'muted', null, 'A CiliumNode without a Kubernetes Node'));
        if (n.obj && !n.ready) head.appendChild(K.chip('node not ready', 'error', 'alert'));
        if (n.unschedulable) head.appendChild(K.chip('cordoned', 'warn'));
        if (n.zone) head.appendChild(el('span', 'push faint small', n.zone));
        card.appendChild(head);

        // The agent.
        var agent = el('div', 'agent-line ' + (n.agent ? (n.agentReady ? 'ok' : 'error') : 'muted'));
        var mark = el('span', 'agent-mark');
        mark.appendChild(K.icon('pod'));
        var words = el('div', 'agent-words');
        if (n.agent) {
            add(
                words,
                K.link(n.agent.metadata.name, function () {
                    open({ kind: M.KINDS.pods, namespace: n.agent.metadata.namespace, name: n.agent.metadata.name });
                }),
                el('span', 'agent-state', n.agentReady ? 'ready' + (n.agentRestarts ? ' · ' + M.plural(n.agentRestarts, 'restart') : '') : n.agentTrouble || 'not ready'),
            );
        } else {
            add(words, el('span', '', model.agentsKnown ? 'No Cilium agent on this node' : 'Agent pods could not be found'));
        }
        add(agent, mark, words);
        if (n.agent) {
            agent.appendChild(
                K.iconButton('logs', 'Agent logs', function () {
                    sdk.logs({ kind: M.KINDS.pods, namespace: n.agent.metadata.namespace, name: n.agent.metadata.name }).catch(fail);
                }),
            );
        }
        card.appendChild(agent);

        // Addresses.
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
            p.cidrs.forEach(function (c) {
                cidrs.appendChild(el('code', 'ipchip', c + ' · ' + p.pool));
            });
        });
        if (cidrs.childNodes.length) fact('Pod CIDRs', cidrs);
        var enc = M.nodeEncryption(model, n);
        if (enc) fact('Encryption', enc.tone === 'ok' ? add(el('span', 'enc-on'), K.icon('lock'), enc.text) : el('span', enc.tone === 'warn' ? 'bad-text' : 'faint', enc.text));
        card.appendChild(dl);

        // IPAM usage.
        if (n.ipamUsed !== null) {
            var use = el('div', 'ipam');
            var frac = n.ipamCapacity ? n.ipamUsed / n.ipamCapacity : 0;
            var line = el('div', 'ipam-line');
            add(line, el('span', 'faint', 'Pod addresses'), el('strong', '', n.ipamUsed + (n.ipamCapacity ? ' / ' + K.num(n.ipamCapacity) : '')), n.ipamCapacity ? el('span', 'pct ' + K.fillTone(frac), M.percent(frac)) : null);
            add(use, line, n.ipamCapacity ? K.meter(frac, K.fillTone(frac)) : null);
            card.appendChild(use);
        }
        if (n.ipamError) {
            var err = el('div', 'why error small');
            add(err, K.icon('alert'), el('span', '', n.ipamError));
            card.appendChild(err);
        }

        var foot = el('footer', 'ncard-foot');
        add(foot, K.icon('hex'), el('span', '', M.plural(n.endpoints, 'endpoint')));
        if (n.notReady) foot.appendChild(K.chip(n.notReady + ' not ready', 'warn'));
        var sessions = model.bgp && model.bgp.nodes[n.name];
        if (sessions && sessions.length) {
            var bgp = el('span', 'bgp-dots push');
            bgp.appendChild(el('span', 'faint small', 'BGP'));
            sessions.forEach(function (s) {
                bgp.appendChild(K.dot(s.tone, s.address + ' — ' + s.state));
            });
            foot.appendChild(bgp);
        }
        card.appendChild(foot);
        return card;
    }

    // ----- LB IPAM ----------------------------------------------------------------

    function drawLB(model) {
        var box = $('lbipam');
        box.textContent = '';
        box.hidden = !model.lb;
        if (!model.lb) return;
        var pools = model.lb.pools;
        var used = 0;
        var total = 0;
        pools.forEach(function (p) {
            used += p.used;
            if (isFinite(p.total)) total += p.total;
        });
        secHead(box, 'grid', 'LB IPAM pools', pools.length ? used + ' of ' + K.num(total) + ' addresses in use across ' + M.plural(pools.length, 'pool') : 'no pools');
        if (model.lb.pending.length) {
            var wait = el('div', 'pending');
            add(wait, el('div', 'pending-head', M.plural(model.lb.pending.length, 'LoadBalancer service is', 'LoadBalancer services are') + ' waiting for an address'));
            var list = el('ul', 'pending-list');
            model.lb.pending.slice(0, 8).forEach(function (s) {
                var li = el('li');
                add(
                    li,
                    K.icon('service'),
                    K.link(s.namespace + '/' + s.name, function () {
                        open({ kind: M.KINDS.services, namespace: s.namespace, name: s.name });
                    }),
                    el('span', 'faint', s.reason ? ' — ' + s.reason : s.lbClass ? ' — class ' + s.lbClass : ''),
                );
                list.appendChild(li);
            });
            wait.appendChild(list);
            box.appendChild(wait);
        }
        if (!pools.length) {
            box.appendChild(el('p', 'quiet', 'LB IPAM is served, but there is no CiliumLoadBalancerIPPool, so LoadBalancer services get no address from Cilium.'));
            return;
        }
        var grid = el('div', 'lbcards');
        pools.forEach(function (p) {
            grid.appendChild(poolCard(model, p));
        });
        box.appendChild(grid);
    }

    function poolCard(model, p) {
        var tone = p.conflict ? 'error' : p.disabled ? 'muted' : K.fillTone(p.fraction);
        var card = el('article', 'lbcard ' + tone);
        var head = el('header', 'lbcard-head');
        var name = K.link(p.name, function () {
            open({ kind: M.KINDS.lbPools, namespace: '', name: p.name });
        });
        name.classList.add('lbcard-name');
        add(head, name);
        if (state.ctx.write) head.appendChild(toggle(p));
        card.appendChild(head);

        var chips = el('div', 'chips');
        if (p.conflict) chips.appendChild(K.chip('conflict', 'error', 'alert', p.conflict));
        if (p.disabled) chips.appendChild(K.chip('disabled', 'muted', null, 'No new addresses are handed out from this pool'));
        if (p.allowFirstLast) chips.appendChild(K.chip('first & last IPs used', 'muted'));
        chips.appendChild(K.chip(p.serviceSelector ? 'services: ' + M.selectorText(p.serviceSelector) : 'any service', 'muted', 'service'));
        card.appendChild(chips);

        var use = el('div', 'lb-use');
        var ring = K.ring(p.fraction, 64, p.disabled ? '' : K.fillTone(p.fraction), M.percent(p.fraction) + ' in use');
        var nums = el('div', 'lb-nums');
        var free = p.available !== null ? p.available : Math.max(0, p.total - p.used);
        add(nums, el('div', 'lb-big', p.used + ' / ' + (isFinite(p.total) ? K.num(p.total) : '∞')), el('div', 'faint small', M.percent(p.fraction) + ' in use · ' + (isFinite(free) ? K.num(free) : 'plenty') + ' free'));
        var blocks = el('div', 'ips');
        p.blocks.forEach(function (b) {
            blocks.appendChild(el('code', 'ipchip', b.text + (b.v === 4 ? ' · ' + K.num(b.size) : '')));
        });
        nums.appendChild(blocks);
        add(use, ring, nums);
        card.appendChild(use);
        if (p.conflict) {
            var why = el('div', 'why error small');
            add(why, K.icon('alert'), el('span', '', p.conflict));
            card.appendChild(why);
        }

        if (p.holders.length) {
            var list = el('ul', 'holders');
            p.holders.slice(0, MAX_HOLDERS).forEach(function (h) {
                var li = el('li');
                var who = K.link(h.svc.namespace + '/' + h.svc.name, function () {
                    open({ kind: M.KINDS.services, namespace: h.svc.namespace, name: h.svc.name });
                });
                add(li, el('code', 'holder-ip', h.ip), who);
                if (h.svc.announcer) li.appendChild(el('span', 'holder-node faint', '↳ ' + h.svc.announcer));
                list.appendChild(li);
            });
            card.appendChild(list);
            if (p.holders.length > MAX_HOLDERS) card.appendChild(el('div', 'faint small', 'and ' + (p.holders.length - MAX_HOLDERS) + ' more'));
        } else {
            card.appendChild(el('div', 'faint small', 'No service holds an address from it yet.'));
        }
        return card;
    }

    function toggle(p) {
        var on = !p.disabled;
        var b = K.button('', 'switch' + (on ? ' on' : ''), null, function () {
            K.apply(sdk, { kind: M.KINDS.lbPools, namespace: '', name: p.name }, { spec: { disabled: on } })
                .then(function (done) {
                    if (done) notice((on ? 'Disabled ' : 'Enabled ') + p.name + '. ' + (on ? 'Services keep the addresses they have; no new ones come from it.' : 'It hands out addresses again.'));
                })
                .catch(fail);
        });
        b.setAttribute('role', 'switch');
        b.setAttribute('aria-checked', on ? 'true' : 'false');
        b.title = on ? 'Enabled — click to stop handing out addresses from this pool' : 'Disabled — click to hand out addresses again';
        add(b, el('span', 'switch-track'), el('span', 'switch-label', on ? 'Enabled' : 'Disabled'));
        return b;
    }

    // ----- L2 ---------------------------------------------------------------------

    function drawL2(model) {
        var box = $('l2');
        box.textContent = '';
        box.hidden = !model.l2;
        if (!model.l2) return;
        secHead(box, 'l2', 'L2 announcements', model.l2.length ? M.plural(model.l2.length, 'policy', 'policies') + ' · ARP / NDP answered by one node per service' : 'no policies');
        if (!model.l2.length) {
            box.appendChild(el('p', 'quiet', 'No CiliumL2AnnouncementPolicy exists, so no node answers ARP or NDP for service addresses.'));
            return;
        }
        var grid = el('div', 'l2cards');
        model.l2.forEach(function (p) {
            var card = el('article', 'l2card' + (p.errors.length ? ' error' : ''));
            var head = el('header', 'l2card-head');
            var name = K.link(p.name, function () {
                open({ kind: M.KINDS.l2, namespace: '', name: p.name });
            });
            name.classList.add('lbcard-name');
            add(head, K.icon('l2'), name);
            card.appendChild(head);
            var chips = el('div', 'chips');
            if (p.loadBalancerIPs) chips.appendChild(K.chip('LoadBalancer IPs', 'info'));
            if (p.externalIPs) chips.appendChild(K.chip('external IPs', 'info'));
            if (!p.loadBalancerIPs && !p.externalIPs) chips.appendChild(K.chip('announces no address type', 'warn', 'alert'));
            chips.appendChild(K.chip(p.interfaces.length ? 'on ' + p.interfaces.join(', ') : 'any interface', 'muted'));
            card.appendChild(chips);
            p.errors.forEach(function (e) {
                var why = el('div', 'why error small');
                add(why, K.icon('alert'), el('span', '', e));
                card.appendChild(why);
            });
            var dl = el('dl', 'facts compact');
            add(dl, el('dt', '', 'Nodes'), add(el('dd'), K.selectorChip(p.nodeSelector, 'every node'), el('span', 'faint', ' · ' + M.plural(p.nodes.length, 'node'))));
            add(dl, el('dt', '', 'Services'), add(el('dd'), K.selectorChip(p.serviceSelector, 'every service'), el('span', 'faint', ' · ' + M.plural(p.services.length, 'LoadBalancer'))));
            card.appendChild(dl);
            var list = el('ul', 'holders');
            p.services.slice(0, MAX_HOLDERS).forEach(function (s) {
                var li = el('li');
                add(
                    li,
                    el('code', 'holder-ip', s.ips[0] || 'no address'),
                    K.link(s.namespace + '/' + s.name, function () {
                        open({ kind: M.KINDS.services, namespace: s.namespace, name: s.name });
                    }),
                );
                if (s.announcer) {
                    var n = el('span', 'holder-node');
                    add(
                        n,
                        K.icon('l2'),
                        K.link(s.announcer, function () {
                            open(nodeRef(s.announcer));
                        }),
                    );
                    li.appendChild(n);
                } else if (model.leasesRead) {
                    li.appendChild(el('span', 'holder-node faint', 'no node elected'));
                }
                list.appendChild(li);
            });
            if (p.services.length) card.appendChild(list);
            if (p.services.length > MAX_HOLDERS) card.appendChild(el('div', 'faint small', 'and ' + (p.services.length - MAX_HOLDERS) + ' more'));
            grid.appendChild(card);
        });
        box.appendChild(grid);
    }

    // ----- BGP --------------------------------------------------------------------

    function drawBGP(model) {
        var box = $('bgp');
        box.textContent = '';
        box.hidden = !model.bgp;
        state.bgpWires = null;
        if (!model.bgp) return;
        var bgp = model.bgp;
        var up = bgp.sessions.filter(function (s) {
            return s.state === 'established';
        }).length;
        var key = el('div', 'bkey');
        add(key, keyLine('ok', 'established'), keyLine('warn', 'connecting'), keyLine('error', 'down'), keyLine('muted', 'unknown'));
        secHead(box, 'bgp', 'BGP', bgp.sessions.length ? (bgp.known ? up + ' of ' + M.plural(bgp.sessions.length, 'session') + ' established' : M.plural(bgp.sessions.length, 'session') + ' configured') : 'no sessions', bgp.sessions.length ? key : null);
        if (bgp.mode === 'legacy') {
            var note = el('div', 'ov-note');
            add(note, K.icon('info'), el('span', '', 'Configured with CiliumBGPPeeringPolicy, which reports no session state. Sessions are drawn as configured.'));
            box.appendChild(note);
        }
        if (!bgp.sessions.length) {
            box.appendChild(el('p', 'quiet', bgp.clusterConfigs.length ? 'CiliumBGPClusterConfigs exist, but no node reports a peer yet.' : 'The BGP control plane kinds are served, but nothing is configured.'));
            bgp.clusterConfigs.forEach(function (c) {
                c.errors.forEach(function (e) {
                    var why = el('div', 'why warn small');
                    add(why, K.icon('alert'), el('span', '', c.name + ': ' + e));
                    box.appendChild(why);
                });
            });
            return;
        }

        var wrap = el('div', 'bgpmap');
        var wires = K.svg('svg', { class: 'bwires', 'aria-hidden': 'true' });
        wrap.appendChild(wires);
        var colNodes = el('div', 'bcol');
        var colPeers = el('div', 'bcol right');
        colNodes.appendChild(el('div', 'fcol-head', 'Nodes'));
        colPeers.appendChild(el('div', 'fcol-head', 'Peers'));
        var nodeNames = Object.keys(bgp.nodes).sort();
        nodeNames.forEach(function (name) {
            var sessions = bgp.nodes[name];
            var worst = sessions.some(function (s) {
                return s.tone === 'error';
            })
                ? 'error'
                : sessions.some(function (s) {
                        return s.tone === 'warn';
                    })
                  ? 'warn'
                  : sessions.every(function (s) {
                          return s.tone === 'ok';
                      })
                    ? 'ok'
                    : 'muted';
            var b = K.button('', 'bnode ' + worst, null, function () {
                open({ kind: bgp.mode === 'legacy' ? M.KINDS.nodes : M.KINDS.bgpNodes, namespace: '', name: name });
            });
            b.dataset.id = 'n:' + name;
            var top = el('span', 'bnode-top');
            add(top, K.icon('node'), el('span', 'bnode-name', name));
            var asn = sessions[0] && sessions[0].localASN ? 'AS' + sessions[0].localASN : '';
            add(b, top, el('span', 'bnode-sub', [asn, M.plural(sessions.length, 'session')].filter(Boolean).join(' · ')));
            colNodes.appendChild(b);
        });
        bgp.peers.forEach(function (p) {
            var tone = p.down ? 'error' : p.up === p.sessions.length ? 'ok' : p.up ? 'warn' : 'muted';
            var b = K.button('', 'bnode peer ' + tone, null, null);
            b.dataset.id = 'p:' + p.key;
            var top = el('span', 'bnode-top');
            add(top, K.icon('peer'), el('code', 'bnode-name', p.address));
            var sub = [p.asn ? 'AS' + p.asn : '', p.name, bgp.known ? p.up + '/' + p.sessions.length + ' up' : ''].filter(Boolean).join(' · ');
            add(b, top, el('span', 'bnode-sub', sub));
            colPeers.appendChild(b);
        });
        add(wrap, colNodes, el('div', 'bcol mid'), colPeers);
        box.appendChild(wrap);

        // A table of the same, for the numbers.
        var table = el('div', 'table-wrap');
        var t = el('table', 'grid-table');
        var thead = el('thead');
        var tr = el('tr');
        ['Node', 'Peer', 'ASN', 'State', 'Up since', 'Routes in / out'].forEach(function (h) {
            tr.appendChild(el('th', '', h));
        });
        thead.appendChild(tr);
        t.appendChild(thead);
        var tbody = el('tbody');
        bgp.sessions
            .slice()
            .sort(function (a, b) {
                var rank = { error: 0, warn: 1, muted: 2, ok: 3 };
                return rank[a.tone] - rank[b.tone] || a.node.localeCompare(b.node);
            })
            .slice(0, 80)
            .forEach(function (s) {
                var row = el('tr');
                var routesIn = 0;
                var routesOut = 0;
                s.routes.forEach(function (r) {
                    routesIn += Number(r.received) || 0;
                    routesOut += Number(r.advertised) || 0;
                });
                add(
                    row,
                    add(el('td'), s.node),
                    add(el('td'), el('code', '', s.address), s.name ? el('span', 'faint', ' ' + s.name) : null),
                    el('td', '', s.asn ? 'AS' + s.asn : '—'),
                    add(el('td'), K.chip(s.state.replace('_', ' '), s.tone)),
                    el('td', 'faint', s.since ? K.ago(s.since) : s.uptime || '—'),
                    el('td', '', s.routes.length ? routesIn + ' / ' + routesOut : '—'),
                );
                tbody.appendChild(row);
            });
        t.appendChild(tbody);
        table.appendChild(t);
        box.appendChild(table);

        state.bgpWires = function () {
            wires.textContent = '';
            var r0 = wrap.getBoundingClientRect();
            wires.setAttribute('width', String(r0.width));
            wires.setAttribute('height', String(r0.height));
            var at = {};
            wrap.querySelectorAll('.bnode').forEach(function (n) {
                var r = n.getBoundingClientRect();
                at[n.dataset.id] = { left: r.left - r0.left, right: r.right - r0.left, mid: r.top - r0.top + r.height / 2 };
            });
            bgp.sessions.forEach(function (s) {
                var a = at['n:' + s.node];
                var b = at['p:' + s.address + '|' + s.asn];
                if (!a || !b) return;
                var x1 = a.right;
                var x2 = b.left;
                var bend = Math.max(30, (x2 - x1) / 2);
                var d = 'M' + x1 + ' ' + a.mid + ' C' + (x1 + bend) + ' ' + a.mid + ' ' + (x2 - bend) + ' ' + b.mid + ' ' + x2 + ' ' + b.mid;
                var path = K.svg('path', { d: d, class: 'bwire ' + s.tone });
                path.dataset.from = 'n:' + s.node;
                path.dataset.to = 'p:' + s.address + '|' + s.asn;
                var title = K.svg('title', {});
                title.textContent = s.node + ' → ' + s.address + ': ' + s.state;
                path.appendChild(title);
                wires.appendChild(path);
            });
            light();
        };
        requestAnimationFrame(state.bgpWires);
    }

    function keyLine(tone, text) {
        var line = el('div', 'bkey-line');
        add(line, el('i', 'bkey-wire ' + tone), el('span', '', text));
        return line;
    }

    function light() {
        var wrap = document.querySelector('.bgpmap');
        if (!wrap) return;
        var id = state.hover;
        wrap.classList.toggle('tracing', !!id);
        wrap.querySelectorAll('.bwire').forEach(function (p) {
            p.classList.toggle('lit', !!id && (p.dataset.from === id || p.dataset.to === id));
        });
        wrap.querySelectorAll('.bnode').forEach(function (n) {
            var on = false;
            if (id) {
                if (n.dataset.id === id) on = true;
                else {
                    wrap.querySelectorAll('.bwire.lit').forEach(function (p) {
                        if (p.dataset.from === n.dataset.id || p.dataset.to === n.dataset.id) on = true;
                    });
                }
            }
            n.classList.toggle('lit', on);
        });
    }

    // ----- egress gateways ----------------------------------------------------------

    function drawEgress(model) {
        var box = $('egress');
        box.textContent = '';
        box.hidden = !model.egress;
        if (!model.egress) return;
        secHead(box, 'exit', 'Egress gateways', model.egress.length ? M.plural(model.egress.length, 'policy', 'policies') : 'no policies');
        if (!model.egress.length) {
            box.appendChild(el('p', 'quiet', 'No CiliumEgressGatewayPolicy exists, so pods leave the cluster from the node they run on, with its address.'));
            return;
        }
        var list = el('div', 'egress-list');
        model.egress.forEach(function (p) {
            var row = el('article', 'egress-row');
            var src = el('div', 'eg-stop');
            var name = K.link(p.name, function () {
                open({ kind: M.KINDS.egress, namespace: '', name: p.name });
            });
            name.classList.add('lbcard-name');
            add(src, name, el('span', 'eg-sub', M.plural(p.sources, 'endpoint') + ' leave through it'));
            var selectors = el('div', 'chips');
            p.selectors.slice(0, 3).forEach(function (s) {
                if (s.namespaceSelector) selectors.appendChild(K.selectorChip(s.namespaceSelector));
                if (s.podSelector) selectors.appendChild(K.selectorChip(s.podSelector));
            });
            src.appendChild(selectors);
            var gws = el('div', 'eg-stop');
            add(gws, el('span', 'mini-title', 'Gateway'));
            p.gateways.forEach(function (g) {
                var line = el('div', 'eg-gw');
                var nodes = g.nodes.length
                    ? g.nodes.slice(0, 3).map(function (n) {
                          return K.link(n.name, function () {
                              open(nodeRef(n.name));
                          });
                      })
                    : [el('span', 'bad-text', 'no node matches')];
                add(line, K.icon('node'), nodes);
                if (g.nodes.length > 3) line.appendChild(el('span', 'faint', ' +' + (g.nodes.length - 3)));
                gws.appendChild(line);
                var ip = el('div', 'eg-ip');
                add(ip, el('code', '', g.egressIP || (g.iface ? 'first IP on ' + g.iface : 'the node’s own IP')));
                gws.appendChild(ip);
            });
            var dst = el('div', 'eg-stop');
            add(dst, el('span', 'mini-title', 'To'));
            var cidrs = el('div', 'ips');
            p.destinations.forEach(function (c) {
                cidrs.appendChild(el('code', 'ipchip', c));
            });
            p.excluded.forEach(function (c) {
                cidrs.appendChild(el('code', 'ipchip excluded', 'except ' + c));
            });
            dst.appendChild(cidrs);
            add(row, src, K.icon('arrow', 'eg-arrow'), gws, K.icon('arrow', 'eg-arrow'), dst);
            list.appendChild(row);
        });
        box.appendChild(list);
    }

    // ----- putting it together ------------------------------------------------------

    function drawJump(model) {
        var box = $('jump');
        box.textContent = '';
        [
            ['nodes', 'Nodes', true],
            ['lbipam', 'LB IPAM', !!model.lb],
            ['l2', 'L2', !!model.l2],
            ['bgp', 'BGP', !!model.bgp],
            ['egress', 'Egress', !!model.egress],
        ].forEach(function (j) {
            if (!j[2]) return;
            box.appendChild(
                K.button(j[1], 'jump-btn', null, function () {
                    $(j[0]).scrollIntoView({ behavior: 'smooth', block: 'start' });
                }),
            );
        });
    }

    function drawEmpty(model) {
        var box = $('empty');
        box.hidden = false;
        K.whyAbsent(sdk).then(function (summary) {
            K.absent(box, { sdk: sdk, summary: summary, contextName: state.ctx.contextName, missing: model.missing, fail: fail });
        });
    }

    function render() {
        var model = state.model;
        var where = state.ctx.contextName;
        if (model.version) where += ' · Cilium ' + model.version;
        $('where').textContent = where;
        if (!model.installed) {
            $('body').hidden = true;
            drawEmpty(model);
            return;
        }
        $('empty').hidden = true;
        $('body').hidden = false;
        drawJump(model);
        drawNodes(model);
        drawLB(model);
        drawL2(model);
        drawBGP(model);
        drawEgress(model);
        var none = $('none');
        none.hidden = !!(model.lb || model.l2 || model.bgp || model.egress);
        if (!none.hidden && !none.childNodes.length) {
            add(none, K.icon('info'), el('span', '', 'This cluster serves none of the kinds for LB IPAM, L2 announcements, BGP or egress gateways, so there is nothing more to show here.'));
        }
    }

    function tick() {
        M.load(sdk, { extras: true })
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

    $('bgp').addEventListener('pointerover', function (event) {
        var n = event.target.closest && event.target.closest('.bnode');
        var id = n ? n.dataset.id : '';
        if (id === state.hover) return;
        state.hover = id;
        light();
    });
    $('bgp').addEventListener('pointerleave', function () {
        state.hover = '';
        light();
    });
    if (typeof ResizeObserver === 'function') {
        new ResizeObserver(function () {
            if (state.bgpWires) state.bgpWires();
        }).observe($('bgp'));
    }
    $('logo').appendChild(K.logo());
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

    sdk.ready()
        .then(function (context) {
            state.ctx = context;
            $('where').textContent = context.contextName;
            tick();
        })
        .catch(fail);
})();
