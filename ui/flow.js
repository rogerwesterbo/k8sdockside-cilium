// A policy drawn as a flow: who may reach the selected endpoints on the left,
// the endpoints themselves in the middle, where they may go on the right, a
// wire from each peer labelled with its ports -- and the same policy said in
// plain words underneath. Shared by the policy map and the policy panel.
(function () {
    'use strict';

    var M = window.Cilium;
    var K = window.CiliumKit;
    var el = K.el;
    var add = K.add;

    var PEER_ICON = { endpoints: 'hex', k8s: 'hex', entity: 'entity', cidr: 'cidr', fqdn: 'fqdn', service: 'service', nodes: 'node', group: 'peer', any: 'world' };

    // ----- words ------------------------------------------------------------------

    function portText(p) {
        var proto = p.proto && p.proto !== 'ANY' ? p.proto + ' ' : '';
        if (!p.port || p.port === '0') return proto ? proto.trim() + ' any port' : 'any port';
        return proto + p.port + (p.end && String(p.end) !== p.port ? '–' + p.end : '');
    }

    function portsText(section) {
        var out = [];
        section.ports.forEach(function (pr) {
            pr.ports.forEach(function (p) {
                out.push(portText(p));
            });
            if (!pr.ports.length && pr.l7.length) out.push('any port');
        });
        section.icmps.forEach(function (i) {
            out.push('ICMP ' + i);
        });
        return out;
    }

    function l7Text(r) {
        if (r.type === 'http') return [r.method || 'any method', r.path || '/*', r.host ? 'on ' + r.host : ''].filter(Boolean).join(' ') + (r.headers ? ' + headers' : '');
        if (r.type === 'dns') return 'DNS ' + r.value;
        if (r.type === 'kafka') return 'Kafka ' + (r.value || 'any');
        return r.value;
    }

    function peerInfo(model, policy, peer) {
        var info = { icon: PEER_ICON[peer.type] || 'info', type: peer.type, title: '', sub: '', count: null, resolved: null };
        switch (peer.type) {
            case 'endpoints': {
                var r = M.resolvePeer(model, policy, peer);
                info.resolved = r;
                info.title = M.isEmptySelector(peer.sel) ? (policy.kind === 'cnp' ? 'every endpoint' : 'every endpoint') : M.selectorText(peer.sel);
                info.count = r.endpoints.length;
                var scope = policy.kind === 'cnp' && !M.namesNamespace(peer.sel) ? 'in ' + policy.namespace : r.namespaces.length ? 'in ' + M.names(r.namespaces, 2) : '';
                info.sub = M.plural(r.endpoints.length, 'endpoint') + (scope ? ' ' + scope : '');
                break;
            }
            case 'k8s': {
                var k = M.resolvePeer(model, policy, peer);
                info.resolved = k;
                var pods = peer.pod ? (M.isEmptySelector(peer.pod) ? 'every pod' : 'pods ' + M.selectorText(peer.pod)) : 'every pod';
                var nss = peer.ns ? (M.isEmptySelector(peer.ns) ? 'every namespace' : 'namespaces ' + M.selectorText(peer.ns)) : 'this namespace';
                info.title = pods;
                info.count = k.endpoints.length;
                info.sub = 'in ' + nss + ' · ' + M.plural(k.endpoints.length, 'endpoint');
                break;
            }
            case 'entity':
                info.title = peer.value;
                info.sub = M.ENTITIES[peer.value] || 'a Cilium entity';
                break;
            case 'cidr':
                info.title = peer.value || '—';
                info.sub = peer.group ? 'CIDR group' : peer.except.length ? 'except ' + peer.except.join(', ') : 'addresses';
                if (peer.group && peer.except.length) info.sub += ' · except ' + peer.except.join(', ');
                break;
            case 'fqdn':
                info.title = peer.value;
                info.sub = peer.pattern ? 'names matching this pattern' : 'this DNS name';
                break;
            case 'service':
                info.title = peer.value;
                info.sub = 'Kubernetes service';
                break;
            case 'nodes': {
                var n = M.resolvePeer(model, policy, peer);
                info.title = M.selectorText(peer.sel, 'every node');
                info.sub = M.plural(n.nodes.length, 'node');
                break;
            }
            case 'group':
                info.title = peer.value + ' group';
                info.sub = peer.detail;
                break;
            default:
                info.title = String(peer.value || peer.type);
        }
        return info;
    }

    function peerPhrase(model, policy, peer) {
        var i = peerInfo(model, policy, peer);
        switch (peer.type) {
            case 'endpoints':
                return M.isEmptySelector(peer.sel) ? 'any endpoint ' + (policy.kind === 'cnp' ? 'in ' + policy.namespace : 'in the cluster') + ' (' + i.count + ')' : 'endpoints with ' + i.title + ' (' + i.sub + ')';
            case 'k8s':
                return i.title + ' ' + i.sub.split(' · ')[0] + ' (' + i.count + ')';
            case 'entity':
                return peer.value + ' — ' + (M.ENTITIES[peer.value] || 'a Cilium entity');
            case 'cidr':
                return (peer.group ? 'the CIDR group ' : '') + peer.value + (peer.except.length ? ' except ' + peer.except.join(', ') : '');
            case 'fqdn':
                return peer.pattern ? 'names matching ' + peer.value : peer.value;
            case 'service':
                return 'the service ' + peer.value;
            case 'nodes':
                return 'nodes with ' + i.title + ' (' + i.sub + ')';
            default:
                return i.title;
        }
    }

    function list(words) {
        if (words.length <= 1) return words.join('');
        return words.slice(0, -1).join(', ') + ' and ' + words[words.length - 1];
    }

    // The policy in sentences, as DOM nodes.
    function explain(model, policy) {
        var out = el('div', 'explain');
        if (policy.valid === false) {
            var bad = el('p');
            add(bad, el('strong', 'bad', 'Cilium rejected this policy'), ', so none of what follows is in force — the endpoints it would select keep whatever other policies give them.');
            out.appendChild(bad);
        }
        policy.rules.forEach(function (rule, ri) {
            var block = el('div', 'explain-rule');
            if (policy.rules.length > 1) block.appendChild(el('h4', '', 'Rule ' + (ri + 1)));
            var first = el('p');
            var kind = policy.kindLabel;
            if (rule.subject.type === 'nodes') {
                add(first, 'This ' + kind + ' is a ', el('strong', '', 'host policy'), ': it applies to ', el('strong', '', M.plural(rule.nodes.length, 'node')), ' with ', el('code', '', M.selectorText(rule.subject.sel, 'any labels')), '.');
            } else {
                var where = policy.kind === 'ccnp' ? 'anywhere in the cluster' : 'in ' + policy.namespace;
                if (rule.selected.length === 0) {
                    add(first, 'This ' + kind + ' ', el('strong', 'bad', 'selects no endpoint'), ' right now: nothing ' + where + ' has ', el('code', '', M.selectorText(rule.subject.sel)), '. Until something does, it has no effect.');
                } else {
                    add(first, 'This ' + kind + ' applies to ', el('strong', '', M.plural(rule.selected.length, 'endpoint')), ' ' + where, M.isEmptySelector(rule.subject.sel) ? ' — all of them' : [' with ', el('code', '', M.selectorText(rule.subject.sel))], '.');
                }
            }
            block.appendChild(first);
            ['in', 'out'].forEach(function (dir) {
                var p = el('p');
                var word = dir === 'in' ? 'Incoming' : 'Outgoing';
                var has = dir === 'in' ? rule.hasIngress : rule.hasEgress;
                var denyAll = dir === 'in' ? rule.denyAllIn : rule.denyAllOut;
                var dd = dir === 'in' ? rule.defaultDeny.ingress : rule.defaultDeny.egress;
                var allows = rule.sections.filter(function (s) {
                    return s.dir === dir && !s.deny && !s.nothing;
                });
                var denies = rule.sections.filter(function (s) {
                    return s.dir === dir && s.deny;
                });
                if (!has) {
                    add(p, el('strong', '', word + ':'), ' not restricted by this policy.');
                    block.appendChild(p);
                    return;
                }
                if (denyAll) {
                    add(p, el('strong', '', word + ':'), ' ', el('strong', 'bad', 'everything is denied'), ' — the policy lists no ' + (dir === 'in' ? 'ingress' : 'egress') + ' rule.');
                    block.appendChild(p);
                    return;
                }
                add(p, el('strong', '', word + ': '));
                if (allows.length) {
                    var clauses = allows.map(function (s) {
                        var who = s.anyPeer ? 'any peer' : list(
                            s.peers.map(function (peer) {
                                return peerPhrase(model, policy, peer);
                            }),
                        );
                        var ports = portsText(s);
                        var l7 = [];
                        s.ports.forEach(function (pr) {
                            pr.l7.forEach(function (r) {
                                l7.push(l7Text(r));
                            });
                        });
                        var text = (dir === 'in' ? 'from ' : 'to ') + who + (ports.length ? ' on ' + list(ports) : '');
                        if (s.requires.length) text += ', if the peer also has ' + s.requires.map(function (r) {
                            return M.selectorText(r);
                        }).join('; ');
                        if (l7.length) text += ' — and only ' + list(l7);
                        if (s.auth) text += ' (mutual authentication ' + s.auth + ')';
                        return text;
                    });
                    add(p, 'allowed ' + clauses.join('; ') + '. ');
                }
                if (denies.length) {
                    var d = denies.map(function (s) {
                        var who = s.anyPeer ? 'any peer' : list(
                            s.peers.map(function (peer) {
                                return peerPhrase(model, policy, peer);
                            }),
                        );
                        var ports = portsText(s);
                        return (dir === 'in' ? 'from ' : 'to ') + who + (ports.length ? ' on ' + list(ports) : '');
                    });
                    add(p, el('strong', 'bad', 'denied'), ' ' + d.join('; ') + ' — a deny wins over any allow, in this policy or another. ');
                }
                if (dd) add(p, allows.length || denies.length ? 'Anything else is dropped, unless another policy allows it.' : 'Nothing is allowed by this rule: it only turns on default deny.');
                else add(p, el('span', 'faint', 'Default deny is switched off for this direction, so traffic no policy mentions still flows.'));
                block.appendChild(p);
            });
            out.appendChild(block);
        });
        if (policy.description && policy.rules.length === 1) {
            var desc = el('p', 'explain-desc');
            add(desc, K.icon('info'), el('span', '', policy.description));
            out.appendChild(desc);
        }
        return out;
    }

    // ----- the diagram ------------------------------------------------------------

    function peerRow(model, policy, peer) {
        var info = peerInfo(model, policy, peer);
        var row = el('div', 'prow t-' + peer.type);
        var badge = el('span', 'ptile');
        badge.appendChild(K.icon(info.icon));
        var text = el('span', 'ptext');
        add(text, el('span', 'ptitle', info.title), el('span', 'psub', info.sub));
        row.title = info.title + ' — ' + info.sub;
        add(row, badge, text);
        if (info.resolved && info.resolved.endpoints.length) {
            var mini = el('span', 'pdots');
            info.resolved.endpoints.slice(0, 6).forEach(function (ep) {
                mini.appendChild(el('i', 'hx e-' + ep.enforcement));
            });
            row.appendChild(mini);
        }
        return row;
    }

    function sectionCard(model, policy, s, i, opts) {
        var card = K.button('', 'pcard ' + (s.dir === 'in' ? 'is-in' : 'is-out') + (s.deny ? ' deny' : '') + (s.nothing ? ' nothing' : ''), null, opts.onSection ? function () {
            opts.onSection(s);
        } : null);
        card.dataset.sid = String(i);
        if (s.deny) {
            var tag = el('span', 'deny-tag');
            add(tag, K.icon('deny'), el('span', '', 'deny'));
            card.appendChild(tag);
        }
        if (s.nothing) {
            add(card, peerRowText('Nobody', 'an empty rule — it only turns on default deny', 'deny'));
        } else if (s.anyPeer) {
            add(card, peerRowText(s.dir === 'in' ? 'Any source' : 'Any destination', 'no peer is named, only ports', 'any'));
        } else {
            var shown = opts.compact ? s.peers.slice(0, 3) : s.peers.slice(0, 6);
            shown.forEach(function (peer) {
                card.appendChild(peerRow(model, policy, peer));
            });
            if (s.peers.length > shown.length) card.appendChild(el('div', 'pmore', '+' + (s.peers.length - shown.length) + ' more'));
        }
        if (s.requires.length) {
            var req = el('div', 'preq');
            add(
                req,
                el('span', 'faint', 'only if also '),
                s.requires.map(function (r) {
                    return K.selectorChip(r);
                }),
            );
            card.appendChild(req);
        }
        var ports = portsText(s);
        var l7 = [];
        s.ports.forEach(function (pr) {
            pr.l7.forEach(function (r) {
                l7.push(r);
            });
        });
        if (ports.length || l7.length || s.auth) {
            var foot = el('div', 'pfoot');
            ports.slice(0, 6).forEach(function (t) {
                foot.appendChild(el('code', 'port', t));
            });
            if (ports.length > 6) foot.appendChild(el('span', 'faint small', '+' + (ports.length - 6)));
            if (s.auth) foot.appendChild(K.chip('mutual auth', 'info', 'lock'));
            card.appendChild(foot);
            if (l7.length) {
                var rules = el('ul', 'l7list');
                l7.slice(0, opts.compact ? 3 : 8).forEach(function (r) {
                    var li = el('li', 'l7-' + r.type);
                    if (r.type === 'http') {
                        add(li, el('span', 'verb', r.method || 'ANY'), el('code', '', (r.host ? r.host : '') + (r.path || '/*')));
                        if (r.headers) li.appendChild(el('span', 'faint small', '+ headers'));
                    } else {
                        add(li, el('span', 'verb', r.type === 'dns' ? 'DNS' : r.type === 'kafka' ? 'KAFKA' : 'L7'), el('code', '', r.value || '*'));
                    }
                    rules.appendChild(li);
                });
                if (l7.length > (opts.compact ? 3 : 8)) rules.appendChild(el('li', 'faint small', '+' + (l7.length - (opts.compact ? 3 : 8)) + ' more rules'));
                card.appendChild(rules);
            }
        }
        return card;
    }

    function peerRowText(title, sub, type) {
        var row = el('div', 'prow t-' + type);
        var badge = el('span', 'ptile');
        badge.appendChild(K.icon(type === 'deny' ? 'deny' : 'world'));
        var text = el('span', 'ptext');
        add(text, el('span', 'ptitle', title), el('span', 'psub', sub));
        add(row, badge, text);
        return row;
    }

    function placeholder(text, tone) {
        return el('div', 'fempty' + (tone ? ' ' + tone : ''), text);
    }

    function subjectCard(model, policy, rule, opts) {
        var box = el('div', 'subject');
        var head = el('div', 'subject-head');
        var hosts = rule.subject.type === 'nodes';
        var n = hosts ? rule.nodes.length : rule.selected.length;
        var tile = el('span', 'subject-tile');
        tile.appendChild(K.icon(hosts ? 'node' : 'shieldCheck'));
        var words = el('div', 'subject-words');
        add(words, el('span', 'subject-label', hosts ? 'Selected nodes' : 'Selected endpoints'), el('span', 'subject-n' + (n ? '' : ' bad'), n ? K.num(n) : 'none'));
        add(head, tile, words);
        box.appendChild(head);
        var where = el('div', 'subject-where');
        add(where, K.selectorChip(rule.subject.sel, hosts ? 'every node' : 'every endpoint'));
        if (!hosts) where.appendChild(el('span', 'faint', policy.kind === 'ccnp' ? 'cluster-wide' : 'in ' + policy.namespace));
        box.appendChild(where);
        if (hosts) {
            var nl = el('div', 'subject-nodes');
            rule.nodes.slice(0, 8).forEach(function (node) {
                nl.appendChild(K.chip(node.name, 'muted', 'node'));
            });
            if (rule.nodes.length > 8) nl.appendChild(el('span', 'faint small', '+' + (rule.nodes.length - 8)));
            box.appendChild(nl);
        } else if (rule.selected.length) {
            box.appendChild(K.miniHexes(rule.selected, { cols: opts.compact ? 12 : 11, max: opts.compact ? 36 : 55 }));
            var nss = {};
            rule.selected.forEach(function (ep) {
                nss[ep.namespace] = (nss[ep.namespace] || 0) + 1;
            });
            if (policy.kind === 'ccnp') box.appendChild(el('div', 'faint small', 'in ' + M.names(Object.keys(nss).sort(), 3)));
        } else {
            box.appendChild(el('div', 'subject-none', 'No endpoint has these labels, so this rule does nothing yet.'));
        }
        var dd = el('div', 'subject-dd');
        if (policy.valid === false) {
            dd.appendChild(K.chip('not in force — invalid', 'error', 'alert'));
        } else {
            dd.appendChild(ddChip('in', rule));
            dd.appendChild(ddChip('out', rule));
        }
        box.appendChild(dd);
        return box;
    }

    function ddChip(dir, rule) {
        var has = dir === 'in' ? rule.hasIngress : rule.hasEgress;
        var on = dir === 'in' ? rule.defaultDeny.ingress : rule.defaultDeny.egress;
        var word = dir === 'in' ? 'Ingress' : 'Egress';
        if (!has) return K.chip(word + ' open', 'muted', 'unlock', 'This policy does not restrict ' + word.toLowerCase());
        if (!on) return K.chip(word + ': no default deny', 'warn', 'unlock', 'enableDefaultDeny is false: only what other rules deny is dropped');
        return K.chip(word + ' default deny', 'ok', 'lock', 'Only what the rules allow gets through');
    }

    // One rule as a flow. Returns { node, redraw }; call redraw once the node
    // is in the page, and whenever its size changes.
    function diagram(model, policy, rule, opts) {
        opts = opts || {};
        var wrap = el('div', 'flow' + (opts.compact ? ' compact' : ''));
        var wires = K.svg('svg', { class: 'fwires', 'aria-hidden': 'true' });
        wrap.appendChild(wires);
        var labels = el('div', 'flabels');
        wrap.appendChild(labels);

        var colIn = el('div', 'fcol fcol-in');
        var colMid = el('div', 'fcol fcol-mid');
        var colOut = el('div', 'fcol fcol-out');
        colIn.appendChild(colHead('From', 'who may connect in'));
        colOut.appendChild(colHead('To', 'where they may connect'));
        colMid.appendChild(colHead(rule.subject.type === 'nodes' ? 'Host policy' : 'Policy applies to', ''));

        var ins = [];
        var outs = [];
        rule.sections.forEach(function (s, i) {
            var card = sectionCard(model, policy, s, i, opts);
            if (s.dir === 'in') {
                colIn.appendChild(card);
                ins.push({ card: card, s: s });
            } else {
                colOut.appendChild(card);
                outs.push({ card: card, s: s });
            }
        });
        if (!ins.length) colIn.appendChild(rule.denyAllIn ? placeholder('No ingress rule — all incoming traffic is denied', 'deny') : rule.hasIngress ? placeholder('Nothing allowed in') : placeholder('Ingress is not restricted by this policy'));
        if (!outs.length) colOut.appendChild(rule.denyAllOut ? placeholder('No egress rule — all outgoing traffic is denied', 'deny') : rule.hasEgress ? placeholder('Nothing allowed out') : placeholder('Egress is not restricted by this policy'));
        var subject = subjectCard(model, policy, rule, opts);
        colMid.appendChild(subject);
        add(wrap, colIn, colMid, colOut);

        function redraw() {
            wires.textContent = '';
            labels.textContent = '';
            var box = wrap.getBoundingClientRect();
            if (!box.width) return;
            wires.setAttribute('width', String(box.width));
            wires.setAttribute('height', String(box.height));
            wires.setAttribute('viewBox', '0 0 ' + box.width + ' ' + box.height);
            var sb = subject.getBoundingClientRect();
            var sTop = sb.top - box.top;
            var sLeft = sb.left - box.left;
            var sRight = sb.right - box.left;
            var sH = sb.height;

            function ports(items, side) {
                // Where each wire meets the subject: spread over its middle.
                var n = items.length;
                return items.map(function (item, i) {
                    var y = sTop + sH * (n === 1 ? 0.5 : 0.25 + (0.5 * i) / (n - 1));
                    return { item: item, x: side === 'in' ? sLeft : sRight, y: y };
                });
            }
            function wire(x1, y1, x2, y2, s) {
                var bend = Math.max(20, (x2 - x1) / 2);
                var d = 'M' + x1 + ' ' + y1 + ' C' + (x1 + bend) + ' ' + y1 + ' ' + (x2 - bend) + ' ' + y2 + ' ' + x2 + ' ' + y2;
                var cls = 'fwire' + (s.deny ? ' deny' : '') + (s.nothing ? ' nothing' : '') + (s.dir === 'in' ? ' in' : ' out');
                wires.appendChild(K.svg('path', { d: d, class: cls + ' under' }));
                wires.appendChild(K.svg('path', { d: d, class: cls }));
                // An arrowhead where the traffic arrives.
                var ax = x2;
                var ay = y2;
                wires.appendChild(K.svg('path', { d: 'M' + (ax - 7) + ' ' + (ay - 4.5) + ' L' + ax + ' ' + ay + ' L' + (ax - 7) + ' ' + (ay + 4.5), class: 'fhead' + (s.deny ? ' deny' : '') }));
                var text = portsText(s);
                var first = text.length ? text[0] + (text.length > 1 ? ' +' + (text.length - 1) : '') : s.deny ? 'all' : 'any port';
                var label = s.nothing ? '' : (s.deny ? '✕ ' : '') + first;
                if (!label || opts.compact) return;
                // The bezier's midpoint, nudged down past a label already there.
                var mx = (x1 + x2) / 2;
                var my = (y1 + y2) / 2;
                var side = s.dir;
                placed.forEach(function (p) {
                    if (p.side === side && Math.abs(p.y - my) < 20) my = p.y + 20;
                });
                placed.push({ side: side, y: my });
                var pill = el('span', 'flabel' + (s.deny ? ' deny' : ''), label);
                pill.title = (s.deny ? 'deny ' : '') + text.join(', ');
                pill.style.left = mx + 'px';
                pill.style.top = my + 'px';
                labels.appendChild(pill);
            }
            var placed = [];
            ports(ins, 'in').forEach(function (p) {
                var r = p.item.card.getBoundingClientRect();
                wire(r.right - box.left, r.top - box.top + Math.min(r.height / 2, 30), p.x, p.y, p.item.s);
            });
            ports(outs, 'out').forEach(function (p) {
                var r = p.item.card.getBoundingClientRect();
                wire(p.x, p.y, r.left - box.left, r.top - box.top + Math.min(r.height / 2, 30), p.item.s);
            });
        }

        if (typeof ResizeObserver === 'function') {
            var ro = new ResizeObserver(function () {
                redraw();
            });
            ro.observe(wrap);
        }
        return { node: wrap, redraw: redraw };
    }

    // The same policy as lines, for a narrow panel: what it selects, then one
    // line per rule section, in and out.
    function compact(model, policy) {
        var box = el('div', 'cflow');
        policy.rules.forEach(function (rule, ri) {
            var block = el('div', 'crule');
            var subj = el('div', 'cline subj');
            var hosts = rule.subject.type === 'nodes';
            var n = hosts ? rule.nodes.length : rule.selected.length;
            add(subj, el('span', 'cdir', policy.rules.length > 1 ? 'Rule ' + (ri + 1) : 'Selects'), K.selectorChip(rule.subject.sel, hosts ? 'every node' : 'every endpoint'), el('span', 'ccount' + (n ? '' : ' bad'), hosts ? M.plural(n, 'node') : M.plural(n, 'endpoint')));
            if (!hosts && n) subj.appendChild(K.miniHexes(rule.selected, { cols: 18, max: 18 }));
            block.appendChild(subj);
            ['in', 'out'].forEach(function (dir) {
                var has = dir === 'in' ? rule.hasIngress : rule.hasEgress;
                var denyAll = dir === 'in' ? rule.denyAllIn : rule.denyAllOut;
                var secs = rule.sections.filter(function (s) {
                    return s.dir === dir;
                });
                if (!has) {
                    var open = el('div', 'cline quiet');
                    add(open, el('span', 'cdir ' + dir, dir === 'in' ? '↘ In' : '↗ Out'), el('span', 'faint', 'not restricted by this policy'));
                    block.appendChild(open);
                    return;
                }
                if (denyAll || !secs.length) {
                    var none = el('div', 'cline deny');
                    add(none, el('span', 'cdir ' + dir, dir === 'in' ? '↘ In' : '↗ Out'), el('span', 'bad-text', 'everything denied'));
                    block.appendChild(none);
                    return;
                }
                secs.forEach(function (s) {
                    var line = el('div', 'cline' + (s.deny ? ' deny' : ''));
                    add(line, el('span', 'cdir ' + dir, dir === 'in' ? '↘ In' : '↗ Out'));
                    if (s.deny) line.appendChild(el('span', 'deny-tag small', 'deny'));
                    var who = el('span', 'cwho');
                    if (s.nothing) who.appendChild(el('span', 'faint', 'nobody — default deny only'));
                    else if (s.anyPeer) who.appendChild(el('span', '', 'anyone'));
                    s.peers.slice(0, 4).forEach(function (peer) {
                        var info = peerInfo(model, policy, peer);
                        var c = el('span', 'cpeer t-' + peer.type);
                        add(c, K.icon(info.icon), el('span', '', info.title));
                        if (info.count !== null) c.appendChild(el('span', 'faint', ' ' + info.count));
                        c.title = info.title + ' — ' + info.sub;
                        who.appendChild(c);
                    });
                    if (s.peers.length > 4) who.appendChild(el('span', 'faint', '+' + (s.peers.length - 4) + ' more'));
                    line.appendChild(who);
                    var ports = portsText(s);
                    ports.slice(0, 3).forEach(function (t) {
                        line.appendChild(el('code', 'port', t));
                    });
                    if (ports.length > 3) line.appendChild(el('span', 'faint small', '+' + (ports.length - 3)));
                    s.ports.forEach(function (pr) {
                        pr.l7.slice(0, 2).forEach(function (r) {
                            line.appendChild(el('code', 'port l7', l7Text(r)));
                        });
                        if (pr.l7.length > 2) line.appendChild(el('span', 'faint small', '+' + (pr.l7.length - 2) + ' more'));
                    });
                    block.appendChild(line);
                });
            });
            box.appendChild(block);
        });
        return box;
    }

    function colHead(title, hint) {
        var head = el('div', 'fcol-head');
        add(head, el('span', 'fcol-title', title));
        if (hint) head.appendChild(el('span', 'fcol-hint', hint));
        return head;
    }

    window.CiliumFlow = {
        diagram: diagram,
        compact: compact,
        explain: explain,
        portsText: portsText,
        peerInfo: peerInfo,
        peerPhrase: peerPhrase,
        l7Text: l7Text,
    };
})();
