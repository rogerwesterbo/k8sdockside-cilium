// Cilium's own overview, in place of the page the app generates for every
// plugin. It answers what the generated one does -- is this even installed
// here? -- and then what that page cannot: whether every node's agent is up,
// how much of the cluster is actually under policy, how the datapath is set
// up, what needs attention, and what Cilium has been doing lately.
(function () {
    'use strict';

    var sdk = window.k8sdockside;
    var M = window.Cilium;
    var K = window.CiliumKit;
    var el = K.el;
    var add = K.add;

    var POLL = 5000;
    var EVENTS_EVERY = 15000;
    var SUMMARY_EVERY = 30000;
    var CHARTS_EVERY = 60000;
    var HISTORY_MINUTES = 360;
    var MAX_NODES = 36;
    var MAX_SERIES = 5;

    var state = {
        ctx: null,
        model: null,
        sig: '',
        summary: null,
        panel: null,
        events: null,
        error: '',
    };

    var $ = function (id) {
        return document.getElementById(id);
    };

    function fail(err) {
        state.error = (err && err.message) || String(err);
        $('error').textContent = state.error;
        $('error').hidden = false;
    }

    function clearError() {
        state.error = '';
        $('error').hidden = true;
    }

    function open(ref) {
        sdk.open(ref).catch(fail);
    }

    function openView(id) {
        sdk.openView(id).catch(fail);
    }

    var plural = M.plural;

    function b(text, className) {
        return el('strong', className || '', text);
    }

    // ----- the hero ----------------------------------------------------------

    function issues(model) {
        return model.findings.filter(function (f) {
            return f.tone === 'error' || f.tone === 'warn';
        });
    }

    function verdict(model, found) {
        var errors = found.filter(function (f) {
            return f.tone === 'error';
        }).length;
        var nodes = model.nodes.filter(function (n) {
            return n.obj;
        }).length;
        if (found.length === 0) {
            return { tone: 'ok', icon: 'check', text: nodes ? 'Cilium is healthy on ' + (nodes === 1 ? 'the one node' : nodes === 2 ? 'both nodes' : 'all ' + nodes + ' nodes') : 'Cilium is healthy' };
        }
        return { tone: errors ? 'error' : 'warn', icon: 'alert', text: plural(found.length, 'thing needs', 'things need') + ' attention' };
    }

    function story(model) {
        var p = el('p', 'ov-story');
        var cov = model.coverage;
        var enforced = cov.total ? (cov.total - cov.none) / cov.total : 0;
        var nodes = model.nodes.filter(function (n) {
            return n.obj;
        }).length;
        add(p, 'Networking ', b(plural(cov.total, 'endpoint')), ' on ', b(plural(nodes, 'node')), ' with ', b(plural(model.identityCount, 'security identity', 'security identities')), '. ');
        if (cov.total) {
            add(p, b(M.percent(enforced), enforced < 0.5 ? 'warnish' : ''), ' of endpoints are under a policy that is enforced');
            if (cov.none) add(p, ' — the other ', b(K.num(cov.none)), ' accept anything');
            add(p, '. ');
        }
        if (model.config.ok) {
            var routing = M.feature(model, 'routing');
            var kpr = M.feature(model, 'kpr');
            var enc = M.feature(model, 'encryption');
            var parts = [];
            if (routing) parts.push(['Pods are routed ', b(routing.value === 'Native' ? 'natively' : 'through a ' + routing.value.replace('Tunnel · ', '') + ' tunnel')]);
            if (kpr) parts.push([', services by ', b(kpr.on ? 'eBPF instead of kube-proxy' : kpr.value === 'Partial' ? 'eBPF and kube-proxy' : 'kube-proxy')]);
            if (enc) parts.push([', and traffic between nodes is ', enc.on ? b('encrypted with ' + enc.value) : b('not encrypted', 'warnish')]);
            parts.forEach(function (part) {
                add(p, part);
            });
            if (parts.length) add(p, '.');
        }
        return p;
    }

    var LENSES = [
        { id: 'both', label: 'Ingress + egress', cls: 'e-both' },
        { id: 'ingress', label: 'Ingress only', cls: 'e-ingress' },
        { id: 'egress', label: 'Egress only', cls: 'e-egress' },
        { id: 'none', label: 'Not enforced', cls: 'e-none' },
    ];

    var LENS_COLOR = {
        both: 'var(--c-both)',
        ingress: 'var(--c-ingress)',
        egress: 'var(--c-egress)',
        none: 'var(--c-none-strong)',
    };

    function coverage(model) {
        var cov = model.coverage;
        var side = el('div', 'ov-hero-side');
        var orbit = el('div', 'ov-orbit');
        var slices = LENSES.map(function (l) {
            return { value: cov[l.id], color: LENS_COLOR[l.id], label: l.label };
        });
        var enforced = cov.total ? (cov.total - cov.none) / cov.total : 0;
        orbit.appendChild(K.donut(slices, 232, 20, M.percent(enforced) + ' of endpoints under enforced policy'));
        var centre = el('div', 'ov-centre');
        add(centre, el('div', 'ov-centre-big', cov.total ? M.percent(enforced) : '—'), el('div', 'ov-centre-small', 'under policy'));
        orbit.appendChild(centre);
        side.appendChild(orbit);

        var legend = el('ul', 'ov-legend');
        legend.appendChild(el('li', 'ov-legend-title', 'Policy enforcement per endpoint'));
        LENSES.forEach(function (l) {
            var item = el('li');
            var row = K.button('', 'ov-legend-row', null, function () {
                openView('endpoints');
            });
            var sw = el('i', 'hx ' + l.cls);
            var n = cov[l.id];
            row.title = n + ' endpoints — open the endpoint map';
            add(row, sw, el('span', 'ov-legend-name', l.label), el('span', 'ov-legend-num', K.num(n)), el('span', 'ov-legend-pct', cov.total ? M.percent(n / cov.total) : '—'));
            item.appendChild(row);
            legend.appendChild(item);
        });
        side.appendChild(legend);
        return side;
    }

    function drawHero(model) {
        var hero = $('hero');
        hero.textContent = '';
        var found = issues(model);
        var v = verdict(model, found);
        hero.className = 'ov-hero ' + v.tone;

        var main = el('div', 'ov-hero-main');
        var eyebrow = el('div', 'ov-eyebrow');
        add(eyebrow, K.logo(), el('span', '', 'Cilium' + (model.version ? ' ' + model.version : '')), el('span', 'faint', '· ' + state.ctx.contextName + ' · ' + model.namespace));
        main.appendChild(eyebrow);

        var head = el('h1', 'ov-verdict ' + v.tone);
        add(head, K.icon(v.icon), el('span', '', v.text));
        main.appendChild(head);
        main.appendChild(story(model));

        var cta = el('div', 'ov-cta');
        add(
            cta,
            K.button('Open the endpoint map', 'primary', 'map', function () {
                openView('endpoints');
            }),
            K.button('Policy map', 'ghost', 'shield', function () {
                openView('policy-map');
            }),
            K.button('Nodes & addresses', 'ghost', 'node', function () {
                openView('network');
            }),
        );
        main.appendChild(cta);
        hero.appendChild(main);
        if (model.coverage.total) hero.appendChild(coverage(model));
    }

    // ----- the datapath ------------------------------------------------------

    function drawDatapath(model) {
        var box = $('datapath');
        box.textContent = '';
        box.hidden = false;
        var head = el('div', 'ov-section-head');
        add(head, K.icon('chip'), el('h2', '', 'Datapath'));
        if (model.config.ok) {
            var src = el('span', 'ov-head-note');
            add(
                src,
                'from ',
                K.link(M.CONFIG_NAME, function () {
                    open({ kind: M.KINDS.configmaps, namespace: model.namespace, name: M.CONFIG_NAME });
                }),
                ' in ' + model.namespace,
            );
            head.appendChild(src);
        }
        box.appendChild(head);
        if (!model.config.ok) {
            var warn = el('div', 'ov-note warn');
            add(warn, K.icon('alert'), el('span', '', 'The ' + M.CONFIG_NAME + ' ConfigMap in ' + model.namespace + ' could not be read (' + model.config.error + '). What follows is what the cluster’s objects give away.'));
            box.appendChild(warn);
        }
        var grid = el('div', 'dp-grid');
        model.features.forEach(function (f) {
            var tone = f.on === true ? 'on' : f.on === false ? 'off' : 'unknown';
            var tile = el('div', 'dp-tile ' + tone + ' f-' + f.id);
            var badge = el('span', 'dp-icon');
            badge.appendChild(K.icon(f.icon));
            var words = el('div', 'dp-words');
            add(words, el('span', 'dp-label', f.label), el('span', 'dp-value', f.value), el('span', 'dp-detail', f.detail));
            tile.title = f.label + ': ' + f.value + (f.detail ? ' — ' + f.detail : '');
            add(tile, badge, words);
            grid.appendChild(tile);
        });
        box.appendChild(grid);
    }

    // ----- the path ----------------------------------------------------------

    function stage(tone, iconName, label, big, small, onClick) {
        var node = K.button('', 'ov-stage ' + tone, null, onClick);
        var badge = el('span', 'ov-stage-icon');
        badge.appendChild(K.icon(iconName));
        add(node, badge, el('span', 'ov-stage-label', label), el('span', 'ov-stage-big', big), el('span', 'ov-stage-small', small));
        node.title = label + ': ' + big + ' — ' + small;
        return node;
    }

    function wire(tone) {
        var node = el('div', 'ov-link ' + tone);
        var svg = K.svg('svg', { viewBox: '0 0 60 12', preserveAspectRatio: 'none', 'aria-hidden': 'true' });
        svg.appendChild(K.svg('line', { x1: 0, y1: 6, x2: 60, y2: 6, class: 'ov-link-track' }));
        svg.appendChild(K.svg('line', { x1: 0, y1: 6, x2: 60, y2: 6, class: 'ov-link-flow' }));
        node.appendChild(svg);
        return node;
    }

    function drawPath(model) {
        var box = $('path');
        box.textContent = '';
        box.hidden = false;
        var agent = model.components.agent;
        var operator = model.components.operator;
        var nodes = model.nodes.filter(function (n) {
            return n.obj;
        });
        var missing = model.agentsKnown
            ? nodes.filter(function (n) {
                  return !n.agent;
              }).length
            : 0;
        var cov = model.coverage;
        var enforced = cov.total ? (cov.total - cov.none) / cov.total : 0;
        var invalid = model.policies.filter(function (p) {
            return p.valid === false;
        }).length;
        var idle = model.policies.filter(function (p) {
            return p.selected.length === 0 && p.nodes.length === 0;
        }).length;
        var open = model.namespaces.filter(function (ns) {
            return ns.open;
        }).length;
        var pc = model.policyCounts;

        var agentDown = agent.total - agent.ready;
        var steps = [
            agent.total
                ? stage(agentDown || missing ? 'error' : 'ok', 'node', 'Agents', K.num(agent.ready) + ' / ' + K.num(agent.total + missing), agentDown ? agentDown + ' not ready' : missing ? missing + ' node' + (missing === 1 ? '' : 's') + ' without one' : 'ready on every node', function () {
                      openView('agents');
                  })
                : stage('muted', 'node', 'Agents', '—', 'no agent pods found', function () {
                      openView('agents');
                  }),
            operator.total
                ? stage(operator.ready ? 'ok' : 'error', 'operator', 'Operator', operator.ready + ' / ' + operator.total, operator.ready ? (operator.total > 1 ? 'one leads, ' + (operator.total - 1) + ' stand by' : 'ready') : 'not ready', function () {
                      openView('operator');
                  })
                : stage('warn', 'operator', 'Operator', '—', 'no operator pods found', function () {
                      openView('operator');
                  }),
            stage(model.notReady.length ? 'warn' : cov.total ? 'ok' : 'muted', 'hex', 'Endpoints', K.num(cov.total - model.notReady.length) + ' / ' + K.num(cov.total), model.notReady.length ? model.notReady.length + ' not ready' : cov.total ? 'all ready' : 'no endpoints yet', function () {
                openView('endpoints');
            }),
            stage(model.identityCount ? 'ok' : 'muted', 'tag', 'Identities', K.num(model.identityCount), 'for ' + plural(cov.total, 'endpoint'), function () {
                openView('identities');
            }),
            stage(invalid ? 'error' : idle ? 'warn' : pc.total ? 'ok' : 'muted', 'shield', 'Policies', K.num(pc.total), invalid ? invalid + ' invalid' : idle ? idle + ' select nothing' : [pc.cnp ? pc.cnp + ' CNP' : '', pc.ccnp ? pc.ccnp + ' CCNP' : '', pc.knp ? pc.knp + ' K8s' : ''].filter(Boolean).join(' · ') || 'none — all allowed', function () {
                openView('policy-map');
            }),
            stage(!cov.total ? 'muted' : open ? 'warn' : 'ok', 'shieldCheck', 'Enforced', cov.total ? M.percent(enforced) : '—', open ? plural(open, 'namespace') + ' open' : cov.both + ' both ways · ' + (cov.ingress + cov.egress) + ' one way', function () {
                openView('endpoints');
            }),
        ];
        steps.forEach(function (s, i) {
            if (i > 0) {
                var next = s.classList.contains('error') ? 'error' : s.classList.contains('warn') ? 'warn' : s.classList.contains('muted') ? 'muted' : 'ok';
                box.appendChild(wire(next));
            }
            box.appendChild(s);
        });
    }

    // ----- the nodes ----------------------------------------------------------

    function drawNodes(model) {
        var box = $('nodes');
        box.textContent = '';
        var nodes = model.nodes.filter(function (n) {
            return n.obj;
        });
        box.hidden = nodes.length === 0;
        if (box.hidden) return;
        var head = el('div', 'ov-section-head');
        var up = nodes.filter(function (n) {
            return M.nodeTone(model, n) === 'ok';
        }).length;
        add(
            head,
            K.icon('node'),
            el('h2', '', 'Nodes'),
            el('span', 'ov-head-note', up + ' of ' + nodes.length + ' healthy'),
            K.button('Nodes & addresses', 'ghost small push', 'arrow', function () {
                openView('network');
            }),
        );
        box.appendChild(head);

        var rank = { error: 0, warn: 1, muted: 2, ok: 3 };
        var shown = nodes.slice();
        if (shown.length > MAX_NODES) {
            shown.sort(function (a, b) {
                return rank[M.nodeTone(model, a)] - rank[M.nodeTone(model, b)] || a.name.localeCompare(b.name);
            });
            shown = shown.slice(0, MAX_NODES - 1);
        }
        var strip = el('div', 'nstrip');
        var maxEp = Math.max.apply(
            null,
            nodes.map(function (n) {
                return n.endpoints;
            }).concat([1]),
        );
        shown.forEach(function (n) {
            var tone = M.nodeTone(model, n);
            var tile = K.button('', 'ntile ' + tone, null, function () {
                open({ kind: M.KINDS.nodes, namespace: '', name: n.name });
            });
            var top = el('span', 'ntile-top');
            add(top, K.dot(tone), el('span', 'ntile-name', n.name));
            if (n.roles.indexOf('control-plane') >= 0) top.appendChild(el('span', 'ntile-role', 'cp'));
            tile.appendChild(top);
            var agentText = !n.agent ? (model.agentsKnown ? 'no agent' : 'agent unknown') : n.agentReady ? (n.agentRestarts ? 'agent ready · ' + n.agentRestarts + '↻' : 'agent ready') : n.agentTrouble || 'agent not ready';
            tile.appendChild(el('span', 'ntile-agent ' + (n.agent && !n.agentReady ? 'bad' : ''), agentText));
            var eps = el('span', 'ntile-eps');
            add(eps, el('strong', '', K.num(n.endpoints)), el('span', 'faint', n.endpoints === 1 ? ' endpoint' : ' endpoints'));
            if (n.notReady) eps.appendChild(el('span', 'ntile-warn', ' · ' + n.notReady + ' not ready'));
            tile.appendChild(eps);
            tile.appendChild(K.meter(n.endpoints / maxEp, 'accent'));
            var foot = el('span', 'ntile-foot');
            if (n.podCIDRs.length) foot.appendChild(el('code', '', n.podCIDRs[0] + (n.podCIDRs.length > 1 ? ' +' + (n.podCIDRs.length - 1) : '')));
            if (n.zone) foot.appendChild(el('span', 'faint', n.zone));
            tile.appendChild(foot);
            tile.title = n.name + ' — ' + agentText + (n.internalIP ? ' · ' + n.internalIP : '');
            strip.appendChild(tile);
        });
        if (nodes.length > shown.length) {
            var more = K.button('', 'ntile more', null, function () {
                openView('network');
            });
            add(more, el('span', 'ntile-big', '+' + (nodes.length - shown.length)), el('span', 'faint', 'more nodes'));
            strip.appendChild(more);
        }
        box.appendChild(strip);
    }

    // ----- attention and activity --------------------------------------------

    function drawAttention(model) {
        var box = $('attention');
        box.textContent = '';
        var found = issues(model);
        var head = el('div', 'ov-card-head');
        add(head, K.icon(found.length ? 'alert' : 'check'), el('h2', '', found.length ? 'Needs attention' : 'All clear'));
        if (found.length) head.appendChild(el('span', 'count ' + (found.some(function (f) {
            return f.tone === 'error';
        }) ? 'error' : 'warn'), String(found.length)));
        box.appendChild(head);
        box.className = 'ov-card' + (found.length ? '' : ' clear');

        if (found.length === 0) {
            box.appendChild(el('p', 'ov-quiet', 'Every agent is ready, every endpoint is ready, every policy is valid and selects something, and no namespace is left without a policy.'));
            var infos = model.findings.filter(function (f) {
                return f.tone === 'info';
            });
            if (infos.length) box.appendChild(el('p', 'ov-quiet faint', infos[0].title + ' — ' + infos[0].text));
            return;
        }
        var list = el('ul', 'ov-issues');
        found.slice(0, 7).forEach(function (f) {
            var item = el('li', 'ov-issue ' + f.tone);
            var mark = el('span', 'ov-issue-icon');
            mark.appendChild(K.icon(f.icon || 'alert'));
            item.appendChild(mark);
            var body = el('div');
            add(body, el('div', 'ov-issue-title', f.title), el('div', 'ov-issue-text', f.text));
            item.appendChild(body);
            var tools = el('div', 'ov-issue-tools');
            if (f.logs) {
                tools.appendChild(
                    K.iconButton('logs', 'Logs', function () {
                        sdk.logs(f.logs).catch(fail);
                    }),
                );
            }
            if (f.view || f.policy) {
                tools.appendChild(
                    K.iconButton(f.policy ? 'shield' : 'map', f.policy ? 'Show in the policy map' : 'Show', function () {
                        openView(f.policy ? 'policy-map' : f.view);
                    }),
                );
            }
            if (f.ref) {
                tools.appendChild(
                    K.iconButton('open', 'Open', function () {
                        open(f.ref);
                    }),
                );
            }
            item.appendChild(tools);
            list.appendChild(item);
        });
        box.appendChild(list);
        if (found.length > 7) box.appendChild(el('p', 'ov-quiet faint', 'and ' + (found.length - 7) + ' more.'));
    }

    function eventIcon(ev) {
        if (ev.type === 'Warning') return 'alert';
        if (/Policy/.test(ev.kind)) return 'shield';
        if (ev.kind === 'Pod') return 'pod';
        if (ev.kind === 'Node' || ev.kind === 'CiliumNode') return 'node';
        return 'activity';
    }

    function drawActivity() {
        var box = $('activity');
        box.textContent = '';
        var head = el('div', 'ov-card-head');
        add(head, K.icon('activity'), el('h2', '', 'Recent activity'));
        box.appendChild(head);

        if (state.events === null) {
            box.appendChild(el('p', 'ov-quiet', 'Reading events…'));
            return;
        }
        if (state.events.length === 0) {
            box.appendChild(el('p', 'ov-quiet', 'Nothing from Cilium lately. Kubernetes keeps events for about an hour, so a quiet cluster reads as an empty list — Hubble is where flows are.'));
            return;
        }
        var list = el('ol', 'ov-timeline');
        state.events.slice(0, 9).forEach(function (ev) {
            var item = el('li', 'ov-event' + (ev.type === 'Warning' ? ' warn' : ''));
            var mark = el('span', 'ov-event-mark');
            mark.appendChild(K.icon(eventIcon(ev)));
            item.appendChild(mark);
            var body = el('div', 'ov-event-body');
            var line = el('div', 'ov-event-line');
            var who = (ev.namespace ? ev.namespace + '/' : '') + ev.name;
            add(
                line,
                ev.appKind
                    ? K.link(who, function () {
                          open({ kind: ev.appKind, namespace: ev.namespace, name: ev.name });
                      })
                    : el('strong', '', who),
                ' ',
                el('span', '', ev.message),
            );
            body.appendChild(line);
            body.appendChild(el('div', 'ov-event-meta', [K.ago(ev.when), ev.count > 1 ? ev.count + '×' : '', ev.reason, ev.kind].filter(Boolean).join(' · ')));
            item.appendChild(body);
            list.appendChild(item);
        });
        box.appendChild(list);
    }

    // ----- history -----------------------------------------------------------

    function formatValue(v, unit) {
        if (!isFinite(v)) return '—';
        if (unit === 'percent') return (Math.round(v * 1000) / 10).toLocaleString() + '%';
        if (unit === 'count') return Math.round(v).toLocaleString();
        var text = Math.abs(v) >= 100 ? Math.round(v).toLocaleString() : String(Math.round(v * 100) / 100);
        return unit === 'ops/s' ? text + '/s' : text;
    }

    // Busy charts keep their biggest series and fold the rest into one.
    function fold(series) {
        if (series.length <= MAX_SERIES) return series;
        var last = function (s) {
            var p = s.points[s.points.length - 1];
            return p && isFinite(p.v) ? p.v : 0;
        };
        var sorted = series.slice().sort(function (a, b) {
            return last(b) - last(a);
        });
        var keep = sorted.slice(0, MAX_SERIES - 1);
        var rest = sorted.slice(MAX_SERIES - 1);
        var sums = {};
        rest.forEach(function (s) {
            s.points.forEach(function (p) {
                if (isFinite(p.v)) sums[p.t] = (sums[p.t] || 0) + p.v;
            });
        });
        var points = Object.keys(sums)
            .map(Number)
            .sort(function (a, b) {
                return a - b;
            })
            .map(function (t) {
                return { t: t, v: sums[t] };
            });
        return keep.concat([{ name: rest.length + ' others', points: points }]);
    }

    function sparkChart(chart) {
        var card = el('article', 'ov-chart');
        var head = el('div', 'ov-chart-head');
        head.appendChild(el('h3', '', chart.label));
        if (chart.description) head.title = chart.description;
        card.appendChild(head);

        var series = fold(
            chart.series.filter(function (s) {
                return s.points.length > 0;
            }),
        );
        if (chart.error || series.length === 0) {
            card.appendChild(el('p', 'ov-quiet', chart.error || 'No data for this window. ' + (chart.description || '')));
            return card;
        }

        var minT = Infinity;
        var maxT = -Infinity;
        var maxV = 0;
        series.forEach(function (s) {
            s.points.forEach(function (p) {
                minT = Math.min(minT, p.t);
                maxT = Math.max(maxT, p.t);
                if (isFinite(p.v)) maxV = Math.max(maxV, p.v);
            });
        });
        if (maxT === minT) maxT = minT + 1;
        var top = chart.unit === 'percent' ? Math.max(1, maxV * 1.1) : maxV > 0 ? maxV * 1.15 : 1;
        var W = 600;
        var H = 140;
        var x = function (t) {
            return ((t - minT) / (maxT - minT)) * W;
        };
        var y = function (v) {
            return H - (v / top) * H;
        };
        var step = (maxT - minT) / 60;

        var svg = K.svg('svg', { viewBox: '0 0 ' + W + ' ' + H, preserveAspectRatio: 'none', class: 'ov-spark' });
        [0.25, 0.5, 0.75].forEach(function (f) {
            svg.appendChild(K.svg('line', { x1: 0, x2: W, y1: H * f, y2: H * f, class: 'ov-grid' }));
        });
        series.forEach(function (s, i) {
            var runs = [];
            var run = [];
            s.points.forEach(function (p, j) {
                var gapHere = j > 0 && p.t - s.points[j - 1].t > step * 3;
                if (!isFinite(p.v) || gapHere) {
                    if (run.length) runs.push(run);
                    run = [];
                    if (!isFinite(p.v)) return;
                }
                run.push(p);
            });
            if (run.length) runs.push(run);
            var colour = K.chart(i);
            runs.forEach(function (r) {
                var line = r
                    .map(function (p, j) {
                        return (j ? 'L' : 'M') + x(p.t).toFixed(1) + ' ' + y(p.v).toFixed(1);
                    })
                    .join(' ');
                var area = line + ' L' + x(r[r.length - 1].t).toFixed(1) + ' ' + H + ' L' + x(r[0].t).toFixed(1) + ' ' + H + ' Z';
                var fill = K.svg('path', { d: area, class: 'ov-area' });
                fill.style.fill = colour;
                svg.appendChild(fill);
                var stroke = K.svg('path', { d: line, class: 'ov-line' });
                stroke.style.stroke = colour;
                svg.appendChild(stroke);
            });
        });
        card.appendChild(svg);

        var legend = el('div', 'ov-chart-legend');
        series.forEach(function (s, i) {
            var last = s.points[s.points.length - 1];
            var key = el('span', 'ov-chart-key');
            var d = el('i', 'dot');
            d.style.background = K.chart(i);
            add(key, d, el('span', 'ov-chart-name', s.name || chart.label), el('strong', '', formatValue(last.v, chart.unit)));
            key.title = (s.name || chart.label) + ': ' + formatValue(last.v, chart.unit);
            legend.appendChild(key);
        });
        card.appendChild(legend);
        return card;
    }

    function drawHistory() {
        var box = $('history');
        box.textContent = '';
        var panel = state.panel;
        box.hidden = !panel || !panel.attached;
        if (box.hidden) return;
        var head = el('div', 'ov-section-head');
        add(head, K.icon('chart'), el('h2', '', 'Over the last ' + Math.round(HISTORY_MINUTES / 60) + ' hours'));
        if (panel.source && panel.source.describe) head.appendChild(el('span', 'ov-head-note', 'from ' + panel.source.describe));
        box.appendChild(head);
        if (!panel.source.available) {
            var none = el('p', 'ov-quiet', 'No Prometheus was found in this cluster, so there is no history to draw. Set one in the cluster settings panel if it lives somewhere the app did not look.');
            if (panel.source.error) none.title = panel.source.error;
            box.appendChild(none);
            return;
        }
        var row = el('div', 'ov-chart-row');
        panel.charts.forEach(function (chart) {
            row.appendChild(sparkChart(chart));
        });
        box.appendChild(row);
    }

    // ----- the foot ----------------------------------------------------------

    var DESTINATIONS = [
        { id: 'endpoints', label: 'Endpoint map', icon: 'map' },
        { id: 'policy-map', label: 'Policy map', icon: 'shield' },
        { id: 'network', label: 'Nodes & addresses', icon: 'node' },
        { id: 'cnp', label: 'Network policies', icon: 'shield' },
        { id: 'ccnp', label: 'Cluster-wide policies', icon: 'shield' },
        { id: 'cilium-endpoints', label: 'Cilium endpoints', icon: 'hex' },
        { id: 'identities', label: 'Identities', icon: 'tag' },
        { id: 'agents', label: 'Agents', icon: 'pod' },
    ];

    function drawFoot() {
        var box = $('foot');
        box.textContent = '';
        box.hidden = false;

        var go = el('div', 'ov-go');
        DESTINATIONS.forEach(function (d) {
            go.appendChild(
                K.button(d.label, 'ov-go-tile', d.icon, function () {
                    openView(d.id);
                }),
            );
        });
        box.appendChild(go);

        if (state.summary && state.summary.requirements && state.summary.requirements.length) {
            var reqs = el('div', 'ov-reqs');
            reqs.appendChild(el('span', 'ov-reqs-label', 'This cluster serves'));
            state.summary.requirements.forEach(function (r) {
                var tone = r.error ? 'warn' : r.served ? 'ok' : r.optional ? 'muted' : 'error';
                reqs.appendChild(K.chip(r.label, tone, r.error ? 'alert' : r.served ? 'check' : 'close', r.error || r.kind));
            });
            box.appendChild(reqs);
        }
        add(box, K.about(sdk, state.ctx && state.ctx.plugin, fail));
    }

    // ----- not here, or not reachable ----------------------------------------

    function drawAbsent(summary, model) {
        var hero = $('hero');
        hero.textContent = '';
        hero.className = 'ov-hero absent';
        ['datapath', 'path', 'nodes', 'columns', 'history', 'foot'].forEach(function (id) {
            $(id).hidden = true;
        });
        var main = el('div', 'ov-hero-main empty');
        K.absent(main, { sdk: sdk, summary: summary, contextName: state.ctx.contextName, missing: model && model.missing, fail: fail });
        add(main, K.about(sdk, state.ctx && state.ctx.plugin, fail));
        hero.appendChild(main);
    }

    // ----- putting it together -----------------------------------------------

    function render() {
        var model = state.model;
        var summary = state.summary;
        if (summary && (!summary.checked || !summary.installed)) {
            drawAbsent(summary, model);
            return;
        }
        if (!model) return;
        if (!model.installed) {
            drawAbsent(summary, model);
            return;
        }
        $('columns').hidden = false;
        drawHero(model);
        drawDatapath(model);
        drawPath(model);
        drawNodes(model);
        drawAttention(model);
        drawActivity();
        drawHistory();
        drawFoot();
    }

    function every(ms, fn) {
        function run() {
            Promise.resolve()
                .then(fn)
                .catch(fail)
                .then(function () {
                    setTimeout(run, ms);
                });
        }
        run();
    }

    function refreshEvents() {
        if (!state.model || !state.model.installed) return;
        M.loadEvents(sdk, state.model)
            .then(function (events) {
                var changed = JSON.stringify(events) !== JSON.stringify(state.events);
                state.events = events;
                if (changed) drawActivity();
            })
            .catch(fail);
    }

    sdk.ready()
        .then(function (context) {
            state.ctx = context;

            every(POLL, function () {
                return M.load(sdk, { extras: true }).then(function (model) {
                    clearError();
                    if (model.sig === state.sig) return;
                    var first = !state.model;
                    state.model = model;
                    state.sig = model.sig;
                    render();
                    if (first) refreshEvents();
                });
            });
            every(SUMMARY_EVERY, function () {
                if (!sdk.summary) return null;
                return sdk.summary().then(function (summary) {
                    var changed = JSON.stringify(summary) !== JSON.stringify(state.summary);
                    state.summary = summary;
                    if (changed) render();
                });
            });
            every(CHARTS_EVERY, function () {
                if (!sdk.charts) return null;
                return sdk.charts({ minutes: HISTORY_MINUTES }).then(function (panel) {
                    state.panel = panel;
                    if (state.model && state.model.installed) drawHistory();
                });
            });
            setInterval(refreshEvents, EVENTS_EVERY);
        })
        .catch(fail);
})();
