// The drawing kit the Cilium pages share: icons, gauges, the hexagon cells an
// endpoint is drawn as, chips for identity labels, the floating tip, the grip
// that resizes a side panel, and the few calls that ask the app to change
// something.
//
// Everything that came from the cluster is written with textContent, never
// innerHTML: the frame is sandboxed, but a page that let a pod's name run as
// markup would be handing that name the bridge.
(function () {
    'use strict';

    var M = window.Cilium;
    var SVG = 'http://www.w3.org/2000/svg';

    function el(tag, className, text) {
        var node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = text;
        return node;
    }

    function add(parent) {
        for (var i = 1; i < arguments.length; i++) {
            var child = arguments[i];
            if (child === null || child === undefined || child === false) continue;
            if (Array.isArray(child)) {
                child.forEach(function (c) {
                    add(parent, c);
                });
                continue;
            }
            parent.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
        }
        return parent;
    }

    function svg(tag, attrs) {
        var node = document.createElementNS(SVG, tag);
        Object.keys(attrs || {}).forEach(function (k) {
            node.setAttribute(k, attrs[k]);
        });
        return node;
    }

    // A pointy-topped hexagon as a path, centred on (cx, cy).
    function hexD(cx, cy, r) {
        var pts = [];
        for (var i = 0; i < 6; i++) {
            var a = (Math.PI / 3) * i - Math.PI / 2;
            pts.push((cx + r * Math.cos(a)).toFixed(2) + ' ' + (cy + r * Math.sin(a)).toFixed(2));
        }
        return 'M' + pts.join('L') + 'Z';
    }

    // Single-stroke icons on a 24-unit grid.
    var ICONS = {
        logo: [hexD(7.6, 8, 4.3), hexD(16.4, 8, 4.3), hexD(12, 15.6, 4.3)],
        hex: [hexD(12, 12, 9)],
        map: [hexD(7.3, 6.6, 3.7), hexD(15.1, 6.6, 3.7), hexD(11.2, 13.3, 3.7), hexD(4.4, 18.2, 0.4), hexD(19, 13.3, 3.7), hexD(7.3, 20, 0.4)],
        node: ['M4 4h16v6H4z', 'M4 14h16v6H4z', 'M8 7h.01', 'M8 17h.01'],
        pod: ['M12 3l8 4.5v9L12 21l-8-4.5v-9z', 'M12 12l8-4.5', 'M12 12v9', 'M12 12L4 7.5'],
        service: ['M12 3l8 4.5v9L12 21l-8-4.5v-9z', 'M12 12l8-4.5', 'M12 12v9', 'M12 12L4 7.5'],
        shield: ['M12 3l7 3v5.5c0 4.5-3 8-7 9.5-4-1.5-7-5-7-9.5V6z'],
        shieldCheck: ['M12 3l7 3v5.5c0 4.5-3 8-7 9.5-4-1.5-7-5-7-9.5V6z', 'M9 12l2.2 2.2L15.5 10'],
        shieldOff: ['M12 3l7 3v5.5c0 4.5-3 8-7 9.5-4-1.5-7-5-7-9.5V6z', 'M4 4l16 16'],
        tag: ['M3 12V4h8l9 9-8 8z', 'M7.5 7.5h.01'],
        tunnel: ['M3 19v-8a9 9 0 0 1 18 0v8', 'M7.5 19v-7.5a4.5 4.5 0 0 1 9 0V19', 'M2 19h20'],
        route: ['M6 19a2 2 0 1 0 0-4 2 2 0 0 0 0 4z', 'M18 9a2 2 0 1 0 0-4 2 2 0 0 0 0 4z', 'M8 17h6a3 3 0 0 0 0-6h-4a3 3 0 0 1 0-6h6'],
        lock: ['M6 11h12v10H6z', 'M8.5 11V7.5a3.5 3.5 0 0 1 7 0V11'],
        unlock: ['M6 11h12v10H6z', 'M8.5 11V7.5a3.5 3.5 0 0 1 6.6-1.6'],
        eye: ['M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z', 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z'],
        eyeOff: ['M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z', 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z', 'M4 4l16 16'],
        grid: ['M4 4h7v7H4z', 'M13 4h7v7h-7z', 'M4 13h7v7H4z', 'M13 13h7v7h-7z'],
        l2: ['M12 18.5h.01', 'M8.5 15a5 5 0 0 1 7 0', 'M5.5 12a9 9 0 0 1 13 0', 'M2.5 9a13 13 0 0 1 19 0'],
        bgp: ['M5 19a2 2 0 1 0 0-4 2 2 0 0 0 0 4z', 'M19 9a2 2 0 1 0 0-4 2 2 0 0 0 0 4z', 'M7 17h4a4 4 0 0 0 4-4v-2a4 4 0 0 1 2-3.4'],
        peer: ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M3 12h18', 'M12 3a14 14 0 0 1 0 18', 'M12 3a14 14 0 0 0 0 18'],
        world: ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M3 12h18', 'M12 3a14 14 0 0 1 0 18', 'M12 3a14 14 0 0 0 0 18'],
        gauge: ['M4 18a8 8 0 1 1 16 0', 'M12 18l4-6', 'M7.5 12.5h.01', 'M12 9h.01'],
        gateway: ['M4 21V9l8-6 8 6v12', 'M9 21v-6h6v6'],
        mesh: ['M6 8a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z', 'M18 8a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z', 'M12 21a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z', 'M8.5 5.5h7', 'M7.3 7.8l3.4 8.4', 'M16.7 7.8l-3.4 8.4'],
        wall: ['M3 5h18v14H3z', 'M3 9.7h18', 'M3 14.3h18', 'M9 5v4.7', 'M15 5v4.7', 'M6 9.7v4.6', 'M12 9.7v4.6', 'M18 9.7v4.6', 'M9 14.3V19', 'M15 14.3V19'],
        layers: ['M12 3l9 5-9 5-9-5z', 'M3 13l9 5 9-5'],
        operator: ['M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z', 'M12 2.5v3', 'M12 18.5v3', 'M2.5 12h3', 'M18.5 12h3', 'M5.3 5.3l2.1 2.1', 'M16.6 16.6l2.1 2.1', 'M5.3 18.7l2.1-2.1', 'M16.6 7.4l2.1-2.1'],
        bolt: ['M13 2.5L4.5 13.5H11L10 21.5l8.5-11H12z'],
        http: ['M3.5 5h17v14h-17z', 'M3.5 9h17', 'M6.5 7h.01', 'M9 7h.01'],
        dns: ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M3 12h18', 'M12 3a14 14 0 0 1 0 18', 'M12 3a14 14 0 0 0 0 18'],
        fqdn: ['M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1', 'M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1'],
        cidr: ['M3 7h18', 'M3 12h18', 'M3 17h18', 'M8 4v16', 'M16 4v16'],
        entity: ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8z', 'M12 12h.01'],
        deny: ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M5.6 5.6l12.8 12.8'],
        chip: ['M7 7h10v10H7z', 'M10 3v4', 'M14 3v4', 'M10 17v4', 'M14 17v4', 'M3 10h4', 'M3 14h4', 'M17 10h4', 'M17 14h4'],
        exit: ['M14 4h6v16h-6', 'M3 12h11', 'M10 8l4 4-4 4'],
        cycle: ['M20 11a8 8 0 0 0-14.8-4', 'M4 3.5V7.5h4', 'M4 13a8 8 0 0 0 14.8 4', 'M20 20.5v-4h-4'],
        pin: ['M12 21s-6-5.3-6-11a6 6 0 1 1 12 0c0 5.7-6 11-6 11z', 'M12 12.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z'],
        alert: ['M12 3l10 18H2z', 'M12 10v4', 'M12 17.5h.01'],
        check: ['M4 12.5l5 5L20 6.5'],
        info: ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M12 11v6', 'M12 7.5h.01'],
        search: ['M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14z', 'M20 20l-4-4'],
        arrow: ['M5 12h14', 'M13 6l6 6-6 6'],
        arrowLeft: ['M19 12H5', 'M11 6l-6 6 6 6'],
        edit: ['M4 20h4L19 9l-4-4L4 16z', 'M14 6l4 4'],
        open: ['M14 4h6v6', 'M20 4l-9 9', 'M18 14v6H4V6h6'],
        logs: ['M4 5h16', 'M4 10h16', 'M4 15h11', 'M4 20h7'],
        activity: ['M3 12h4l3-8 4 16 3-8h4'],
        clock: ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M12 7v5l3 2'],
        chart: ['M4 4v16h16', 'M8 15l3-4 3 2 5-6'],
        close: ['M6 6l12 12', 'M18 6L6 18'],
        plus: ['M12 5v14', 'M5 12h14'],
        filter: ['M4 5h16l-6 7.5V19l-4 2v-8.5z'],
        ports: ['M4 9h16', 'M4 15h16', 'M9 4l-2 16', 'M17 4l-2 16'],
        key: ['M14.5 14a5 5 0 1 0-4.7-3.3L3 17.5V21h3.5v-2h2v-2h2l1.3-1.3', 'M16.5 8.5h.01'],
        users: ['M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z', 'M2 21v-1a6 6 0 0 1 6-6h2a6 6 0 0 1 6 6v1', 'M17 3.5a4 4 0 0 1 0 7', 'M22 21v-1a6 6 0 0 0-4-5.6'],
    };

    function icon(name, className) {
        var node = svg('svg', { viewBox: '0 0 24 24', class: 'ico' + (className ? ' ' + className : ''), 'aria-hidden': 'true' });
        (ICONS[name] || ICONS.info).forEach(function (d) {
            node.appendChild(svg('path', { d: d }));
        });
        return node;
    }

    // The plugin's mark: three hexagons on a tile of their own colour.
    function logo(className) {
        var tile = el('span', 'logo' + (className ? ' ' + className : ''));
        tile.appendChild(icon('logo'));
        return tile;
    }

    function chip(text, tone, iconName, title) {
        var node = el('span', 'chip' + (tone ? ' ' + tone : ''));
        if (iconName) node.appendChild(icon(iconName));
        node.appendChild(el('span', '', text));
        if (title) node.title = title;
        return node;
    }

    function button(text, className, iconName, onClick) {
        var node = el('button', className || '');
        node.type = 'button';
        if (iconName) node.appendChild(icon(iconName));
        if (text) node.appendChild(el('span', '', text));
        if (onClick) node.addEventListener('click', onClick);
        return node;
    }

    function iconButton(iconName, label, onClick, className) {
        var node = button('', 'icon-button' + (className ? ' ' + className : ''), iconName, onClick);
        node.title = label;
        node.setAttribute('aria-label', label);
        return node;
    }

    function link(text, onClick, title) {
        var node = el('button', 'link', text);
        node.type = 'button';
        if (title) node.title = title;
        node.addEventListener('click', onClick);
        return node;
    }

    // What the plugin is about, from its manifest's links.
    function about(sdk, plugin, onError) {
        if (!plugin || !plugin.links || !plugin.links.length) return null;
        var row = el('div', 'about');
        row.appendChild(el('span', 'about-label', plugin.version ? 'Plugin ' + plugin.version + ' ·' : 'About'));
        plugin.links.forEach(function (l) {
            row.appendChild(
                link(
                    l.label,
                    function () {
                        sdk.openUrl(l.url).catch(onError || function () {});
                    },
                    l.url,
                ),
            );
        });
        return row;
    }

    // A ring gauge: the share done, drawn round from twelve o'clock.
    function ring(fraction, size, tone, label) {
        var r = size / 2 - 5;
        var c = 2 * Math.PI * r;
        var node = svg('svg', { viewBox: '0 0 ' + size + ' ' + size, class: 'ring ' + (tone || ''), width: size, height: size, role: 'img' });
        node.setAttribute('aria-label', label || Math.round(fraction * 100) + '%');
        node.appendChild(svg('circle', { cx: size / 2, cy: size / 2, r: r, class: 'track' }));
        // Nothing done draws no arc: a round cap on an empty dash is a dot.
        if (!(fraction > 0)) return node;
        node.appendChild(
            svg('circle', {
                cx: size / 2,
                cy: size / 2,
                r: r,
                class: 'arc',
                'stroke-dasharray': Math.max(fraction > 0 ? 2 : 0, fraction * c) + ' ' + c,
                transform: 'rotate(-90 ' + size / 2 + ' ' + size / 2 + ')',
            }),
        );
        return node;
    }

    // A ring cut into slices: [{ value, color, label }].
    function donut(slices, size, width, label) {
        var mid = size / 2;
        var r = mid - width / 2 - 2;
        var c = 2 * Math.PI * r;
        var total = slices.reduce(function (n, s) {
            return n + s.value;
        }, 0);
        var node = svg('svg', { viewBox: '0 0 ' + size + ' ' + size, class: 'donut', role: 'img' });
        node.setAttribute('aria-label', label || '');
        node.appendChild(svg('circle', { cx: mid, cy: mid, r: r, class: 'donut-track', 'stroke-width': width }));
        var shown = slices.filter(function (s) {
            return s.value > 0;
        });
        var gap = shown.length > 1 ? 3 : 0;
        var start = 0;
        shown.forEach(function (s, i) {
            var length = total ? (s.value / total) * c : 0;
            var arc = svg('circle', {
                cx: mid,
                cy: mid,
                r: r,
                class: 'donut-arc',
                'stroke-width': width,
                'stroke-dasharray': Math.max(1, length - gap) + ' ' + c,
                'stroke-dashoffset': String(-start),
                transform: 'rotate(-90 ' + mid + ' ' + mid + ')',
            });
            arc.style.stroke = s.color;
            arc.style.animationDelay = i * 90 + 'ms';
            var title = svg('title', {});
            title.textContent = s.label + ': ' + s.value;
            arc.appendChild(title);
            node.appendChild(arc);
            start += length;
        });
        return node;
    }

    function meter(fraction, tone) {
        var node = el('div', 'meter ' + (tone || ''));
        var fill = el('i');
        fill.style.width = fraction > 0 ? Math.max(1.5, Math.min(1, fraction) * 100) + '%' : '0';
        node.appendChild(fill);
        return node;
    }

    // A bar cut into parts: [{ value, cls, label }].
    function stack(parts, className) {
        var total = parts.reduce(function (n, p) {
            return n + p.value;
        }, 0);
        var node = el('div', 'stack' + (className ? ' ' + className : ''));
        parts.forEach(function (p) {
            if (!p.value) return;
            var seg = el('i', p.cls);
            seg.style.width = (p.value / total) * 100 + '%';
            seg.title = p.label + ': ' + p.value;
            node.appendChild(seg);
        });
        return node;
    }

    function fillTone(fraction) {
        if (fraction >= 0.95) return 'error';
        if (fraction >= 0.8) return 'warn';
        return 'ok';
    }

    function dot(tone, title) {
        var node = el('i', 'sdot ' + (tone || ''));
        if (title) node.title = title;
        return node;
    }

    // ----- colours -------------------------------------------------------------

    var FALLBACK = ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#008300', '#9085e9', '#e66767'];

    // Twenty-four colours from the theme's eight: each as it is, then leaning
    // towards the text colour, then towards the background. The same index
    // is the same colour on every page.
    function palette(i) {
        i = Math.abs(i) % 24;
        var base = 'var(--chart-' + ((i % 8) + 1) + ', ' + FALLBACK[i % 8] + ')';
        var band = Math.floor(i / 8);
        if (band === 0) return base;
        if (band === 1) return 'color-mix(in srgb, ' + base + ' 62%, var(--c-text))';
        return 'color-mix(in srgb, ' + base + ' 58%, var(--c-bg))';
    }

    function chart(i) {
        return 'var(--chart-' + Math.min(i + 1, 8) + ', ' + FALLBACK[Math.min(i, 7)] + ')';
    }

    // A stable colour for an identity: the same number, the same colour.
    function identityColor(id) {
        if (id === null || id === undefined) return 'var(--c-faint)';
        var n = Number(id);
        var h = (n * 2654435761) >>> 0;
        return palette(h % 24);
    }

    // ----- identity labels -----------------------------------------------------

    // One label as a chip, its source dimmed: "k8s:" is on every pod label.
    // Cilium's copies of the namespace's labels are written short:
    // "k8s:io.cilium.k8s.namespace.labels.team" reads as "ns label team".
    var NS_LABEL = 'io.cilium.k8s.namespace.labels.';

    function labelChip(label, extra) {
        var node = el('span', 'lchip' + (extra ? ' ' + extra : ''));
        var key = label.key;
        if (key.indexOf(NS_LABEL) === 0) {
            node.appendChild(el('span', 'lsrc ns', 'ns label'));
            key = key.slice(NS_LABEL.length);
        } else if (label.source && label.source !== 'any') {
            node.appendChild(el('span', 'lsrc', label.source + ':'));
        }
        node.appendChild(el('span', 'lkey', key));
        if (label.value !== '') {
            node.appendChild(el('span', 'leq', '='));
            node.appendChild(el('span', 'lval', label.value));
        }
        node.title = label.text;
        return node;
    }

    // The labels worth reading first: the pod's own before the namespace's
    // copies and Cilium's bookkeeping.
    function sortLabels(list) {
        function rank(l) {
            if (l.source === 'reserved') return 0;
            if (/^io\.cilium\.k8s\.namespace\.labels\./.test(l.key)) return 4;
            if (/^io\.cilium\.k8s\.policy\./.test(l.key)) return 3;
            if (/^io\.kubernetes\.pod\.namespace$/.test(l.key)) return 2;
            return 1;
        }
        return list.slice().sort(function (a, b) {
            return rank(a) - rank(b) || a.key.localeCompare(b.key);
        });
    }

    function selectorChip(sel, emptyText) {
        var text = M.selectorText(sel, emptyText);
        var node = el('code', 'selchip', text);
        node.title = text;
        return node;
    }

    // ----- hexagons --------------------------------------------------------------

    // A small honeycomb of endpoints for a card: rows of `cols`, the odd
    // ones shifted by half a cell. `cls(ep)` names each cell's colour class.
    function miniHexes(endpoints, opts) {
        opts = opts || {};
        var cols = opts.cols || 14;
        var max = opts.max || 84;
        var wrap = el('div', 'mhex');
        var row = null;
        var shown = endpoints.slice(0, max);
        shown.forEach(function (ep, i) {
            if (i % cols === 0) {
                row = el('div', 'hrow' + (Math.floor(i / cols) % 2 ? ' odd' : ''));
                wrap.appendChild(row);
            }
            var cell = el('i', 'hx ' + (opts.cls ? opts.cls(ep) : 'e-' + ep.enforcement));
            if (opts.color) cell.style.setProperty('--hc', opts.color(ep));
            cell.dataset.ep = ep.key;
            row.appendChild(cell);
        });
        if (endpoints.length > max) wrap.appendChild(el('div', 'mhex-more', '+' + (endpoints.length - max) + ' more'));
        return wrap;
    }

    // ----- segmented control, filter chips ---------------------------------------

    // opts: [{ id, label, icon, title }]; onPick(id)
    function seg(options, current, onPick, label) {
        var node = el('div', 'seg');
        node.setAttribute('role', 'group');
        if (label) node.setAttribute('aria-label', label);
        options.forEach(function (o) {
            var b = button(o.label, 'seg-btn' + (o.id === current ? ' on' : ''), o.icon, function () {
                onPick(o.id);
            });
            b.dataset.id = o.id;
            b.setAttribute('aria-pressed', o.id === current ? 'true' : 'false');
            if (o.title) b.title = o.title;
            node.appendChild(b);
        });
        return node;
    }

    function fchip(label, n, on, tone, onClick, title) {
        var b = button('', 'fchip' + (on ? ' on' : '') + (tone ? ' ' + tone : ''), null, onClick);
        if (tone) b.appendChild(el('i', 'sdot ' + tone));
        b.appendChild(el('span', '', label));
        if (n !== null && n !== undefined) b.appendChild(el('span', 'fchip-n', String(n)));
        if (on) b.appendChild(el('span', 'fchip-x', '×'));
        b.setAttribute('aria-pressed', on ? 'true' : 'false');
        if (title) b.title = title;
        return b;
    }

    // ----- the tooltip -----------------------------------------------------------

    // One floating tip for the page, filled by `describe` for whatever
    // matches `selector` under the pointer.
    function tooltip(root, selector, describe) {
        var tip = el('div', 'tip');
        tip.hidden = true;
        tip.setAttribute('role', 'tooltip');
        document.body.appendChild(tip);
        var current = null;

        function place(event) {
            var pad = 14;
            var w = tip.offsetWidth;
            var h = tip.offsetHeight;
            var x = event.clientX + pad;
            var y = event.clientY + pad;
            if (x + w > window.innerWidth - 8) x = event.clientX - w - pad;
            if (y + h > window.innerHeight - 8) y = event.clientY - h - pad;
            tip.style.left = Math.max(8, x) + 'px';
            tip.style.top = Math.max(8, y) + 'px';
        }

        root.addEventListener('pointerover', function (event) {
            var node = event.target.closest && event.target.closest(selector);
            if (!node || !root.contains(node)) return;
            if (node === current && !tip.hidden) return;
            current = node;
            tip.textContent = '';
            if (!describe(node, tip)) {
                tip.hidden = true;
                return;
            }
            tip.hidden = false;
            place(event);
        });
        root.addEventListener('pointermove', function (event) {
            if (!tip.hidden) place(event);
        });
        root.addEventListener('pointerout', function (event) {
            var node = event.target.closest && event.target.closest(selector);
            if (node && !node.contains(event.relatedTarget)) {
                tip.hidden = true;
                current = null;
            }
        });
        root.addEventListener('pointerleave', function () {
            tip.hidden = true;
            current = null;
        });
        return tip;
    }

    // ----- time ------------------------------------------------------------------

    function age(timestamp) {
        if (!timestamp) return '';
        var seconds = Math.max(0, (Date.now() - new Date(timestamp).getTime()) / 1000);
        if (seconds < 90) return Math.round(seconds) + 's';
        if (seconds < 5400) return Math.round(seconds / 60) + 'm';
        if (seconds < 172800) return Math.round(seconds / 3600) + 'h';
        return Math.round(seconds / 86400) + 'd';
    }

    function ago(timestamp) {
        if (!timestamp) return '';
        if (Date.now() - new Date(timestamp).getTime() < 10000) return 'just now';
        return age(timestamp) + ' ago';
    }

    // ----- the page's state, in its address --------------------------------------

    // Switching tabs unloads a page; what it was showing lives in the hash.
    function readHash() {
        var parts = {};
        String(location.hash || '')
            .replace(/^#/, '')
            .split('&')
            .forEach(function (kv) {
                var cut = kv.indexOf('=');
                if (cut > 0) {
                    try {
                        parts[kv.slice(0, cut)] = decodeURIComponent(kv.slice(cut + 1));
                    } catch (e) {
                        // A mangled value is dropped, not fatal.
                    }
                }
            });
        return parts;
    }

    function writeHash(values) {
        var parts = [];
        Object.keys(values).forEach(function (k) {
            var v = values[k];
            if (v === '' || v === null || v === undefined || v === false || v === 0) return;
            parts.push(k + '=' + encodeURIComponent(String(v)));
        });
        try {
            history.replaceState(null, '', '#' + parts.join('&'));
        } catch (e) {
            // A frame that may not touch its history keeps the state in memory.
        }
    }

    // What the page keeps between sessions, when the app can keep it.
    function store(sdk) {
        var ok = !!(sdk && sdk.storage && typeof sdk.storage.get === 'function');
        return {
            get: function (key) {
                if (!ok) return Promise.resolve(null);
                return sdk.storage.get(key).catch(function () {
                    return null;
                });
            },
            set: function (key, value) {
                if (!ok) return;
                sdk.storage.set(key, value).catch(function () {});
            },
        };
    }

    // ----- asking the app to change something ------------------------------------

    // The app shows every change to the user first; a "no" is not an error.
    function declined(err) {
        return /declin|cancel/i.test((err && err.message) || '');
    }

    function apply(sdk, ref, patch) {
        return sdk.patch({ kind: ref.kind, namespace: ref.namespace, name: ref.name, patch: patch }).then(
            function () {
                return true;
            },
            function (err) {
                if (declined(err)) return false;
                throw err;
            },
        );
    }

    function create(sdk, request) {
        return sdk.create(request).then(
            function (res) {
                return res || { name: '' };
            },
            function (err) {
                if (declined(err)) return null;
                throw err;
            },
        );
    }

    // ----- the grip --------------------------------------------------------------

    // A grab strip on the inner edge of a side panel: drag it, or focus it
    // and use the arrow keys, to make the panel wider or narrower; a double
    // click puts it back. The width is a custom property on the root.
    // opts: { panel, prop, min, room, initial, label, className, side, onResize(px, done) }
    //   side      'right' (default) for a panel on the right, 'left' for one on the left
    function grip(opts) {
        var root = document.documentElement;
        var node = el('div', 'grip' + (opts.className ? ' ' + opts.className : ''));
        var left = opts.side === 'left';
        node.tabIndex = 0;
        node.title = 'Drag to resize · double-click to reset';
        node.setAttribute('role', 'separator');
        node.setAttribute('aria-orientation', 'vertical');
        node.setAttribute('aria-label', opts.label || 'Resize the panel');
        var wanted = opts.initial > 0 ? opts.initial : 0;
        var drag = null;
        var frame = 0;

        function fit(px) {
            return Math.round(Math.max(opts.min, Math.min(px, window.innerWidth - opts.room)));
        }

        function set() {
            if (wanted) root.style.setProperty(opts.prop, fit(wanted) + 'px');
            else root.style.removeProperty(opts.prop);
        }

        function tell(done) {
            if (!opts.onResize) return;
            cancelAnimationFrame(frame);
            frame = 0;
            if (done) opts.onResize(wanted, true);
            else
                frame = requestAnimationFrame(function () {
                    frame = 0;
                    opts.onResize(wanted, false);
                });
        }

        function resize(px, done) {
            wanted = px ? fit(px) : 0;
            set();
            tell(done);
        }

        function release(event) {
            if (!drag) return;
            drag = null;
            document.body.classList.remove('gripping');
            if (node.hasPointerCapture(event.pointerId)) node.releasePointerCapture(event.pointerId);
            tell(true);
        }

        node.addEventListener('pointerdown', function (event) {
            if (event.button !== 0) return;
            event.preventDefault();
            node.setPointerCapture(event.pointerId);
            drag = { x: event.clientX, from: opts.panel.getBoundingClientRect().width };
            document.body.classList.add('gripping');
        });
        node.addEventListener('pointermove', function (event) {
            if (!drag) return;
            var delta = left ? event.clientX - drag.x : drag.x - event.clientX;
            resize(drag.from + delta, false);
        });
        node.addEventListener('pointerup', release);
        node.addEventListener('pointercancel', release);
        node.addEventListener('dblclick', function () {
            resize(0, true);
        });
        node.addEventListener('keydown', function (event) {
            var step = event.shiftKey ? 48 : 16;
            var now = wanted || opts.panel.getBoundingClientRect().width;
            var grow = left ? 'ArrowRight' : 'ArrowLeft';
            var shrink = left ? 'ArrowLeft' : 'ArrowRight';
            if (event.key === grow) resize(now + step, true);
            else if (event.key === shrink) resize(now - step, true);
            else return;
            event.preventDefault();
        });
        window.addEventListener('resize', function () {
            if (!wanted) return;
            set();
            tell(false);
        });
        set();
        return node;
    }

    // ----- shared bits of pages --------------------------------------------------

    function plural(n, one, many) {
        return M.plural(n, one, many);
    }

    function num(n) {
        return Number(n || 0).toLocaleString();
    }

    // "Cilium is not installed in <context>", with what is and is not served.
    function absent(box, opts) {
        var sdk = opts.sdk;
        box.textContent = '';
        var art = el('div', 'empty-art');
        art.appendChild(icon('logo'));
        box.appendChild(art);
        var summary = opts.summary;
        var unreachable = summary && !summary.checked;
        box.appendChild(el('h2', '', unreachable ? 'This cluster did not answer' : 'Cilium is not installed in ' + opts.contextName));
        box.appendChild(
            el(
                'p',
                'faint',
                unreachable
                    ? 'Whether Cilium is here could not be checked, which is not the same as it being absent. ' + (summary.error || '')
                    : 'This cluster does not serve the kinds every Cilium install has, so its pods are networked by another CNI — and Cilium policies would do nothing here.',
            ),
        );
        if (summary && summary.requirements && summary.requirements.length) {
            box.appendChild(reqList(summary.requirements));
        } else if (opts.missing) {
            box.appendChild(el('p', 'faint small', opts.missing));
        }
        if (!unreachable) {
            var cta = el('div', 'cta-row');
            cta.appendChild(
                button('How to install Cilium', 'primary', 'open', function () {
                    sdk.openUrl('https://docs.cilium.io/en/stable/gettingstarted/k8s-install-default/').catch(opts.fail);
                }),
            );
            box.appendChild(cta);
        }
    }

    // The kinds every install has as rows; the optional ones as chips.
    function reqList(requirements) {
        var box = el('div');
        var list = el('ul', 'req-list');
        var optional = el('div', 'req-opt');
        optional.appendChild(el('span', 'req-opt-label', 'Optional, for features this cluster may not use'));
        requirements.forEach(function (r) {
            var tone = r.error ? 'warn' : r.served ? 'ok' : r.optional ? 'muted' : 'error';
            if (r.optional) {
                optional.appendChild(chip(r.label, tone, r.served ? 'check' : 'close', r.error || r.kind.replace(/^crd:/, '')));
                return;
            }
            var item = el('li', tone);
            add(item, icon(r.error ? 'alert' : r.served ? 'check' : 'close'), el('span', '', r.label), el('code', 'faint', r.kind.replace(/^crd:/, '')));
            if (r.error) item.title = r.error;
            list.appendChild(item);
        });
        box.appendChild(list);
        if (optional.childNodes.length > 1) box.appendChild(optional);
        return box;
    }

    // Asks for the summary once, to tell "not installed" from "not reachable"
    // when the core kinds cannot be read.
    function whyAbsent(sdk) {
        if (!sdk.summary) return Promise.resolve(null);
        return sdk.summary().catch(function () {
            return null;
        });
    }

    window.CiliumKit = {
        el: el,
        add: add,
        svg: svg,
        hexD: hexD,
        icon: icon,
        logo: logo,
        chip: chip,
        button: button,
        iconButton: iconButton,
        link: link,
        about: about,
        ring: ring,
        donut: donut,
        meter: meter,
        stack: stack,
        fillTone: fillTone,
        dot: dot,
        palette: palette,
        chart: chart,
        identityColor: identityColor,
        labelChip: labelChip,
        sortLabels: sortLabels,
        selectorChip: selectorChip,
        miniHexes: miniHexes,
        seg: seg,
        fchip: fchip,
        tooltip: tooltip,
        age: age,
        ago: ago,
        readHash: readHash,
        writeHash: writeHash,
        store: store,
        apply: apply,
        create: create,
        grip: grip,
        plural: plural,
        num: num,
        absent: absent,
        reqList: reqList,
        whyAbsent: whyAbsent,
    };
})();
