// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
// LYSS topology map. Neighbour names come from the network (LLDP/CDP) and are untrusted:
// they are only ever inserted with textContent / setAttribute, never as HTML.
(function () {
  "use strict";
  var svg = document.getElementById("topo");
  if (!svg) return;
  var NS = "http://www.w3.org/2000/svg";
  var STORE = "lyss-topology-positions", ROOT_STORE = "lyss-topology-root";
  var data = null, byId = {}, adj = {}, pos = {}, saved = {}, rootId = null;
  var showEndpoints = false, selected = null;
  var view = { x: 0, y: 0, w: 1000, h: 600 };

  try { saved = JSON.parse(localStorage.getItem(STORE) || "{}"); } catch (e) { saved = {}; }
  try { rootId = localStorage.getItem(ROOT_STORE); } catch (e) { rootId = null; }

  function el(tag, attrs, parent) {
    var e = document.createElementNS(NS, tag);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  function text(parent, x, y, value, cls) {
    var t = el("text", { x: x, y: y, "class": cls || "" }, parent);
    t.textContent = value;
    return t;
  }
  function short(value, n) { return value.length > n ? value.slice(0, n - 1) + "…" : value; }
  function isSwitch(n) { return n.kind === "switch"; }
  function visible(n) { return isSwitch(n) || showEndpoints; }

  // ---------------- layout ----------------
  function layout() {
    var switches = data.nodes.filter(isSwitch);
    function swDegree(n) { return adj[n.id].filter(function (x) { return isSwitch(byId[x]); }).length; }
    var managed = switches.filter(function (n) { return n.managed; });
    // top of the map: the switch the user chose, else one named "core", else the best connected
    function isCore(n) { return /core/i.test(n.id + " " + (n.hostname || "")); }
    managed.sort(function (a, b) {
      return (b.id === rootId) - (a.id === rootId) || isCore(b) - isCore(a) || swDegree(b) - swDegree(a);
    });

    // breadth-first layers from that switch; other islands go below
    var layer = {}, layers = [];
    function bfs(start, base) {
      var queue = [start.id];
      layer[start.id] = base;
      while (queue.length) {
        var id = queue.shift();
        (layers[layer[id]] = layers[layer[id]] || []).push(id);
        adj[id].forEach(function (x) {
          if (isSwitch(byId[x]) && layer[x] === undefined) { layer[x] = layer[id] + 1; queue.push(x); }
        });
      }
    }
    if (managed.length) bfs(managed[0], 0);
    switches.forEach(function (s) { if (layer[s.id] === undefined) bfs(s, layers.length); });

    function endpoints(id) {
      return adj[id].filter(function (x) { return !isSwitch(byId[x]); });
    }
    function slotWidth(id) {
      return showEndpoints ? Math.max(200, Math.min(5, endpoints(id).length) * 74 + 20) : 200;
    }
    var y = 0, xs = {};
    layers.forEach(function (ids, L) {
      // order by the mean position of the parents already placed (fewer crossings)
      ids.sort(function (a, b) {
        function bary(id) {
          var p = adj[id].filter(function (x) { return xs[x] !== undefined && layer[x] < L; });
          return p.length ? p.reduce(function (s, x) { return s + xs[x]; }, 0) / p.length : 0;
        }
        return bary(a) - bary(b);
      });
      var total = ids.reduce(function (s, id) { return s + slotWidth(id); }, 0);
      var x = -total / 2, maxRows = 0;
      ids.forEach(function (id) {
        var w = slotWidth(id);
        xs[id] = x + w / 2;
        pos[id] = { x: xs[id], y: y };
        if (showEndpoints) {
          var eps = endpoints(id);
          maxRows = Math.max(maxRows, Math.ceil(eps.length / 5));
          eps.forEach(function (e, i) {
            var row = Math.floor(i / 5), col = i % 5, inRow = Math.min(5, eps.length - row * 5);
            pos[e] = { x: xs[id] + (col - (inRow - 1) / 2) * 74, y: y + 105 + row * 74 };
          });
        }
        x += w;
      });
      y += 170 + (showEndpoints ? maxRows * 74 + 30 : 0);
    });
    Object.keys(saved).forEach(function (id) { if (pos[id]) pos[id] = saved[id]; });
  }

  // ---------------- rendering ----------------
  function render() {
    svg.replaceChildren();
    var gEdges = el("g", {}, svg), gNodes = el("g", {}, svg);

    data.edges.forEach(function (e) {
      var a = byId[e.a], b = byId[e.b];
      if (!visible(a) || !visible(b) || !pos[e.a] || !pos[e.b]) return;
      var p1 = pos[e.a], p2 = pos[e.b];
      var dx = p2.x - p1.x, dy = p2.y - p1.y, len = Math.sqrt(dx * dx + dy * dy) || 1;
      var nx = -dy / len, ny = dx / len, n = e.ports.length;
      var endpoint = !isSwitch(a) || !isSwitch(b);
      var g = el("g", { "class": "edge" + (endpoint ? " edge-end" : "") + (selected && (e.a === selected || e.b === selected) ? " edge-sel" : "") }, gEdges);
      e.ports.forEach(function (p, k) {
        var off = (k - (n - 1) / 2) * 7;
        el("line", { x1: p1.x + nx * off, y1: p1.y + ny * off, x2: p2.x + nx * off, y2: p2.y + ny * off,
                     "class": "link" + (p.confirmed ? "" : " link-oneside") }, g);
      });
      // port names near each end
      var la = e.ports.map(function (p) { return p.a_port; }).filter(Boolean).join(" + ");
      var lb = e.ports.map(function (p) { return p.b_port; }).filter(Boolean).join(" + ");
      // endpoint links are many and short: their port names only show for the selected switch
      var labelled = !endpoint || selected === e.a || selected === e.b;
      var ta = endpoint ? 0.5 : 0.3;
      if (labelled && la && isSwitch(a)) text(g, p1.x + dx * ta, p1.y + dy * ta, la, "port");
      if (labelled && lb && isSwitch(b)) text(g, p2.x - dx * ta, p2.y - dy * ta, lb, "port");
      if (n > 1 && !endpoint) text(g, p1.x + dx / 2 + nx * 14, p1.y + dy / 2 + ny * 14, "×" + n, "port port-multi");
    });

    data.nodes.forEach(function (node) {
      if (!visible(node) || !pos[node.id]) return;
      var p = pos[node.id];
      var cls = "node node-" + node.kind + (node.managed ? " managed lvl-" + (node.level === null || node.level === undefined ? "na" : node.level) : " external") + (selected === node.id ? " selected" : "");
      var g = el("g", { "class": cls, transform: "translate(" + p.x + "," + p.y + ")", "data-id": node.id }, gNodes);
      var title = el("title", {}, g);
      title.textContent = node.label + (node.host ? " (" + node.host + ")" : "");
      if (isSwitch(node)) {
        el("rect", { x: -82, y: -27, width: 164, height: 54, rx: 10, "class": "box" }, g);
        el("rect", { x: -82, y: -27, width: 7, height: 54, rx: 3, "class": "stripe" }, g);
        text(g, -68, -6, short(node.label, 20), "name");
        text(g, -68, 13, short(node.managed ? (node.model || node.host || "") : "not in LYSS", 22), "sub");
        if (node.managed && node.level !== null && node.level !== undefined) {
          el("rect", { x: 46, y: -21, width: 28, height: 18, rx: 9, "class": "badge" }, g);
          text(g, 60, -8, "L" + node.level, "badge-text");
        }
        var eps = adj[node.id].filter(function (x) { return !isSwitch(byId[x]); }).length;
        if (!showEndpoints && eps) {
          el("circle", { cx: 74, cy: 22, r: 11, "class": "count" }, g);
          text(g, 74, 26, String(eps), "count-text");
        }
      } else {
        if (node.kind === "server") el("rect", { x: -17, y: -13, width: 34, height: 26, rx: 5, "class": "box" }, g);
        else el("circle", { r: node.kind === "ap" ? 16 : 11, "class": "box" }, g);
        text(g, 0, 4, { ap: "AP", server: "ESX", phone: "TEL" }[node.kind] || "", "glyph");
        text(g, 0, node.kind === "ap" ? 31 : 27, short(node.label, 18), "ep-label");
      }
    });
  }

  // ---------------- details panel ----------------
  function showPanel(id) {
    var n = byId[id];
    document.getElementById("tp-title").textContent = n.label;
    document.getElementById("tp-sub").textContent = n.managed
      ? n.host + (n.hostname ? " · hostname " + n.hostname : "")
      : (n.kind === "switch" ? "Switch seen by its neighbours, not managed by LYSS" : "Endpoint (" + n.kind + ")");
    var facts = document.getElementById("tp-facts");
    facts.replaceChildren();
    var rows = n.managed
      ? [["Model", n.model], ["Firmware", n.firmware], ["LYSS level", n.level === null || n.level === undefined ? "not scanned" : "Level " + n.level], ["Failed controls", n.fail]]
      : [["Platform", n.platform], ["Seen via", (n.protocols || []).join(", ").toUpperCase()]];
    rows.forEach(function (r) {
      if (r[1] === undefined || r[1] === null || r[1] === "") return;
      var dt = document.createElement("dt"), dd = document.createElement("dd");
      dt.textContent = r[0]; dd.textContent = r[1];
      facts.append(dt, dd);
    });
    var list = document.getElementById("tp-links");
    list.replaceChildren();
    data.edges.forEach(function (e) {
      if (e.a !== id && e.b !== id) return;
      var other = byId[e.a === id ? e.b : e.a];
      e.ports.forEach(function (p) {
        var mine = e.a === id ? p.a_port : p.b_port, theirs = e.a === id ? p.b_port : p.a_port;
        var li = document.createElement("li");
        var port = document.createElement("span");
        port.className = "mono";
        port.textContent = mine || "?";
        var arrow = document.createElement("span");
        arrow.className = "muted";
        arrow.textContent = " → ";
        var peer = document.createElement("span");
        peer.textContent = other.label + (theirs ? " " + theirs : "");
        li.append(port, arrow, peer);
        if (!p.confirmed) li.title = "Seen from one end only";
        list.append(li);
      });
    });
    var link = document.getElementById("tp-report");
    link.hidden = !n.managed;
    if (n.managed) link.setAttribute("href", "/devices/" + encodeURIComponent(n.id));
    document.getElementById("tp-root").hidden = !n.managed || n.id === rootId;
  }

  document.getElementById("tp-root").addEventListener("click", function () {
    if (!selected) return;
    rootId = selected;
    saved = {};
    try { localStorage.setItem(ROOT_STORE, rootId); localStorage.removeItem(STORE); } catch (e) { /* storage unavailable */ }
    document.getElementById("tp-root").hidden = true;
    layout(); render(); fit();
  });

  // ---------------- view: fit, zoom, pan, drag ----------------
  function applyView() { svg.setAttribute("viewBox", [view.x, view.y, view.w, view.h].join(" ")); }
  function fit() {
    var ids = data.nodes.filter(visible).map(function (n) { return n.id; }).filter(function (id) { return pos[id]; });
    if (!ids.length) return;
    var xs = ids.map(function (id) { return pos[id].x; }), ys = ids.map(function (id) { return pos[id].y; });
    var minX = Math.min.apply(null, xs) - 120, maxX = Math.max.apply(null, xs) + 120;
    var minY = Math.min.apply(null, ys) - 70, maxY = Math.max.apply(null, ys) + 70;
    var rect = svg.getBoundingClientRect(), ratio = rect.width / Math.max(rect.height, 1);
    var w = maxX - minX, h = maxY - minY;
    if (w / h < ratio) { var nw = h * ratio; minX -= (nw - w) / 2; w = nw; } else { var nh = w / ratio; minY -= (nh - h) / 2; h = nh; }
    view = { x: minX, y: minY, w: w, h: h };
    applyView();
  }
  function toSvg(evt) {
    var r = svg.getBoundingClientRect();
    return { x: view.x + (evt.clientX - r.left) / r.width * view.w, y: view.y + (evt.clientY - r.top) / r.height * view.h };
  }

  var drag = null;
  svg.addEventListener("pointerdown", function (evt) {
    var g = evt.target.closest("g.node");
    svg.setPointerCapture(evt.pointerId);
    drag = g ? { id: g.getAttribute("data-id"), start: toSvg(evt), moved: false }
             : { pan: true, start: { x: evt.clientX, y: evt.clientY }, view: Object.assign({}, view), moved: false };
  });
  svg.addEventListener("pointermove", function (evt) {
    if (!drag) return;
    if (drag.pan) {
      var r = svg.getBoundingClientRect();
      var dx = (evt.clientX - drag.start.x) / r.width * view.w, dy = (evt.clientY - drag.start.y) / r.height * view.h;
      if (Math.abs(dx) + Math.abs(dy) > 2) drag.moved = true;
      view.x = drag.view.x - dx; view.y = drag.view.y - dy;
      applyView();
    } else {
      var p = toSvg(evt);
      if (Math.abs(p.x - drag.start.x) + Math.abs(p.y - drag.start.y) > 3) drag.moved = true;
      if (drag.moved) { pos[drag.id] = { x: p.x, y: p.y }; render(); }
    }
  });
  svg.addEventListener("pointerup", function () {
    if (drag && !drag.pan) {
      if (drag.moved) {
        saved[drag.id] = pos[drag.id];
        try { localStorage.setItem(STORE, JSON.stringify(saved)); } catch (e) { /* storage unavailable */ }
      } else {
        selected = drag.id;
        showPanel(drag.id);
        render();
      }
    }
    drag = null;
  });
  svg.addEventListener("wheel", function (evt) {
    evt.preventDefault();
    var p = toSvg(evt), k = evt.deltaY > 0 ? 1.12 : 1 / 1.12;
    view = { x: p.x - (p.x - view.x) * k, y: p.y - (p.y - view.y) * k, w: view.w * k, h: view.h * k };
    applyView();
  }, { passive: false });

  document.getElementById("topo-endpoints").addEventListener("change", function (evt) {
    showEndpoints = evt.target.checked;
    layout(); render(); fit();
  });
  document.getElementById("topo-fit").addEventListener("click", fit);
  document.getElementById("topo-reset").addEventListener("click", function () {
    saved = {};
    try { localStorage.removeItem(STORE); } catch (e) { /* storage unavailable */ }
    layout(); render(); fit();
  });

  fetch("/api/topology", { credentials: "same-origin", cache: "no-store" })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      data = d;
      data.nodes.forEach(function (n) { byId[n.id] = n; adj[n.id] = []; });
      data.edges.forEach(function (e) { adj[e.a].push(e.b); adj[e.b].push(e.a); });
      if (!data.edges.length) document.getElementById("topo-empty").hidden = false;
      layout(); render(); fit();
    });
})();
