// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
// LYSS UI behaviour. Loaded as an external script (CSP forbids inline script).
(function () {
  "use strict";

  // controls bars: widths come from data-w (inline style attributes are blocked by CSP)
  document.querySelectorAll("[data-w]").forEach(function (el) {
    el.style.width = el.dataset.w + "%";
  });

  // confirmation for destructive buttons
  document.querySelectorAll("[data-confirm]").forEach(function (btn) {
    btn.addEventListener("click", function (e) {
      if (!window.confirm(btn.dataset.confirm)) e.preventDefault();
    });
  });

  // switch search
  var search = document.getElementById("search");
  if (search) {
    search.addEventListener("input", function () {
      var q = search.value.trim().toLowerCase();
      document.querySelectorAll("#devices tbody tr").forEach(function (tr) {
        tr.hidden = q !== "" && tr.dataset.search.toLowerCase().indexOf(q) < 0;
      });
    });
  }

  // export menu
  document.querySelectorAll("[data-menu]").forEach(function (btn) {
    var list = btn.nextElementSibling;
    btn.addEventListener("click", function (e) { e.stopPropagation(); list.hidden = !list.hidden; });
    document.addEventListener("click", function () { list.hidden = true; });
  });

  // copy a recommended fix
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function (e) {
      e.preventDefault();
      var pre = btn.closest(".label").nextElementSibling;
      navigator.clipboard.writeText(pre.textContent).then(function () {
        btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = "Copy"; }, 1500);
      });
    });
  });

  // device form: username/password only when the switch has its own credentials
  var cred = document.getElementById("cred-select");
  if (cred) {
    var syncCred = function () {
      document.querySelectorAll("[data-own-cred]").forEach(function (el) { el.hidden = cred.value !== ""; });
    };
    cred.addEventListener("change", syncCred);
    syncCred();
  }

  // discovery: select all + range scan progress
  var all = document.querySelector("[data-check-all]");
  if (all) {
    all.addEventListener("change", function () {
      document.querySelectorAll('input[name="ips"]:not([disabled])').forEach(function (c) { c.checked = all.checked; });
    });
  }
  var disc = document.getElementById("disc-progress");
  if (disc && !disc.hidden) {
    var pollDisc = function () {
      fetch("/api/discovery", { credentials: "same-origin", cache: "no-store" })
        .then(function (r) { return r.json(); })
        .then(function (s) {
          document.getElementById("disc-count").textContent = s.done + " / " + s.total;
          document.getElementById("disc-bar").style.width = (s.total ? 100 * s.done / s.total : 0) + "%";
          document.getElementById("disc-found").textContent = s.found + " switch-like device(s) found";
          if (s.running) setTimeout(pollDisc, 1000); else window.location.reload();
        })
        .catch(function () { setTimeout(pollDisc, 3000); });
    };
    pollDisc();
  }

  // findings filter
  var chips = document.querySelectorAll(".chip[data-filter]");
  chips.forEach(function (chip) {
    chip.addEventListener("click", function () {
      chips.forEach(function (c) { c.classList.toggle("active", c === chip); });
      var f = chip.dataset.filter;
      document.querySelectorAll(".finding").forEach(function (el) {
        el.classList.toggle("hidden", f !== "all" && el.dataset.verdict !== f);
      });
    });
  });

  // scan progress
  var panel = document.getElementById("job");
  if (!panel) return;
  var labels = { queued: "queued", running: "collecting…", collected: "auditing…", done: "done", error: "error" };
  var wasRunning = false;

  function render(job) {
    var ids = Object.keys(job.items || {});
    var running = ids.length > 0 && !job.finished;
    panel.hidden = !running;
    document.querySelectorAll("[data-scan]").forEach(function (b) { b.disabled = running; });
    if (!running) {
      if (wasRunning) window.location.reload();
      return;
    }
    wasRunning = true;
    var finished = ids.filter(function (id) { return ["done", "error"].indexOf(job.items[id].status) >= 0; }).length;
    document.getElementById("job-count").textContent = finished + " / " + ids.length;
    document.getElementById("job-bar").style.width = (100 * finished / ids.length) + "%";
    var list = document.getElementById("job-items");
    list.replaceChildren();
    ids.forEach(function (id) {
      var item = job.items[id];
      var li = document.createElement("li");
      var name = document.createElement("span");
      name.textContent = id;
      var st = document.createElement("span");
      st.className = "st-" + item.status;
      st.textContent = item.status === "done" ? item.message : labels[item.status] || item.status;
      if (item.status === "error") st.title = item.message;
      li.append(name, st);
      list.append(li);
    });
  }

  function poll() {
    fetch("/api/job", { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : {}; })
      .then(function (job) {
        render(job);
        if (job.items && !job.finished) setTimeout(poll, 1000);
      })
      .catch(function () { setTimeout(poll, 3000); });
  }
  poll();
})();
