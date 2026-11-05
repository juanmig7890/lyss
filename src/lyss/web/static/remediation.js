// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
// Remediation page: per-switch "select all" and live progress with percentages (text only).
(function () {
  "use strict";
  document.querySelectorAll("[data-select-device]").forEach(function (box) {
    box.addEventListener("change", function () {
      document.querySelectorAll('input[name="fix"][data-device="' + box.dataset.selectDevice + '"]:not([disabled])')
        .forEach(function (c) { c.checked = box.checked; });
    });
  });

  var panel = document.getElementById("rem-job");
  if (!panel || panel.hidden) return;

  function row(id, it) {
    var li = document.createElement("li");
    li.className = "st-" + it.status;
    var head = document.createElement("div");
    head.className = "rp-head";
    var name = document.createElement("strong");
    name.textContent = id;
    var pct = document.createElement("span");
    pct.className = "rp-pct";
    pct.textContent = (it.percent || 0) + " %";
    head.append(name, pct);
    var bar = document.createElement("div");
    bar.className = "progress";
    var fill = document.createElement("div");
    fill.style.width = (it.percent || 0) + "%";
    bar.append(fill);
    var msg = document.createElement("div");
    msg.className = "rp-msg";
    msg.textContent = it.outcome || it.message || (it.status === "queued" ? "waiting" : it.status);
    li.append(head, bar, msg);
    return li;
  }

  function poll() {
    fetch("/api/remediation", { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (job) {
        var ids = Object.keys(job.items || {});
        var done = ids.filter(function (id) { return ["done", "error"].indexOf(job.items[id].status) >= 0; }).length;
        document.getElementById("rem-count").textContent = done + " / " + ids.length + " switches";
        document.getElementById("rem-pct").textContent = (job.percent || 0) + " %";
        document.getElementById("rem-bar").style.width = (job.percent || 0) + "%";
        var list = document.getElementById("rem-items");
        list.replaceChildren();
        ids.forEach(function (id) { list.append(row(id, job.items[id])); });
        if (job.finished) setTimeout(function () { window.location.reload(); }, 1500);
        else setTimeout(poll, 1000);
      })
      .catch(function () { setTimeout(poll, 3000); });
  }
  poll();
})();
