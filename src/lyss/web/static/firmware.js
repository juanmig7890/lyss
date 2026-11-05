// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
// Firmware page: live progress of the running staging / activation (text only).
(function () {
  "use strict";
  var panel = document.getElementById("fw-job");
  if (!panel || panel.hidden) return;
  function poll() {
    fetch("/api/firmware", { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (job) {
        document.getElementById("fw-title").textContent = (job.action || "") + " " + (job.device || "");
        document.getElementById("fw-msg").textContent = job.message || "";
        if (job.finished) window.location.reload(); else setTimeout(poll, 2000);
      })
      .catch(function () { setTimeout(poll, 4000); });
  }
  poll();
})();
