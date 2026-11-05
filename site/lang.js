// Language switch (English / French). Remembers the choice; defaults to the browser language.
(function () {
  var root = document.documentElement;
  function apply(lang) {
    root.setAttribute("data-lang", lang);
    root.setAttribute("lang", lang);
    document.querySelectorAll("[data-set-lang]").forEach(function (b) {
      b.setAttribute("aria-pressed", String(b.getAttribute("data-set-lang") === lang));
    });
  }
  var saved = null;
  try { saved = localStorage.getItem("lyss-lang"); } catch (e) {}
  apply(saved || ((navigator.language || "en").toLowerCase().indexOf("fr") === 0 ? "fr" : "en"));
  document.querySelectorAll("[data-set-lang]").forEach(function (b) {
    b.addEventListener("click", function () {
      var lang = b.getAttribute("data-set-lang");
      apply(lang);
      try { localStorage.setItem("lyss-lang", lang); } catch (e) {}
    });
  });
})();
