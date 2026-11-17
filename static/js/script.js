/* SecureBrowse — UI behaviour: nav, reveal, scanner, activity table. */
(function () {
  "use strict";

  document.documentElement.classList.add("has-js");

  /* ---------- Sticky nav state ---------- */
  const nav = document.getElementById("nav");
  const onScroll = () => nav.classList.toggle("is-scrolled", window.scrollY > 12);
  onScroll();
  window.addEventListener("scroll", onScroll, { passive: true });

  /* ---------- Mobile menu ---------- */
  const toggle = document.getElementById("nav-toggle");
  const links = document.getElementById("nav-links");
  if (toggle && links) {
    toggle.addEventListener("click", () => {
      const open = links.classList.toggle("is-open");
      toggle.setAttribute("aria-expanded", String(open));
      toggle.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    });
    links.addEventListener("click", (event) => {
      if (event.target.closest("a")) {
        links.classList.remove("is-open");
        toggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  /* ---------- Reveal on scroll ---------- */
  const revealables = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.08 }
    );
    revealables.forEach((element) => observer.observe(element));
  } else {
    revealables.forEach((element) => element.classList.add("is-visible"));
  }

  /* ---------- Active section link ---------- */
  const sectionLinks = Array.from(document.querySelectorAll(".nav__links a"));
  const sections = sectionLinks
    .map((link) => document.querySelector(link.getAttribute("href")))
    .filter(Boolean);
  if ("IntersectionObserver" in window && sections.length) {
    const spy = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          sectionLinks.forEach((link) =>
            link.classList.toggle("is-active", link.getAttribute("href") === "#" + entry.target.id)
          );
        });
      },
      { rootMargin: "-45% 0px -50% 0px" }
    );
    sections.forEach((section) => spy.observe(section));
  }

  /* ---------- Example links ---------- */
  const input = document.getElementById("url-input");
  document.querySelectorAll("[data-fill]").forEach((button) => {
    button.addEventListener("click", () => {
      input.value = button.dataset.fill;
      input.focus();
    });
  });

  /* ---------- Scanner ---------- */
  const form = document.getElementById("scan-form");
  const button = document.getElementById("scan-button");
  const alertBox = document.getElementById("scan-alert");
  const panel = document.getElementById("scan-result");
  const scoreEl = document.getElementById("result-score");
  const badgeEl = document.getElementById("result-badge");
  const domainEl = document.getElementById("result-domain");
  const urlEl = document.getElementById("result-url");
  const reasonEl = document.getElementById("result-reason");
  const findingsEl = document.getElementById("result-findings");
  const findingCount = document.getElementById("finding-count");
  const sourcesEl = document.getElementById("result-sources");
  const sourceCount = document.getElementById("source-count");
  const footEl = document.getElementById("result-foot");
  const gaugeFill = document.getElementById("gauge-fill");
  const GAUGE_LENGTH = 251.3;

  const STATE_TEXT = {
    match: "match",
    clear: "clear",
    error: "error",
    not_configured: "not checked",
  };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function setAlert(message) {
    alertBox.textContent = message;
    alertBox.hidden = !message;
  }

  function renderResult(result) {
    panel.hidden = false;
    panel.dataset.level = result.level;

    scoreEl.textContent = String(result.score);
    badgeEl.textContent = result.level_label;
    badgeEl.className = "badge badge--" + result.level;
    domainEl.textContent = result.domain;
    urlEl.textContent = result.url;
    reasonEl.textContent = result.reason;

    // Gauge animates from empty to the new score.
    gaugeFill.style.strokeDashoffset = String(GAUGE_LENGTH);
    const offset = GAUGE_LENGTH * (1 - Math.min(100, Math.max(0, result.score)) / 100);
    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => {
        gaugeFill.style.strokeDashoffset = String(offset);
      });
    });

    findingsEl.replaceChildren();
    if (!result.findings.length) {
      findingsEl.appendChild(
        el("li", "findings__empty", "No suspicious structure was found in this address.")
      );
    } else {
      result.findings.forEach((finding) => {
        const item = el("li");
        item.dataset.sev = finding.severity;
        item.appendChild(el("b", null, finding.label));
        item.appendChild(el("span", "w", "+" + finding.weight));
        item.appendChild(el("span", null, finding.detail));
        findingsEl.appendChild(item);
      });
    }
    findingCount.textContent = String(result.findings.length);

    sourcesEl.replaceChildren();
    result.sources.forEach((source) => {
      const item = el("li");
      const left = el("div");
      left.appendChild(el("span", "s-name", source.source));
      left.appendChild(el("span", "s-detail", source.detail));
      const state = el("span", "s-state", STATE_TEXT[source.status] || source.status);
      state.dataset.state = source.status;
      item.append(left, state);
      sourcesEl.appendChild(item);
    });
    sourceCount.textContent = result.sources_checked + "/" + result.sources_total;

    let foot = "Checked " + result.sources_checked + " of " + result.sources_total + " threat sources.";
    if (result.incomplete) {
      foot += " Incomplete scan: " + result.unavailable.join(", ") + " could not be checked.";
    }
    foot += " " + result.disclaimer;
    footEl.textContent = foot;
  }

  function renderHistory(payload) {
    const body = document.getElementById("activity-body");
    const empty = document.getElementById("activity-empty");
    if (!body) return;

    body.replaceChildren();
    payload.history.forEach((row) => {
      const tr = document.createElement("tr");

      const domain = el("td", "activity__domain", row.domain);
      domain.title = row.url;

      const levelCell = document.createElement("td");
      levelCell.appendChild(el("span", "badge badge--sm badge--" + row.level, row.level_label));
      if (row.incomplete) levelCell.appendChild(el("span", "mini", "incomplete"));

      tr.append(
        domain,
        levelCell,
        el("td", "activity__score", String(row.score)),
        el("td", "activity__when", row.when)
      );
      body.appendChild(tr);
    });

    empty.hidden = payload.history.length > 0;

    const stats = payload.stats;
    const map = { "stat-total": stats.total, "stat-high": stats.high, "stat-medium": stats.medium, "stat-low": stats.low };
    Object.keys(map).forEach((id) => {
      const node = document.getElementById(id);
      if (node) node.textContent = String(map[id]);
    });
  }

  if (form) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const value = input.value.trim();
      setAlert("");

      if (!value) {
        setAlert("Enter a URL to analyse.");
        input.focus();
        return;
      }

      button.disabled = true;
      button.classList.add("is-loading");
      button.querySelector(".btn__label").textContent = "Analysing";

      try {
        const response = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: value }),
        });
        const payload = await response.json();

        if (!response.ok || !payload.ok) {
          setAlert(payload.error || "That address could not be analysed.");
          panel.hidden = true;
          return;
        }

        renderResult(payload.result);
        renderHistory(payload);
        panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
      } catch (error) {
        setAlert("The analyser did not respond. Check that the Flask server is running and try again.");
      } finally {
        button.disabled = false;
        button.classList.remove("is-loading");
        button.querySelector(".btn__label").textContent = "Analyse URL";
      }
    });
  }
})();
