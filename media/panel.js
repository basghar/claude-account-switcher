(function () {
  const vscode = acquireVsCodeApi();
  let state = { accounts: [], warnThreshold: 80 };

  const listEl = document.getElementById("list");
  const emptyEl = document.getElementById("empty");

  document.getElementById("addBtn").addEventListener("click", () => {
    vscode.postMessage({ type: "add" });
  });
  document.getElementById("loginBtn").addEventListener("click", () => {
    vscode.postMessage({ type: "login" });
  });
  document.getElementById("sayHiBtn").addEventListener("click", () => {
    vscode.postMessage({ type: "sayHiAll" });
  });
  const refreshBtn = document.getElementById("refreshBtn");
  refreshBtn.addEventListener("click", () => {
    vscode.postMessage({ type: "refreshAll" });
  });

  window.addEventListener("message", (event) => {
    const msg = event.data;
    if (msg.type === "state") {
      state = msg;
      render();
    }
  });

  function fmtReset(iso) {
    if (!iso) return "";
    const t = new Date(iso).getTime();
    if (isNaN(t)) return "";
    const diff = t - Date.now();
    if (diff <= 0) return "resets soon";
    const mins = Math.round(diff / 60000);
    if (mins < 60) return `resets in ${mins} min`;
    const hours = Math.floor(mins / 60);
    const rem = mins % 60;
    if (hours < 24) return `resets in ${hours}h ${rem}m`;
    const days = Math.floor(hours / 24);
    return `resets in ${days}d ${hours % 24}h`;
  }

  function fmtAgo(ts) {
    if (!ts) return "no data";
    const diff = Date.now() - ts;
    const s = Math.round(diff / 1000);
    if (s < 60) return `updated ${s}s ago`;
    const m = Math.round(s / 60);
    return `updated ${m} min ago`;
  }

  function meter(w, warn) {
    const cls = w.percent >= warn ? "danger" : w.percent >= warn * 0.75 ? "warn" : "";
    const wrap = document.createElement("div");
    wrap.className = "meter";

    const label = document.createElement("div");
    label.className = "meter-label";
    const left = document.createElement("span");
    left.textContent = w.label;
    const right = document.createElement("span");
    right.textContent = w.percent + "%";
    label.append(left, right);

    const bar = document.createElement("div");
    bar.className = "bar";
    const fill = document.createElement("div");
    fill.className = "fill " + cls;
    fill.style.width = Math.min(100, Math.max(0, w.percent)) + "%";
    bar.appendChild(fill);

    wrap.append(label, bar);
    const reset = fmtReset(w.resetsAt);
    if (reset) {
      const r = document.createElement("div");
      r.className = "reset";
      r.textContent = reset;
      wrap.appendChild(r);
    }
    return wrap;
  }

  // Lucide (MIT) outline paths, drawn inline so they inherit the theme colour and
  // stay crisp at any zoom. Font glyphs like "\u27f3" rendered far too small here.
  const ICONS = {
    refresh: ["M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8", "M21 3v5h-5"],
    pencil: [
      "M21.17 6.81a1 1 0 0 0-3.98-3.99L3.84 16.17a2 2 0 0 0-.5.83l-1.32 4.35a.5.5 0 0 0 .62.63l4.35-1.32a2 2 0 0 0 .83-.5z",
      "m15 5 4 4",
    ],
    trash: [
      "M3 6h18",
      "M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6",
      "M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2",
      "M10 11v6",
      "M14 11v6",
    ],
  };

  function icon(name) {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    for (const d of ICONS[name] || []) {
      const path = document.createElementNS(ns, "path");
      path.setAttribute("d", d);
      svg.appendChild(path);
    }
    return svg;
  }

  function iconButton(name, title, onClick) {
    const b = document.createElement("button");
    b.className = "icon-btn";
    b.appendChild(icon(name));
    b.title = title;
    b.setAttribute("aria-label", title);
    b.addEventListener("click", onClick);
    return b;
  }

  function card(acc, warn) {
    const el = document.createElement("div");
    el.className = "card" + (acc.isActive ? " active" : "");

    const head = document.createElement("div");
    head.className = "card-head";

    const title = document.createElement("div");
    title.className = "title";
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = acc.label;
    title.appendChild(name);
    if (acc.subscriptionType) {
      const plan = document.createElement("span");
      plan.className = "badge";
      plan.textContent = acc.subscriptionType;
      title.appendChild(plan);
    }
    if (acc.isActive) {
      const badge = document.createElement("span");
      badge.className = "badge active";
      badge.textContent = "active";
      title.appendChild(badge);
    }
    head.appendChild(title);

    const headBtns = document.createElement("div");
    headBtns.appendChild(
      iconButton("refresh", "Refresh usage limits", () =>
        vscode.postMessage({ type: "refresh", id: acc.id })
      )
    );
    head.appendChild(headBtns);
    el.appendChild(head);

    if (acc.windows && acc.windows.length) {
      for (const w of acc.windows) {
        el.appendChild(meter(w, warn));
      }
    } else if (!acc.error) {
      const s = document.createElement("div");
      s.className = "sub";
      s.style.marginTop = "8px";
      s.textContent = "No usage data — click the refresh icon";
      el.appendChild(s);
    }

    if (acc.error) {
      const e = document.createElement("div");
      e.className = "error";
      e.textContent = "⚠ " + acc.error;
      el.appendChild(e);
    }

    const foot = document.createElement("div");
    foot.className = "sub";
    foot.style.marginTop = "6px";
    foot.textContent = fmtAgo(acc.fetchedAt);
    el.appendChild(foot);

    const actions = document.createElement("div");
    actions.className = "actions";

    const win = document.createElement("button");
    win.textContent = "Window";
    win.title = "Open this account in an independent VS Code window";
    win.addEventListener("click", () => vscode.postMessage({ type: "openWindow", id: acc.id }));
    actions.appendChild(win);

    if (!acc.isActive) {
      const sw = document.createElement("button");
      sw.className = "primary";
      sw.textContent = "Switch";
      sw.addEventListener("click", () => vscode.postMessage({ type: "switch", id: acc.id }));
      actions.appendChild(sw);

      const hi = document.createElement("button");
      hi.textContent = "Hi";
      hi.title = "Run a one-turn Haiku warmup without switching accounts";
      hi.addEventListener("click", () => vscode.postMessage({ type: "sayHi", id: acc.id }));
      actions.appendChild(hi);
    }

    if (acc.needsReauthorization) {
      const auth = document.createElement("button");
      auth.textContent = "Auth";
      auth.title = "Reauthorize this profile in an isolated Claude login";
      auth.addEventListener("click", () => vscode.postMessage({ type: "reauthorize", id: acc.id }));
      actions.appendChild(auth);
    }

    actions.appendChild(
      iconButton("pencil", "Rename", () => vscode.postMessage({ type: "rename", id: acc.id }))
    );
    actions.appendChild(
      iconButton("trash", "Remove profile", () => vscode.postMessage({ type: "remove", id: acc.id }))
    );
    el.appendChild(actions);

    return el;
  }

  function render() {
    listEl.innerHTML = "";
    const accounts = state.accounts || [];
    if (accounts.length === 0) {
      emptyEl.classList.remove("hidden");
      return;
    }
    emptyEl.classList.add("hidden");
    for (const acc of accounts) {
      listEl.appendChild(card(acc, state.warnThreshold || 80));
    }
  }

  // Refresh countdowns every minute.
  setInterval(render, 60000);

  refreshBtn.appendChild(icon("refresh"));

  vscode.postMessage({ type: "ready" });
})();
