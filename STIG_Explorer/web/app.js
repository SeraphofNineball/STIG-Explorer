/* STIG Explorer front end. Works from file:// (data loaded via <script>) or
 * from the container web server. All data strings are HTML-escaped before
 * insertion. */
(function () {
  "use strict";

  const D = window.STIG_DATA;
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));

  if (!D) {
    $("#dataInfo").textContent = "Data file not found. Run: python -m stig_explorer.build";
    return;
  }

  // ---------------------------------------------------------------- helpers
  const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ESC[c]);
  const store = {
    get(k, d) { try { const v = localStorage.getItem("stigx." + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { try { localStorage.setItem("stigx." + k, JSON.stringify(v)); } catch { /* storage unavailable */ } },
  };
  const SEV_ORDER = { high: 0, medium: 1, low: 2 };
  const ROLE_LABEL = { dc: "Domain controller only", ms: "Member server only" };
  const SHELL_LABEL = { powershell: "PowerShell", cmd: "CMD", bash: "Bash" };
  const SRC_LABEL = { disa: "From DISA check text", generated: "Generated from the setting", curated: "STIG Explorer command" };
  const SEV_LABEL = { high: "CAT I", medium: "CAT II", low: "CAT III" };
  const LEVELS = {
    generic: ["L3", "General Audience", "Plain language for readers with limited security or IT background"],
    admin: ["L2", "System Administrator", "What changes, where it lives, how to check and fix it"],
    pro: ["L1", "Cyber Security Professional", "Risk, threat context, ATT&CK and NIST 800-53 mapping"],
  };
  const TYPE_SHORT = { registry: "Registry", gpo: "Group Policy", sysctl: "sysctl", audit_rule: "Audit rule",
    config: "Config file", dconf: "dconf", service: "Service", package: "Package", permission: "Permission",
    feature: "Feature", command: "Command" };

  const stigByKey = Object.fromEntries(D.stigs.map((s) => [s.key, s]));
  const stigOrder = Object.fromEntries(D.stigs.map((s, i) => [s.key, i]));  // build order: platform, then version
  const byStig = (a, b) => stigOrder[a.stig] - stigOrder[b.stig];
  // Topic text for an OS family (rhel/ubuntu/windows), falling back to the platform (linux/windows).
  const topicTxt = (t, f, plat, os) => { const v = t[f]; return v && typeof v === "object" ? (v[os] || v[plat] || Object.values(v)[0]) : (v || ""); };
  const nist = (r, rev) => { const out = []; for (const c of r.ccis) for (const i of (D.ccis[c]?.[rev] || [])) if (!out.includes(i)) out.push(i); return out; };
  const normCtl = (s) => s.toUpperCase().replace(/\s+/g, "");

  // Custom tags (e.g. FMCC) compiled from tags/*.csv into data/tags.js. Optional.
  const TAGS = window.STIG_TAGS || { tags: [], rules: {} };
  const tagDef = Object.fromEntries(TAGS.tags.map((t) => [t.id, t]));
  for (const r of D.rules) {
    r._tags = (TAGS.rules[r.id] || []).filter(([t]) => tagDef[t]);   // [[tagId, [notes]]]
    r._tagLabels = r._tags.map(([t]) => tagDef[t].label);
  }

  // Precompute search haystacks and per-rule data.
  for (const r of D.rules) {
    const s = r.settings.map((x) => `${x.target} ${x.name} ${x.value}`).join(" ");
    const t = r.topics.map((id) => D.topics[id].name).join(" ");
    const n = ["rev3", "rev4", "rev5"].map((rev) => nist(r, rev).join(" ")).join(" ");
    r._hay = [r.title, r.vuln_id, r.stig_id, r.id, r.srg, r.ccis.join(" "), n, s, t, stigByKey[r.stig].product,
      r.discussion, r.fix, r.check, (r.legacy_ids || []).join(" "), (r.validate || []).map((v) => v.cmd).join("\n"),
      ROLE_LABEL[r.role] || "", r._tags.map(([t]) => `${tagDef[t].label} ${tagDef[t].name}`).join(" ")].join("\n").toLowerCase();
    r._nist = { rev3: nist(r, "rev3"), rev4: nist(r, "rev4"), rev5: nist(r, "rev5") };
  }
  const eqGroups = {};
  for (const r of D.rules) if (r.eq !== null && r.eq !== undefined) (eqGroups[r.eq] ||= []).push(r);
  const ruleById = Object.fromEntries(D.rules.map((r) => [r.id, r]));

  // ------------------------------------------------------------------ state
  const state = {
    q: "",
    stigs: new Set(store.get("stigs", D.stigs.map((s) => s.key)).filter((k) => stigByKey[k])),
    sev: new Set(["high", "medium", "low"]),
    topic: "", rev: "rev5", family: "", control: "", impl: "", doc: false, role: "", tags: new Set(),
    sort: "stig", level: store.get("level", "generic"), view: "rules",
    results: [], shown: 0, selected: null,
  };
  if (!state.stigs.size) D.stigs.forEach((s) => state.stigs.add(s.key));
  const PAGE = 120;

  // -------------------------------------------------------------- filters UI
  function buildFilters() {
    const counts = {};
    for (const r of D.rules) counts[r.stig] = (counts[r.stig] || 0) + 1;
    const groups = { rhel: "Red Hat Enterprise Linux", ubuntu: "Canonical Ubuntu", windows: "Microsoft Windows" };
    let html = "";
    for (const [plat, label] of Object.entries(groups)) {
      const ss = D.stigs.filter((s) => s.family === plat);
      if (!ss.length) continue;
      html += `<div class="group-label">${esc(label)} <a class="link-btn small" data-only="${plat}">only</a></div>`;
      for (const s of ss) {
        html += `<label class="check"><input type="checkbox" data-stig="${esc(s.key)}" ${state.stigs.has(s.key) ? "checked" : ""}>
          ${esc(shortProduct(s.product))}
          <span class="count">${esc(s.label)} · ${counts[s.key] || 0}</span></label>`;
      }
    }
    const servers = D.stigs.filter((s) => s.key.includes("SERVER"));
    if (servers.length) {
      html += `<div class="group-label">Domain controller views</div>`;
      for (const s of servers) {
        const n = D.rules.filter((r) => r.stig === s.key && (r.role === "dc" || r.role === "both")).length;
        const only = D.rules.filter((r) => r.stig === s.key && r.role === "dc").length;
        html += `<a class="dc-link" data-dcview="${esc(s.key)}" title="Show only the ${esc(shortProduct(s.product))} rules that apply to domain controllers">
          ${esc(shortProduct(s.product))} DC<span class="count">${n} rules · ${only} DC-only</span></a>`;
      }
    }
    $("#stigFilters").innerHTML = html;
    if (TAGS.tags.length) {
      $("#tagSection").hidden = false;
      $("#tagFilters").innerHTML = TAGS.tags.map((t) =>
        `<label class="check" title="${esc(t.description || t.name)}"><input type="checkbox" data-tag="${esc(t.id)}">
          <span class="tag-badge" data-tagcolor="${esc(t.color)}">${esc(t.label)}</span> ${esc(t.name)}
          <span class="count">${t.count}</span></label>` +
        (t.count ? "" : `<p class="small muted">No rules tagged yet. Add IDs to tags/${esc(t.source)} and run <code>python -m stig_explorer.tags</code>.</p>`)).join("");
      paintTags($("#tagFilters"));
    }
    $("#sevFilters").innerHTML = ["high", "medium", "low"].map((k) =>
      `<label class="check"><input type="checkbox" data-sev="${k}" checked> <span class="sev ${k}">${SEV_LABEL[k]}</span> ${k}</label>`).join("");

    const tc = {};
    for (const r of D.rules) tc[r.topics[0]] = (tc[r.topics[0]] || 0) + 1;
    $("#topicFilter").innerHTML += Object.entries(D.topics).sort((a, b) => a[1].name.localeCompare(b[1].name))
      .map(([id, t]) => `<option value="${esc(id)}">${esc(t.name)} (${tc[id] || 0})</option>`).join("");

    const impl = new Set(); D.rules.forEach((r) => r.setting_cats.forEach((c) => impl.add(c)));
    $("#implFilter").innerHTML += [...impl].sort().map((c) => `<option>${esc(c)}</option>`).join("");
    buildFamilies();
  }

  function buildFamilies() {
    const fam = {};
    for (const r of D.rules) for (const f of new Set(r._nist[state.rev].map((i) => i.slice(0, 2)))) fam[f] = (fam[f] || 0) + 1;
    const cur = state.family;
    $("#familyFilter").innerHTML = `<option value="">All control families</option>` + Object.keys(fam).sort().map((f) =>
      `<option value="${esc(f)}" ${f === cur ? "selected" : ""}>${esc(f)}: ${esc(D.meta.families[f] || "")} (${fam[f]})</option>`).join("");
  }

  // ---------------------------------------------------------------- search
  function parseQuery(q) {
    const terms = [], neg = [];
    const re = /(-?)"([^"]+)"|(-?)(\S+)/g;
    let m;
    while ((m = re.exec(q))) {
      const isNeg = (m[1] || m[3]) === "-";
      const t = (m[2] || m[4] || "").toLowerCase();
      if (!t || t === "-") continue;
      (isNeg ? neg : terms).push(t);
    }
    return { terms, neg };
  }

  function ctlMatch(list, q) {
    const nq = normCtl(q);
    return list.some((i) => { const n = normCtl(i); return n.startsWith(nq) && !/\d/.test(n.charAt(nq.length)); });
  }

  function runSearch() {
    const { terms, neg } = parseQuery(state.q);
    const out = [];
    for (const r of D.rules) {
      if (!state.stigs.has(r.stig) || !state.sev.has(r.severity)) continue;
      if (state.topic && !r.topics.includes(state.topic)) continue;
      if (state.impl && !r.setting_cats.includes(state.impl)) continue;
      if (state.doc && !r.documentable) continue;
      if (state.tags.size && !r._tags.some(([t]) => state.tags.has(t))) continue;
      if (state.role) {
        if (!r.role) continue;
        if (state.role === "dc" && r.role === "ms") continue;
        if (state.role === "ms" && r.role === "dc") continue;
        if (state.role === "dc-only" && r.role !== "dc") continue;
        if (state.role === "ms-only" && r.role !== "ms") continue;
      }
      const nl = r._nist[state.rev];
      if (state.family && !nl.some((i) => i.startsWith(state.family + "-"))) continue;
      if (state.control && !ctlMatch(nl, state.control)) continue;
      let ok = true;
      for (const t of terms) if (!r._hay.includes(t)) { ok = false; break; }
      if (!ok) continue;
      for (const t of neg) if (r._hay.includes(t)) { ok = false; break; }
      if (!ok) continue;
      out.push(r);
    }
    const tl = (r) => r.title.toLowerCase();
    if (terms.length) {
      // Rank: exact ID hits, then title hits, then everything else.
      const score = (r) => {
        let s = 0;
        for (const t of terms) {
          if (r.vuln_id.toLowerCase() === t || r.stig_id.toLowerCase() === t || r.id.toLowerCase() === t) s += 100;
          if (tl(r).includes(t)) s += 10;
          if (r.settings.some((x) => (x.name + " " + x.target).toLowerCase().includes(t))) s += 4;
        }
        return s;
      };
      out.forEach((r) => (r._score = score(r)));
    } else out.forEach((r) => (r._score = 0));
    const cmp = {
      stig: (a, b) => byStig(a, b) || a.stig_id.localeCompare(b.stig_id),
      sev: (a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || byStig(a, b) || a.stig_id.localeCompare(b.stig_id),
      topic: (a, b) => D.topics[a.topics[0]].name.localeCompare(D.topics[b.topics[0]].name) || a.stig_id.localeCompare(b.stig_id),
    }[state.sort];
    out.sort((a, b) => (b._score - a._score) || cmp(a, b));
    state.results = out;
    state.shown = 0;
    $("#list").innerHTML = "";
    renderMore();
    const c = { high: 0, medium: 0, low: 0 };
    out.forEach((r) => c[r.severity]++);
    $("#resultCount").textContent = `${out.length.toLocaleString()} of ${D.rules.length.toLocaleString()} rules`;
    $("#sevSummary").innerHTML = ["high", "medium", "low"].map((k) => `<span class="sev ${k}">${SEV_LABEL[k]} ${c[k]}</span>`).join(" ");
    if (window.STIGX_SCRIPT) {
      const n = window.STIGX_SCRIPT.counts(out);
      $("#ps1Count").textContent = `${n.windows.toLocaleString()} Windows rules`;
      $("#shCount").textContent = `${n.linux.toLocaleString()} Linux rules`;
      $$("#scriptMenu [data-script]").forEach((b) => (b.disabled = !(b.dataset.script === "ps1" ? n.windows : n.linux)));
    }
  }

  function highlight(text, terms) {
    let h = esc(text);
    for (const t of terms) {
      if (t.length < 2) continue;
      const re = new RegExp("(" + esc(t).replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")", "ig");
      h = h.replace(/(<[^>]*>)|([^<]+)/g, (m, tag, txt) => tag || txt.replace(re, "<mark>$1</mark>"));
    }
    return h;
  }

  function renderMore() {
    const { terms } = parseQuery(state.q);
    const slice = state.results.slice(state.shown, state.shown + PAGE);
    const html = slice.map((r) => {
      const s = stigByKey[r.stig];
      const t = D.topics[r.topics[0]];
      return `<li class="rule-item" data-id="${esc(r.id)}" tabindex="0" ${state.selected === r ? 'aria-current="true"' : ""}>
        <span class="sev ${esc(r.severity)}">${SEV_LABEL[r.severity]}</span>
        <div class="title">${tagBadges(r)}${highlight(r.title, terms)}</div>
        <div class="meta"><span class="chip ${esc(s.family)}">${esc(shortProduct(s.product))}</span>
          <span>${esc(r.stig_id)}</span><span>${esc(r.vuln_id)}</span>${roleChip(r)}<span class="chip">${esc(t.name)}</span></div>
      </li>`;
    }).join("");
    $("#list").insertAdjacentHTML("beforeend", html);
    paintTags($("#list"));
    state.shown += slice.length;
    const more = $("#moreBtn");
    more.hidden = state.shown >= state.results.length;
    more.textContent = `Show more (${(state.results.length - state.shown).toLocaleString()} remaining)`;
  }

  const roleChip = (r) => (ROLE_LABEL[r.role] ? `<span class="chip role-${esc(r.role)}">${esc(ROLE_LABEL[r.role])}</span>` : "");

  const shortProduct = (p) => p.replace("Red Hat Enterprise Linux", "RHEL").replace("Microsoft ", "").replace("Canonical ", "");

  // ---------------------------------------------------------------- detail
  function selectRule(r, push = true) {
    state.selected = r;
    $$(".rule-item").forEach((el) => (el.dataset.id === r.id
      ? el.setAttribute("aria-current", "true") : el.removeAttribute("aria-current")));
    renderDetail();
    $("#detail").classList.add("open");
    $("#detail").scrollTop = 0;
    if (push) history.replaceState(null, "", "#rule=" + encodeURIComponent(r.id));
  }

  function levelBlock(key, inner) {
    const [badge, name, sub] = LEVELS[key];
    return `<section class="level-block"><header><span class="badge ${key}">${badge}</span><h3>${esc(name)}</h3>
      <span class="muted small">${esc(sub)}</span></header><div class="level-body">${inner}</div></section>`;
  }

  function codeBlock(label, text, id) {
    return `<div class="code-head"><h4>${esc(label)}</h4><button class="copy" data-copy="${esc(id)}">Copy</button></div>
      <pre class="code" id="${esc(id)}">${esc(text)}</pre>`;
  }

  function genericHtml(r) {
    const t = D.topics[r.topics[0]];
    const [sl, sp] = D.meta.severity_plain[r.severity];
    let h = `<h4>In plain terms</h4><p class="plain-lead">${esc(r.plain)}</p>
      <h4>Why it matters</h4><p>${esc(t.generic)}</p>
      <h4>How important is it?</h4><p class="callout"><span class="sev ${esc(r.severity)}">${esc(sl)}</span> ${esc(sp)}</p>`;
    if (r.glossary.length) {
      h += `<h4>Key terms</h4><dl class="gloss">${r.glossary.map((g) => `<dt>${esc(g.term)}</dt><dd>${esc(g.definition)}</dd>`).join("")}</dl>`;
    }
    return h;
  }

  function settingsTable(r) {
    const real = r.settings.filter((s) => s.type !== "command");
    if (!real.length) {
      return `<p>No single machine-readable setting was extracted. This rule is implemented via <b>${esc(r.setting_cats.join(", "))}</b>. See the fix procedure below.</p>`;
    }
    return `<div class="tablewrap"><table class="settings"><thead><tr><th>Type</th><th>Location</th><th>Setting</th><th>Required value</th></tr></thead><tbody>
      ${real.map((s) => `<tr><td data-label="Type">${esc(TYPE_SHORT[s.type] || s.type)}</td><td data-label="Location"><code>${esc(s.target)}</code></td>
        <td data-label="Setting"><code>${esc(s.name)}</code></td><td data-label="Required value">${esc(s.value)}</td></tr>`).join("")}</tbody></table></div>`;
  }

  function unsafeNote(cmd) {
    const S = window.STIGX_SCRIPT;
    if (!S || S.approvedCommand(cmd)) return "";
    const why = S.unsafeReason(cmd.cmd) || "is not on the approved read-only export allowlist";
    return `<p class="val-warn">⚠ Manual review: this command ${esc(why)}. It will not run automatically in exported scripts.</p>`;
  }

  function validationHtml(r) {
    const v = r.validate || [];
    let h = `<h4>Command-line validation</h4>`;
    if (!v.length) {
      return h + `<p class="muted">No single command can validate this rule. It is a procedural or manual check, so follow the DISA check procedure below.</p>`;
    }
    h += `<p class="small muted">Review a command before copying it into ${r.platform === "windows" ? "PowerShell or Command Prompt (run as Administrator where noted)" : "a terminal"} instead of browsing ${r.platform === "windows" ? "the Group Policy editor" : "configuration files"}. Some original checks can change settings or expose sensitive data. Only allowlisted read-only queries are included in exported scripts. DISA's check procedure remains the authoritative test.</p>`;
    v.forEach((c, i) => {
      const id = `val-${r.vuln_id}-${i}`;
      h += `<div class="val"><div class="val-head"><span class="shell ${esc(c.shell)}">${esc(SHELL_LABEL[c.shell] || c.shell)}</span>
        <span class="muted small">${esc(SRC_LABEL[c.src] || "")}</span><span class="spacer"></span><button class="copy" data-copy="${esc(id)}">Copy</button></div>
        <pre class="code" id="${esc(id)}">${esc(c.cmd)}</pre>${c.expect ? `<p class="val-expect"><b>Expected:</b> ${esc(c.expect)}</p>` : ""}
        ${unsafeNote(c)}</div>`;
    });
    return h;
  }

  function adminHtml(r) {
    const ts = r.topics.map((id) => D.topics[id]);
    const p = r.platform;
    const cmds = r.settings.filter((s) => s.type === "command").map((s) => s.name);
    let h = `<h4>Settings changed</h4>${settingsTable(r)}`;
    h += validationHtml(r);
    if (cmds.length) h += `<h4>Remediation commands</h4><pre class="code">${esc(cmds.map((c) => "$ sudo " + c).join("\n"))}</pre>`;
    h += `<h4>How it works</h4><p>${esc(topicTxt(ts[0], "admin", p, r.os))}</p>`;
    if (ts[1]) h += `<h4>Also related: ${esc(ts[1].name)}</h4><p>${esc(topicTxt(ts[1], "admin", p, r.os))}</p>`;
    h += `<h4>Operational impact</h4><p>${esc(topicTxt(ts[0], "impact", p, r.os))}</p>`;
    if (r.potential_impacts) h += `<h4>DISA-noted potential impacts</h4><p>${esc(r.potential_impacts)}</p>`;
    h += codeBlock("Check procedure (DISA)", r.check, "chk-" + r.vuln_id);
    h += codeBlock("Fix procedure (DISA)", r.fix, "fix-" + r.vuln_id);
    return h;
  }

  function proHtml(r) {
    const ts = r.topics.map((id) => D.topics[id]);
    const seen = new Set(); const att = [];
    for (const t of ts) for (const [id, name] of t.attack) if (!seen.has(id)) { seen.add(id); att.push([id, name]); }
    let h = `<h4>Vulnerability discussion (DISA)</h4><p>${esc(r.discussion).replace(/\n\n/g, "</p><p>")}</p>
      <h4>Threat &amp; control context</h4><p>${esc(ts[0].pro)}</p>`;
    if (att.length) {
      h += `<h4>MITRE ATT&amp;CK techniques</h4><ul class="attack">${att.map(([id, n]) =>
        `<li><code>${esc(id)}</code> ${esc(n)}</li>`).join("")}</ul>`;
    }
    h += `<h4>Severity</h4><p>${esc(D.meta.severity_text[r.severity])}</p>`;
    h += `<h4>Compliance mapping (CCI → NIST SP 800-53)</h4>`;
    for (const c of r.ccis) {
      const i = D.ccis[c] || {};
      h += `<div class="cci"><b>${esc(c)}</b>: ${esc(i.definition || "")}
        <div class="revs"><b>Rev 5:</b> ${esc((i.rev5 || []).join(", ") || "n/a")} &nbsp;·&nbsp; <b>Rev 4:</b> ${esc((i.rev4 || []).join(", ") || "n/a")}
        &nbsp;·&nbsp; <b>Rev 3:</b> ${esc((i.rev3 || []).join(", ") || "n/a")}</div></div>`;
    }
    if (r.mitigations) h += `<h4>Mitigations (DISA)</h4><p>${esc(r.mitigations)}</p>`;
    if (r.severity_override) h += `<h4>Severity override guidance</h4><p>${esc(r.severity_override)}</p>`;
    if (r.third_party_tools) h += `<h4>Third-party tools</h4><p>${esc(r.third_party_tools)}</p>`;
    h += `<h4>Assessment notes</h4><table class="kv">
      <tr><th>SRG</th><td>${esc(r.srg)}</td></tr>
      <tr><th>Documentable</th><td>${r.documentable ? "Yes: deviation may be documented with the ISSO/AO" : "No"}</td></tr>
      ${r.legacy_ids ? `<tr><th>Legacy IDs</th><td>${esc(r.legacy_ids.join(", "))}</td></tr>` : ""}</table>`;
    return h;
  }

  function renderDetail() {
    const r = state.selected;
    if (!r) return;
    const s = stigByKey[r.stig];
    const lvl = state.level;
    let body = "";
    const order = ["generic", "admin", "pro"];
    for (const k of order) {
      if (lvl !== "all" && lvl !== k) continue;
      body += levelBlock(k, k === "generic" ? genericHtml(r) : k === "admin" ? adminHtml(r) : proHtml(r));
    }
    const eq = (r.eq !== null && r.eq !== undefined ? eqGroups[r.eq] : []).filter((x) => x !== r);
    const eqHtml = eq.length ? `<section class="level-block"><header><h3>Related rules in other STIGs</h3>
      <span class="muted small">Same requirement or setting on other platforms/versions</span></header>
      <div class="level-body"><ul class="eq-list">${eq.sort(byStig).map((x) =>
        `<li><span class="chip ${esc(stigByKey[x.stig].family)}">${esc(shortProduct(stigByKey[x.stig].product))}</span>
         <a data-goto="${esc(x.id)}">${esc(x.stig_id)}</a> <span class="sev ${esc(x.severity)}">${SEV_LABEL[x.severity]}</span>
         <span class="muted">${esc(x.title)}</span></li>`).join("")}</ul></div></section>` : "";
    const nist5 = r._nist.rev5.join(", ");
    $("#detail").innerHTML = `
      <div class="d-head">
        <button class="btn ghost close-detail" id="closeDetail">← Back to results</button>
        <div class="d-ids"><span class="sev ${esc(r.severity)}">${SEV_LABEL[r.severity]}</span>
          <span class="chip ${esc(s.family)}">${esc(s.product)} ${esc(s.label)}</span>
          <code>${esc(r.vuln_id)}</code><code>${esc(r.stig_id)}</code><code>${esc(r.id)}</code>${roleChip(r)}</div>
        <h2>${tagBadges(r)}${esc(r.title)}</h2>
        ${r._tags.map(([t, notes]) => `<p class="tag-callout" data-tagcolor="${esc(tagDef[t].color)}"><span class="tag-badge" data-tagcolor="${esc(tagDef[t].color)}">${esc(tagDef[t].label)}</span>
          <b>${esc(tagDef[t].name)}</b>${notes.length ? `: ${esc(notes.join("; "))}` : ""}</p>`).join("")}
        <div class="d-ids">${r.topics.map((t) => `<span class="chip topic" data-topic="${esc(t)}" title="Filter by this topic">${esc(D.topics[t].name)}</span>`).join("")}
          ${r.ccis.map((c) => `<span class="chip">${esc(c)}</span>`).join("")}
          ${nist5 ? `<span class="chip" title="NIST SP 800-53 Rev 5">800-53r5: ${esc(nist5)}</span>` : ""}</div>
        <div class="d-actions">
          <button class="btn ghost" id="copyLink">Copy link</button>
          <button class="btn ghost" id="copyMd">Copy as Markdown</button>
          <button class="btn ghost" id="printBtn">Print</button>
        </div>
      </div>
      ${body}${eqHtml}
      <p class="disclaimer">Check/fix procedures, vulnerability discussion and CCI definitions are quoted from DISA. Topic explanations,
      threat context and plain-language text are STIG Explorer guidance. The DISA STIG remains the authoritative source.</p>`;
    paintTags($("#detail"));
  }

  function tagBadges(r) {
    return r._tags.map(([t]) => `<span class="tag-badge" data-tagcolor="${esc(tagDef[t].color)}" title="${esc(tagDef[t].name)}">${esc(tagDef[t].label)}</span>`).join("");
  }

  // Tag colors come from the tag files. They're applied through the CSSOM rather than inline
  // style attributes so the server's Content-Security-Policy (style-src 'self') allows them.
  function paintTags(el) {
    el.querySelectorAll("[data-tagcolor]").forEach((n) => {
      if (/^#[0-9a-f]{6}$/i.test(n.dataset.tagcolor)) n.style.setProperty("--tag", n.dataset.tagcolor);
    });
  }

  function ruleMarkdown(r) {
    const s = stigByKey[r.stig];
    const t = D.topics[r.topics[0]];
    const p = r.platform;
    const set = r.settings.filter((x) => x.type !== "command").map((x) => `- ${TYPE_SHORT[x.type]}: \`${x.target}\` → \`${x.name}\` = ${x.value}`).join("\n");
    return `## ${r._tagLabels.map((l) => `[${l}] `).join("")}${r.vuln_id} · ${r.stig_id} · ${SEV_LABEL[r.severity]}: ${r.title}
*${s.product} ${s.label}* | CCI: ${r.ccis.join(", ")} | NIST 800-53 Rev 5: ${r._nist.rev5.join(", ") || "n/a"} | Rev 3: ${r._nist.rev3.join(", ") || "n/a"}

### General audience
${r.plain}

${t.generic}

### System administrator
${set || "_No single machine-readable setting; see fix text._"}

**Command-line validation:**
${(r.validate || []).map((v) => `- ${SHELL_LABEL[v.shell]}: \`${v.cmd}\`${v.expect ? ` (expected: ${v.expect})` : ""}`).join("\n") || "_Procedural/manual check; follow the DISA check procedure._"}

${topicTxt(t, "admin", p, r.os)}

**Check:**
\`\`\`
${r.check}
\`\`\`
**Fix:**
\`\`\`
${r.fix}
\`\`\`

### Cyber security professional
${r.discussion}

${t.pro}
`;
  }

  // ---------------------------------------------------------------- topics
  function renderTopics() {
    const tc = {};
    for (const r of D.rules) tc[r.topics[0]] = (tc[r.topics[0]] || 0) + 1;
    const lvl = state.level === "all" ? "generic" : state.level;
    $("#topicGrid").innerHTML = Object.entries(D.topics).sort((a, b) => (tc[b[0]] || 0) - (tc[a[0]] || 0)).map(([id, t]) => {
      let body;
      if (lvl === "generic") body = `<p>${esc(t.generic)}</p>`;
      else if (lvl === "admin") body = [["RHEL", "linux", "rhel"], ["Ubuntu", "linux", "ubuntu"], ["Windows", "windows", "windows"]]
        .map(([label, plat, os]) => `<p><b>${label}:</b> ${esc(topicTxt(t, "admin", plat, os))}</p>`).join("");
      else body = `<p>${esc(t.pro)}</p>${t.attack.length ? `<p class="small muted">ATT&amp;CK: ${t.attack.map(([a, b]) => esc(a + " " + b)).join("; ")}</p>` : ""}`;
      return `<div class="topic-card"><h3>${esc(t.name)}</h3><p class="muted small">${esc(t.short)}</p>${body}
        <div class="foot"><span class="muted small">${tc[id] || 0} rules</span><button class="btn ghost" data-topicgo="${esc(id)}">View rules →</button></div></div>`;
    }).join("");
  }

  function renderAbout() {
    const rows = D.stigs.map((s) => {
      const rs = D.rules.filter((r) => r.stig === s.key);
      const c = { high: 0, medium: 0, low: 0 }; rs.forEach((r) => c[r.severity]++);
      return `<tr><td>${esc(s.product)}</td><td>${esc(s.label)}</td><td>${esc(s.date)}</td><td>${rs.length}</td><td>${c.high}</td><td>${c.medium}</td><td>${c.low}</td></tr>`;
    }).join("");
    $("#about").innerHTML = `
      <h2>About STIG Explorer</h2>
      <p>STIG Explorer makes the DISA Security Technical Implementation Guides (STIGs) for Red Hat Enterprise Linux, Canonical Ubuntu and Microsoft Windows
      desktop and server operating systems searchable, and explains every rule at three levels:</p>
      <ul>
        <li><b>General Audience (L3):</b> plain language and an everyday analogy.</li>
        <li><b>System Administrator (L2):</b> the exact registry values, Group Policy paths, config-file lines, kernel parameters, services,
          packages and audit rules a rule changes, plus how to verify and fix it and the operational impact.</li>
        <li><b>Cyber Security Professional (L1):</b> DISA's vulnerability discussion, threat context, MITRE ATT&amp;CK techniques, and the CCI to
          NIST SP 800-53 Revision 3 / 4 / 5 control mapping.</li>
      </ul>
      <h2>Content</h2>
      <p>Data generated ${esc(D.meta.generated)} from ${esc(D.meta.source)}. ${D.rules.length.toLocaleString()} rules.</p>
      <table><thead><tr><th>STIG</th><th>Release</th><th>Benchmark date</th><th>Rules</th><th>CAT I</th><th>CAT II</th><th>CAT III</th></tr></thead><tbody>${rows}</tbody></table>
      <h2>Search tips</h2>
      <ul>
        <li>All words must match (AND). Use <code>"quoted phrases"</code> and <code>-word</code> to exclude.</li>
        <li>Search by any identifier: <code>V-257777</code>, <code>RHEL-09-211010</code>, <code>WN22-SO-000150</code>, <code>CCI-000366</code>, <code>AC-7</code>.</li>
        <li>Search by setting: <code>RestrictAnonymous</code>, <code>sshd_config</code>, <code>net.ipv4</code>, <code>faillock</code>, <code>LmCompatibilityLevel</code>.</li>
        <li>Use the NIST filter to pick a revision (Rev 5/4/3) and a control family or a specific control such as <code>IA-5(1)</code>.</li>
        <li>Links to a rule (<b>Copy link</b>) open that rule directly.</li>
      </ul>
      <h2>Keeping it current</h2>
      <p>Run <code>python -m stig_explorer.build --fetch --docs</code> to download the newest DISA releases and regenerate this data plus the Markdown/Word documents.</p>
      <h2>Disclaimer</h2>
      <p>Check/fix text, vulnerability discussions and CCI definitions are DISA's. Topic explanations, threat context and plain-language summaries
      are written guidance generated by this tool and are not DISA-authoritative. Always validate against the official STIG and your AO's direction.</p>`;
  }

  // ---------------------------------------------------------------- CSV
  function exportCsv() {
    const cols = ["STIG", "Release", "Vuln ID", "STIG ID", "Rule ID", "Severity", "Title", "Plain language", "Topic", "SRG", "Server role", "CCI",
      "NIST 800-53 Rev5", "NIST 800-53 Rev4", "NIST 800-53 Rev3", "Settings", "Validation commands", "Check", "Fix", "Tags"];
    const q = window.STIGX_SECURITY.csvCell;
    const lines = [cols.map(q).join(",")];
    for (const r of state.results) {
      const s = stigByKey[r.stig];
      lines.push([s.product, s.label, r.vuln_id, r.stig_id, r.id, SEV_LABEL[r.severity], r.title, r.plain,
        r.topics.map((t) => D.topics[t].name).join("; "), r.srg, ROLE_LABEL[r.role] || (r.role ? "All servers" : ""), r.ccis.join("; "), r._nist.rev5.join("; "), r._nist.rev4.join("; "),
        r._nist.rev3.join("; "), r.settings.filter((x) => x.type !== "command").map((x) => `${x.target} | ${x.name} = ${x.value}`).join("\n"),
        (r.validate || []).map((v) => `[${SHELL_LABEL[v.shell]}] ${v.cmd}`).join("\n"),
        r.check, r.fix, r._tags.map(([t, n]) => tagDef[t].label + (n.length ? ` (${n.join("; ")})` : "")).join("; ")].map(q).join(","));
    }
    const blob = new Blob(["﻿" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `stig_explorer_${state.results.length}_rules.csv`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }

  function filterSummary() {
    const parts = [];
    if (state.q) parts.push(`search "${state.q}"`);
    if (state.sev.size < 3) parts.push("severity " + [...state.sev].map((k) => SEV_LABEL[k]).join("/"));
    if (state.topic) parts.push("topic " + D.topics[state.topic].name);
    if (state.role) parts.push("server role " + state.role);
    if (state.family) parts.push(`NIST ${state.rev} family ${state.family}`);
    if (state.control) parts.push(`NIST ${state.rev} control ${state.control}`);
    if (state.impl) parts.push("implemented via " + state.impl);
    if (state.doc) parts.push("documentable only");
    if (state.tags.size) parts.push("tags " + [...state.tags].map((t) => tagDef[t].label).join("/"));
    return parts.join("; ");
  }

  function download(text, name, type) {
    const blob = new Blob([text], { type });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }

  function exportScript(kind) {
    const S = window.STIGX_SCRIPT;
    const stamp = new Date().toISOString().slice(0, 10);
    if (kind === "ps1") download(S.powershell(state.results, D.meta, filterSummary()), `stig_validation_${stamp}.ps1`, "text/plain;charset=utf-8");
    else download(S.bash(state.results, D.meta, filterSummary()), `stig_validation_${stamp}.sh`, "text/x-shellscript;charset=utf-8");
    $("#scriptMenu").open = false;
  }

  // ---------------------------------------------------------------- misc UI
  function setLevel(l) {
    state.level = l; store.set("level", l);
    $$(".level-pick button").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.level === l)));
    renderDetail();
    if (state.view === "topics") renderTopics();
  }

  function setView(v) {
    state.view = v;
    $$(".views button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.view === v)));
    $("#view-rules").hidden = v !== "rules";
    $("#view-topics").hidden = v !== "topics";
    $("#view-about").hidden = v !== "about";
    if (v === "topics") renderTopics();
    if (v === "about") renderAbout();
  }

  function applyTheme(t) {
    if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
  }

  async function copy(text, btn) {
    try { await navigator.clipboard.writeText(text); }
    catch {
      const ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); } catch { /* ignore */ } ta.remove();
    }
    if (btn) { const o = btn.textContent; btn.textContent = "Copied"; setTimeout(() => (btn.textContent = o), 1200); }
  }

  let timer;
  function bind() {
    $("#q").addEventListener("input", (e) => { clearTimeout(timer); timer = setTimeout(() => { state.q = e.target.value; runSearch(); }, 120); });
    $("#stigFilters").addEventListener("change", (e) => {
      const k = e.target.dataset.stig; if (!k) return;
      e.target.checked ? state.stigs.add(k) : state.stigs.delete(k);
      store.set("stigs", [...state.stigs]); runSearch();
    });
    $("#stigFilters").addEventListener("click", (e) => {
      const dc = e.target.closest("[data-dcview]");
      if (dc) {
        state.stigs = new Set([dc.dataset.dcview]); state.role = "dc"; $("#roleFilter").value = "dc";
        $$("#stigFilters input").forEach((i) => (i.checked = state.stigs.has(i.dataset.stig)));
        store.set("stigs", [...state.stigs]); runSearch(); return;
      }
      const plat = e.target.dataset?.only; if (!plat) return;
      e.preventDefault();
      state.stigs = new Set(D.stigs.filter((s) => s.family === plat).map((s) => s.key));
      $$("#stigFilters input").forEach((i) => (i.checked = state.stigs.has(i.dataset.stig)));
      store.set("stigs", [...state.stigs]); runSearch();
    });
    $("#sevFilters").addEventListener("change", (e) => {
      const k = e.target.dataset.sev; e.target.checked ? state.sev.add(k) : state.sev.delete(k); runSearch();
    });
    $("#topicFilter").addEventListener("change", (e) => { state.topic = e.target.value; runSearch(); });
    $("#implFilter").addEventListener("change", (e) => { state.impl = e.target.value; runSearch(); });
    $("#familyFilter").addEventListener("change", (e) => { state.family = e.target.value; runSearch(); });
    $("#controlFilter").addEventListener("input", (e) => { clearTimeout(timer); timer = setTimeout(() => { state.control = e.target.value.trim(); runSearch(); }, 150); });
    $("#docFilter").addEventListener("change", (e) => { state.doc = e.target.checked; runSearch(); });
    $("#roleFilter").addEventListener("change", (e) => { state.role = e.target.value; runSearch(); });
    $("#tagFilters").addEventListener("change", (e) => {
      const t = e.target.dataset.tag; if (!t) return;
      e.target.checked ? state.tags.add(t) : state.tags.delete(t); runSearch();
    });
    $("#revSeg").addEventListener("click", (e) => {
      const rev = e.target.dataset.rev; if (!rev) return;
      state.rev = rev;
      $$("#revSeg button").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.rev === rev)));
      buildFamilies(); runSearch();
    });
    $("#sortSel").addEventListener("change", (e) => { state.sort = e.target.value; runSearch(); });
    $("#resetBtn").addEventListener("click", () => {
      state.q = ""; $("#q").value = ""; state.topic = ""; $("#topicFilter").value = ""; state.impl = ""; $("#implFilter").value = "";
      state.family = ""; state.control = ""; $("#controlFilter").value = ""; state.doc = false; $("#docFilter").checked = false;
      state.role = ""; $("#roleFilter").value = "";
      state.tags.clear(); $$("#tagFilters input").forEach((i) => (i.checked = false));
      state.stigs = new Set(D.stigs.map((s) => s.key)); state.sev = new Set(["high", "medium", "low"]);
      $$("#stigFilters input, #sevFilters input").forEach((i) => (i.checked = true));
      store.set("stigs", [...state.stigs]); buildFamilies(); runSearch();
    });
    $("#moreBtn").addEventListener("click", renderMore);
    $("#list").addEventListener("click", (e) => { const li = e.target.closest(".rule-item"); if (li) selectRule(ruleById[li.dataset.id]); });
    $("#list").addEventListener("keydown", (e) => {
      const li = e.target.closest(".rule-item"); if (!li) return;
      if (e.key === "Enter") selectRule(ruleById[li.dataset.id]);
      if (e.key === "ArrowDown") { e.preventDefault(); li.nextElementSibling?.focus(); }
      if (e.key === "ArrowUp") { e.preventDefault(); li.previousElementSibling?.focus(); }
    });
    $("#csvBtn").addEventListener("click", exportCsv);
    $("#scriptMenu").addEventListener("click", (e) => {
      const b = e.target.closest("[data-script]"); if (b && !b.disabled) exportScript(b.dataset.script);
    });
    document.addEventListener("click", (e) => { if (!e.target.closest("#scriptMenu")) $("#scriptMenu").open = false; });
    $$(".level-pick button").forEach((b) => b.addEventListener("click", () => setLevel(b.dataset.level)));
    $$(".views button").forEach((b) => b.addEventListener("click", () => setView(b.dataset.view)));
    $("#filterToggle").addEventListener("click", () => $("#filters").classList.toggle("open"));
    $("#themeBtn").addEventListener("click", () => {
      const dark = document.documentElement.dataset.theme
        ? document.documentElement.dataset.theme === "dark"
        : matchMedia("(prefers-color-scheme: dark)").matches;
      const t = dark ? "light" : "dark"; applyTheme(t); store.set("theme", t);
    });
    $("#detail").addEventListener("click", (e) => {
      const t = e.target;
      if (t.id === "closeDetail") { $("#detail").classList.remove("open"); return; }
      if (t.dataset.copy) return copy($("#" + CSS.escape(t.dataset.copy)).textContent, t);
      if (t.dataset.goto) return selectRule(ruleById[t.dataset.goto]);
      if (t.dataset.topic) { state.topic = t.dataset.topic; $("#topicFilter").value = state.topic; runSearch(); return; }
      if (t.id === "copyLink") return copy(location.href.split("#")[0] + "#rule=" + encodeURIComponent(state.selected.id), t);
      if (t.id === "copyMd") return copy(ruleMarkdown(state.selected), t);
      if (t.id === "printBtn") return window.print();
    });
    $("#topicGrid").addEventListener("click", (e) => {
      const id = e.target.dataset.topicgo; if (!id) return;
      state.topic = id; $("#topicFilter").value = id; setView("rules"); runSearch();
    });
    $("#filters").addEventListener("click", (e) => { if (e.target === $("#filters")) $("#filters").classList.remove("open"); });
    window.addEventListener("hashchange", fromHash);
  }

  function fromHash() {
    const lv = location.hash.match(/level=(generic|admin|pro|all)/);
    if (lv) setLevel(lv[1]);
    const v = location.hash.match(/view=(rules|topics|about)/);
    if (v) setView(v[1]);
    const q = location.hash.match(/[#&]q=([^&]*)/);
    if (q) {
      try { state.q = decodeURIComponent(q[1].replace(/\+/g, " ")).slice(0, 256); }
      catch { state.q = ""; }
      $("#q").value = state.q; runSearch();
    }
    const m = location.hash.match(/rule=([^&]+)/);
    if (m) {
      const id = decodeURIComponent(m[1]);
      const r = ruleById[id] || D.rules.find((x) => x.vuln_id === id || x.stig_id === id);
      if (r) { setView("rules"); selectRule(r, false); }
    }
  }

  // ---------------------------------------------------------------- init
  applyTheme(store.get("theme", null));
  $("#dataInfo").textContent = `${D.rules.length.toLocaleString()} rules · ${D.stigs.length} STIGs · data ${D.meta.generated}`;
  buildFilters();
  bind();
  setLevel(state.level);
  runSearch();
  fromHash();
})();
