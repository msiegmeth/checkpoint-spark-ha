/*
 * Check Point Quantum Spark card – shipped with the checkpoint_spark integration.
 * No dependencies: plain custom element, HA theme variables, own detail dialog.
 * All values coming from the gateway (names, hosts, URLs) are HTML-escaped.
 *
 * Config:
 *   type: custom:checkpoint-spark-card
 *   device_id: <device>            # optional, first Quantum Spark device otherwise
 *   period: daily|weekly|monthly   # report used for the key figures (default daily)
 *   resolvers: [192.168.1.53]      # optional: own DNS resolvers (marked in host lists)
 *   names: {192.168.1.10: NAS}     # optional: names for IPs without a device tracker
 */
const VERSION = "0.6.0";
const DOMAIN = "checkpoint_spark";

const T = {
  en: {
    title: "Firewall", traffic: "Traffic", sessions: "Sessions", ips: "IPS events", blocked: "Blocked",
    bots: "Bots", infected: "Infected", threats: "Threats", hosts: "Hosts", apps: "Apps & sites",
    realtime: "Real-time", system: "System", online: "online", offline: "offline", noInfection: "no active infection",
    threat: "threat active", blades: "blades", bladeOff: "blade off", hwOk: "hardware OK", hwProblem: "hardware problem",
    none: "none", time: "Time", name: "Name", hits: "Hits", severity: "Severity", source: "Source", target: "Target",
    action: "Action", incidents: "Incidents", volume: "Volume", app: "App", site: "Site", host: "Host",
    d24: "24 h", d7: "7 days", d30: "30 days", resolver: "DNS resolver – usually DNS trap, no infection",
    blockedHint: "Mostly DNS trap: access to a known malicious domain was prevented – not an infection. Real infections show under “Infected”.",
    topProt: "Top IPS protections", topMal: "Malware / DNS blocked", hostsInc: "Hosts with incidents",
    lastDet: "Stored detections", drops: "Firewall drops", topSrc: "Top sources (24 h)", topSvc: "Top services (24 h)",
    syslogOff: "Syslog reception is off – enable it in the integration options for real-time detections.",
    internet: "Internet", since: "since", vpn: "VPN tunnels up", cpu: "CPU / DDR", mem: "Memory", emmc: "eMMC wear",
    contracts: "Contracts until", firmware: "Firmware", expired: "expired", report: "Report", close: "Close",
    noDevice: "No Check Point Quantum Spark device found.", scanned: "Scanned hosts (h/day/week)",
    unique: "Threats, unique (h/day/week)", perDay: "Per day", requested: "Requested",
    highRisk: "High-risk apps", newInf: "newly infected", critInf: "critically infected", servers: "infected servers",
  },
  de: {
    title: "Firewall", traffic: "Datenvolumen", sessions: "Sitzungen", ips: "IPS-Ereignisse", blocked: "Blockiert",
    bots: "Bots", infected: "Infiziert", threats: "Bedrohungen", hosts: "Hosts", apps: "Apps & Seiten",
    realtime: "Echtzeit", system: "System", online: "online", offline: "offline", noInfection: "keine aktive Infektion",
    threat: "Bedrohung aktiv", blades: "Blades", bladeOff: "Blade aus", hwOk: "Hardware OK", hwProblem: "Hardware-Problem",
    none: "keine", time: "Zeit", name: "Name", hits: "Treffer", severity: "Schwere", source: "Quelle", target: "Ziel",
    action: "Aktion", incidents: "Vorfälle", volume: "Volumen", app: "App", site: "Seite", host: "Host",
    d24: "24 h", d7: "7 Tage", d30: "30 Tage", resolver: "DNS-Resolver – meist DNS-Trap, kein Befall",
    blockedHint: "Meist DNS-Trap: Der Zugriff auf eine bekannte schädliche Domain wurde verhindert – kein Befall. Ein echter Befall zeigt sich unter „Infiziert“.",
    topProt: "Top-IPS-Schutzfunktionen", topMal: "Malware / DNS blockiert", hostsInc: "Hosts mit Vorfällen",
    lastDet: "Gespeicherte Treffer", drops: "Firewall-Drops", topSrc: "Top-Quellen (24 h)", topSvc: "Top-Dienste (24 h)",
    syslogOff: "Syslog-Empfang ist aus – in den Optionen der Integration einschalten, dann gibt es Echtzeit-Treffer.",
    internet: "Internet", since: "seit", vpn: "VPN-Tunnel aktiv", cpu: "CPU / DDR", mem: "Arbeitsspeicher", emmc: "eMMC-Verschleiß",
    contracts: "Verträge bis", firmware: "Firmware", expired: "abgelaufen", report: "Report", close: "Schließen",
    noDevice: "Kein Check-Point-Quantum-Spark-Gerät gefunden.", scanned: "Gescannte Hosts (h/Tag/Woche)",
    unique: "Bedrohungen, eindeutig (h/Tag/Woche)", perDay: "Je Tag", requested: "Angefragt",
    highRisk: "Riskante Apps", newInf: "neu infiziert", critInf: "kritisch infiziert", servers: "infizierte Server",
  },
};

const SEV = { "1": "low", "2": "medium", "3": "high", "4": "critical", low: "low", medium: "medium", high: "high", critical: "critical", info: "info" };
const SEV_COLOR = { low: "var(--success-color, #43a047)", medium: "var(--warning-color, #ffa000)", high: "#fb8c00", critical: "var(--error-color, #db4437)", info: "var(--secondary-text-color)" };
const SEV_TXT = {
  en: { low: "low", medium: "medium", high: "high", critical: "critical", info: "info" },
  de: { low: "niedrig", medium: "mittel", high: "hoch", critical: "kritisch", info: "Info" },
};
const BLADE = {
  fw: "Firewall", vpn_remote_access: "Remote Access VPN", vpn_site_to_site: "Site-to-Site VPN", ips: "IPS",
  anti_virus: "Anti-Virus", url_filtering: "URL Filtering", anti_spam: "Anti-Spam", qos: "QoS",
  identity_awareness: "Identity Awareness", application_control: "Application Control", anti_bot: "Anti-Bot",
  threat_emulation: "Threat Emulation",
};

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

class CheckpointSparkCard extends HTMLElement {
  static getConfigForm() {
    return {
      schema: [
        { name: "device_id", selector: { device: { integration: DOMAIN } } },
        {
          name: "period", default: "daily",
          selector: { select: { mode: "dropdown", options: [
            { value: "daily", label: "24 h" }, { value: "weekly", label: "7 d" }, { value: "monthly", label: "30 d" },
            { value: "hourly", label: "1 h" }] } },
        },
      ],
    };
  }

  static getStubConfig(hass) {
    const ent = Object.values(hass.entities || {}).find((e) => e.platform === DOMAIN && e.device_id);
    return ent ? { device_id: ent.device_id } : {};
  }

  setConfig(config) {
    this._config = { period: "daily", resolvers: [], names: {}, ...config };
    this._tab = this._tab || "threats";
    if (!this.shadowRoot) this.attachShadow({ mode: "open" });
    this._render();
  }

  set hass(hass) {
    const first = !this._hass;
    this._hass = hass;
    // re-render only when one of our entities changed (cheap check)
    const sig = this._signature();
    if (first || sig !== this._sig) {
      this._sig = sig;
      this._render();
    }
  }

  getCardSize() { return 8; }
  getGridOptions() { return { columns: 12, min_columns: 6 }; }

  /* ------------------------------------------------------------ data -- */
  get _t() { return T[(this._hass?.locale?.language || this._hass?.language || "en").startsWith("de") ? "de" : "en"]; }
  get _lang() { return (this._hass?.locale?.language || this._hass?.language || "en").startsWith("de") ? "de" : "en"; }

  _entities() {
    const hass = this._hass;
    if (!hass) return {};
    let dev = this._config.device_id;
    const all = Object.values(hass.entities || {}).filter((e) => e.platform === DOMAIN);
    if (!dev && all.length) dev = all.find((e) => e.device_id)?.device_id;
    const map = {};
    for (const e of all) {
      if (dev && e.device_id !== dev) continue;
      const key = e.translation_key || e.entity_id.split(".")[1];
      map[key] = e.entity_id;
    }
    this._device = dev;
    return map;
  }

  _signature() {
    const ids = Object.values(this._entities());
    return ids.map((id) => {
      const s = this._hass.states[id];
      return s ? s.last_updated : "";
    }).join("|") + "|" + (this._hass.locale?.language || "");
  }

  _s(key) { const id = this._map[key]; return id ? this._hass.states[id] : undefined; }
  _v(key) { const s = this._s(key); const n = s ? parseFloat(s.state) : NaN; return isNaN(n) ? null : n; }
  _a(key, attr) { const s = this._s(key); return (s && s.attributes && s.attributes[attr]) ?? null; }
  _p(metric, period) { return `${period || this._config.period}_${metric}`; }

  _num(n, digits = 0) {
    if (n == null) return "–";
    return Number(n).toLocaleString(this._hass?.locale?.language || undefined, { maximumFractionDigits: digits });
  }
  _gb(bytes) {
    if (bytes == null) return "–";
    const gb = bytes / 1e9;
    return `${this._num(gb, gb < 10 ? 2 : 1)} GB`;
  }
  _sev(s) {
    const k = SEV[String(s ?? "").toLowerCase()];
    if (!k) return s ? esc(s) : "–";
    return `<span class="pill" style="--c:${SEV_COLOR[k]}">${esc(SEV_TXT[this._lang][k])}</span>`;
  }
  _time(iso) {
    const d = new Date(iso);
    if (isNaN(d)) return "–";
    return d.toLocaleString(this._hass?.locale?.language || undefined, { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
  }
  /** Device name for an IP (any device_tracker with attribute ip) + resolver hint. */
  _who(ip) {
    if (!ip) return "–";
    const t = Object.values(this._hass.states).find((s) => s.entity_id.startsWith("device_tracker.") && s.attributes.ip === ip);
    let name = (this._config.names || {})[ip] || (t ? (t.attributes.friendly_name || t.attributes.host_name || "") : "");
    const w = name.split(" ");
    if (w.length % 2 === 0 && w.slice(0, w.length / 2).join(" ") === w.slice(w.length / 2).join(" ")) name = w.slice(0, w.length / 2).join(" ");
    const res = (this._config.resolvers || []).includes(ip) ? ` <span class="muted">· ${esc(this._t.resolver)}</span>` : "";
    return (name ? `${esc(name)} <span class="muted">${esc(ip)}</span>` : esc(ip)) + res;
  }

  /* ---------------------------------------------------------- render -- */
  _render() {
    if (!this.shadowRoot || !this._config) return;
    if (!this._hass) { this.shadowRoot.innerHTML = ""; return; }
    this._map = this._entities();
    const t = this._t;
    if (!Object.keys(this._map).length) {
      this.shadowRoot.innerHTML = `<ha-card><div class="empty">${esc(t.noDevice)}</div></ha-card>`;
      return;
    }
    const dev = this._device && this._hass.devices ? this._hass.devices[this._device] : null;
    const title = this._config.title || (dev && (dev.name_by_user || dev.name)) || t.title;
    const period = this._config.period;
    const periodLabel = { hourly: "1 h", daily: t.d24, weekly: t.d7, monthly: t.d30 }[period] || period;
    const kpis = [
      ["traffic", "mdi:swap-vertical-bold", t.traffic, this._gb(this._v(this._p("traffic")) != null ? this._v(this._p("traffic")) * 1e9 : null), "var(--info-color, #42a5f5)"],
      ["sessions", "mdi:lan-connect", t.sessions, this._num(this._v(this._p("sessions"))), "#ab47bc"],
      ["ips", "mdi:shield-alert", t.ips, this._num(this._v(this._p("ips_events"))), this._warn(this._v(this._p("ips_events")), "#ffa000")],
      ["blocked", "mdi:virus", t.blocked, this._num(this._v(this._p("virus_incidents"))), this._warn(this._v(this._p("virus_incidents")), "#ffa000")],
      ["bots", "mdi:robot-angry", t.bots, this._num(this._v(this._p("bot_incidents"))), this._warn(this._v(this._p("bot_incidents")), "var(--error-color, #db4437)")],
      ["infected", "mdi:laptop-off", t.infected, this._num(this._v(this._p("infected_hosts"))), this._warn(this._v(this._p("infected_hosts")), "var(--error-color, #db4437)")],
    ];
    const tabs = [["threats", t.threats], ["hosts", t.hosts], ["apps", t.apps], ["realtime", t.realtime], ["system", t.system]];
    this.shadowRoot.innerHTML = `
      <style>${CSS}</style>
      <ha-card>
        <div class="head">
          <div class="title"><ha-icon icon="mdi:shield-half-full"></ha-icon><span>${esc(title)}</span>
            <span class="muted small">${esc(periodLabel)}</span></div>
          <div class="chips">${this._chips()}</div>
        </div>
        <div class="kpis">${kpis.map(([k, icon, label, val, color]) => `
          <button class="kpi" data-kpi="${k}" style="--c:${color}">
            <ha-icon icon="${icon}"></ha-icon><div><div class="val">${val}</div><div class="lbl">${esc(label)}</div></div>
          </button>`).join("")}</div>
        <div class="tabs">${tabs.map(([k, l]) => `<button class="tab ${this._tab === k ? "on" : ""}" data-tab="${k}">${esc(l)}</button>`).join("")}</div>
        <div class="body">${this._tabContent(this._tab)}</div>
      </ha-card>
      <div class="dlg" hidden><div class="dlg-box"><div class="dlg-head"><span class="dlg-title"></span>
        <button class="x" aria-label="${esc(t.close)}"><ha-icon icon="mdi:close"></ha-icon></button></div><div class="dlg-body"></div></div></div>`;
    const root = this.shadowRoot;
    root.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => { this._tab = b.dataset.tab; this._render(); }));
    root.querySelectorAll(".kpi").forEach((b) => b.addEventListener("click", () => this._open(b.dataset.kpi)));
    root.querySelectorAll("[data-det]").forEach((b) => b.addEventListener("click", () => this._openDetection(Number(b.dataset.det))));
    root.querySelector(".x").addEventListener("click", () => this._close());
    root.querySelector(".dlg").addEventListener("click", (e) => { if (e.target.classList.contains("dlg")) this._close(); });
  }

  _warn(v, color) { return v == null ? "var(--secondary-text-color)" : v > 0 ? color : "var(--success-color, #43a047)"; }

  _chips() {
    const t = this._t;
    const chip = (ok, text, icon) => `<span class="chip" style="--c:${ok ? "var(--success-color, #43a047)" : "var(--error-color, #db4437)"}"><ha-icon icon="${icon}"></ha-icon>${esc(text)}</span>`;
    const out = [];
    const inet = this._s("internet");
    if (inet) out.push(chip(inet.state === "on", `${t.internet} ${inet.state === "on" ? t.online : t.offline}`, "mdi:web"));
    const thr = this._s("threat_active");
    if (thr) out.push(chip(thr.state !== "on", thr.state === "on" ? t.threat : t.noInfection, "mdi:shield-check"));
    const blades = this._a("active_blades", "blades") || {};
    const bf = this._s("blade_failure");
    const n = Object.values(blades).filter(Boolean).length;
    if (Object.keys(blades).length) out.push(chip(!bf || bf.state !== "on", bf && bf.state === "on" ? `${t.bladeOff}: ${(bf.attributes.disabled || []).join(", ")}` : `${n}/${Object.keys(blades).length} ${t.blades}`, "mdi:puzzle"));
    const hw = this._s("hardware_problem");
    if (hw) out.push(chip(hw.state !== "on", hw.state === "on" ? t.hwProblem : t.hwOk, "mdi:chip"));
    return out.join("");
  }

  _table(head, rows, empty) {
    if (!rows.length) return `<div class="muted pad">${esc(empty || this._t.none)}</div>`;
    return `<table><tr>${head.map((h, i) => `<th class="${i ? "r" : ""}">${esc(h)}</th>`).join("")}</tr>${rows.join("")}</table>`;
  }
  _bar(v, max, color) {
    return `<div class="bar"><div style="width:${Math.max(2, Math.round((100 * v) / (max || 1)))}%;background:${color}"></div></div>`;
  }

  _tabContent(tab) {
    const t = this._t;
    if (tab === "threats") {
      const prot = this._a(this._p("ips_events", "weekly"), "top_protections") || [];
      const mal = this._a(this._p("virus_incidents", "weekly"), "top_malwares") || [];
      return `<h4>${esc(t.topProt)} · ${esc(t.d7)}</h4>` +
        this._table([t.name, t.hits, t.severity], prot.slice(0, 10).map((i) => `<tr><td class="n">${esc(i.name)}${i.cve ? `<div class="muted small">${esc(i.cve.split(",")[0])}</div>` : ""}</td><td class="r">${this._num(i.sessions)}</td><td class="r">${this._sev(i.severity)}</td></tr>`)) +
        `<h4>${esc(t.topMal)} · ${esc(t.d7)}</h4>` +
        this._table([t.name, t.incidents, t.severity], mal.slice(0, 10).map((i) => `<tr><td class="n">${esc(i.name)}</td><td class="r">${this._num(i.incidents)}</td><td class="r">${this._sev(i.severity)}</td></tr>`)) +
        `<div class="muted small pad">${esc(t.blockedHint)}</div>`;
    }
    if (tab === "hosts") {
      const hosts = this._a(this._p("infected_hosts", "weekly"), "top_infected_hosts") || [];
      const max = Math.max(1, ...hosts.map((h) => h.count || 0));
      return `<h4>${esc(t.hostsInc)} · ${esc(t.d7)}</h4>` +
        this._table([t.host, t.incidents], hosts.map((h) => `<tr><td class="n">${this._who(h.name)}${this._bar(h.count || 0, max, "var(--error-color, #db4437)")}</td><td class="r">${this._num(h.count)}</td></tr>`));
    }
    if (tab === "apps") {
      const apps = this._a(this._p("traffic", "daily"), "top_apps_by_bandwidth") || [];
      const sites = this._a(this._p("traffic", "daily"), "top_sites_by_bandwidth") || [];
      const ma = Math.max(1, ...apps.map((a) => a.bytes || 0)), ms = Math.max(1, ...sites.map((a) => a.bytes || 0));
      return `<h4>${esc(t.app)} · ${esc(t.d24)}</h4>` +
        this._table([t.app, t.volume], apps.slice(0, 10).map((a) => `<tr><td class="n">${esc(a.name)}${this._bar(a.bytes || 0, ma, "var(--info-color, #42a5f5)")}</td><td class="r">${this._gb(a.bytes)}</td></tr>`)) +
        `<h4>${esc(t.site)} · ${esc(t.d24)}</h4>` +
        this._table([t.site, t.volume], sites.slice(0, 10).map((a) => `<tr><td class="n">${esc(a.name)}${this._bar(a.bytes || 0, ms, "#ab47bc")}</td><td class="r">${this._gb(a.bytes)}</td></tr>`));
    }
    if (tab === "realtime") {
      if (!this._s("syslog_messages")) return `<div class="muted pad">${esc(t.syslogOff)}</div>`;
      const hist = this._a("detections_30d", "history") || [];
      const drops = this._s("firewall_drops_1h");
      const src = (drops && drops.attributes.top_sources) || [];
      const sc = this._s("scanned_hosts"), dt = this._s("detected_threats");
      const triple = (s) => (s ? `${s.attributes.hour ?? "–"} / ${esc(s.state)} / ${s.attributes.week ?? "–"}` : "–");
      return `<div class="kv"><span>${esc(t.ips)} / h</span><b>${this._num(this._v("ips_events_1h"))}</b></div>
        <div class="kv"><span>${esc(t.drops)} / h</span><b>${this._num(this._v("firewall_drops_1h"))}</b></div>
        <div class="kv"><span>${esc(t.scanned)}</span><b>${triple(sc)}</b></div>
        <div class="kv"><span>${esc(t.unique)}</span><b>${triple(dt)}</b></div>
        <h4>${esc(t.lastDet)}</h4>` +
        this._table([t.name, t.time, t.severity], hist.slice(0, 15).map((h, i) => `<tr class="click" data-det="${i}"><td class="n">${esc(h.name || h.attack || "–")}<div class="muted small">${this._who(h.src)}</div></td><td class="r">${esc(this._time(h.time))}</td><td class="r">${this._sev(h.severity)} ›</td></tr>`)) +
        `<h4>${esc(t.topSrc)}</h4>` +
        this._table([t.source, t.hits], src.map((s) => `<tr><td class="n">${this._who(s.name)}</td><td class="r">${this._num(s.count)}</td></tr>`));
    }
    // system
    const blades = this._a("active_blades", "blades") || {};
    const inet = this._s("internet_connected_since");
    const cpu = this._v("cpu_temperature"), ddr = this._v("ddr_temperature");
    const exp = this._s("next_contract_expiry");
    const kv = (k, v) => `<div class="kv"><span>${esc(k)}</span><b>${v}</b></div>`;
    return `<div class="blades">${Object.entries(blades).map(([k, on]) => `<span class="${on ? "" : "off"}"><ha-icon icon="${on ? "mdi:check-circle" : "mdi:minus-circle-outline"}"></ha-icon>${esc(BLADE[k] || k)}</span>`).join("")}</div>` +
      kv(t.internet, inet && inet.state && !isNaN(new Date(inet.state)) ? `${esc(t.since)} ${esc(this._time(inet.state))}` : "–") +
      kv(t.vpn, this._num(this._v("vpn_tunnels_up"))) +
      kv(t.cpu, `${cpu == null ? "–" : Math.round(cpu) + " °C"} / ${ddr == null ? "–" : Math.round(ddr) + " °C"}`) +
      kv(t.mem, this._v("memory_used") == null ? "–" : `${this._num(this._v("memory_used"))} MB`) +
      kv(t.emmc, this._v("emmc_wear") == null ? "–" : `≤ ${this._num(this._v("emmc_wear"))} %`) +
      kv(t.contracts, exp && !isNaN(new Date(exp.state)) ? `${esc(new Date(exp.state).toLocaleDateString(this._hass.locale?.language))}${(exp.attributes.expired_contracts || []).length ? ` <span class="muted">· ${(exp.attributes.expired_contracts || []).length} ${esc(t.expired)}</span>` : ""}` : "–") +
      kv(t.firmware, esc(this._s("firmware")?.state || "–")) +
      kv(t.report, esc(this._time(this._s(this._p("report_time"))?.state)));
  }

  /* ---------------------------------------------------------- dialog -- */
  _open(kpi) {
    const t = this._t;
    const per = [["daily", t.d24], ["weekly", t.d7], ["monthly", t.d30]];
    const counts = (rows) => this._table(["", ...per.map((p) => p[1])],
      rows.map(([label, metric]) => `<tr><td>${esc(label)}</td>${per.map(([p]) => `<td class="r">${this._num(this._v(`${p}_${metric}`))}</td>`).join("")}</tr>`));
    let title = "", body = "";
    switch (kpi) {
      case "traffic": {
        title = t.traffic;
        body = this._table(["", ...per.map((p) => p[1])], [["traffic", t.traffic], ["download", "↓"], ["upload", "↑"]].map(([m, l]) =>
          `<tr><td>${esc(l)}</td>${per.map(([p]) => `<td class="r">${this._gb(this._v(`${p}_${m}`) != null ? this._v(`${p}_${m}`) * 1e9 : null)}</td>`).join("")}</tr>`)) +
          this._tabContent("apps");
        break;
      }
      case "sessions": {
        title = t.sessions;
        const apps = this._a(this._p("sessions", "daily"), "top_apps_by_sessions") || [];
        body = counts([[t.sessions, "sessions"], [t.highRisk, "high_risk_sessions"]]) +
          `<h4>${esc(t.app)} · ${esc(t.d24)}</h4>` +
          this._table([t.app, t.sessions], apps.slice(0, 10).map((a) => `<tr><td class="n">${esc(a.name)}${a.category ? `<div class="muted small">${esc(a.category)}</div>` : ""}</td><td class="r">${this._num(a.sessions)}</td></tr>`));
        break;
      }
      case "ips": {
        title = t.ips;
        const prot = this._a(this._p("ips_events", "daily"), "top_protections") || [];
        body = counts([[t.ips, "ips_events"]]) + `<h4>${esc(t.topProt)} · ${esc(t.d24)}</h4>` +
          this._table([t.name, t.hits, t.severity], prot.map((i) => `<tr><td class="n">${esc(i.name)}${i.cve ? `<div class="muted small">${i.cve.split(",").map((c) => c.trim()).filter((c) => /^CVE-\d+-\d+$/.test(c)).slice(0, 3).map((c) => `<a href="https://nvd.nist.gov/vuln/detail/${c}" target="_blank" rel="noopener">${c}</a>`).join(" · ")}</div>` : ""}</td><td class="r">${this._num(i.sessions)}</td><td class="r">${this._sev(i.severity)}</td></tr>`)) +
          this._detList("ips_attack");
        break;
      }
      case "blocked": {
        title = t.blocked;
        body = `<div class="hint">${esc(t.blockedHint)}</div>` + counts([[t.blocked, "virus_incidents"]]) +
          this._detList("malware_detected") + this._tabContent("threats").split(`<h4>${esc(t.topMal)}`).slice(1).map((x) => `<h4>${esc(t.topMal)}` + x).join("") +
          this._tabContent("hosts");
        break;
      }
      case "bots": title = t.bots; body = counts([[t.bots, "bot_incidents"]]); break;
      default: {
        title = t.infected;
        body = counts([[t.infected, "infected_hosts"], [t.newInf, "new_infected_hosts"], [t.critInf, "critical_infected_hosts"], [t.servers, "infected_servers"]]) + this._tabContent("hosts");
      }
    }
    this._show(title, body);
  }

  _detList(kind) {
    const t = this._t;
    if (!this._s("detections_30d")) return "";
    const hist = (this._a("detections_30d", "history") || []).map((h, i) => [h, i]).filter(([h]) => h.kind === kind);
    return `<h4>${esc(t.lastDet)}</h4>` + this._table([t.time, t.name, t.source], hist.slice(0, 15).map(([h, i]) =>
      `<tr class="click" data-det="${i}"><td>${esc(this._time(h.time))}</td><td class="n">${esc(h.name || h.attack || "–")}</td><td class="r">${this._who(h.src)} ›</td></tr>`));
  }

  _openDetection(i) {
    const t = this._t;
    const h = (this._a("detections_30d", "history") || [])[i];
    if (!h) return;
    const kv = (k, v) => `<div class="kv"><span>${esc(k)}</span><b>${v}</b></div>`;
    const cves = String(h.cve || "").split(",").map((c) => c.trim()).filter((c) => /^CVE-\d+-\d+$/.test(c));
    this._show(h.name || h.attack || "–",
      kv(t.time, esc(new Date(h.time).toLocaleString(this._hass.locale?.language))) +
      kv(t.severity, this._sev(h.severity)) + kv(t.action, esc(h.action || "–")) +
      kv(t.source, this._who(h.src)) + kv(t.target, this._who(h.dst)) +
      (h.product ? kv("Blade", esc(h.product)) : "") +
      (cves.length ? kv("CVE", cves.map((c) => `<a href="https://nvd.nist.gov/vuln/detail/${c}" target="_blank" rel="noopener">${c}</a>`).join(" · ")) : "") +
      (h.resource ? `<div class="kv"><span>${esc(t.requested)}</span></div><code>${esc(h.resource)}</code>` : ""));
  }

  _show(title, body) {
    const d = this.shadowRoot.querySelector(".dlg");
    d.querySelector(".dlg-title").textContent = title;
    d.querySelector(".dlg-body").innerHTML = body;
    d.querySelectorAll("[data-det]").forEach((b) => b.addEventListener("click", () => this._openDetection(Number(b.dataset.det))));
    d.hidden = false;
  }
  _close() { this.shadowRoot.querySelector(".dlg").hidden = true; }
}

const CSS = `
  :host { display: block; }
  ha-card { padding: 12px 12px 8px; overflow: hidden; }
  .empty, .pad { padding: 12px 4px; }
  .muted { color: var(--secondary-text-color); }
  .small { font-size: 11px; }
  .head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px; }
  .title { display: flex; align-items: center; gap: 8px; font-size: 18px; font-weight: 500; }
  .title ha-icon { color: var(--primary-color); }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; }
  .chip { display: inline-flex; align-items: center; gap: 4px; padding: 2px 10px; border-radius: 12px; font-size: 12px;
          color: var(--c); background: color-mix(in srgb, var(--c) 15%, transparent); }
  .chip ha-icon { --mdc-icon-size: 14px; }
  .kpis { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 6px; margin: 12px 0 8px; }
  .kpi { display: flex; align-items: center; gap: 8px; padding: 8px; border: none; border-radius: 12px; cursor: pointer;
         background: var(--secondary-background-color, rgba(127,127,127,.08)); color: var(--primary-text-color); text-align: left; font: inherit; }
  .kpi:hover { filter: brightness(1.1); }
  .kpi ha-icon { color: var(--c); flex: none; }
  .kpi .val { font-size: 20px; font-weight: 500; color: var(--c); line-height: 1.15; white-space: nowrap; }
  .kpi .lbl { font-size: 11px; color: var(--secondary-text-color); text-transform: uppercase; letter-spacing: .4px; }
  .tabs { display: flex; gap: 4px; overflow-x: auto; border-bottom: 1px solid var(--divider-color); margin-top: 4px; }
  .tab { background: none; border: none; padding: 8px 10px; cursor: pointer; color: var(--secondary-text-color); font: inherit; font-size: 13px;
         border-bottom: 2px solid transparent; white-space: nowrap; }
  .tab.on { color: var(--primary-color); border-bottom-color: var(--primary-color); }
  .body { padding: 4px 0; }
  h4 { margin: 12px 0 4px; font-size: 11px; font-weight: 500; text-transform: uppercase; letter-spacing: .5px; color: var(--secondary-text-color); }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th { text-align: left; font-size: 11px; font-weight: 500; color: var(--secondary-text-color); padding: 4px 6px; }
  td { padding: 5px 6px; border-top: 1px solid var(--divider-color); vertical-align: top; }
  .r { text-align: right; white-space: nowrap; }
  td.n { width: 100%; word-break: break-word; }
  tr.click { cursor: pointer; }
  tr.click:hover td { background: var(--secondary-background-color, rgba(127,127,127,.08)); }
  .bar { height: 4px; border-radius: 2px; margin-top: 3px; background: var(--divider-color); }
  .bar > div { height: 4px; border-radius: 2px; }
  .pill { display: inline-block; padding: 0 8px; border-radius: 9px; font-size: 11px; line-height: 18px;
          color: var(--c); background: color-mix(in srgb, var(--c) 18%, transparent); }
  .kv { display: flex; justify-content: space-between; gap: 12px; padding: 6px 4px; border-top: 1px solid var(--divider-color); font-size: 14px; }
  .kv span { color: var(--secondary-text-color); }
  .kv b { font-weight: 500; text-align: right; }
  .blades { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 2px 12px; font-size: 13px; margin: 8px 0; }
  .blades span { display: flex; align-items: center; gap: 6px; }
  .blades ha-icon { --mdc-icon-size: 16px; color: var(--success-color, #43a047); }
  .blades .off { color: var(--secondary-text-color); }
  .blades .off ha-icon { color: var(--disabled-text-color, #999); }
  .hint { padding: 8px 10px; border-radius: 8px; font-size: 13px; background: color-mix(in srgb, var(--warning-color, #ffa000) 12%, transparent); }
  code { display: block; padding: 6px; border-radius: 6px; font-size: 12px; word-break: break-all;
         background: var(--secondary-background-color, rgba(127,127,127,.1)); }
  a { color: var(--primary-color); }
  .dlg { position: fixed; inset: 0; z-index: 10; display: flex; align-items: center; justify-content: center;
         background: rgba(0,0,0,.5); padding: 16px; }
  .dlg[hidden] { display: none; }
  .dlg-box { width: min(640px, 100%); max-height: 85vh; overflow: auto; border-radius: 16px; padding: 12px 16px 16px;
             background: var(--card-background-color, var(--ha-card-background, #1c1c1c)); color: var(--primary-text-color);
             box-shadow: 0 8px 32px rgba(0,0,0,.4); }
  .dlg-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; font-size: 18px; font-weight: 500; }
  .x { background: none; border: none; color: var(--secondary-text-color); cursor: pointer; padding: 4px; }
  @media (max-width: 450px) { .kpi .val { font-size: 17px; } .kpis { gap: 4px; } }
`;

if (!customElements.get("checkpoint-spark-card")) {
  customElements.define("checkpoint-spark-card", CheckpointSparkCard);
  window.customCards = window.customCards || [];
  window.customCards.push({
    type: "checkpoint-spark-card",
    name: "Check Point Quantum Spark",
    description: "Firewall overview: key figures, threats, hosts, real-time detections and gateway health.",
    preview: true,
    documentationURL: "https://github.com/msiegmeth/checkpoint-spark-ha",
  });
  console.info(`%c checkpoint-spark-card ${VERSION} `, "background:#e5007e;color:#fff;border-radius:3px");
}
