/*
 * Check Point Quantum Spark – interactive event viewer card (shipped with the checkpoint_spark integration).
 * No dependencies: plain custom element, HA theme variables, own SVG charts (bars + sankey).
 * Every value coming from the gateway (names, hosts, URLs) is HTML-escaped. No external requests:
 * brand logos come from checkpoint-spark-icons.js (Simple Icons, CC0) next to this file, fallback are
 * the Material Design Icons that ship with Home Assistant.
 *
 * Config:
 *   type: custom:checkpoint-spark-card
 *   device_id: <device>            # optional, first Quantum Spark device otherwise
 *   period: hourly|daily|weekly|monthly   # initial period (default daily)
 *   resolvers: [192.168.1.53]      # optional: own DNS resolvers (marked in host lists)
 *   names: {192.168.1.10: NAS}     # optional: names for IPs without a device tracker
 */
const VERSION = "0.6.0";
const DOMAIN = "checkpoint_spark";

const T = {
  en: {
    title: "Firewall", p_hourly: "1 h", p_daily: "24 h", p_weekly: "7 days", p_monthly: "30 days",
    traffic: "Traffic", tp: "Threat Prevention", system: "System", volume: "Volume", down: "Download", up: "Upload",
    sessions: "Sessions", ips: "IPS", blocked: "Malware / DNS", bots: "Bots", infected: "Infected", topApp: "Top app",
    topSite: "Top site", history: "Volume over time", flow: "Flow", apps: "Apps", sites: "Sites",
    categories: "Categories", byVolume: "by volume", bySessions: "by sessions", highRisk: "High-risk apps",
    all: "All", type: "Type", dir: "Direction", inbound: "external → internal", internal: "internal → internal",
    outbound: "internal → external", unknown: "unknown", events: "Events (syslog)", noEvents: "No events in this period.",
    noSyslog: "Syslog reception is off – enable it in the integration options to see single events with time, source and direction.",
    reportPart: "From the report (totals, no time/source)", protections: "Top IPS protections", malware: "Malware / DNS blocked",
    hosts: "Hosts with incidents", time: "Time", name: "Name", sev: "Severity", action: "Action", src: "Source", dst: "Target",
    hits: "Hits", incidents: "Incidents", host: "Host", none: "none", requested: "Requested", resolver: "DNS resolver – usually DNS trap",
    dnsHint: "Mostly DNS trap: access to a known malicious domain was prevented – not an infection.",
    online: "online", offline: "offline", noInfection: "no active infection", threat: "threat active", blades: "blades",
    bladeOff: "blade off", hwOk: "hardware OK", hwProblem: "hardware problem", internet: "Internet", since: "since",
    vpn: "VPN tunnels up", cpu: "CPU / DDR", mem: "Memory", emmc: "eMMC wear", contracts: "Contracts until",
    firmware: "Firmware", expired: "expired", report: "Report", noDevice: "No Check Point Quantum Spark device found.",
    blockedA: "blocked", detectedA: "detected", allowedA: "allowed", other: "Other", noData: "no data",
    infHosts: "infected hosts", newInf: "newly infected", critInf: "critically infected", servers: "infected servers",
    noReport: "not in this report", severity: "Severity", times: "×", targets: "targets", occurrences: "Occurrences",
    first: "first", last: "last", reportOnly: "report total only", loading: "loading…",
    temps: "Temperature", ram: "Memory", noStats: "No statistics yet for this period.",
    cpuLoad: "CPU load", wan: "Internet line", latency: "Latency / jitter", conns: "Connections", booted: "Running since",
    perf: "Load (OpenTelemetry)", noTelemetry: "Enable OpenTelemetry in the integration options for CPU load, throughput and line quality.",
    noSyslogType: "The gateway sends no single events for this type via syslog (or not with details) – only the report totals below.",
  },
  de: {
    title: "Firewall", p_hourly: "1 h", p_daily: "24 h", p_weekly: "7 Tage", p_monthly: "30 Tage",
    traffic: "Traffic", tp: "Threat Prevention", system: "System", volume: "Volumen", down: "Download", up: "Upload",
    sessions: "Sitzungen", ips: "IPS", blocked: "Malware / DNS", bots: "Bots", infected: "Infiziert", topApp: "Top-App",
    topSite: "Top-Seite", history: "Volumen im Verlauf", flow: "Fluss", apps: "Apps", sites: "Seiten",
    categories: "Kategorien", byVolume: "nach Volumen", bySessions: "nach Sitzungen", highRisk: "Riskante Apps",
    all: "Alle", type: "Art", dir: "Richtung", inbound: "extern → intern", internal: "intern → intern",
    outbound: "intern → extern", unknown: "unbekannt", events: "Ereignisse (Syslog)", noEvents: "Keine Ereignisse in diesem Zeitraum.",
    noSyslog: "Syslog-Empfang ist aus – in den Optionen der Integration einschalten, dann gibt es einzelne Ereignisse mit Zeit, Quelle und Richtung.",
    reportPart: "Aus dem Report (Summen, ohne Zeit/Quelle)", protections: "Top-IPS-Schutzfunktionen", malware: "Malware / DNS blockiert",
    hosts: "Hosts mit Vorfällen", time: "Zeit", name: "Name", sev: "Schwere", action: "Aktion", src: "Quelle", dst: "Ziel",
    hits: "Treffer", incidents: "Vorfälle", host: "Host", none: "keine", requested: "Angefragt", resolver: "DNS-Resolver – meist DNS-Trap",
    dnsHint: "Meist DNS-Trap: Der Zugriff auf eine bekannte schädliche Domain wurde verhindert – kein Befall.",
    online: "online", offline: "offline", noInfection: "keine aktive Infektion", threat: "Bedrohung aktiv", blades: "Blades",
    bladeOff: "Blade aus", hwOk: "Hardware OK", hwProblem: "Hardware-Problem", internet: "Internet", since: "seit",
    vpn: "VPN-Tunnel aktiv", cpu: "CPU / DDR", mem: "Arbeitsspeicher", emmc: "eMMC-Verschleiß", contracts: "Verträge bis",
    firmware: "Firmware", expired: "abgelaufen", report: "Report", noDevice: "Kein Check-Point-Quantum-Spark-Gerät gefunden.",
    blockedA: "blockiert", detectedA: "erkannt", allowedA: "durchgelassen", other: "Weitere", noData: "keine Daten",
    infHosts: "infizierte Hosts", newInf: "neu infiziert", critInf: "kritisch infiziert", servers: "infizierte Server",
    noReport: "nicht in diesem Report", severity: "Schwere", times: "×", targets: "Ziele", occurrences: "Vorkommen",
    first: "erstes", last: "letztes", reportOnly: "nur Report-Summe", loading: "lädt…",
    temps: "Temperatur", ram: "Arbeitsspeicher", noStats: "Für diesen Zeitraum gibt es noch keine Statistik.",
    cpuLoad: "CPU-Auslastung", wan: "Internetleitung", latency: "Latenz / Jitter", conns: "Verbindungen", booted: "Läuft seit",
    perf: "Auslastung (OpenTelemetry)", noTelemetry: "OpenTelemetry in den Optionen der Integration einschalten, dann gibt es CPU-Auslastung, Durchsatz und Leitungsqualität.",
    noSyslogType: "Für diese Art schickt das Gateway per Syslog keine (oder keine verwertbaren) Einzelereignisse – nur die Report-Summen unten.",
  },
};

const PERIODS = ["hourly", "daily", "weekly", "monthly"];
const PERIOD_HOURS = { hourly: 1, daily: 24, weekly: 168, monthly: 720 };
const SEV = { "1": "low", "2": "medium", "3": "high", "4": "critical", low: "low", medium: "medium", high: "high", critical: "critical", info: "info" };
const SEV_TXT = { en: { low: "low", medium: "medium", high: "high", critical: "critical", info: "info" },
                  de: { low: "niedrig", medium: "mittel", high: "hoch", critical: "kritisch", info: "Info" } };
const C = {
  blue: "var(--info-color, #42a5f5)", purple: "#ab47bc", amber: "var(--warning-color, #ffa000)", orange: "#fb8c00",
  red: "var(--error-color, #db4437)", green: "var(--success-color, #43a047)", grey: "var(--secondary-text-color)",
};
const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const sevKey = (h) => SEV[String(h.severity ?? "").toLowerCase()] || "info";
const SEV_COLOR = { low: C.green, medium: C.amber, high: C.orange, critical: C.red, info: C.grey };
const DIR_COLOR = { inbound: C.amber, internal: C.orange, outbound: C.red, unknown: C.grey };
const DIR_ICON = { inbound: "mdi:arrow-down-bold", internal: "mdi:swap-horizontal-bold", outbound: "mdi:arrow-up-bold" };
const TYPE_COLOR = { ips: C.amber, malware: C.red, bot: C.purple };
const ACT_COLOR = { blocked: C.green, detected: C.amber, allowed: C.red };
const PALETTE = ["#42a5f5", "#26a69a", "#ab47bc", "#ffa000", "#ef5350", "#7e57c2", "#66bb6a", "#8d6e63", "#78909c"];
const BLADE = {
  fw: "Firewall", vpn_remote_access: "Remote Access VPN", vpn_site_to_site: "Site-to-Site VPN", ips: "IPS",
  anti_virus: "Anti-Virus", url_filtering: "URL Filtering", anti_spam: "Anti-Spam", qos: "QoS",
  identity_awareness: "Identity Awareness", application_control: "Application Control", anti_bot: "Anti-Bot",
  threat_emulation: "Threat Emulation",
};

/* Icons for well-known apps, sites and categories: [pattern, Material Design Icon (fallback), Simple Icons slug].
 * Brand logos come from checkpoint-spark-icons.js (Simple Icons, CC0) – loaded on demand, no external requests.
 * First match wins; unknown entries get a neutral icon per list type. */
const ICONS = [
  [/youtube|google video/i, "mdi:youtube", "youtube"], [/netflix/i, "mdi:netflix", "netflix"],
  [/instagram/i, "mdi:instagram", "instagram"], [/whatsapp/i, "mdi:whatsapp", "whatsapp"], [/messenger/i, "mdi:facebook-messenger", "messenger"],
  [/threads/i, "mdi:at", "threads"], [/facebook|\bmeta\b/i, "mdi:facebook", "facebook"], [/tiktok|capcut/i, "mdi:music-note", "tiktok"],
  [/snapchat/i, "mdi:snapchat", "snapchat"], [/pinterest/i, "mdi:pinterest", "pinterest"], [/reddit/i, "mdi:reddit", "reddit"],
  [/telegram/i, "mdi:send", "telegram"], [/signal/i, "mdi:message-lock", "signal"], [/discord/i, "mdi:chat", "discord"],
  [/twitter|\bx\.com/i, "mdi:alpha-x-box", "x"], [/bluesky|bsky/i, "mdi:butterfly", "bluesky"], [/mastodon/i, "mdi:mastodon", "mastodon"],
  [/spotify/i, "mdi:spotify", "spotify"], [/deezer/i, "mdi:music", "deezer"], [/tidal/i, "mdi:music", "tidal"], [/soundcloud/i, "mdi:soundcloud", "soundcloud"],
  [/apple music/i, "mdi:music", "applemusic"], [/apple tv/i, "mdi:apple", "appletv"], [/icloud/i, "mdi:apple-icloud", "icloud"],
  [/apple|facetime|itunes/i, "mdi:apple", "apple"], [/twitch/i, "mdi:twitch", "twitch"], [/kick\.com|\bkick\b/i, "mdi:play-box", "kick"],
  [/dazn/i, "mdi:soccer", "dazn"], [/vimeo/i, "mdi:vimeo", "vimeo"], [/dailymotion/i, "mdi:play-box", "dailymotion"],
  [/plex/i, "mdi:plex", "plex"], [/jellyfin/i, "mdi:play-box", "jellyfin"], [/emby/i, "mdi:play-box", "emby"], [/\bsky\b/i, "mdi:television", "sky"],
  [/steam|valve/i, "mdi:steam", "steam"], [/playstation|psn/i, "mdi:sony-playstation", "playstation"], [/xbox/i, "mdi:microsoft-xbox", null],
  [/epic games|epicgames|fortnite/i, "mdi:gamepad-variant", "epicgames"], [/ubisoft/i, "mdi:gamepad-variant", "ubisoft"],
  [/\bea\b|electronic arts|origin/i, "mdi:gamepad-variant", "ea"], [/roblox/i, "mdi:gamepad-variant", "roblox"],
  [/microsoft 365|office|outlook|teams/i, "mdi:microsoft-office", null], [/microsoft|windows|azure|bing/i, "mdi:microsoft", null],
  [/amazon web|aws|cloudfront/i, "mdi:aws", null], [/amazon|prime video/i, "mdi:cart", null],
  [/google play/i, "mdi:google-play", "googleplay"], [/google cloud/i, "mdi:google-cloud", "googlecloud"], [/chrome/i, "mdi:google-chrome", "googlechrome"],
  [/googleapis|googleusercontent|gstatic|google/i, "mdi:google", "google"], [/android/i, "mdi:android", "android"],
  [/cloudflare/i, "mdi:cloud", "cloudflare"], [/akamai/i, "mdi:cloud", "akamai"], [/dropbox/i, "mdi:dropbox", "dropbox"],
  [/github/i, "mdi:github", "github"], [/atlassian/i, "mdi:briefcase", "atlassian"], [/jira/i, "mdi:briefcase", "jira"], [/notion/i, "mdi:note-text", "notion"],
  [/autodesk/i, "mdi:cube-outline", "autodesk"], [/teamviewer/i, "mdi:remote-desktop", "teamviewer"], [/anydesk/i, "mdi:remote-desktop", "anydesk"],
  [/zoom/i, "mdi:video", "zoom"], [/linkedin/i, "mdi:linkedin", null], [/firefox/i, "mdi:firefox", "firefox"], [/mozilla/i, "mdi:firefox", "mozilla"],
  [/duckduckgo/i, "mdi:duck", "duckduckgo"], [/paypal/i, "mdi:credit-card", "paypal"], [/ebay/i, "mdi:cart", "ebay"], [/aliexpress/i, "mdi:cart", "aliexpress"],
  [/zalando/i, "mdi:cart", "zalando"], [/airbnb/i, "mdi:home", "airbnb"], [/uber/i, "mdi:car", "uber"], [/sonos/i, "mdi:speaker", "sonos"],
  [/synology/i, "mdi:nas", "synology"], [/home ?assistant|nabu ?casa/i, "mdi:home-assistant", "homeassistant"], [/tailscale/i, "mdi:vpn", "tailscale"],
  [/ubiquiti|unifi/i, "mdi:access-point", "ubiquiti"], [/openvpn/i, "mdi:vpn", "openvpn"], [/wireguard/i, "mdi:vpn", "wireguard"],
  [/bittorrent|torrent/i, "mdi:file-swap", "bittorrent"],
  [/quic|https?|tls|ssl|tcp|udp|dns|ntp|stun|icmp|protocol/i, "mdi:lan", null], [/vpn|ipsec/i, "mdi:vpn", null],
  [/p2p|file shar/i, "mdi:file-swap", null], [/update|download|content-storage|cdn|content deliver/i, "mdi:cloud-download", null],
  [/game|gaming/i, "mdi:gamepad-variant", null], [/video|stream|media|entertain/i, "mdi:play-box", null], [/music|audio|radio/i, "mdi:music", null],
  [/social/i, "mdi:account-group", null], [/shop/i, "mdi:cart", null], [/business|econom|finance|bank/i, "mdi:briefcase", null],
  [/search|portal/i, "mdi:magnify", null], [/mail/i, "mdi:email", null], [/news/i, "mdi:newspaper", null], [/sex|adult/i, "mdi:eye-off", null],
  [/low risk/i, "mdi:shield-check", null], [/medium risk/i, "mdi:shield-alert-outline", null], [/high risk|critical risk/i, "mdi:shield-alert", null],
  [/computers|internet/i, "mdi:laptop", null], [/unknown/i, "mdi:help-circle-outline", null],
];
const ICON_DEFAULT = { apps: "mdi:application-outline", sites: "mdi:web", categories: "mdi:shape-outline" };

// Simple Icons, loaded once on demand (module next to this file)
let SI = null;
const SI_READY = import(new URL(`./checkpoint-spark-icons.js?v=${VERSION}`, import.meta.url))
  .then((m) => { SI = m.SIMPLE_ICONS || {}; })
  .catch(() => { SI = {}; });

/** Brand colours that are too dark/light for one of the themes use the text colour instead. */
function brandFill(hex) {
  const n = parseInt(hex, 16);
  const [r, g, b] = [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  const l = (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255;
  return l < 0.2 || l > 0.85 ? "currentColor" : `#${hex}`;
}

/** Icon markup: brand logo (Simple Icons) if available, otherwise a Material Design Icon. */
function iconHtml(name, kind) {
  const hit = ICONS.find(([re]) => re.test(name || ""));
  const si = hit && hit[2] && SI && SI[hit[2]];
  if (si) return `<svg class="si" viewBox="0 0 24 24" role="img"><path fill="${brandFill(si[0])}" d="${si[1]}"/></svg>`;
  return `<ha-icon icon="${hit ? hit[1] : ICON_DEFAULT[kind] || "mdi:circle-small"}"></ha-icon>`;
}

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

/** 1-2-5 step for a nice axis. */
function niceStep(max, ticks = 4) {
  if (!(max > 0)) return 1;
  const raw = max / ticks;
  const p = Math.pow(10, Math.floor(Math.log10(raw)));
  const f = raw / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
}

/** Event type of a stored syslog detection. */
function evType(h) {
  if (h.kind === "ips_attack") return "ips";
  return /bot/i.test(h.product || "") ? "bot" : "malware";
}
function evAction(h) {
  const a = String(h.action || "").toLowerCase();
  if (["reject", "drop", "prevent", "block", "blocked"].includes(a)) return "blocked";
  if (["accept", "allow", "allowed"].includes(a)) return "allowed";
  return "detected";
}

class CheckpointSparkCard extends HTMLElement {
  static getConfigForm() {
    return {
      schema: [
        { name: "device_id", selector: { device: { integration: DOMAIN } } },
        { name: "period", default: "daily", selector: { select: { mode: "dropdown", options: [
          { value: "hourly", label: "1 h" }, { value: "daily", label: "24 h" }, { value: "weekly", label: "7 d" }, { value: "monthly", label: "30 d" }] } } },
      ],
    };
  }

  static getStubConfig(hass) {
    const ent = Object.values(hass.entities || {}).find((e) => e.platform === DOMAIN && e.device_id);
    return ent ? { device_id: ent.device_id } : {};
  }

  setConfig(config) {
    this._config = { period: "daily", resolvers: [], names: {}, ...config };
    this._st = this._st || {
      period: this._config.period, tab: "traffic", list: "apps", metric: "volume",
      type: "all", dir: "all", sev: "all", open: new Set(),
    };
    if (!this.shadowRoot) this.attachShadow({ mode: "open" });
    if (!SI) SI_READY.then(() => this._render());
    this._render();
  }

  set hass(hass) {
    const first = !this._hass;
    this._hass = hass;
    const sig = this._signature();
    if (first || sig !== this._sig) {
      this._sig = sig;
      this._render();
    }
  }

  connectedCallback() {
    // charts are drawn 1:1 in the real width (no stretching → undistorted text)
    if (!this._ro && window.ResizeObserver) {
      this._ro = new ResizeObserver((entries) => {
        const w = Math.round(entries[0].contentRect.width);
        if (w && Math.abs(w - (this._w || 0)) > 8) {
          this._w = w;
          clearTimeout(this._rt);
          this._rt = setTimeout(() => this._render(), 60);
        }
      });
      this._ro.observe(this);
    }
  }

  disconnectedCallback() {
    if (this._ro) { this._ro.disconnect(); this._ro = null; }
  }

  /** Drawing width for SVG charts = card content width. */
  get _cw() { return Math.max(300, (this._w || 640) - 28); }

  getCardSize() { return 12; }
  // full width in sections views (event viewer needs the space); users can still resize it
  getGridOptions() { return { columns: "full", min_columns: 6 }; }

  /* ------------------------------------------------------------ data -- */
  get _lang() { return (this._hass?.locale?.language || this._hass?.language || "en").startsWith("de") ? "de" : "en"; }
  get _t() { return T[this._lang]; }
  get _loc() { return this._hass?.locale?.language || undefined; }

  _entities() {
    const hass = this._hass;
    let dev = this._config.device_id;
    const all = Object.values(hass.entities || {}).filter((e) => e.platform === DOMAIN);
    if (!dev && all.length) dev = all.find((e) => e.device_id)?.device_id;
    const map = {};
    for (const e of all) {
      if (dev && e.device_id !== dev) continue;
      map[e.translation_key || e.entity_id.split(".")[1]] = e.entity_id;
    }
    this._device = dev;
    return map;
  }

  _signature() {
    const ids = Object.values(this._entities());
    return ids.map((id) => this._hass.states[id]?.last_updated || "").join("|") + "|" + (this._hass.locale?.language || "");
  }

  _s(key) { const id = this._map[key]; return id ? this._hass.states[id] : undefined; }
  _v(key) { const s = this._s(key); const n = s ? parseFloat(s.state) : NaN; return isNaN(n) ? null : n; }
  _a(key, attr) { return this._s(key)?.attributes?.[attr] ?? null; }
  _pk(metric) { return `${this._st.period}_${metric}`; }

  _num(n, d = 0) { return n == null ? "–" : Number(n).toLocaleString(this._loc, { maximumFractionDigits: d }); }
  _bytes(b) {
    if (b == null) return "–";
    const u = [["TB", 1e12], ["GB", 1e9], ["MB", 1e6], ["KB", 1e3]].find(([, f]) => b >= f) || ["B", 1];
    const v = b / u[1];
    return `${this._num(v, v < 10 ? 2 : v < 100 ? 1 : 0)} ${u[0]}`;
  }
  _gbState(key) { const v = this._v(key); return v == null ? null : v * 1e9; } // sensors are in GB
  _time(iso, withDate = true) {
    const d = new Date(iso);
    if (isNaN(d)) return "–";
    return d.toLocaleString(this._loc, withDate ? { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" } : { hour: "2-digit", minute: "2-digit" });
  }
  _pill(text, color, icon) {
    return `<span class="pill" style="--c:${color}">${icon ? `<ha-icon icon="${icon}"></ha-icon>` : ""}${esc(text)}</span>`;
  }
  _sev(s) {
    const k = SEV[String(s ?? "").toLowerCase()];
    return k ? this._pill(SEV_TXT[this._lang][k], SEV_COLOR[k]) : (s ? esc(s) : "–");
  }
  _dir(d) { return DIR_ICON[d] ? this._pill(this._t[d], DIR_COLOR[d], DIR_ICON[d]) : ""; }
  _who(ip) {
    if (!ip) return "–";
    const tr = Object.values(this._hass.states).find((s) => s.entity_id.startsWith("device_tracker.") && s.attributes.ip === ip);
    let name = (this._config.names || {})[ip] || (tr ? tr.attributes.friendly_name || tr.attributes.host_name || "" : "");
    const w = name.split(" ");
    if (w.length % 2 === 0 && w.slice(0, w.length / 2).join(" ") === w.slice(w.length / 2).join(" ")) name = w.slice(0, w.length / 2).join(" ");
    const res = (this._config.resolvers || []).includes(ip) ? ` <span class="muted small">· ${esc(this._t.resolver)}</span>` : "";
    return (name ? `${esc(name)} <span class="muted small">${esc(ip)}</span>` : esc(ip)) + res;
  }

  /** Stored syslog detections within the selected period, newest first. */
  _events() {
    const hist = this._a("detections_30d", "history") || [];
    const cutoff = Date.now() - PERIOD_HOURS[this._st.period] * 3600e3;
    return hist.filter((h) => new Date(h.time).getTime() >= cutoff);
  }

  /* ---------------------------------------------------------- render -- */
  _render() {
    if (!this.shadowRoot || !this._config) return;
    if (!this._hass) { this.shadowRoot.innerHTML = ""; return; }
    this._map = this._entities();
    const t = this._t, st = this._st;
    if (!Object.keys(this._map).length) {
      this.shadowRoot.innerHTML = `<style>${CSS}</style><ha-card><div class="pad muted">${esc(t.noDevice)}</div></ha-card>`;
      return;
    }
    const dev = this._device && this._hass.devices ? this._hass.devices[this._device] : null;
    const title = this._config.title || (dev && (dev.name_by_user || dev.name)) || t.title;
    if (st.tab === "system") this._loadStats();
    const body = st.tab === "traffic" ? this._traffic() : st.tab === "tp" ? this._threats() : this._system();
    this.shadowRoot.innerHTML = `<style>${CSS}</style>
      <ha-card>
        <div class="head">
          <div class="title"><ha-icon icon="mdi:shield-half-full"></ha-icon><span>${esc(title)}</span></div>
          <div class="chips">${this._chips()}</div>
        </div>
        <div class="seg">${PERIODS.map((p) => `<button class="${st.period === p ? "on" : ""}" data-period="${p}">${esc(t["p_" + p])}</button>`).join("")}</div>
        ${this._summary()}
        <div class="tabs">${[["traffic", t.traffic, "mdi:swap-vertical-bold"], ["tp", t.tp, "mdi:shield-alert"], ["system", t.system, "mdi:chip"]]
          .map(([k, l, i]) => `<button class="tab ${st.tab === k ? "on" : ""}" data-tab="${k}"><ha-icon icon="${i}"></ha-icon>${esc(l)}</button>`).join("")}</div>
        <div class="body">${body}</div>
      </ha-card>`;
    this._bind();
  }

  _bind() {
    const root = this.shadowRoot, st = this._st;
    const on = (sel, fn) => root.querySelectorAll(sel).forEach((el) => el.addEventListener("click", () => fn(el)));
    on("[data-period]", (el) => { st.period = el.dataset.period; st.open.clear(); this._render(); });
    on("[data-tab]", (el) => { st.tab = el.dataset.tab; this._render(); });
    on("[data-list]", (el) => { st.list = el.dataset.list; this._render(); });
    on("[data-metric]", (el) => { st.metric = el.dataset.metric; this._render(); });
    on("[data-type]", (el) => { st.type = el.dataset.type; st.open.clear(); this._render(); });
    on("[data-dir]", (el) => { st.dir = el.dataset.dir; st.open.clear(); this._render(); });
    on("[data-sev]", (el) => { st.sev = el.dataset.sev; st.open.clear(); this._render(); });
    on("[data-ev]", (el) => {
      const k = el.dataset.ev;
      st.open.has(k) ? st.open.delete(k) : st.open.add(k);
      this._render();
    });
  }

  _chips() {
    const t = this._t;
    const chip = (ok, text, icon) => this._pill(text, ok ? C.green : C.red, icon);
    const out = [];
    const inet = this._s("internet");
    if (inet) out.push(chip(inet.state === "on", `${t.internet} ${inet.state === "on" ? t.online : t.offline}`, "mdi:web"));
    const thr = this._s("threat_active");
    if (thr) out.push(chip(thr.state !== "on", thr.state === "on" ? t.threat : t.noInfection, "mdi:shield-check"));
    const blades = this._a("active_blades", "blades") || {};
    const bf = this._s("blade_failure");
    if (Object.keys(blades).length) {
      const n = Object.values(blades).filter(Boolean).length;
      out.push(chip(!bf || bf.state !== "on", bf?.state === "on" ? `${t.bladeOff}: ${(bf.attributes.disabled || []).join(", ")}` : `${n}/${Object.keys(blades).length} ${t.blades}`, "mdi:puzzle"));
    }
    const hw = this._s("hardware_problem");
    if (hw) out.push(chip(hw.state !== "on", hw.state === "on" ? t.hwProblem : t.hwOk, "mdi:chip"));
    return out.join("");
  }

  /** Summary strip like page 1 of the gateway's PDF report – display only. */
  _summary() {
    const t = this._t;
    const total = this._gbState(this._pk("traffic"));
    const apps = this._a(this._pk("traffic"), "top_apps_by_bandwidth") || [];
    const sites = this._a(this._pk("traffic"), "top_sites_by_bandwidth") || [];
    const pct = (b) => (total && b ? ` · ${this._num((100 * b) / total, 0)} %` : "");
    const val = (key) => (this._s(this._pk(key)) ? this._num(this._v(this._pk(key))) : "–");
    const warn = (key, color) => { const v = this._v(this._pk(key)); return v == null ? C.grey : v > 0 ? color : C.green; };
    const cell = (label, value, color, sub) => `<div class="sum"><div class="v" style="color:${color}">${value}</div><div class="l">${esc(label)}</div>${sub ? `<div class="s">${sub}</div>` : ""}</div>`;
    return `<div class="sums">
      ${cell(t.volume, this._bytes(total), C.blue, `↓ ${this._bytes(this._gbState(this._pk("download")))} · ↑ ${this._bytes(this._gbState(this._pk("upload")))}`)}
      ${cell(t.sessions, val("sessions"), C.purple, apps[0] ? `${esc(t.topApp)}: ${esc(apps[0].name)}${pct(apps[0].bytes)}` : "")}
      ${cell(t.ips, val("ips_events"), warn("ips_events", C.amber), this._s(this._pk("ips_events")) ? "" : esc(t.noReport))}
      ${cell(t.blocked, val("virus_incidents"), warn("virus_incidents", C.amber), sites[0] ? `${esc(t.topSite)}: ${esc(sites[0].name)}` : "")}
      ${cell(t.bots, val("bot_incidents"), warn("bot_incidents", C.red))}
      ${cell(t.infected, val("infected_hosts"), warn("infected_hosts", C.red))}
    </div>`;
  }

  /* --------------------------------------------------------- traffic -- */
  _traffic() {
    const t = this._t, st = this._st;
    const tk = this._pk("traffic"), sk = this._pk("sessions");
    const lists = {
      apps: [tk, "top_apps_by_bandwidth", sk, "top_apps_by_sessions"],
      sites: [tk, "top_sites_by_bandwidth", sk, "top_sites_by_sessions"],
      categories: [tk, "top_categories_by_bandwidth", sk, "top_categories_by_sessions"],
    }[st.list];
    const items = (st.metric === "volume" ? this._a(lists[0], lists[1]) : this._a(lists[2], lists[3])) || [];
    const key = st.metric === "volume" ? "bytes" : "sessions";
    const max = Math.max(1, ...items.map((i) => i[key] || 0));
    const color = { apps: PALETTE[0], sites: PALETTE[2], categories: PALETTE[1] }[st.list];
    const rows = items.slice(0, 10).map((i) => `<tr><td class="ic">${iconHtml(i.name + " " + (i.category || ""), st.list)}</td>
        <td class="n">${esc(i.name)}${i.category ? ` <span class="muted small">${esc(i.category)}</span>` : ""}${this._bar(i[key] || 0, max, color)}</td>
        <td class="r">${st.metric === "volume" ? this._bytes(i.bytes) : this._num(i.sessions)}</td>
        <td class="r muted small">${st.metric === "volume" ? `↓ ${this._bytes(i.down_bytes)}<br>↑ ${this._bytes(i.up_bytes)}` : this._bytes(i.bytes)}</td></tr>`);
    const risky = this._a(this._pk("high_risk_sessions"), "top_high_risk_apps");
    return `<h4>${esc(t.history)}</h4>${this._barChart()}
      <h4>${esc(t.flow)}: ↓/↑ → ${esc(t.categories)}</h4>${this._trafficSankey()}
      <div class="row">
        <div class="seg sm">${[["apps", t.apps], ["sites", t.sites], ["categories", t.categories]].map(([k, l]) => `<button class="${st.list === k ? "on" : ""}" data-list="${k}">${esc(l)}</button>`).join("")}</div>
        <div class="seg sm">${[["volume", t.byVolume], ["sessions", t.bySessions]].map(([k, l]) => `<button class="${st.metric === k ? "on" : ""}" data-metric="${k}">${esc(l)}</button>`).join("")}</div>
      </div>
      ${this._table(["", t.name, st.metric === "volume" ? t.volume : t.sessions, ""], rows)}
      ${risky ? `<h4>${esc(t.highRisk)}</h4>` + this._table(["", t.name, t.sessions, ""], risky.map((r) => `<tr><td class="ic">${iconHtml(r.name + " " + (r.category || ""), "apps")}</td><td class="n">${esc(r.name)}${r.category ? ` <span class="muted small">${esc(r.category)}</span>` : ""}</td><td class="r">${this._num(r.sessions)}</td><td class="r">${this._sev(r.risk)}</td></tr>`)) : ""}`;
  }

  _bar(v, max, color) { return `<div class="bar"><div style="width:${Math.max(2, Math.round((100 * v) / (max || 1)))}%;background:${color}"></div></div>`; }

  _table(head, rows, empty) {
    if (!rows.length) return `<div class="muted pad">${esc(empty || this._t.none)}</div>`;
    return `<table><tr>${head.map((h, i) => `<th class="${i > 1 ? "r" : ""}">${esc(h)}</th>`).join("")}</tr>${rows.join("")}</table>`;
  }

  /** Stacked bars (download/upload) with a soft grid and 1-2-5 steps. */
  _barChart() {
    const hist = [...(this._a(this._pk("traffic"), "bandwidth_history") || [])].reverse();
    if (!hist.length) return `<div class="muted pad">${esc(this._t.noData)}</div>`;
    const W = this._cw, H = 150, L = 54, B = 20, top = 8;
    const totals = hist.map((h) => (h.down_bytes || 0) + (h.up_bytes || 0));
    const step = niceStep(Math.max(...totals, 1));
    const ymax = Math.ceil(Math.max(...totals, 1) / step) * step;
    const y = (v) => top + (H - top - B) * (1 - v / ymax);
    const bw = (W - L) / hist.length;
    let svg = "";
    for (let g = 0; g <= ymax * 1.0001; g += step) {
      svg += `<line x1="${L}" x2="${W}" y1="${y(g)}" y2="${y(g)}" class="grid"/><text x="${L - 6}" y="${y(g) + 3}" class="ax" text-anchor="end">${esc(this._bytes(g))}</text>`;
    }
    const every = Math.ceil(hist.length / Math.max(3, Math.floor(W / 90)));
    const withDate = this._st.period === "weekly" || this._st.period === "monthly";
    hist.forEach((h, i) => {
      const x = L + i * bw + bw * 0.15, w = bw * 0.7;
      const d = h.down_bytes || 0, u = h.up_bytes || 0;
      svg += `<rect x="${x}" y="${y(d)}" width="${w}" height="${Math.max(0, y(0) - y(d))}" fill="${PALETTE[0]}" rx="1"><title>${esc(this._time(h.time))} ↓ ${esc(this._bytes(d))}</title></rect>`;
      svg += `<rect x="${x}" y="${y(d + u)}" width="${w}" height="${Math.max(0, y(d) - y(d + u))}" fill="${PALETTE[1]}" rx="1"><title>${esc(this._time(h.time))} ↑ ${esc(this._bytes(u))}</title></rect>`;
      if (i % every === 0) {
        const lab = withDate ? new Date(h.time).toLocaleDateString(this._loc, { day: "2-digit", month: "2-digit" }) : this._time(h.time, false);
        svg += `<text x="${x + w / 2}" y="${H - 5}" class="ax" text-anchor="middle">${esc(lab)}</text>`;
      }
    });
    return `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" class="chart">${svg}</svg>
      <div class="legend">${this._pill(this._t.down, PALETTE[0])} ${this._pill(this._t.up, PALETTE[1])}</div>`;
  }

  /** Sankey: Download / Upload → categories (top 7 + other). */
  _trafficSankey() {
    const cats = this._a(this._pk("traffic"), "top_categories_by_bandwidth") || [];
    if (!cats.length) return `<div class="muted pad">${esc(this._t.noData)}</div>`;
    const top = cats.slice(0, 7), rest = cats.slice(7);
    const right = top.map((c, i) => ({ id: "c" + i, label: c.name, color: PALETTE[(i + 2) % PALETTE.length], down: c.down_bytes || 0, up: c.up_bytes || 0 }));
    if (rest.length) right.push({ id: "co", label: this._t.other, color: PALETTE[8], down: rest.reduce((s, c) => s + (c.down_bytes || 0), 0), up: rest.reduce((s, c) => s + (c.up_bytes || 0), 0) });
    const links = [];
    right.forEach((r) => { links.push({ s: "down", t: r.id, v: r.down }); links.push({ s: "up", t: r.id, v: r.up }); });
    return this._sankey([[{ id: "down", label: this._t.down, color: PALETTE[0] }, { id: "up", label: this._t.up, color: PALETTE[1] }], right], links, (v) => this._bytes(v));
  }

  /**
   * Minimal sankey: columns of nodes, node height ∝ max(in, out), links as bezier bands.
   * cols = [[{id,label,color}], …], links = [{s,t,v}]
   */
  _sankey(cols, links, fmt) {
    links = links.filter((l) => l.v > 0);
    if (!links.length) return `<div class="muted pad">${esc(this._t.noData)}</div>`;
    const W = this._cw, padY = 6, nodeW = 10, gap = 8;
    const val = {};
    for (const l of links) { val[l.s] = val[l.s] || { i: 0, o: 0 }; val[l.t] = val[l.t] || { i: 0, o: 0 }; val[l.s].o += l.v; val[l.t].i += l.v; }
    const used = cols.map((c) => c.filter((n) => val[n.id]));
    const colTotal = used.map((c) => c.reduce((s, n) => s + Math.max(val[n.id].i, val[n.id].o), 0));
    const maxN = Math.max(...used.map((c) => c.length));
    const H = Math.max(140, maxN * 26 + 20);
    const scale = Math.min(...used.map((c, i) => (c.length ? (H - 2 * padY - gap * (c.length - 1)) / (colTotal[i] || 1) : Infinity)));
    const pos = {};
    const narrow = W < 480;
    const x0 = narrow ? 95 : 140, x1 = W - (narrow ? 120 : 190);
    used.forEach((c, ci) => {
      const x = x0 + ((x1 - x0) * ci) / Math.max(1, cols.length - 1);
      const h = c.reduce((s, n) => s + Math.max(val[n.id].i, val[n.id].o) * scale, 0) + gap * Math.max(0, c.length - 1);
      let yy = (H - h) / 2;
      for (const n of c) {
        const nh = Math.max(2, Math.max(val[n.id].i, val[n.id].o) * scale);
        pos[n.id] = { x, y: yy, h: nh, oy: yy, iy: yy, n, ci };
        yy += nh + gap;
      }
    });
    let svg = "";
    for (const l of links) {
      const a = pos[l.s], b = pos[l.t];
      if (!a || !b) continue;
      const th = Math.max(1, l.v * scale);
      const xa = a.x + nodeW, xb = b.x, ya = a.oy + th / 2, yb = b.iy + th / 2, mx = (xa + xb) / 2;
      svg += `<path d="M${xa},${ya} C${mx},${ya} ${mx},${yb} ${xb},${yb}" stroke="${b.n.color}" stroke-width="${th}" fill="none" class="link"><title>${esc(a.n.label)} → ${esc(b.n.label)}: ${esc(fmt(l.v))}</title></path>`;
      a.oy += th; b.iy += th;
    }
    for (const p of Object.values(pos)) {
      const v = Math.max(val[p.n.id].i, val[p.n.id].o);
      const last = p.ci === cols.length - 1;
      const maxLen = narrow ? 13 : 26;
      const label = p.n.label.length > maxLen ? p.n.label.slice(0, maxLen - 1) + "…" : p.n.label;
      svg += `<rect x="${p.x}" y="${p.y}" width="${nodeW}" height="${p.h}" fill="${p.n.color}" rx="2"><title>${esc(p.n.label)}: ${esc(fmt(v))}</title></rect>`;
      svg += `<text x="${last ? p.x + nodeW + 6 : p.x - 6}" y="${p.y + p.h / 2 + 4}" class="lab" text-anchor="${last ? "start" : "end"}">${esc(label)} <tspan class="sub">${esc(fmt(v))}</tspan></text>`;
    }
    return `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" class="sankey">${svg}</svg>`;
  }

  /* ------------------------------------------------ threat prevention -- */
  _threats() {
    const t = this._t, st = this._st;
    const hasSyslog = !!this._s("syslog_messages") || !!this._s("detections_30d");
    const evAll = this._events();
    const match = (h, skip) => (skip === "type" || st.type === "all" || evType(h) === st.type)
      && (skip === "dir" || st.dir === "all" || (h.direction || "unknown") === st.dir)
      && (skip === "sev" || st.sev === "all" || sevKey(h) === st.sev);
    const ev = evAll.filter((h) => match(h));
    // counts per chip respect the other two filters
    const count = (skip, pred) => evAll.filter((h) => match(h, skip) && pred(h)).length;
    const report = { malware: this._v(this._pk("virus_incidents")), bot: this._v(this._pk("bot_incidents")) };
    const typeBtn = (k, label, color) => {
      const n = k === "all" ? count("type", () => true) : count("type", (h) => evType(h) === k);
      const r = report[k];
      const badge = n === 0 && r ? `<span class="cnt" title="${esc(t.reportOnly)}">Σ ${this._num(r)}</span>` : `<span class="cnt">${n}</span>`;
      return `<button class="${st.type === k ? "on" : ""}" data-type="${k}" style="--c:${color}">${esc(label)}${badge}</button>`;
    };
    const dirBtn = (k, label) => `<button class="${st.dir === k ? "on" : ""}" data-dir="${k}" style="--c:${DIR_COLOR[k] || C.grey}">${DIR_ICON[k] ? `<ha-icon icon="${DIR_ICON[k]}"></ha-icon>` : ""}${esc(label)}<span class="cnt">${k === "all" ? count("dir", () => true) : count("dir", (h) => (h.direction || "unknown") === k)}</span></button>`;
    const sevBtn = (k, label) => `<button class="${st.sev === k ? "on" : ""}" data-sev="${k}" style="--c:${SEV_COLOR[k] || C.grey}">${esc(label)}<span class="cnt">${k === "all" ? count("sev", () => true) : count("sev", (h) => sevKey(h) === k)}</span></button>`;
    const sevTxt = SEV_TXT[this._lang];
    const filters = `<div class="filters">
      <span class="fl">${esc(t.type)}</span><div class="seg sm chips-seg">
        ${typeBtn("all", t.all, C.grey)}${typeBtn("ips", t.ips, TYPE_COLOR.ips)}${typeBtn("malware", t.blocked, TYPE_COLOR.malware)}${typeBtn("bot", t.bots, TYPE_COLOR.bot)}</div>
      <span class="fl">${esc(t.dir)}</span><div class="seg sm chips-seg">
        ${dirBtn("all", t.all)}${["inbound", "internal", "outbound"].map((d) => dirBtn(d, t[d])).join("")}</div>
      <span class="fl">${esc(t.severity)}</span><div class="seg sm chips-seg">
        ${sevBtn("all", t.all)}${["critical", "high", "medium", "low"].map((k) => sevBtn(k, sevTxt[k])).join("")}</div>
    </div>`;
    const noType = (st.type === "malware" || st.type === "bot") && count("type", (h) => evType(h) === st.type) === 0;
    const events = !hasSyslog ? `<div class="hint">${esc(t.noSyslog)}</div>`
      : noType ? `<div class="hint">${esc(t.noSyslogType)}</div>`
      : `<h4>${esc(t.flow)}: ${esc(t.dir)} → ${esc(t.type)} → ${esc(t.action)}</h4>${this._threatSankey(ev)}
         <h4>${esc(t.events)} · ${ev.length}</h4>${this._eventTable(ev)}`;
    return filters + events + this._reportThreats();
  }

  _threatSankey(ev) {
    const t = this._t;
    const dirs = ["inbound", "internal", "outbound", "unknown"].map((d) => ({ id: "d_" + d, label: t[d], color: DIR_COLOR[d] }));
    const types = [["ips", t.ips], ["malware", t.blocked], ["bot", t.bots]].map(([k, l]) => ({ id: "t_" + k, label: l, color: TYPE_COLOR[k] }));
    const acts = [["blocked", t.blockedA], ["detected", t.detectedA], ["allowed", t.allowedA]].map(([k, l]) => ({ id: "a_" + k, label: l, color: ACT_COLOR[k] }));
    const agg = {};
    for (const h of ev) {
      const d = "d_" + (h.direction || "unknown"), ty = "t_" + evType(h), a = "a_" + evAction(h);
      agg[d + ">" + ty] = (agg[d + ">" + ty] || 0) + 1;
      agg[ty + ">" + a] = (agg[ty + ">" + a] || 0) + 1;
    }
    const links = Object.entries(agg).map(([k, v]) => { const [s, tt] = k.split(">"); return { s, t: tt, v }; });
    return this._sankey([dirs, types, acts], links, (v) => this._num(v));
  }

  /** Events grouped by type + name + source host: one row per "same alert from the same host". */
  _eventTable(ev) {
    const t = this._t, st = this._st;
    if (!ev.length) return `<div class="muted pad">${esc(t.noEvents)}</div>`;
    const groups = new Map();
    for (const h of ev) {
      const type = evType(h);
      const key = `${type}|${h.name || h.attack || ""}|${h.src || ""}`;
      let g = groups.get(key);
      if (!g) groups.set(key, (g = { key, type, h, items: [], dsts: new Map(), dirs: new Set(), sev: "info" }));
      g.items.push(h);
      g.dsts.set(h.dst || "–", (g.dsts.get(h.dst || "–") || 0) + 1);
      if (h.direction) g.dirs.add(h.direction);
      if (SEV_RANK[sevKey(h)] > SEV_RANK[g.sev]) g.sev = sevKey(h);
    }
    const list = [...groups.values()].sort((a, b) => new Date(b.items[0].time) - new Date(a.items[0].time));
    const rows = list.slice(0, 40).map((g) => {
      const h = g.h, last = g.items[0], first = g.items[g.items.length - 1];
      const open = st.open.has(g.key);
      const cves = String(h.cve || "").split(",").map((c) => c.trim()).filter((c) => /^CVE-\d+-\d+$/.test(c));
      const typeLabel = g.type === "ips" ? t.ips : g.type === "bot" ? t.bots : t.blocked;
      const many = g.items.length > 1;
      const when = many ? `${esc(this._time(last.time))}<div class="muted small">${esc(t.first)} ${esc(this._time(first.time))}</div>` : esc(this._time(last.time));
      const dsts = [...g.dsts.entries()].sort((a, b) => b[1] - a[1]);
      const detail = open ? `<tr class="det"><td colspan="4">
          <div class="kv"><span>${esc(t.src)}</span><b>${this._who(h.src)}</b></div>
          <div class="kv"><span>${esc(t.dst)}</span><b>${dsts.map(([d, n]) => `${this._who(d === "–" ? "" : d)}${many ? ` <span class="muted small">×${n}</span>` : ""}`).join("<br>")}</b></div>
          <div class="kv"><span>${esc(t.dir)}</span><b>${[...g.dirs].map((d) => this._dir(d)).join(" ") || "–"}</b></div>
          <div class="kv"><span>${esc(t.action)}</span><b>${esc([...new Set(g.items.map((i) => i.action || "–"))].join(", "))}</b></div>
          ${h.attack && h.attack !== h.name ? `<div class="kv"><span>${esc(t.type)}</span><b>${esc(h.attack)}</b></div>` : ""}
          ${h.product ? `<div class="kv"><span>Blade</span><b>${esc(h.product)}</b></div>` : ""}
          ${cves.length ? `<div class="kv"><span>CVE</span><b>${cves.map((c) => `<a href="https://nvd.nist.gov/vuln/detail/${c}" target="_blank" rel="noopener">${c}</a>`).join(" · ")}</b></div>` : ""}
          ${last.resource ? `<div class="kv"><span>${esc(t.requested)}</span></div><code>${esc(last.resource)}</code>` : ""}
          ${g.type === "malware" ? `<div class="muted small pad">${esc(t.dnsHint)}</div>` : ""}
          ${many ? `<h4>${esc(t.occurrences)} · ${g.items.length}</h4><table class="occ">${g.items.slice(0, 20).map((i) =>
            `<tr><td class="nw">${esc(this._time(i.time))}</td><td class="n">${this._who(i.dst)}</td><td class="r">${this._dir(i.direction)}</td><td class="r muted small">${esc(i.action || "")}</td></tr>`).join("")}</table>` : ""}
        </td></tr>` : "";
      return `<tr class="click ${open ? "open" : ""}" data-ev="${esc(g.key)}">
          <td class="nw">${when}</td>
          <td class="n">${this._pill(typeLabel, TYPE_COLOR[g.type])} ${esc(h.name || h.attack || "–")}${many ? ` <span class="pill" style="--c:var(--primary-color)">×${g.items.length}</span>` : ""}
            <div class="small">${[...g.dirs].map((d) => this._dir(d)).join(" ")} <span class="muted">${this._who(h.src)}${dsts.length > 1 ? ` · ${dsts.length} ${esc(t.targets)}` : ""}</span></div></td>
          <td class="r">${this._sev(g.sev)}</td><td class="r chev">${open ? "▾" : "▸"}</td></tr>${detail}`;
    });
    return `<table><tr><th>${esc(t.time)}</th><th>${esc(t.name)}</th><th class="r">${esc(t.sev)}</th><th></th></tr>${rows.join("")}</table>`;
  }

  /** Report totals (no time/source) for the selected period and type filter. */
  _reportThreats() {
    const t = this._t, st = this._st;
    let out = `<h4 class="sep">${esc(t.reportPart)}</h4>`;
    if (st.type === "all" || st.type === "ips") {
      const prot = this._a(this._pk("ips_events"), "top_protections");
      out += `<h4>${esc(t.protections)}</h4>` + (prot ? this._table(["", t.name, t.hits, t.sev], prot.slice(0, 10).map((i) =>
        `<tr><td class="ic"><ha-icon icon="mdi:shield-alert-outline"></ha-icon></td><td class="n">${esc(i.name)}${i.cve ? `<div class="muted small">${esc(i.cve.split(",")[0])}</div>` : ""}</td><td class="r">${this._num(i.sessions)}</td><td class="r">${this._sev(i.severity)}</td></tr>`)) : `<div class="muted pad">${esc(t.noReport)}</div>`);
    }
    if (st.type === "all" || st.type === "malware") {
      const mal = this._a(this._pk("virus_incidents"), "top_malwares") || [];
      out += `<h4>${esc(t.malware)}</h4>` + this._table(["", t.name, t.incidents, t.sev], mal.slice(0, 10).map((i) =>
        `<tr><td class="ic"><ha-icon icon="mdi:virus-outline"></ha-icon></td><td class="n">${esc(i.name)}</td><td class="r">${this._num(i.incidents)}</td><td class="r">${this._sev(i.severity)}</td></tr>`)) +
        `<div class="muted small pad">${esc(t.dnsHint)}</div>`;
    }
    if (st.type !== "ips") {
      const hosts = this._a(this._pk("infected_hosts"), "top_infected_hosts") || [];
      const max = Math.max(1, ...hosts.map((h) => h.count || 0));
      out += `<h4>${esc(t.hosts)}</h4>` + this._table(["", t.host, t.incidents], hosts.map((h) =>
        `<tr><td class="ic"><ha-icon icon="mdi:laptop"></ha-icon></td><td class="n">${this._who(h.name)}${this._bar(h.count || 0, max, C.red)}</td><td class="r">${this._num(h.count)}</td></tr>`));
      const inf = [[t.infHosts, "infected_hosts"], [t.newInf, "new_infected_hosts"], [t.critInf, "critical_infected_hosts"], [t.servers, "infected_servers"]];
      out += `<div class="grid4">${inf.map(([l, k]) => { const v = this._v(this._pk(k)); return `<div class="mini"><b style="color:${v ? C.red : C.green}">${this._num(v)}</b><span>${esc(l)}</span></div>`; }).join("")}</div>`;
    }
    return out;
  }

  /* ------------------------------------------------ system statistics -- */
  /** Long-term statistics (recorder) for the system charts; cached per period for 5 minutes. */
  _loadStats() {
    const ids = ["cpu_temperature", "ddr_temperature", "memory_used", "cpu_load", "memory_load", "wan_download",
      "wan_upload", "wan_latency", "wan_jitter", "connections"].map((k) => this._map[k]).filter(Boolean);
    if (!ids.length || !this._hass?.callWS) return;
    const period = this._st.period;
    const c = this._stats;
    if (c && c.period === period && (c.loading || Date.now() - c.at < 300e3)) return;
    this._stats = { period, loading: true, at: Date.now(), data: c && c.period === period ? c.data : null };
    const end = new Date(), start = new Date(end - PERIOD_HOURS[period] * 3600e3);
    this._hass.callWS({
      type: "recorder/statistics_during_period", start_time: start.toISOString(), end_time: end.toISOString(),
      statistic_ids: ids, period: PERIOD_HOURS[period] > 24 ? "hour" : "5minute", types: ["mean", "min", "max"],
    }).then((data) => {
      if (this._stats.period === period) { this._stats = { period, loading: false, at: Date.now(), data }; this._render(); }
    }).catch(() => { this._stats = { period, loading: false, at: Date.now(), data: {} }; this._render(); });
  }

  /** Line chart (mean, with min/max band) in the real card width, soft grid, 1-2-5 steps. */
  _lineChart(series, unit, digits = 0) {
    const pts = series.map((sr) => ({ ...sr, rows: (this._stats?.data?.[sr.id] || []).filter((r) => r.mean != null) }));
    if (!pts.some((p) => p.rows.length)) {
      return `<div class="muted pad">${esc(this._stats?.loading ? this._t.loading : this._t.noStats)}</div>`;
    }
    const W = this._cw, H = 140, L = 54, B = 20, top = 8;
    const all = pts.flatMap((p) => p.rows.flatMap((r) => [r.min ?? r.mean, r.max ?? r.mean]));
    let lo = Math.min(...all), hi = Math.max(...all);
    if (hi - lo < 1e-9) { lo -= 1; hi += 1; }
    const step = niceStep(hi - lo, 4);
    lo = Math.floor(lo / step) * step; hi = Math.ceil(hi / step) * step;
    const t0 = Date.now() - PERIOD_HOURS[this._st.period] * 3600e3, t1 = Date.now();
    const x = (t) => L + ((W - L - 4) * (t - t0)) / (t1 - t0);
    const y = (v) => top + (H - top - B) * (1 - (v - lo) / (hi - lo));
    let svg = "";
    for (let g = lo; g <= hi + step / 2; g += step) {
      svg += `<line x1="${L}" x2="${W}" y1="${y(g)}" y2="${y(g)}" class="grid"/><text x="${L - 6}" y="${y(g) + 3}" class="ax" text-anchor="end">${esc(this._num(g, digits))} ${esc(unit)}</text>`;
    }
    const ticks = Math.max(3, Math.floor(W / 110));
    const withDate = PERIOD_HOURS[this._st.period] > 24;
    for (let i = 0; i <= ticks; i++) {
      const t = t0 + ((t1 - t0) * i) / ticks;
      const lab = withDate ? new Date(t).toLocaleDateString(this._loc, { day: "2-digit", month: "2-digit" }) : this._time(new Date(t).toISOString(), false);
      svg += `<text x="${x(t)}" y="${H - 5}" class="ax" text-anchor="${i === 0 ? "start" : i === ticks ? "end" : "middle"}">${esc(lab)}</text>`;
    }
    for (const p of pts) {
      if (!p.rows.length) continue;
      const band = p.rows.map((r) => `${x(r.start)},${y(r.max ?? r.mean)}`).join(" ") + " " +
        [...p.rows].reverse().map((r) => `${x(r.start)},${y(r.min ?? r.mean)}`).join(" ");
      svg += `<polygon points="${band}" fill="${p.color}" opacity=".15"/>`;
      svg += `<polyline points="${p.rows.map((r) => `${x(r.start)},${y(r.mean)}`).join(" ")}" fill="none" stroke="${p.color}" stroke-width="2" stroke-linejoin="round"/>`;
    }
    const legend = pts.map((p) => {
      const last = p.rows[p.rows.length - 1];
      return this._pill(`${p.label}${last ? ` ${this._num(last.mean, digits)} ${unit}` : ""}`, p.color);
    }).join(" ");
    return `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" class="chart">${svg}</svg><div class="legend">${legend}</div>`;
  }

  /* ---------------------------------------------------------- system -- */
  _system() {
    const t = this._t;
    const blades = this._a("active_blades", "blades") || {};
    const inet = this._s("internet_connected_since");
    const cpu = this._v("cpu_temperature"), ddr = this._v("ddr_temperature");
    const exp = this._s("next_contract_expiry");
    const kv = (k, v) => `<div class="kv"><span>${esc(k)}</span><b>${v}</b></div>`;
    const expired = exp?.attributes?.expired_contracts || [];
    return `<div class="blades">${Object.entries(blades).map(([k, on]) => `<span class="${on ? "" : "off"}"><ha-icon icon="${on ? "mdi:check-circle" : "mdi:minus-circle-outline"}"></ha-icon>${esc(BLADE[k] || k)}</span>`).join("")}</div>` +
      kv(t.internet, inet && !isNaN(new Date(inet.state)) ? `${esc(t.since)} ${esc(this._time(inet.state))}` : "–") +
      kv(t.vpn, this._num(this._v("vpn_tunnels_up"))) +
      kv(t.cpu, `${cpu == null ? "–" : Math.round(cpu) + " °C"} / ${ddr == null ? "–" : Math.round(ddr) + " °C"}`) +
      kv(t.mem, this._v("memory_used") == null ? "–" : `${this._num(this._v("memory_used"))} MB`) +
      kv(t.emmc, this._v("emmc_wear") == null ? "–" : `≤ ${this._num(this._v("emmc_wear"))} %`) +
      kv(t.contracts, exp && !isNaN(new Date(exp.state)) ? `${esc(new Date(exp.state).toLocaleDateString(this._loc))}${expired.length ? ` <span class="muted">· ${expired.length} ${esc(t.expired)}</span>` : ""}` : "–") +
      kv(t.firmware, esc(this._s("firmware")?.state || "–")) +
      kv(t.report, esc(this._time(this._s(this._pk("report_time"))?.state))) +
      this._perf() +
      `<h4>${esc(t.temps)}</h4>` + this._lineChart([
        { id: this._map.cpu_temperature, label: "CPU", color: "#fb8c00" },
        { id: this._map.ddr_temperature, label: "DDR", color: "#ffca28" }], "°C") +
      (this._map.memory_load ? "" : `<h4>${esc(t.ram)}</h4>` + this._lineChart([{ id: this._map.memory_used, label: "RAM", color: "#ab47bc" }], "MB"));
  }

  /** Load section from OpenTelemetry sensors (CPU, memory, WAN throughput, line quality). */
  _perf() {
    const t = this._t;
    if (!this._map.cpu_load) return `<div class="hint">${esc(t.noTelemetry)}</div>`;
    const v = (k, d = 0) => this._num(this._v(k), d);
    const boot = this._s("boot_time");
    const tiles = [
      [t.cpuLoad, `${v("cpu_load")} %`, "#ef5350"], [t.ram, `${v("memory_load")} %`, "#ab47bc"],
      ["WAN ↓ / ↑", `${v("wan_download", 1)} / ${v("wan_upload", 1)} Mbit/s`, "#42a5f5"],
      [t.latency, `${v("wan_latency")} / ${v("wan_jitter")} ms`, "#26a69a"], [t.conns, v("connections"), "#7e57c2"],
      [t.booted, boot && !isNaN(new Date(boot.state)) ? esc(this._time(boot.state)) : "–", "var(--secondary-text-color)"],
    ];
    return `<h4>${esc(t.perf)}</h4><div class="sums">${tiles.map(([l, val, c]) =>
      `<div class="sum"><div class="v" style="color:${c};font-size:17px">${val}</div><div class="l">${esc(l)}</div></div>`).join("")}</div>
      <h4>${esc(t.cpuLoad)} / ${esc(t.ram)}</h4>` + this._lineChart([
        { id: this._map.cpu_load, label: "CPU", color: "#ef5350" },
        { id: this._map.memory_load, label: "RAM", color: "#ab47bc" }], "%") +
      `<h4>${esc(t.wan)}</h4>` + this._lineChart([
        { id: this._map.wan_download, label: "↓", color: "#42a5f5" },
        { id: this._map.wan_upload, label: "↑", color: "#26a69a" }], "Mbit/s", 1) +
      `<h4>${esc(t.latency)}</h4>` + this._lineChart([
        { id: this._map.wan_latency, label: this._lang === "de" ? "Latenz" : "Latency", color: "#ffa000" },
        { id: this._map.wan_jitter, label: "Jitter", color: "#8d6e63" }], "ms");
  }
}

const CSS = `
  :host { display: block; }
  ha-card { padding: 12px 14px 10px; overflow: hidden; }
  .pad { padding: 8px 2px; }
  .muted { color: var(--secondary-text-color); }
  .small { font-size: 11px; }
  .head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px; }
  .title { display: flex; align-items: center; gap: 8px; font-size: 18px; font-weight: 500; }
  .title ha-icon { color: var(--primary-color); }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; }
  .pill { display: inline-flex; align-items: center; gap: 3px; padding: 1px 8px; border-radius: 10px; font-size: 11px; line-height: 18px;
          color: var(--c); background: color-mix(in srgb, var(--c) 16%, transparent); white-space: nowrap; }
  .pill ha-icon { --mdc-icon-size: 12px; }
  .seg { display: inline-flex; gap: 2px; padding: 3px; border-radius: 10px; background: var(--secondary-background-color, rgba(127,127,127,.1)); margin: 10px 0 4px; flex-wrap: wrap; }
  .seg button { border: none; background: none; padding: 5px 12px; border-radius: 8px; cursor: pointer; color: var(--secondary-text-color);
                font: inherit; font-size: 13px; display: inline-flex; align-items: center; gap: 4px; }
  .seg button.on { background: var(--card-background-color, var(--ha-card-background, #fff)); color: var(--primary-text-color); box-shadow: 0 1px 3px rgba(0,0,0,.25); }
  .seg.sm { margin: 4px 0; } .seg.sm button { padding: 3px 9px; font-size: 12px; }
  .seg button ha-icon { --mdc-icon-size: 14px; }
  .chips-seg button.on { color: var(--c, var(--primary-text-color)); }
  .cnt { font-size: 10px; padding: 0 5px; border-radius: 8px; background: rgba(127,127,127,.18); margin-left: 2px; }
  .sums { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 6px; margin: 8px 0 6px; }
  .sum { padding: 8px 10px; border-radius: 12px; background: var(--secondary-background-color, rgba(127,127,127,.08)); min-width: 0; }
  .sum .v { font-size: 20px; font-weight: 500; line-height: 1.2; white-space: nowrap; }
  .sum .l { font-size: 11px; text-transform: uppercase; letter-spacing: .4px; color: var(--secondary-text-color); }
  .sum .s { font-size: 11px; color: var(--secondary-text-color); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .tabs { display: flex; gap: 4px; overflow-x: auto; border-bottom: 1px solid var(--divider-color); margin-top: 6px; }
  .tab { background: none; border: none; padding: 8px 12px; cursor: pointer; color: var(--secondary-text-color); font: inherit; font-size: 14px;
         border-bottom: 2px solid transparent; white-space: nowrap; display: inline-flex; align-items: center; gap: 6px; }
  .tab ha-icon { --mdc-icon-size: 18px; }
  .tab.on { color: var(--primary-color); border-bottom-color: var(--primary-color); }
  .body { padding: 4px 0; }
  .row { display: flex; flex-wrap: wrap; gap: 8px; justify-content: space-between; margin-top: 8px; }
  .filters { display: grid; grid-template-columns: auto 1fr; align-items: center; gap: 2px 10px; margin: 8px 0; }
  .fl { font-size: 11px; text-transform: uppercase; letter-spacing: .4px; color: var(--secondary-text-color); }
  h4 { margin: 14px 0 4px; font-size: 11px; font-weight: 500; text-transform: uppercase; letter-spacing: .5px; color: var(--secondary-text-color); }
  h4.sep { margin-top: 20px; padding-top: 10px; border-top: 1px dashed var(--divider-color); }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th { text-align: left; font-size: 11px; font-weight: 500; color: var(--secondary-text-color); padding: 4px 6px; }
  td { padding: 6px; border-top: 1px solid var(--divider-color); vertical-align: top; }
  td.ic { width: 22px; padding-right: 0; color: var(--secondary-text-color); } td.ic ha-icon { --mdc-icon-size: 18px; }
  svg.si { width: 18px; height: 18px; display: block; margin-top: 1px; color: var(--primary-text-color); }
  .r { text-align: right; white-space: nowrap; } .nw { white-space: nowrap; }
  td.n { width: 100%; word-break: break-word; }
  tr.click { cursor: pointer; } tr.click:hover td { background: var(--secondary-background-color, rgba(127,127,127,.08)); }
  tr.open td { background: var(--secondary-background-color, rgba(127,127,127,.08)); }
  tr.det td { border-top: none; background: var(--secondary-background-color, rgba(127,127,127,.06)); padding: 2px 12px 10px; }
  .chev { color: var(--secondary-text-color); width: 1%; }
  table.occ { font-size: 12px; } table.occ td { padding: 3px 4px; }
  .bar { height: 4px; border-radius: 2px; margin-top: 4px; background: var(--divider-color); }
  .bar > div { height: 4px; border-radius: 2px; }
  .kv { display: flex; justify-content: space-between; gap: 12px; padding: 6px 2px; border-top: 1px solid var(--divider-color); font-size: 14px; }
  .kv span { color: var(--secondary-text-color); } .kv b { font-weight: 500; text-align: right; }
  .blades { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 2px 12px; font-size: 13px; margin: 8px 0; }
  .blades span { display: flex; align-items: center; gap: 6px; }
  .blades ha-icon { --mdc-icon-size: 16px; color: var(--success-color, #43a047); }
  .blades .off { color: var(--secondary-text-color); } .blades .off ha-icon { color: var(--disabled-text-color, #999); }
  .hint { padding: 10px 12px; border-radius: 10px; font-size: 13px; margin: 8px 0; background: color-mix(in srgb, var(--warning-color, #ffa000) 12%, transparent); }
  code { display: block; padding: 6px; border-radius: 6px; font-size: 12px; word-break: break-all; background: rgba(127,127,127,.12); }
  a { color: var(--primary-color); }
  svg.chart, svg.sankey { display: block; max-width: 100%; height: auto; }
  .grid { stroke: var(--divider-color); stroke-width: 1; opacity: .6; }
  .ax { fill: var(--secondary-text-color); font-size: 10px; }
  .lab { fill: var(--primary-text-color); font-size: 11px; } .lab .sub { fill: var(--secondary-text-color); }
  .link { opacity: .35; } .link:hover { opacity: .65; }
  .legend { display: flex; gap: 6px; margin-top: 2px; }
  .grid4 { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 6px; margin-top: 8px; }
  .mini { display: flex; flex-direction: column; padding: 6px 8px; border-radius: 10px; background: var(--secondary-background-color, rgba(127,127,127,.08)); }
  .mini b { font-size: 18px; font-weight: 500; } .mini span { font-size: 11px; color: var(--secondary-text-color); }
  @media (max-width: 700px) { .sums { grid-template-columns: repeat(3, minmax(0, 1fr)); } .grid4 { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
  @media (max-width: 420px) { .sum .v { font-size: 17px; } .filters { grid-template-columns: 1fr; } }
`;

if (!customElements.get("checkpoint-spark-card")) {
  customElements.define("checkpoint-spark-card", CheckpointSparkCard);
  window.customCards = window.customCards || [];
  window.customCards.push({
    type: "checkpoint-spark-card",
    name: "Check Point Quantum Spark",
    description: "Interactive event viewer: traffic and threat prevention per period, flows, events with details, gateway health.",
    preview: true,
    documentationURL: "https://github.com/msiegmeth/checkpoint-spark-ha",
  });
  console.info(`%c checkpoint-spark-card ${VERSION} `, "background:#e5007e;color:#fff;border-radius:3px");
}
