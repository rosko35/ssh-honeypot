/* ssh-honeypot dashboard.
 *
 * Every string in the API responses (usernames, passwords, commands, URLs,
 * client versions) was chosen by an attacker. DOM nodes are therefore always
 * built with textContent and never with innerHTML, and nothing from the API
 * is ever used as a URL, attribute name or style.
 */
"use strict";

const REFRESH_MS = 30_000;
const regionNames = typeof Intl.DisplayNames === "function"
  ? new Intl.DisplayNames(["en"], { type: "region" })
  : null;
const charts = {};
let selectedSession = null;

const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const fmt = new Intl.NumberFormat("en");

function countryName(code) {
  if (!code || code === "??") return "Unknown";
  try { return regionNames ? regionNames.of(code) : code; } catch { return code; }
}

function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (cls) node.className = cls;
  return node;
}

function td(content, cls) {
  const cell = el("td", null, cls);
  if (content instanceof Node) cell.append(content); else cell.textContent = content ?? "";
  return cell;
}

function fillTable(tbodyId, rows, makeCells, emptyText = "No data yet") {
  const tbody = document.getElementById(tbodyId);
  tbody.replaceChildren();
  if (!rows.length) {
    const tr = el("tr");
    const cell = el("td", emptyText, "muted");
    cell.colSpan = 99;
    tr.append(cell);
    tbody.append(tr);
    return;
  }
  for (const row of rows) {
    const tr = el("tr");
    for (const cell of makeCells(row)) tr.append(cell instanceof Node ? cell : td(cell));
    tbody.append(tr);
  }
}

function utc(ts) {
  return ts ? new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19) : "";
}

function clip(s, n = 48) {
  s = String(s ?? "");
  return s.length > n ? s.slice(0, n) + "…" : s;
}

async function api(path) {
  const res = await fetch(path, { credentials: "same-origin", cache: "no-store" });
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res.json();
}

function upsertChart(id, config) {
  if (charts[id]) {
    charts[id].data = config.data;
    charts[id].update();
    return;
  }
  charts[id] = new Chart(document.getElementById(id), config);
}

function baseOptions(extra = {}) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: { legend: { labels: { color: css("--text") } } },
    scales: {
      x: { ticks: { color: css("--muted") }, grid: { color: css("--grid") } },
      y: { ticks: { color: css("--muted") }, grid: { color: css("--grid") }, beginAtZero: true },
    },
    ...extra,
  };
}

function barChart(id, labels, values, color) {
  upsertChart(id, {
    type: "bar",
    data: { labels: labels.map((l) => clip(l, 32)), datasets: [{ label: "Attempts", data: values, backgroundColor: color }] },
    options: baseOptions({ indexAxis: "y", plugins: { legend: { display: false } } }),
  });
}

function renderSummary(s) {
  const set = (id, v) => { document.getElementById(id).textContent = fmt.format(v); };
  set("kpi-attempts", s.auth_attempts);
  set("kpi-sessions", s.sessions);
  set("kpi-ips", s.unique_ips);
  set("kpi-shells", s.shell_sessions);
  set("kpi-commands", s.commands);
  set("kpi-urls", s.download_urls);
}

function renderTimeline(rows) {
  upsertChart("timeline", {
    type: "bar",
    data: {
      labels: rows.map((r) => utc(r.ts).slice(5, 13) + "h"),
      datasets: [
        { label: "Login attempts", data: rows.map((r) => r.attempts), backgroundColor: css("--c1") },
        { label: "Connections", data: rows.map((r) => r.sessions), type: "line", borderColor: css("--c2"),
          backgroundColor: css("--c2"), pointRadius: 0, tension: 0.25 },
        { label: "Fake-shell logins", data: rows.map((r) => r.shells), type: "line", borderColor: css("--c3"),
          backgroundColor: css("--c3"), pointRadius: 2, tension: 0.25, yAxisID: "y1" },
      ],
    },
    options: baseOptions({
      scales: {
        x: { ticks: { color: css("--muted"), maxTicksLimit: 16 }, grid: { display: false } },
        y: { beginAtZero: true, ticks: { color: css("--muted") }, grid: { color: css("--grid") } },
        y1: { position: "right", beginAtZero: true, ticks: { color: css("--c3"), precision: 0 }, grid: { display: false } },
      },
    }),
  });
}

function renderCountries(rows) {
  const known = rows.filter((r) => r.country !== "??").slice(0, 12);
  const unknown = rows.filter((r) => r.country === "??").reduce((n, r) => n + r.attempts, 0);
  barChart("countries", known.map((r) => countryName(r.country)), known.map((r) => r.attempts), css("--c2"));
  document.getElementById("country-note").textContent = unknown
    ? `${fmt.format(unknown)} attempts from addresses without a known country (no GeoIP database, or private ranges).`
    : "";
}

function renderSessions(rows) {
  fillTable("sessions", rows, (r) => [
    td(utc(r.started), "muted nowrap"),
    td(`${r.src_ip}${r.country ? " " + r.country : ""}`, "mono"),
    td(clip(`${r.login_user ?? ""} / ${r.login_password ?? ""}`, 40), "mono"),
    td(fmt.format(r.commands), "num"),
    td(clip(r.client_version, 32), "small muted"),
  ], "No session has reached the fake shell yet.");
  const tbody = document.getElementById("sessions");
  [...tbody.rows].forEach((tr, i) => {
    const r = rows[i];
    if (!r) return;
    tr.dataset.sid = r.id; // hex id validated by the API; only used for the API path
    if (r.id === selectedSession) tr.classList.add("selected");
    tr.addEventListener("click", () => showTranscript(r.id));
  });
}

function line(parent, cls, text) {
  parent.append(el("span", text, cls), "\n");
}

async function showTranscript(sid) {
  if (!/^[0-9a-f]{12}$/.test(sid)) return;
  selectedSession = sid;
  for (const tr of document.querySelectorAll("#sessions tr")) {
    tr.classList.toggle("selected", tr.dataset.sid === sid);
  }
  const pre = document.getElementById("transcript");
  pre.classList.remove("muted");
  pre.replaceChildren();
  try {
    const s = await api(`/api/sessions/${sid}`);
    document.getElementById("transcript-title").textContent = `${s.id} from ${s.src_ip}`;
    line(pre, "t-meta", `# ${utc(s.started)} UTC  ${s.src_ip}:${s.src_port}  ${s.client_version ?? ""}`);
    line(pre, "t-meta", `# hassh ${s.hassh ?? "-"}  term ${s.term ?? "-"}  end: ${s.end_reason ?? "open"}`);
    for (const a of s.auth) {
      const what = a.method === "password" ? `${a.username} / ${a.password}` : `${a.username} key ${a.key_fingerprint ?? ""}`;
      line(pre, "t-meta", `# auth ${a.success ? "OK  " : "FAIL"} ${what}`);
    }
    for (const r of s.requests) {
      if (r.kind !== "exec") line(pre, "t-meta", `# ${r.accepted ? "accepted" : "refused"} ${r.kind} ${r.detail ?? ""}`);
    }
    for (const c of s.transcript) {
      pre.append(el("span", `[+${c.elapsed.toFixed(1)}s] `, "t-time"));
      line(pre, c.known ? "t-cmd" : "t-unknown", `${c.kind === "exec" ? "(exec) " : "$ "}${c.command}`);
    }
    for (const d of s.downloads) line(pre, "t-url", `# ${d.tool} wanted ${d.url} (not fetched)`);
    if (!s.transcript.length) line(pre, "muted", "(no commands)");
  } catch (err) {
    pre.textContent = `error: ${err.message}`;
  }
}

async function refresh() {
  const days = document.getElementById("days").value;
  const hours = Math.min(days * 24, 24 * 31);
  document.getElementById("range-label").textContent = `last ${days === "1" ? "24 hours" : days + " days"}`;
  try {
    const [summary, timeline, users, passwords, pairs, ips, countries, clients, downloads, sessions] = await Promise.all([
      api(`/api/summary?days=${days}`),
      api(`/api/timeline?hours=${hours}`),
      api(`/api/top-usernames?days=${days}&limit=10`),
      api(`/api/top-passwords?days=${days}&limit=10`),
      api(`/api/top-pairs?days=${days}&limit=10`),
      api(`/api/top-ips?days=${days}&limit=10`),
      api(`/api/countries?days=${days}`),
      api(`/api/client-versions?days=${days}&limit=8`),
      api(`/api/downloads?days=${days}&limit=20`),
      api("/api/sessions/recent?limit=50"),
    ]);
    renderSummary(summary);
    renderTimeline(timeline);
    barChart("usernames", users.map((u) => u.username), users.map((u) => u.count), css("--c1"));
    barChart("passwords", passwords.map((p) => p.password), passwords.map((p) => p.count), css("--c3"));
    fillTable("pairs", pairs, (p) => [td(clip(p.username, 24), "mono"), td(clip(p.password, 24), "mono"),
      td(fmt.format(p.count), "num"), td(fmt.format(p.ips), "num")]);
    fillTable("top-ips", ips, (r) => [td(r.ip, "mono"), td(countryName(r.country)), td(fmt.format(r.sessions), "num"),
      td(fmt.format(r.attempts), "num"), td(fmt.format(r.shells), "num")]);
    renderCountries(countries);
    fillTable("clients", clients, (c) => [td(clip(c.client_version, 60), "mono small"), td(fmt.format(c.sessions), "num"),
      td(fmt.format(c.ips), "num")]);
    fillTable("downloads", downloads, (d) => [td(d.url, "mono small"), td(fmt.format(d.count), "num"),
      td(fmt.format(d.sessions), "num")], "No download attempts.");
    renderSessions(sessions);
    document.getElementById("updated").textContent = `updated ${new Date().toLocaleTimeString()}`;
  } catch (err) {
    document.getElementById("updated").textContent = `error: ${err.message}`;
  }
}

document.getElementById("days").addEventListener("change", refresh);
refresh();
setInterval(refresh, REFRESH_MS);
