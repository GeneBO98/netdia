const state = {
  topology: null,
  hosts: new Map(),
  activeScanId: null,
  pollTimer: null,
};

async function request(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(body || `Request failed: ${response.status}`);
  }
  if (response.status === 204) {
    return null;
  }
  return response.json();
}

function renderTargets(targets) {
  const list = document.getElementById("target-list");
  list.innerHTML = "";
  for (const target of targets) {
    const item = document.createElement("div");
    item.className = "target-item";
    item.innerHTML = `
      <span>${target.cidr}</span>
      <div class="target-actions">
        <button class="secondary toggle-btn" data-id="${target.id}">
          ${target.enabled ? "Disable" : "Enable"}
        </button>
        <button class="secondary remove-btn" data-id="${target.id}">Remove</button>
      </div>
    `;
    item.querySelector(".toggle-btn").addEventListener("click", async () => {
      await request(`/api/targets/${target.id}`, {
        method: "PATCH",
        body: JSON.stringify({ enabled: !target.enabled }),
      });
      await loadTargets();
    });
    item.querySelector(".remove-btn").addEventListener("click", async () => {
      await request(`/api/targets/${target.id}`, { method: "DELETE" });
      await loadTargets();
    });
    list.appendChild(item);
  }
}

async function loadTargets() {
  const targets = await request("/api/targets");
  renderTargets(targets);
}

function updateStatus(text) {
  document.getElementById("scan-status").textContent = text;
}

function setActionButtons(scan) {
  const scanButton = document.getElementById("scan-button");
  const cancelButton = document.getElementById("cancel-button");
  const active = scan && ["queued", "running", "cancelling"].includes(scan.status);
  scanButton.disabled = Boolean(active);
  cancelButton.disabled = !active || scan.status === "cancelling";
}

function formatStage(stage) {
  return (stage || "idle").replaceAll("_", " ");
}

function setProgress(scan) {
  const pill = document.getElementById("scan-stage-pill");
  const bar = document.getElementById("scan-progress-bar");
  const copy = document.getElementById("scan-progress-copy");
  const stage = scan?.stage || "idle";
  const current = scan?.progress_current || 0;
  const total = scan?.progress_total || 0;
  const percent = total > 0 ? Math.max(6, Math.round((current / total) * 100)) : scan?.status === "running" ? 12 : 0;

  pill.textContent = formatStage(stage);
  bar.style.width = `${Math.min(percent, 100)}%`;

  if (!scan) {
    copy.textContent = "Start a scan to see live subnet and host progress.";
    setActionButtons(null);
    return;
  }
  const parts = [];
  if (scan.status_message) parts.push(scan.status_message);
  if (total > 0) parts.push(`${current}/${total}`);
  if (scan.error_summary) parts.push(scan.error_summary);
  copy.textContent = parts.join(" · ");
  setActionButtons(scan);
}

function renderEvents(events) {
  const root = document.getElementById("scan-events");
  if (!events.length) {
    root.innerHTML = `<p class="empty-state">No scan activity yet.</p>`;
    return;
  }
  const wasNearBottom = root.scrollHeight - root.scrollTop - root.clientHeight < 60;
  root.innerHTML = events
    .map(
      (event) => `
        <article class="event-item ${event.level}">
          <div class="event-topline">
            <span class="event-stage">${formatStage(event.stage)}</span>
            <span>${new Date(event.created_at).toLocaleTimeString()}</span>
          </div>
          <strong>${event.message}</strong>
        </article>
      `,
    )
    .join("");
  if (wasNearBottom) {
    root.scrollTop = root.scrollHeight;
  }
}

function deriveHostQueue(events) {
  let discoveredHosts = [];
  let currentHost = null;
  const completedHosts = new Set();

  for (const event of events) {
    if (Array.isArray(event.metadata?.hosts)) {
      discoveredHosts = event.metadata.hosts;
    }
    if (event.stage === "scanning_hosts" && event.metadata?.host) {
      currentHost = event.metadata.host;
    }
    if (event.stage === "completed_host" && event.metadata?.host) {
      completedHosts.add(event.metadata.host);
      if (currentHost === event.metadata.host) {
        currentHost = null;
      }
    }
    if (["cancelled", "completed", "failed"].includes(event.stage)) {
      currentHost = null;
    }
  }

  return { discoveredHosts, currentHost, completedHosts };
}

function renderLiveHosts(events) {
  const currentHostNode = document.getElementById("current-host");
  const queueNode = document.getElementById("host-queue");
  const { discoveredHosts, currentHost, completedHosts } = deriveHostQueue(events);

  currentHostNode.textContent = currentHost || "No active host";
  if (!discoveredHosts.length) {
    queueNode.innerHTML = `<span class="empty-state">No host queue yet.</span>`;
    return;
  }

  queueNode.innerHTML = discoveredHosts
    .map((host) => {
      let status = "pending";
      if (currentHost === host) {
        status = "active";
      } else if (completedHosts.has(host)) {
        status = "completed";
      }
      return `<span class="host-chip ${status}">${host}</span>`;
    })
    .join("");
}

function buildFilters(topology) {
  const subnetFilter = document.getElementById("subnet-filter");
  const existing = new Set([...subnetFilter.options].map(o => o.value));
  for (const subnet of topology.subnets || []) {
    if (!existing.has(subnet.cidr)) {
      const option = document.createElement("option");
      option.value = subnet.cidr;
      option.textContent = subnet.cidr;
      subnetFilter.appendChild(option);
    }
  }
}

// --- Flowchart icon SVGs ---
const FLOW_ICONS = {
  cloud: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M6.5 19a4.5 4.5 0 0 1-.42-8.98A7 7 0 0 1 19.5 11a4.5 4.5 0 0 1-1 8.98H6.5Z"/></svg>`,
  shield: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 2l7 4v5c0 5.25-3.5 9.74-7 11-3.5-1.26-7-5.75-7-11V6l7-4z"/></svg>`,
  server: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><circle cx="7" cy="7" r="1"/><circle cx="7" cy="17" r="1"/></svg>`,
  database: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.66 3.58 3 8 3s8-1.34 8-3V5"/><path d="M4 12c0 1.66 3.58 3 8 3s8-1.34 8-3"/></svg>`,
  globe: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15 15 0 0 1 4 10 15 15 0 0 1-4 10 15 15 0 0 1-4-10A15 15 0 0 1 12 2z"/></svg>`,
  route: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M4 15h8l4-8h4"/><circle cx="18" cy="7" r="2"/><circle cx="4" cy="15" r="2"/></svg>`,
  wifi: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M5 12.55a11 11 0 0 1 14 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><circle cx="12" cy="20" r="1"/></svg>`,
  play: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polygon points="5,3 19,12 5,21"/></svg>`,
  grid: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>`,
  cylinder: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.66 3.58 3 8 3s8-1.34 8-3V5"/></svg>`,
};

function flowIconSvg(iconName) {
  return FLOW_ICONS[iconName] || FLOW_ICONS.grid;
}

function makeFlowNode(id, label, sublabel, iconName, color, extraClass) {
  const el = document.createElement("div");
  el.className = `flow-node ${extraClass || ""}`;
  el.setAttribute("data-nid", id);
  el.innerHTML = `
    <div class="flow-node-icon" style="background:${color}">
      ${flowIconSvg(iconName)}
    </div>
    <div class="flow-node-label">${label}</div>
    ${sublabel ? `<div class="flow-node-sub">${sublabel}</div>` : ""}
  `;
  return el;
}

function makeHostFlowNode(host) {
  const el = document.createElement("div");
  el.className = `flow-node flow-host`;
  el.setAttribute("data-nid", `host-${host.id}`);
  el.addEventListener("click", () => renderHostDetail(host.id));

  const servicePills = host.services.slice(0, 4).map(s =>
    `<span class="flow-svc-pill">${s.label || s.port}/${s.protocol}</span>`
  ).join("");
  const svcExtra = host.services.length > 4 ? `<span class="flow-svc-pill flow-more">+${host.services.length - 4}</span>` : "";

  el.innerHTML = `
    <div class="flow-node-icon" style="background:${host.color}">
      ${flowIconSvg(host.icon)}
    </div>
    <div class="flow-node-label">${host.label}</div>
    <div class="flow-node-sub">${host.ip}</div>
    ${servicePills ? `<div class="flow-svc-list">${servicePills}${svcExtra}</div>` : ""}
  `;
  return el;
}

function makeWebsiteFlowNode(website, nodeId) {
  const el = document.createElement("div");
  el.className = "flow-node flow-site-node";
  el.setAttribute("data-nid", nodeId);
  const displayName = website.title || website.hostname;
  el.innerHTML = `
    <div class="flow-node-icon flow-site-icon" style="background:#457b9d">
      ${website.favicon_url ? `<img src="${website.favicon_url}" onerror="this.parentElement.innerHTML='${flowIconSvg("globe").replace(/'/g, "\\'")}'" />` : flowIconSvg("globe")}
    </div>
    <div class="flow-node-label">${displayName}</div>
    ${website.hostname !== displayName ? `<div class="flow-node-sub">${website.hostname}</div>` : ""}
    ${website.upstream_target ? `<div class="flow-upstream">${website.upstream_target}</div>` : ""}
  `;
  return el;
}

function getDisplayWebsites(websites) {
  // Filter out raw IP probes in favor of named sites
  const named = websites.filter(w => w.title || (w.hostname && !/^\d+\.\d+\.\d+\.\d+$/.test(w.hostname)));
  return named.length ? named : websites;
}

function drawFlowConnections(container) {
  const svg = container.querySelector(".flow-svg");
  if (!svg) return;
  svg.innerHTML = "";
  const rect = container.getBoundingClientRect();
  svg.setAttribute("width", container.scrollWidth);
  svg.setAttribute("height", container.scrollHeight);
  svg.setAttribute("viewBox", `0 0 ${container.scrollWidth} ${container.scrollHeight}`);

  const edges = JSON.parse(container.getAttribute("data-edges") || "[]");
  for (const [fromId, toId] of edges) {
    const fromEl = container.querySelector(`[data-nid="${fromId}"]`);
    const toEl = container.querySelector(`[data-nid="${toId}"]`);
    if (!fromEl || !toEl) continue;

    const fb = fromEl.getBoundingClientRect();
    const tb = toEl.getBoundingClientRect();
    const x1 = fb.left + fb.width / 2 - rect.left + container.scrollLeft;
    const y1 = fb.bottom - rect.top + container.scrollTop;
    const x2 = tb.left + tb.width / 2 - rect.left + container.scrollLeft;
    const y2 = tb.top - rect.top + container.scrollTop;

    const midY = (y1 + y2) / 2;
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", `M${x1},${y1} C${x1},${midY} ${x2},${midY} ${x2},${y2}`);
    path.setAttribute("class", "flow-line");
    svg.appendChild(path);
  }
}

function renderGraph() {
  if (!state.topology) return;
  buildFilters(state.topology);
  const container = document.getElementById("diagram");
  container.innerHTML = "";

  const subnets = state.topology.subnets || [];
  const caddySites = state.topology.caddy_sites || [];
  const search = document.getElementById("search-filter").value.trim().toLowerCase();
  const subnetFilter = document.getElementById("subnet-filter").value;

  // SVG overlay for connections
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.classList.add("flow-svg");
  container.appendChild(svg);

  const edges = [];

  // --- Tier 0: Internet ---
  const tier0 = document.createElement("div");
  tier0.className = "flow-tier";
  const internetNode = makeFlowNode("internet", "Internet", null, "cloud", "#6b7280", "flow-internet");
  tier0.appendChild(internetNode);
  container.appendChild(tier0);

  // --- Tier 1: Firewall / Gateway ---
  let firewallHost = null;
  for (const subnet of subnets) {
    for (const host of subnet.hosts) {
      if (host.category === "firewall") {
        firewallHost = host;
        break;
      }
    }
    if (firewallHost) break;
  }

  const tier1 = document.createElement("div");
  tier1.className = "flow-tier";

  if (firewallHost) {
    const fwNode = makeHostFlowNode(firewallHost);
    fwNode.setAttribute("data-nid", `fw-${firewallHost.id}`);
    tier1.appendChild(fwNode);
    edges.push(["internet", `fw-${firewallHost.id}`]);
  } else {
    const gwNode = makeFlowNode("gateway", "Gateway", null, "route", "#287271", "");
    tier1.appendChild(gwNode);
    edges.push(["internet", "gateway"]);
  }
  container.appendChild(tier1);

  const gatewayId = firewallHost ? `fw-${firewallHost.id}` : "gateway";

  // --- Tier 2: Subnets ---
  const tier2 = document.createElement("div");
  tier2.className = "flow-tier";

  const filteredSubnets = subnets.filter(s => !subnetFilter || s.cidr === subnetFilter);

  for (const subnet of filteredSubnets) {
    const subnetNode = makeFlowNode(`subnet-${subnet.cidr}`, subnet.cidr, `${subnet.hosts.length} hosts`, "grid", "#577590", "flow-subnet-node");
    tier2.appendChild(subnetNode);
    edges.push([gatewayId, `subnet-${subnet.cidr}`]);
  }
  container.appendChild(tier2);

  // --- Tier 3: Hosts per subnet, each with website children ---
  for (const subnet of filteredSubnets) {
    const group = document.createElement("div");
    group.className = "flow-subnet-group";

    const hostsRow = document.createElement("div");
    hostsRow.className = "flow-tier flow-hosts-tier";

    const subnetHosts = subnet.hosts.filter(host => {
      if (firewallHost && host.id === firewallHost.id) return false;
      if (search && !JSON.stringify(host).toLowerCase().includes(search)) return false;
      return true;
    });

    for (const host of subnetHosts) {
      // Build a host column: host node on top, website nodes below
      const hostCol = document.createElement("div");
      hostCol.className = "flow-host-col";

      const hostNode = makeHostFlowNode(host);
      hostCol.appendChild(hostNode);
      edges.push([`subnet-${subnet.cidr}`, `host-${host.id}`]);

      // Website nodes below this host
      const sites = getDisplayWebsites(host.websites);
      const maxSites = 6;
      const sitesRow = document.createElement("div");
      sitesRow.className = "flow-sites-row";

      for (const [i, site] of sites.slice(0, maxSites).entries()) {
        const siteId = `site-${host.id}-${i}`;
        const siteNode = makeWebsiteFlowNode(site, siteId);
        sitesRow.appendChild(siteNode);
        edges.push([`host-${host.id}`, siteId]);
      }
      if (sites.length > maxSites) {
        const moreNode = document.createElement("div");
        moreNode.className = "flow-node flow-site-node flow-more-node";
        moreNode.setAttribute("data-nid", `site-${host.id}-more`);
        moreNode.innerHTML = `<div class="flow-node-label">+${sites.length - maxSites} more</div>`;
        sitesRow.appendChild(moreNode);
        edges.push([`host-${host.id}`, `site-${host.id}-more`]);
      }

      if (sitesRow.children.length) {
        hostCol.appendChild(sitesRow);
      }
      hostsRow.appendChild(hostCol);
    }

    group.appendChild(hostsRow);
    container.appendChild(group);
  }

  // --- Firewall websites as separate tier ---
  if (firewallHost) {
    const fwSites = getDisplayWebsites(firewallHost.websites);
    if (fwSites.length) {
      const fwGroup = document.createElement("div");
      fwGroup.className = "flow-subnet-group";

      const fwLabel = document.createElement("div");
      fwLabel.className = "flow-group-label";
      fwLabel.textContent = `Sites on ${firewallHost.label}`;
      fwGroup.appendChild(fwLabel);

      const fwRow = document.createElement("div");
      fwRow.className = "flow-tier flow-hosts-tier";
      const maxFwSites = 12;

      for (const [i, site] of fwSites.slice(0, maxFwSites).entries()) {
        const siteId = `fwsite-${i}`;
        const siteNode = makeWebsiteFlowNode(site, siteId);
        fwRow.appendChild(siteNode);
        edges.push([`fw-${firewallHost.id}`, siteId]);
      }
      if (fwSites.length > maxFwSites) {
        const moreNode = document.createElement("div");
        moreNode.className = "flow-node flow-site-node flow-more-node";
        moreNode.setAttribute("data-nid", "fwsite-more");
        moreNode.innerHTML = `<div class="flow-node-label">+${fwSites.length - maxFwSites} more</div>`;
        fwRow.appendChild(moreNode);
        edges.push([`fw-${firewallHost.id}`, "fwsite-more"]);
      }

      fwGroup.appendChild(fwRow);
      container.appendChild(fwGroup);
    }
  }

  // --- Orphan Caddy sites (not attached to any host) ---
  if (caddySites.length) {
    const caddyGroup = document.createElement("div");
    caddyGroup.className = "flow-subnet-group";

    const caddyLabel = document.createElement("div");
    caddyLabel.className = "flow-group-label flow-caddy-label";
    caddyLabel.textContent = "Caddy Reverse Proxy Sites";
    caddyGroup.appendChild(caddyLabel);

    const caddyRow = document.createElement("div");
    caddyRow.className = "flow-tier flow-hosts-tier";

    for (const [i, site] of caddySites.entries()) {
      if (search && !JSON.stringify(site).toLowerCase().includes(search)) continue;
      const siteNode = makeWebsiteFlowNode(site, `caddy-${site.id}`);
      caddyRow.appendChild(siteNode);
      edges.push([gatewayId, `caddy-${site.id}`]);
    }

    caddyGroup.appendChild(caddyRow);
    container.appendChild(caddyGroup);
  }

  // Store edges and draw connections after layout
  container.setAttribute("data-edges", JSON.stringify(edges));
  requestAnimationFrame(() => drawFlowConnections(container));
}

function renderInventory() {
  const body = document.getElementById("inventory-body");
  body.innerHTML = "";
  const inventory = state.topology?.inventory || [];
  for (const item of inventory) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${item.ip}</td>
      <td>${item.dns_name || "-"}</td>
      <td>${item.port}/${item.protocol}</td>
      <td>${item.service_name || "-"}</td>
      <td>${item.websites.join(", ") || "-"}</td>
    `;
    row.addEventListener("click", () => renderHostDetail(item.host_id));
    body.appendChild(row);
  }
}

function renderDetailCards(detail) {
  const websiteCards = detail.websites
    .map((site) => {
      const tls = site.tls_names && site.tls_names.length ? `<div class="detail-meta">TLS: ${site.tls_names.join(", ")}</div>` : "";
      const upstream = site.upstream_target ? `<div class="detail-meta">Upstream: ${site.upstream_target}</div>` : "";
      const faviconHtml = site.favicon_url
        ? `<img class="detail-favicon" src="${site.favicon_url}" onerror="this.style.display='none'" />`
        : `<div class="detail-favicon-placeholder">${flowIconSvg("globe")}</div>`;
      return `
        <div class="detail-site-row">
          ${faviconHtml}
          <div class="detail-site-info">
            <div class="detail-site-name">${site.title || site.hostname}</div>
            <div class="detail-meta">${site.scheme}://${site.hostname} · ${site.source}</div>
            ${tls}${upstream}
          </div>
        </div>
      `;
    })
    .join("");

  const serviceCards = detail.services
    .map(
      (service) => `
        <div class="detail-service-row">
          <div class="detail-svc-icon" style="background:${service.category === 'reverse_proxy' ? '#287271' : service.category === 'database' ? '#6d597a' : '#577590'}">
            ${flowIconSvg(service.icon || "grid")}
          </div>
          <div class="detail-svc-info">
            <strong>${service.display_name}</strong>
            <span class="detail-meta">${service.port}/${service.protocol}${service.product ? ` · ${service.product}` : ""}${service.version ? ` ${service.version}` : ""}</span>
          </div>
        </div>
      `,
    )
    .join("");

  document.getElementById("detail-content").innerHTML = `
    <div class="detail-card">
      <div class="detail-host-header">
        <div class="detail-host-icon" style="background:${detail.icon ? ({'firewall':'#e76f51','server':'#2a9d8f','storage':'#264653','database':'#6d597a','media':'#7f5539','reverse_proxy':'#287271'}[detail.category] || '#577590') : '#577590'}">
          ${flowIconSvg(detail.icon || "grid")}
        </div>
        <div>
          <h3 style="margin:0">${detail.label}</h3>
          <div class="detail-meta">${detail.ip}${detail.dns_name ? ` · ${detail.dns_name}` : ""}</div>
        </div>
      </div>
      <div class="kv" style="margin-top:12px">
        <strong>MAC</strong><span>${detail.mac_address || "-"}</span>
        <strong>OS</strong><span>${detail.os_guess || "-"}</span>
        <strong>Category</strong><span>${detail.category}</span>
      </div>
    </div>
    <div class="detail-card">
      <h3>Services (${detail.services.length})</h3>
      <div class="detail-services-list">${serviceCards || "<p class=\"empty-state\">No services detected.</p>"}</div>
    </div>
    <div class="detail-card">
      <h3>Websites (${detail.websites.length})</h3>
      <div class="detail-sites-list">${websiteCards || "<p class=\"empty-state\">No web metadata detected.</p>"}</div>
    </div>
  `;
}

async function renderHostDetail(hostId) {
  const detail = await request(`/api/hosts/${hostId}`);
  renderDetailCards(detail);
}

async function loadTopology() {
  state.topology = await request("/api/topology/latest");
  if (!state.topology.latest_scan) {
    const stage = document.getElementById("scan-stage-pill").textContent.toLowerCase();
    if (!state.activeScanId && stage === "idle") {
      updateStatus("No completed scans yet");
      setProgress(null);
    }
    document.getElementById("inventory-body").innerHTML = "";
    return;
  }
  const scan = state.topology.latest_scan;
  updateStatus(
    `Last scan #${scan.id}: ${scan.status} · ${scan.hosts} hosts · ${scan.services} services · ${scan.websites} websites`,
  );
  setProgress(scan);
  renderGraph();
  renderInventory();
}

async function refreshScan(scanId) {
  const [scan, events] = await Promise.all([
    request(`/api/scans/${scanId}`),
    request(`/api/scans/${scanId}/events`),
  ]);
  updateStatus(
    `Scan #${scanId}: ${scan.status} · ${scan.hosts} hosts · ${scan.services} services · ${scan.websites} websites`,
  );
  setProgress(scan);
  renderEvents(events);
  renderLiveHosts(events);
  return scan;
}

async function pollScan(scanId) {
  state.activeScanId = scanId;
  if (state.pollTimer) {
    clearTimeout(state.pollTimer);
    state.pollTimer = null;
  }
  const tick = async () => {
    const scan = await refreshScan(scanId);
    if (scan.status === "completed" || scan.status === "failed" || scan.status === "cancelled") {
      if (scan.error_summary) {
        updateStatus(`Scan #${scanId} failed: ${scan.error_summary}`);
      }
      await loadTopology();
      state.activeScanId = null;
      return;
    }
    state.pollTimer = setTimeout(tick, 1500);
  };
  await tick();
}

async function startScan() {
  const response = await request("/api/scans", { method: "POST", body: JSON.stringify({}) });
  await pollScan(response.scan_id);
}

async function cancelScan() {
  if (!state.activeScanId) {
    return;
  }
  const scan = await request(`/api/scans/${state.activeScanId}/cancel`, {
    method: "POST",
    body: JSON.stringify({}),
  });
  updateStatus(`Scan #${scan.id}: ${scan.status}`);
  setProgress(scan);
}

async function loadLatestScanActivity() {
  try {
    const scan = await request("/api/scans/latest");
    if (!scan) return;
    if (scan.status === "running" || scan.status === "queued" || scan.status === "cancelling") {
      await pollScan(scan.id);
      return;
    }
    updateStatus(
      `Last scan #${scan.id}: ${scan.status} · ${scan.hosts} hosts · ${scan.services} services · ${scan.websites} websites`,
    );
    setProgress(scan);
    const events = await request(`/api/scans/${scan.id}/events`);
    renderEvents(events);
    renderLiveHosts(events);
  } catch {
    renderEvents([]);
    renderLiveHosts([]);
  }
}

function toggleExpand() {
  const panel = document.querySelector(".graph-panel");
  const btn = document.getElementById("expand-btn");
  const expanded = panel.classList.toggle("expanded");
  btn.innerHTML = expanded
    ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M4 14h6v6m10-10h-6V4m0 6L21 3M3 21l7-7"/></svg>`
    : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"/></svg>`;
  btn.title = expanded ? "Collapse topology" : "Expand topology";
  const diagram = document.getElementById("diagram");
  if (diagram) drawFlowConnections(diagram);
}

function registerEvents() {
  document.getElementById("scan-button").addEventListener("click", startScan);
  document.getElementById("cancel-button").addEventListener("click", cancelScan);
  document.getElementById("expand-btn").addEventListener("click", toggleExpand);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && document.querySelector(".graph-panel.expanded")) {
      toggleExpand();
    }
  });
  document.getElementById("target-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = document.getElementById("target-cidr");
    await request("/api/targets", {
      method: "POST",
      body: JSON.stringify({ cidr: input.value }),
    });
    input.value = "";
    await loadTargets();
  });
  for (const id of ["subnet-filter", "source-filter", "search-filter"]) {
    document.getElementById(id).addEventListener("input", renderGraph);
  }
  window.addEventListener("resize", () => {
    const diagram = document.getElementById("diagram");
    if (diagram) drawFlowConnections(diagram);
  });
}

async function bootstrap() {
  setActionButtons(null);
  registerEvents();
  await loadTargets();
  await loadLatestScanActivity();
  await loadTopology();
}

bootstrap().catch((error) => updateStatus(error.message));
