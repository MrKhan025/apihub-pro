/* Frontend controller for API-Hub-Pro (apihub-pro) v2.0 Dashboard */

const state = {
  defaultProjectId: null,
  defaultUserId: null,
  latestApiKey: null,
};

async function apiFetch(url, options = {}) {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const contentType = res.headers.get("content-type") || "";
  const body = contentType.includes("application/json") ? await res.json() : await res.text();
  return { status: res.status, headers: res.headers, body };
}

function setupTabs() {
  const buttons = document.querySelectorAll(".nav-btn");
  const panels = document.querySelectorAll(".tab-panel");
  const titleEl = document.getElementById("pageTitle");

  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      buttons.forEach((b) => b.classList.remove("active"));
      panels.forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      const target = document.getElementById(`tab-${btn.dataset.tab}`);
      if (target) target.classList.add("active");
      if (titleEl) titleEl.textContent = btn.textContent;
    });
  });
}

async function refreshAll() {
  const [summaryRes, perfRes, svgRes, epRes, keysRes, projRes, usersRes, plansRes, mktRes, whRes, auditRes, secRes] =
    await Promise.all([
      apiFetch("/api/v2/analytics/summary"),
      apiFetch("/api/v2/analytics/endpoints"),
      apiFetch("/api/v2/analytics/chart.svg"),
      apiFetch("/api/v2/gateway/endpoints"),
      apiFetch("/api/v2/keys"),
      apiFetch("/api/v2/projects"),
      apiFetch("/api/v2/users"),
      apiFetch("/api/v2/marketplace/plans"),
      apiFetch("/api/v2/marketplace/listings"),
      apiFetch("/api/v2/webhooks"),
      apiFetch("/api/v2/security/audit-logs?limit=20"),
      apiFetch("/api/v2/security/automated-audit"),
    ]);

  if (projRes.body && projRes.body.projects && projRes.body.projects.length > 0) {
    state.defaultProjectId = projRes.body.projects[0].id;
  }
  if (usersRes.body && usersRes.body.users && usersRes.body.users.length > 0) {
    state.defaultUserId = usersRes.body.users[0].id;
  }

  // Render KPIs
  const s = summaryRes.body || {};
  const lat = s.latency_percentiles || {};
  document.getElementById("kpiTotalReq").textContent = s.total_requests ?? 0;
  document.getElementById("kpiRpm").textContent = `Current RPM: ${s.current_rpm ?? 0} | Avg RPM: ${s.average_rpm ?? 0}`;
  document.getElementById("kpiLatencies").textContent = `${lat.p50_ms ?? 0} / ${lat.p95_ms ?? 0} / ${lat.p99_ms ?? 0} ms`;
  document.getElementById("kpiAvgLat").textContent = `Avg: ${lat.avg_ms ?? 0} ms | Max: ${lat.max_ms ?? 0} ms`;
  document.getElementById("kpiErrorRate").textContent = `${s.error_rate_percent ?? 0}%`;
  const sb = s.status_breakdown || {};
  document.getElementById("kpiStatusBreakdown").textContent = `2xx: ${sb["2xx"] ?? 0} | 4xx: ${sb["4xx"] ?? 0} | 5xx: ${sb["5xx"] ?? 0}`;

  if (secRes.body) {
    document.getElementById("kpiSecurityScore").textContent = `${secRes.body.security_score}/100`;
    document.getElementById("kpiAuditStatus").textContent = secRes.body.audit_chain_integrity?.valid
      ? `HMAC Chain Verified (${secRes.body.audit_chain_integrity.entries_checked} entries)`
      : "Chain Alert";
    document.getElementById("securityAuditOutput").textContent = JSON.stringify(secRes.body, null, 2);
  }

  if (typeof svgRes.body === "string") {
    document.getElementById("svgChartContainer").innerHTML = svgRes.body;
  }

  // Render Endpoint Performance
  const perfTbody = document.querySelector("#endpointPerfTable tbody");
  perfTbody.innerHTML = (perfRes.body?.endpoints || [])
    .map(
      (e) => `<tr>
        <td><code>${e.route}</code></td>
        <td>${e.requests}</td>
        <td>${e.error_rate_percent}%</td>
        <td>${e.cache_hit_rate_percent}%</td>
        <td>${e.p50_ms} / ${e.p95_ms} / ${e.p99_ms} ms</td>
      </tr>`
    )
    .join("");

  // Render Registered Dynamic Endpoints
  const epTbody = document.querySelector("#gatewayEndpointsTable tbody");
  epTbody.innerHTML = (epRes.body?.endpoints || [])
    .map(
      (ep) => `<tr>
        <td><strong>${ep.method}</strong> <code>${ep.full_gateway_path}</code></td>
        <td><span class="badge badge-${ep.lifecycle_state}">${ep.lifecycle_state}</span></td>
        <td>${ep.timeout_ms}ms</td>
        <td>${ep.rate_limit_rpm}</td>
      </tr>`
    )
    .join("");

  // Render API Keys
  const keysTbody = document.querySelector("#apiKeysTable tbody");
  keysTbody.innerHTML = (keysRes.body?.keys || [])
    .map(
      (k) => `<tr>
        <td>${k.name}</td>
        <td><code>${k.key_prefix}...</code></td>
        <td>${k.status}</td>
        <td>${k.rate_limit_rpm}</td>
        <td><button class="btn btn-outline" onclick="rotateKey('${k.id}')">Rotate</button></td>
      </tr>`
    )
    .join("");

  // Render Projects & Users
  document.querySelector("#projectsTable tbody").innerHTML = (projRes.body?.projects || [])
    .map(
      (p) => `<tr>
        <td><strong>${p.name}</strong></td>
        <td><code>${p.slug}</code></td>
        <td>${p.plan_tier.toUpperCase()}</td>
        <td>${p.rpm_limit} RPM</td>
      </tr>`
    )
    .join("");

  document.querySelector("#usersTable tbody").innerHTML = (usersRes.body?.users || [])
    .map(
      (u) => `<tr>
        <td>${u.username}</td>
        <td>${u.email}</td>
        <td><code>${u.role}</code></td>
        <td>${u.mfa_enabled ? "Enabled (TOTP)" : "Not Set"}</td>
      </tr>`
    )
    .join("");

  // Render Marketplace Plans & Listings
  document.getElementById("plansContainer").innerHTML = (plansRes.body?.plans || [])
    .map(
      (pl) => `<div class="kpi-card">
        <span class="kpi-label">${pl.name}</span>
        <strong class="kpi-value">$${pl.price_monthly_usd}/mo</strong>
        <span class="kpi-sub">${pl.rpm_limit} RPM · ${pl.daily_quota.toLocaleString()} req/day</span>
      </div>`
    )
    .join("");

  document.querySelector("#marketplaceTable tbody").innerHTML = (mktRes.body?.listings || [])
    .map(
      (m) => `<tr>
        <td><strong>${m.title}</strong></td>
        <td>${m.category}</td>
        <td><code>${m.sample_endpoint_path}</code></td>
        <td>${m.pricing_plan_required.toUpperCase()}</td>
        <td>${m.subscribers_count}</td>
      </tr>`
    )
    .join("");

  // Render Webhooks
  document.querySelector("#webhooksTable tbody").innerHTML = (whRes.body?.webhooks || [])
    .map(
      (w) => `<tr>
        <td>${w.name}</td>
        <td><code>${w.target_url}</code></td>
        <td>${w.backoff_strategy} (max ${w.max_retries})</td>
        <td>${(w.events || []).join(", ")}</td>
        <td><button class="btn btn-outline" onclick="triggerWebhook('${w.id}')">Trigger</button></td>
      </tr>`
    )
    .join("");

  // Render Audit Logs
  document.querySelector("#auditLogsTable tbody").innerHTML = (auditRes.body?.audit_logs || [])
    .map(
      (a) => `<tr>
        <td><code>${a.event_type}</code></td>
        <td>${a.severity}</td>
        <td>${a.description}</td>
        <td><code>${(a.entry_hash || "").slice(0, 14)}...</code></td>
      </tr>`
    )
    .join("");
}

window.rotateKey = async function (keyId) {
  const res = await apiFetch(`/api/v2/keys/${keyId}/rotate`, {
    method: "POST",
    body: JSON.stringify({ actor_id: state.defaultUserId || "admin", grace_period_seconds: 3600 }),
  });
  if (res.body?.new_key?.api_key) {
    const banner = document.getElementById("issuedKeyBanner");
    banner.classList.remove("hidden");
    banner.textContent = `Rotated Key Issued (Save now): ${res.body.new_key.api_key}`;
    document.getElementById("expApiKey").value = res.body.new_key.api_key;
  }
  await refreshAll();
};

window.triggerWebhook = async function (webhookId) {
  await apiFetch(`/api/v2/webhooks/${webhookId}/trigger`, {
    method: "POST",
    body: JSON.stringify({ event_type: "endpoint.invoked", data: { manual_trigger: true } }),
  });
  await refreshAll();
};

document.addEventListener("DOMContentLoaded", async () => {
  setupTabs();
  await apiFetch("/api/v2/infra/seed-demo", { method: "POST" });
  await refreshAll();

  document.getElementById("refreshAllBtn").addEventListener("click", refreshAll);
  document.getElementById("seedDemoBtn").addEventListener("click", async () => {
    await apiFetch("/api/v2/infra/seed-demo", { method: "POST" });
    await refreshAll();
  });

  document.getElementById("createEndpointForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      project_id: state.defaultProjectId,
      name: document.getElementById("epName").value,
      version: document.getElementById("epVersion").value,
      method: document.getElementById("epMethod").value,
      path: document.getElementById("epPath").value,
      lifecycle_state: document.getElementById("epLifecycle").value,
      timeout_ms: parseInt(document.getElementById("epTimeout").value, 10),
      rate_limit_rpm: parseInt(document.getElementById("epRpm").value, 10),
      mock_response_body: JSON.parse(document.getElementById("epMockBody").value || "{}"),
      response_transform: JSON.parse(document.getElementById("epRespTransform").value || "{}"),
    };
    await apiFetch("/api/v2/gateway/endpoints", { method: "POST", body: JSON.stringify(payload) });
    await refreshAll();
  });

  document.getElementById("createKeyForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const res = await apiFetch("/api/v2/keys", {
      method: "POST",
      body: JSON.stringify({
        project_id: state.defaultProjectId,
        user_id: state.defaultUserId,
        name: document.getElementById("keyName").value,
        rate_limit_rpm: parseInt(document.getElementById("keyRpm").value, 10),
        ttl_days: parseInt(document.getElementById("keyTtl").value, 10),
      }),
    });
    if (res.body?.api_key) {
      const banner = document.getElementById("issuedKeyBanner");
      banner.classList.remove("hidden");
      banner.textContent = `New API Key (Save now): ${res.body.api_key}`;
      document.getElementById("expApiKey").value = res.body.api_key;
    }
    await refreshAll();
  });

  document.getElementById("apiExplorerForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const method = document.getElementById("expMethod").value;
    const path = document.getElementById("expPath").value;
    const apiKey = document.getElementById("expApiKey").value.trim();
    const headers = {};
    if (apiKey) headers["X-API-Key"] = apiKey;
    const opts = { method, headers };
    if (method !== "GET") {
      opts.body = document.getElementById("expBody").value;
    }
    const res = await apiFetch(path, opts);
    const rateHeaders = {
      "X-RateLimit-Limit": res.headers.get("X-RateLimit-Limit"),
      "X-RateLimit-Remaining": res.headers.get("X-RateLimit-Remaining"),
      "X-APIHub-Lifecycle": res.headers.get("X-APIHub-Lifecycle"),
      Deprecation: res.headers.get("Deprecation"),
      Sunset: res.headers.get("Sunset"),
    };
    document.getElementById("explorerOutput").textContent = JSON.stringify(
      { status: res.status, headers: rateHeaders, response: res.body },
      null,
      2
    );
    await refreshAll();
  });

  document.getElementById("runSecurityAuditBtn").addEventListener("click", async () => {
    const res = await apiFetch("/api/v2/security/automated-audit", { method: "POST" });
    document.getElementById("securityAuditOutput").textContent = JSON.stringify(res.body, null, 2);
  });
});
