async function fetchDashboardStats() {
  try {
    const res = await fetch("/api/statistics");
    const data = await res.json();

    document.getElementById("stat-total").innerText = data.total_queries;
    document.getElementById("stat-normal").innerText = data.normal_count;
    document.getElementById("stat-maybe").innerText = data.maybe_count;
    document.getElementById("stat-sqli").innerText = data.sqli_count;
    document.getElementById("stat-blocked").innerText = data.blocked_count;

    // Security summary indicators
    const rateEl = document.getElementById("summary-detection-rate");
    const pctEl = document.getElementById("summary-sqli-pct");

    if (rateEl) rateEl.innerText = `${data.detection_rate_pct}%`;
    if (pctEl) pctEl.innerText = `${data.sqli_percentage}%`;
  } catch (err) {
    console.error("Error fetching statistics:", err);
  }
}

async function fetchRecentActivity() {
  const container = document.getElementById("recent-activity-list");
  if (!container) return;

  try {
    const res = await fetch("/api/recent?limit=8");
    const data = await res.json();

    container.innerHTML = "";
    if (data.recent_activity.length === 0) {
      container.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No recent query activity logged.</td></tr>`;
      return;
    }

    data.recent_activity.forEach(item => {
      let badgeClass = "badge-normal";
      if (item.classification === "MAY BE SQL INJECTION") badgeClass = "badge-maybe";
      else if (item.classification === "SQL INJECTION") badgeClass = "badge-sqli";

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><span style="color: var(--text-muted); font-size: 0.85rem;">${item.time}</span></td>
        <td><span class="query-code-snippet">${escapeHtml(item.query_snippet)}</span></td>
        <td><span class="badge ${badgeClass}">${item.classification}</span></td>
        <td><strong>${item.decision}</strong></td>
        <td><a href="/query/${item.id}" class="btn-action">View</a></td>
      `;
      container.appendChild(tr);
    });
  } catch (err) {
    console.error("Error fetching recent activity:", err);
  }
}

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

document.addEventListener("DOMContentLoaded", () => {
  fetchDashboardStats();
  fetchRecentActivity();

  const seedBtn = document.getElementById("seed-demo-btn");
  if (seedBtn) {
    seedBtn.addEventListener("click", async () => {
      seedBtn.disabled = true;
      seedBtn.innerText = "Seeding Demo Data...";
      try {
        await fetch("/api/demo-data", { method: "POST" });
        await fetchDashboardStats();
        await fetchRecentActivity();
        if (typeof loadDashboardCharts === "function") {
          await loadDashboardCharts();
        }
        seedBtn.innerText = "Demo Data Seeded ✓";
      } catch (err) {
        alert("Failed to seed demo data");
        seedBtn.innerText = "Seed Demo Data";
      } finally {
        setTimeout(() => { seedBtn.disabled = false; }, 2000);
      }
    });
  }
});
