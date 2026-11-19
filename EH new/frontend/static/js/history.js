let currentPage = 1;

async function loadInjectionHistory(page = 1) {
  currentPage = page;
  const tbody = document.getElementById("injection-table-body");
  const paginationContainer = document.getElementById("pagination-controls");
  const searchInput = document.getElementById("search-input");
  const riskSelect = document.getElementById("risk-filter");

  if (!tbody) return;

  const search = searchInput ? searchInput.value.trim() : "";
  const minRisk = riskSelect ? riskSelect.value : "";

  let url = `/api/injections?page=${page}&limit=10`;
  if (search) url += `&search=${encodeURIComponent(search)}`;
  if (minRisk) url += `&min_risk=${encodeURIComponent(minRisk)}`;

  try {
    const response = await fetch(url);
    const res = await response.json();

    tbody.innerHTML = "";

    if (!res.data || res.data.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">No detected SQL Injection attempts matching your filters.</td></tr>`;
      if (paginationContainer) paginationContainer.innerHTML = "";
      return;
    }

    res.data.forEach(item => {
      const tr = document.createElement("tr");
      const patternText = item.detected_patterns && item.detected_patterns.length > 0
        ? item.detected_patterns.join(", ")
        : "Suspicious injection pattern";

      tr.innerHTML = `
        <td>#${item.id}</td>
        <td><span style="color: var(--text-muted); font-size: 0.85rem;">${item.timestamp}</span></td>
        <td><span class="query-code-snippet">${escapeHtml(item.query_text)}</span></td>
        <td><strong style="color: var(--color-sqli);">${item.risk_score}/100</strong></td>
        <td><span style="font-size: 0.85rem; color: #fca5a5;">${escapeHtml(patternText)}</span></td>
        <td><span class="badge badge-sqli">${item.decision}</span></td>
        <td><a href="/query/${item.id}" class="btn-action">View Details</a></td>
      `;
      tbody.appendChild(tr);
    });

    renderPagination(res.page, res.total_pages);
  } catch (err) {
    console.error("Failed to load injection history:", err);
  }
}

function renderPagination(current, total) {
  const container = document.getElementById("pagination-controls");
  if (!container) return;

  container.innerHTML = "";
  if (total <= 1) return;

  for (let p = 1; p <= total; p++) {
    const btn = document.createElement("button");
    btn.className = `btn-action ${p === current ? "active" : ""}`;
    btn.style.margin = "0 0.2rem";
    btn.innerText = p;
    btn.addEventListener("click", () => loadInjectionHistory(p));
    container.appendChild(btn);
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
  loadInjectionHistory(1);

  const filterBtn = document.getElementById("apply-filters-btn");
  if (filterBtn) {
    filterBtn.addEventListener("click", () => loadInjectionHistory(1));
  }

  const searchInput = document.getElementById("search-input");
  if (searchInput) {
    searchInput.addEventListener("keyup", (e) => {
      if (e.key === "Enter") loadInjectionHistory(1);
    });
  }
});
