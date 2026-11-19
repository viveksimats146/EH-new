document.addEventListener("DOMContentLoaded", () => {
  const queryForm = document.getElementById("query-form");
  const queryInput = document.getElementById("query-input");
  const analyzeBtn = document.getElementById("analyze-btn");
  const resultCard = document.getElementById("result-card");
  const alertContainer = document.getElementById("alert-container");

  // Sample query pill click handler
  document.querySelectorAll(".preset-pill").forEach(pill => {
    pill.addEventListener("click", () => {
      queryInput.value = pill.getAttribute("data-query");
      queryInput.focus();
    });
  });

  if (queryForm) {
    queryForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const rawQuery = queryInput.value.trim();

      if (!rawQuery) {
        showAlert("Please enter a query or input for analysis.");
        return;
      }

      clearAlert();
      setLoading(true);

      try {
        const response = await fetch("/api/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query: rawQuery })
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.detail || "Failed to analyze input.");
        }

        renderResult(data);
      } catch (err) {
        showAlert(err.message || "An error occurred during analysis.");
      } finally {
        setLoading(false);
      }
    });
  }

  function setLoading(isLoading) {
    if (isLoading) {
      analyzeBtn.disabled = true;
      analyzeBtn.innerHTML = '<span class="spinner"></span> Analyzing...';
    } else {
      analyzeBtn.disabled = false;
      analyzeBtn.innerHTML = 'Analyze Query';
    }
  }

  function showAlert(msg) {
    if (alertContainer) {
      alertContainer.innerHTML = `<div class="pattern-item" style="border-left-color: var(--color-sqli);">${msg}</div>`;
    }
  }

  function clearAlert() {
    if (alertContainer) alertContainer.innerHTML = "";
  }

  function renderResult(data) {
    if (!resultCard) return;

    const badgeEl = document.getElementById("res-badge");
    const scoreEl = document.getElementById("res-score");
    const decisionEl = document.getElementById("res-decision");
    const methodEl = document.getElementById("res-method");
    const patternsEl = document.getElementById("res-patterns");
    const viewDetailsLink = document.getElementById("res-details-link");

    // Set classification badge
    badgeEl.className = "badge";
    if (data.classification === "NORMAL") {
      badgeEl.classList.add("badge-normal");
      badgeEl.innerText = "NORMAL";
    } else if (data.classification === "MAY BE SQL INJECTION") {
      badgeEl.classList.add("badge-maybe");
      badgeEl.innerText = "MAY BE SQL INJECTION";
    } else {
      badgeEl.classList.add("badge-sqli");
      badgeEl.innerText = "SQL INJECTION";
    }

    scoreEl.innerText = `${data.risk_score}/100`;
    decisionEl.innerText = data.decision;
    methodEl.innerText = data.detection_method;

    if (viewDetailsLink && data.query_id) {
      viewDetailsLink.href = `/query/${data.query_id}`;
      viewDetailsLink.style.display = "inline-block";
    }

    // Render detected patterns
    patternsEl.innerHTML = "";
    if (data.detected_patterns && data.detected_patterns.length > 0) {
      data.detected_patterns.forEach(pat => {
        const li = document.createElement("li");
        li.className = "pattern-item";
        li.innerText = `✓ ${pat}`;
        patternsEl.appendChild(li);
      });
    } else {
      const li = document.createElement("li");
      li.style.color = "var(--text-muted)";
      li.style.fontSize = "0.85rem";
      li.innerText = "✓ No suspicious SQL injection patterns detected.";
      patternsEl.appendChild(li);
    }

    resultCard.style.display = "block";
  }
});
