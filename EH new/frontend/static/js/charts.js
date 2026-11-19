let pieChartInstance = null;
let lineChartInstance = null;

async function loadDashboardCharts() {
  const pieCanvas = document.getElementById("pieChart");
  const lineCanvas = document.getElementById("lineChart");

  if (!pieCanvas || !lineCanvas) return;

  try {
    const response = await fetch("/api/chart-data");
    const data = await response.json();

    // Render Pie/Doughnut Chart
    if (pieChartInstance) pieChartInstance.destroy();
    pieChartInstance = new Chart(pieCanvas, {
      type: "doughnut",
      data: {
        labels: data.distribution.labels,
        datasets: [{
          data: data.distribution.counts,
          backgroundColor: ["#10b981", "#f59e0b", "#ef4444"]
        }]
      },
      options: { responsive: true, maintainAspectRatio: false }
    });

    // Render Timeline Line Chart
    if (lineChartInstance) lineChartInstance.destroy();
    lineChartInstance = new Chart(lineCanvas, {
      type: "line",
      data: {
        labels: data.timeline.labels.length > 0 ? data.timeline.labels : ["Start"],
        datasets: [
          {
            label: "SQL Injection Attacks",
            data: data.timeline.sqli_series.length > 0 ? data.timeline.sqli_series : [0],
            borderColor: "#ef4444",
            backgroundColor: "rgba(239, 68, 68, 0.2)",
            fill: true
          },
          {
            label: "Suspicious Queries",
            data: data.timeline.maybe_series.length > 0 ? data.timeline.maybe_series : [0],
            borderColor: "#f59e0b",
            backgroundColor: "rgba(245, 158, 11, 0.2)"
          }
        ]
      },
      options: { responsive: true, maintainAspectRatio: false }
    });

  } catch (err) {
    console.error("Failed to load chart data:", err);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  loadDashboardCharts();
});
