/**
 * Chart.js Local Offline Library (SOC Dark Theme Edition)
 * Compatible with basic Chart.js initialization: new Chart(ctx, config)
 * Supports Doughnut/Pie charts and Line/Bar charts on HTML5 Canvas without CDN dependencies.
 */
(function (global, factory) {
    typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory() :
    typeof define === 'function' && define.amd ? define(factory) :
    (global = typeof globalThis !== 'undefined' ? globalThis : global || self, global.Chart = factory());
})(this, (function () {
    'use strict';

    class LocalChart {
        constructor(context, config) {
            this.ctx = typeof context === 'string' ? document.getElementById(context).getContext('2d') : context.getContext ? context.getContext('2d') : context;
            this.canvas = this.ctx.canvas;
            this.config = config || {};
            this.type = this.config.type || 'doughnut';
            this.data = this.config.data || {};
            this.options = this.config.options || {};
            this.render();
        }

        destroy() {
            if (this.ctx && this.canvas) {
                this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
            }
        }

        update() {
            this.render();
        }

        render() {
            if (!this.ctx || !this.canvas) return;

            // Handle DPI scaling
            const dpr = window.devicePixelRatio || 1;
            const rect = this.canvas.getBoundingClientRect();

            if (rect.width > 0 && rect.height > 0) {
                this.canvas.width = rect.width * dpr;
                this.canvas.height = rect.height * dpr;
                this.ctx.scale(dpr, dpr);
            }

            const width = rect.width || this.canvas.width;
            const height = rect.height || this.canvas.height;

            this.ctx.clearRect(0, 0, width, height);

            if (this.type === 'doughnut' || this.type === 'pie') {
                this.renderDoughnut(width, height);
            } else if (this.type === 'line' || this.type === 'bar') {
                this.renderLineOrBar(width, height);
            }
        }

        renderDoughnut(width, height) {
            const datasets = this.data.datasets || [];
            if (datasets.length === 0) return;

            const ds = datasets[0];
            const data = ds.data || [];
            const bgColors = ds.backgroundColor || ['#10b981', '#f59e0b', '#ef4444'];
            const labels = this.data.labels || [];

            const total = data.reduce((a, b) => a + b, 0);

            const centerX = width / 2;
            const centerY = height / 2 - 15;
            const outerRadius = Math.min(centerX, centerY) - 20;
            const innerRadius = this.type === 'doughnut' ? outerRadius * 0.6 : 0;

            if (total === 0) {
                // Empty state text
                this.ctx.fillStyle = '#64748b';
                this.ctx.font = '14px Inter, sans-serif';
                this.ctx.textAlign = 'center';
                this.ctx.textBaseline = 'middle';
                this.ctx.fillText('No queries analyzed yet', centerX, centerY);
                return;
            }

            let startAngle = -Math.PI / 2;
            for (let i = 0; i < data.length; i++) {
                const val = data[i];
                if (val <= 0) continue;
                const sliceAngle = (val / total) * 2 * Math.PI;
                const endAngle = startAngle + sliceAngle;

                this.ctx.beginPath();
                this.ctx.arc(centerX, centerY, outerRadius, startAngle, endAngle);
                if (this.type === 'doughnut') {
                    this.ctx.arc(centerX, centerY, innerRadius, endAngle, startAngle, true);
                } else {
                    this.ctx.lineTo(centerX, centerY);
                }
                this.ctx.closePath();

                this.ctx.fillStyle = bgColors[i % bgColors.length];
                this.ctx.fill();

                this.ctx.strokeStyle = '#0f172a';
                this.ctx.lineWidth = 2;
                this.ctx.stroke();

                startAngle = endAngle;
            }

            // Inner total text for Doughnut
            if (this.type === 'doughnut') {
                this.ctx.fillStyle = '#f8fafc';
                this.ctx.font = 'bold 20px Inter, sans-serif';
                this.ctx.textAlign = 'center';
                this.ctx.textBaseline = 'middle';
                this.ctx.fillText(total.toString(), centerX, centerY - 5);
                this.ctx.fillStyle = '#94a3b8';
                this.ctx.font = '11px Inter, sans-serif';
                this.ctx.fillText('TOTAL', centerX, centerY + 15);
            }

            // Legend at bottom
            const legendY = height - 20;
            let legendX = 20;
            this.ctx.font = '12px Inter, sans-serif';

            labels.forEach((label, i) => {
                const color = bgColors[i % bgColors.length];
                const count = data[i] || 0;

                this.ctx.fillStyle = color;
                this.ctx.fillRect(legendX, legendY, 12, 12);

                this.ctx.fillStyle = '#cbd5e1';
                this.ctx.textAlign = 'left';
                this.ctx.textBaseline = 'middle';
                const text = `${label} (${count})`;
                this.ctx.fillText(text, legendX + 18, legendY + 6);

                legendX += this.ctx.measureText(text).width + 35;
            });
        }

        renderLineOrBar(width, height) {
            const datasets = this.data.datasets || [];
            const labels = this.data.labels || [];

            const padding = { top: 30, right: 30, bottom: 40, left: 40 };
            const chartW = width - padding.left - padding.right;
            const chartH = height - padding.top - padding.bottom;

            if (labels.length === 0 || datasets.length === 0) {
                this.ctx.fillStyle = '#64748b';
                this.ctx.font = '14px Inter, sans-serif';
                this.ctx.textAlign = 'center';
                this.ctx.textBaseline = 'middle';
                this.ctx.fillText('No data available', width / 2, height / 2);
                return;
            }

            // Compute max value
            let maxVal = 5;
            datasets.forEach(ds => {
                (ds.data || []).forEach(v => {
                    if (v > maxVal) maxVal = v;
                });
            });

            // Grid lines
            this.ctx.strokeStyle = 'rgba(255, 255, 255, 0.07)';
            this.ctx.lineWidth = 1;
            const gridSteps = 4;
            for (let i = 0; i <= gridSteps; i++) {
                const y = padding.top + (chartH / gridSteps) * i;
                const val = Math.round(maxVal - (maxVal / gridSteps) * i);

                this.ctx.beginPath();
                this.ctx.moveTo(padding.left, y);
                this.ctx.lineTo(width - padding.right, y);
                this.ctx.stroke();

                this.ctx.fillStyle = '#64748b';
                this.ctx.font = '10px Inter, sans-serif';
                this.ctx.textAlign = 'right';
                this.ctx.fillText(val.toString(), padding.left - 8, y + 3);
            }

            // X-axis Labels
            const stepX = chartW / Math.max(1, labels.length - 1);
            labels.forEach((lbl, i) => {
                const x = padding.left + stepX * i;
                this.ctx.fillStyle = '#64748b';
                this.ctx.font = '10px Inter, sans-serif';
                this.ctx.textAlign = 'center';
                this.ctx.fillText(lbl, x, height - padding.bottom + 15);
            });

            // Draw Datasets
            datasets.forEach(ds => {
                const data = ds.data || [];
                const color = ds.borderColor || ds.backgroundColor || '#3b82f6';

                if (this.type === 'line') {
                    this.ctx.beginPath();
                    data.forEach((v, i) => {
                        const x = padding.left + (stepX * i);
                        const y = padding.top + chartH - ((v / maxVal) * chartH);
                        if (i === 0) this.ctx.moveTo(x, y);
                        else this.ctx.lineTo(x, y);
                    });
                    this.ctx.strokeStyle = color;
                    this.ctx.lineWidth = 2.5;
                    this.ctx.stroke();

                    // Points
                    data.forEach((v, i) => {
                        const x = padding.left + (stepX * i);
                        const y = padding.top + chartH - ((v / maxVal) * chartH);
                        this.ctx.beginPath();
                        this.ctx.arc(x, y, 4, 0, 2 * Math.PI);
                        this.ctx.fillStyle = color;
                        this.ctx.fill();
                        this.ctx.strokeStyle = '#0f172a';
                        this.ctx.lineWidth = 1.5;
                        this.ctx.stroke();
                    });
                } else if (this.type === 'bar') {
                    const barW = (stepX * 0.5) / datasets.length;
                    data.forEach((v, i) => {
                        const x = padding.left + (stepX * i) - (barW * datasets.length / 2);
                        const y = padding.top + chartH - ((v / maxVal) * chartH);
                        const barH = (v / maxVal) * chartH;
                        this.ctx.fillStyle = color;
                        this.ctx.fillRect(x, y, barW, barH);
                    });
                }
            });
        }
    }

    return LocalChart;
}));
