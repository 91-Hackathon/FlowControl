/* KPI strip: Grafana-style stat panels. Big number coloured by threshold, sparkline behind it. */
(function () {
  const M = () => window.FCModel;
  const N = 30; // sparkline buckets

  const PANELS = [
    {
      id: "llm", title: "LLM requests",
      value: (s) => s.llm.length,
      spark: (s) => M().buckets(s.llm, N, () => 1),
      color: () => "blue",
    },
    {
      id: "tools", title: "Tool calls",
      value: (s) => s.tools.length,
      spark: (s) => M().buckets(s.tools, N, () => 1),
      color: () => "blue",
    },
    {
      id: "allowed", title: "Allowed", unit: "%",
      // share of judged actions (tool calls and outbound requests) that went through
      value: (s) => (s.judged.length ? (100 * s.judged.filter((e) => !M().isBlock(e)).length) / s.judged.length : null),
      spark: (s) => M().buckets(s.judged, N, (e) => (M().isBlock(e) ? 0 : 100), "avg"),
      color: () => "none", // red is reserved for the Blocked panel
      digits: 1,
    },
    {
      id: "blocked", title: "Blocked",
      value: (s) => s.blocks.length,
      spark: (s) => M().buckets(s.blocks, N, () => 1),
      color: (v) => (v ? "red" : "green"),
    },
    {
      id: "overhead", title: "Gateway overhead", unit: "ms",
      value: (s) => (s.llm.length ? avg(s.llm.map((e) => e.data.latency_ms || 0)) : null),
      spark: (s) => M().buckets(s.llm, N, (e) => e.data.latency_ms || 0, "avg"),
      color: (v) => (v == null ? "none" : v < 10 ? "green" : v < 50 ? "amber" : "red"),
      digits: 1,
    },
    {
      id: "tokens", title: "Tokens",
      value: (s) => s.llm.reduce((a, e) => a + (e.data.input_tokens || 0) + (e.data.output_tokens || 0), 0),
      spark: (s) => M().buckets(s.llm, N, (e) => (e.data.input_tokens || 0) + (e.data.output_tokens || 0)),
      color: () => "purple",
      format: (v) => (v >= 1e6 ? `${(v / 1e6).toFixed(2)}M` : v >= 1000 ? `${(v / 1000).toFixed(1)}K` : String(v)),
    },
  ];

  function build(container) {
    container.innerHTML = PANELS.map((p) => `
      <div class="stat" id="stat-${p.id}">
        <svg class="spark" viewBox="0 0 100 30" preserveAspectRatio="none" aria-hidden="true"><path class="area"/><path class="line"/></svg>
        <div class="stat-title">${p.title}</div>
        <div class="stat-value"><span class="num">—</span>${p.unit ? `<span class="unit">${p.unit}</span>` : ""}</div>
      </div>`).join("");
  }

  /* s: { llm, tools, judged, blocks } event lists */
  function render(container, s) {
    PANELS.forEach((p) => {
      const el = container.querySelector(`#stat-${p.id}`);
      if (!el) return;
      const v = p.value(s);
      el.querySelector(".num").textContent = v == null ? "—" : p.format ? p.format(v) : fmt(v, p.digits);
      el.dataset.color = p.color(v);
      drawSpark(el.querySelector(".spark"), p.spark(s));
    });
  }

  function drawSpark(svg, series) {
    const max = Math.max(1e-9, ...series);
    const pts = series.map((v, i) => [(i / Math.max(1, series.length - 1)) * 100, 29 - (v / max) * 26]);
    const line = pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(2)},${y.toFixed(2)}`).join("");
    svg.querySelector(".line").setAttribute("d", series.some((v) => v) ? line : "");
    svg.querySelector(".area").setAttribute("d", series.some((v) => v) ? `${line}L100,30L0,30Z` : "");
  }

  function avg(a) { return a.reduce((x, y) => x + y, 0) / a.length; }
  function fmt(v, digits) { return digits ? v.toFixed(digits) : String(Math.round(v)); }

  window.FCKpis = { build, render };
})();
