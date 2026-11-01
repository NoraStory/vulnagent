(function () {
  var style = getComputedStyle(document.documentElement);
  var accent = style.getPropertyValue('--accent').trim();
  var accent2 = style.getPropertyValue('--accent2').trim();
  var ink = style.getPropertyValue('--ink').trim();
  var muted = style.getPropertyValue('--muted').trim();
  var rule = style.getPropertyValue('--rule').trim();
  var bg2 = style.getPropertyValue('--bg2').trim();

  var tooltip = {
    appendToBody: true,
    backgroundColor: bg2,
    borderColor: rule,
    textStyle: { color: ink, fontSize: 12 },
    extraCssText: 'box-shadow:0 6px 20px rgba(20,26,32,.12);border-radius:8px;'
  };

  // 图 1：优化前后耗时（对数轴）
  var abChart = echarts.init(document.getElementById('chart-ab'), null, { renderer: 'svg' });
  abChart.setOption({
    animation: false,
    color: [accent2, accent],
    textStyle: { fontFamily: 'Instrument Sans, Microsoft YaHei, sans-serif' },
    grid: { left: 118, right: 44, top: 42, bottom: 38 },
    legend: { top: 4, right: 8, itemWidth: 12, itemHeight: 8, textStyle: { color: muted, fontSize: 12 } },
    tooltip: Object.assign({}, tooltip, {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      valueFormatter: function (v) { return v + ' ms'; }
    }),
    xAxis: {
      type: 'log',
      min: 0.1,
      max: 300,
      name: 'ms（对数）',
      nameTextStyle: { color: muted, fontSize: 11 },
      axisLabel: { color: muted, fontSize: 11, formatter: '{value}' },
      splitLine: { lineStyle: { color: rule } }
    },
    yAxis: {
      type: 'category',
      inverse: true,
      data: ['列表·状态筛选', '列表·默认', '概览 14 天趋势', '批量写入 200 条', '单资产复扫', '单资产匹配'],
      axisLabel: { color: ink, fontSize: 12 },
      axisTick: { show: false },
      axisLine: { lineStyle: { color: rule } }
    },
    series: [
      {
        name: '优化前',
        type: 'bar',
        barWidth: 12,
        itemStyle: { color: accent2, opacity: 0.75, borderRadius: [0, 3, 3, 0] },
        data: [20.1, 1.60, 137, 43.0, 0.78, 26.0],
        label: { show: true, position: 'right', color: muted, fontSize: 10, formatter: '{c}' }
      },
      {
        name: '优化后',
        type: 'bar',
        barWidth: 12,
        itemStyle: { color: accent, borderRadius: [0, 3, 3, 0] },
        data: [1.81, 0.60, 18.5, 3.7, 0.26, 4.9],
        label: { show: true, position: 'right', color: accent, fontSize: 10, formatter: '{c}' }
      }
    ]
  });

  // 图 2：吞吐随并发变化
  var endpoints = [
    { name: '概览', color: accent2, qps: [16.3, 62.9, 63.5] },
    { name: '漏洞搜索', color: accent2 + 'aa', qps: [30.4, 129.5, 128.7] },
    { name: '列表·状态', color: accent + '88', qps: [553, 2065, 2084] },
    { name: '列表·默认', color: accent, qps: [1671, 5668, 5541] },
    { name: '资产列表', color: accent + 'bb', qps: [1195, 4032, 3967] },
    { name: '资产详情', color: muted, qps: [1295, 3505, 3570] }
  ];

  var qpsChart = echarts.init(document.getElementById('chart-qps'), null, { renderer: 'svg' });
  qpsChart.setOption({
    animation: false,
    textStyle: { fontFamily: 'Instrument Sans, Microsoft YaHei, sans-serif' },
    grid: { left: 64, right: 28, top: 48, bottom: 40 },
    legend: { top: 4, right: 8, itemWidth: 14, itemHeight: 8, textStyle: { color: muted, fontSize: 12 } },
    tooltip: Object.assign({}, tooltip, {
      trigger: 'axis',
      valueFormatter: function (v) { return v + ' QPS'; }
    }),
    xAxis: {
      type: 'category',
      data: ['1 并发', '8 并发', '32 并发'],
      axisLabel: { color: ink, fontSize: 12 },
      axisLine: { lineStyle: { color: rule } },
      axisTick: { show: false }
    },
    yAxis: {
      type: 'value',
      name: 'QPS',
      nameTextStyle: { color: muted, fontSize: 11 },
      axisLabel: { color: muted, fontSize: 11 },
      splitLine: { lineStyle: { color: rule } }
    },
    series: endpoints.map(function (e) {
      return {
        name: e.name,
        type: 'line',
        smooth: false,
        symbol: 'circle',
        symbolSize: 7,
        lineStyle: { width: 2, color: e.color },
        itemStyle: { color: e.color },
        data: e.qps
      };
    })
  });

  // 图 3：p95 延迟（对数轴）
  var p95 = [
    { name: '概览', color: accent2, data: [64.1, 176, 735] },
    { name: '漏洞搜索', color: accent2 + 'aa', data: [35.5, 93.2, 506] },
    { name: '列表·状态', color: accent + '88', data: [2.53, 6.53, 33.5] },
    { name: '列表·默认', color: accent, data: [1.51, 2.53, 12.6] },
    { name: '资产列表', color: accent + 'bb', data: [1.51, 3.52, 17.6] },
    { name: '资产详情', color: muted, data: [1.51, 3.52, 15.4] }
  ];

  var p95Chart = echarts.init(document.getElementById('chart-p95'), null, { renderer: 'svg' });
  p95Chart.setOption({
    animation: false,
    textStyle: { fontFamily: 'Instrument Sans, Microsoft YaHei, sans-serif' },
    grid: { left: 64, right: 28, top: 48, bottom: 40 },
    legend: { top: 4, right: 8, itemWidth: 14, itemHeight: 8, textStyle: { color: muted, fontSize: 12 } },
    tooltip: Object.assign({}, tooltip, {
      trigger: 'axis',
      valueFormatter: function (v) { return v + ' ms'; }
    }),
    xAxis: {
      type: 'category',
      data: ['1 并发', '8 并发', '32 并发'],
      axisLabel: { color: ink, fontSize: 12 },
      axisLine: { lineStyle: { color: rule } },
      axisTick: { show: false }
    },
    yAxis: {
      type: 'log',
      name: 'p95（ms，对数）',
      nameTextStyle: { color: muted, fontSize: 11 },
      axisLabel: { color: muted, fontSize: 11 },
      splitLine: { lineStyle: { color: rule } }
    },
    series: p95.map(function (e) {
      return {
        name: e.name,
        type: 'line',
        symbol: 'circle',
        symbolSize: 7,
        lineStyle: { width: 2, color: e.color },
        itemStyle: { color: e.color },
        data: e.data
      };
    })
  });

  window.addEventListener('resize', function () {
    abChart.resize();
    qpsChart.resize();
    p95Chart.resize();
  });
})();
