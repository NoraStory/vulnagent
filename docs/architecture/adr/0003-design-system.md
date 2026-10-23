# ADR 0003：前端设计系统与令牌

- 状态：已接受
- 日期：2026-10-24

## 背景

现有前端 21 个文件、5742 行，颜色/圆角/阴影写死在 Tailwind 配置，业务枚举与风险公式在页面内重复，视觉为早期 Apple 风格拼装。

## 决策

1. 保留 React 18 + Vite 6 + Tailwind 3，不引入图表库与重型 UI 库。
2. 新建 `shared/styles/tokens.css`，用 CSS 变量定义表面、文字、品牌、状态、圆距、阴影、动效。
3. 新建 `shared/ui` 组件层（Button/Card/Table/Drawer/Modal 等），统一焦点陷阱与可访问性。
4. 图表使用自研 SVG 原语（Sparkline/AreaTrend/StackedBars/Donut）。
5. 页面按 feature 目录重组；业务字典与风险公式来自 `GET /api/v1/meta`。

## 后果

- 一次性视觉统一，后续可扩展暗色主题。
- 需要逐页迁移并做三档视口回归。
- 前端不再重复后端规则，减少口径漂移。
