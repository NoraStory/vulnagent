# 外部 CMDB 分页契约

适用集成类型：`cmdb_api`（`server/internal/cloud/cmdb.go`）。所有配置均为可选项，缺省行为与旧版本兼容。

## 1. 配置项

| 键 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `url` | string | 必填 | CMDB JSON API 地址，可自带查询参数 |
| `authType` | string | `none` | `none` / `bearer` / `basic` |
| `pagination` | string | `auto` | `auto` / `none` / `page` / `cursor` |
| `pageParam` | string | `page` | 页码参数名（`page` 模式） |
| `pageSizeParam` | string | `pageSize` | 页大小参数名（`page` 模式） |
| `pageSize` | int | `200` | 每页条数，1–1000 |
| `startPage` | int | `1` | 起始页码 |
| `cursorParam` | string | `cursor` | 游标参数名（`cursor` / `auto` 模式的游标值） |
| `cursorField` | string | `next` | 响应中下一页字段，支持点路径（如 `data.next`） |
| `itemsField` | string | 自动 | 条目数组字段，支持点路径（如 `data.items`） |
| `totalField` | string | `total` | 总条数字段，支持点路径 |
| `maxPages` | int | `50` | 最大翻页数，1–500，防止异常响应导致死循环 |

`pageSize`、`startPage`、`maxPages` 同时接受 JSON 数字与数字字符串。

## 2. 分页模式

| 模式 | 行为 |
|---|---|
| `auto`（默认） | 首页使用 `url`；若响应含 `cursorField`（默认 `next`）且非空则继续，值可以是游标、相对地址或同源绝对地址。`next` 为空即结束。 |
| `none` | 只请求一次，即使响应含 `next` 也不继续（显式关闭分页）。 |
| `page` | 请求 `url?{pageParam}=n&{pageSizeParam}=pageSize`，从 `startPage` 开始递增。响应含 `totalField` 时按总数停止；否则不足一页时停止。 |
| `cursor` | 首页使用 `url`；后续把 `cursorField` 的值作为 `?{cursorParam}=value` 附加到 `url`，直到游标为空。 |

安全上限：任何模式最多请求 `maxPages` 页，累计实例最多 5000 台（`maxInstances`）。

## 3. 响应形态

支持以下三种结构（`itemsField` 可覆盖自动识别）：

```json
[
  {"hostname": "web-01"}
]
```

```json
{
  "items": [{"hostname": "web-01"}],
  "total": 120
}
```

```json
{
  "data": {
    "items": [{"hostname": "web-01"}],
    "next": "cursor-token"
  }
}
```

自动识别的条目键：`items`、`data`、`assets`、`results`、`list`、`records`；若这些键的值是对象，
会继续查找其中的 `items / assets / results / list / records / rows`。未识别到数组时，整个对象按单台实例解析（兼容旧行为）。

字段映射沿用既有规则（`instanceId / hostname / privateIp / osFamily / businessSystem` 等），
详见 `server/internal/cloud/cmdb.go` 的 `cmdbMapInstances`。

## 4. 同源限制

`next` 若为地址：

- 相对地址（`/next`、`?cursor=x`）基于配置的 `url` 解析；
- 绝对地址必须与 `url` 的 `scheme + host` 完全一致，否则同步失败并提示“下一页地址必须与配置的 CMDB 同源”；
- 避免把 Bearer / Basic 凭据随响应中可控的地址发送到其他主机。

## 5. 示例

页码分页（每页 500，最多 20 页）：

```json
{
  "url": "https://cmdb.example.com/api/assets?env=prod",
  "authType": "bearer",
  "pagination": "page",
  "pageParam": "pageNo",
  "pageSizeParam": "limit",
  "pageSize": 500,
  "maxPages": 20
}
```

游标分页（响应 `data.next`，游标参数 `after`）：

```json
{
  "url": "https://cmdb.example.com/api/assets",
  "pagination": "cursor",
  "cursorParam": "after",
  "cursorField": "data.next",
  "itemsField": "data.items"
}
```

自动跟随（默认，无需配置 `pagination`）：

```json
{
  "url": "https://cmdb.example.com/api/assets"
}
```

## 6. 验证

`server/internal/cloud/cmdb_test.go` 覆盖：自动跟随游标/相对地址、页码分页与 total 停止、游标分页、
跨域 `next` 拒绝、单页模式；`server/integrations_test.go` 覆盖分页参数校验。
