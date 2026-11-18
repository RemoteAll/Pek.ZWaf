# Pek.ZWaf

Zig 版 Web 应用防火墙（WAF）公共库，**功能对齐两个既有实现**：

| 参考实现 | 位置 | 本库对齐的部分 |
| --- | --- | --- |
| Rust `Pek.RWaf`（crate `pek-rwaf`） | `G:\Code\Rust\Pek.RWaf` | 决策链、爬虫分级、攻击特征、CC 限速、接口级限流、运行统计、热重载 |
| C# `Pek.WAF` | `G:\Code\Pek.FrameWork\Pek.WAF` | Ruleset JSON 规则引擎**格式兼容**（同一份规则文件可双端共用） |

消费形态：任意基于 [`zzig`](../zzig) 的 Zig HTTP 服务（`zzig.web.App` + `zzig.http_server`）。

## 能力总览

| 能力 | 说明 |
| --- | --- |
| 🤖 爬虫分级 | 6 级：搜索引擎 / GEO-AI 抓取 / 社交预览（放行）；灰色 / 未知（记录 + 限速）；恶意爬虫与扫描器（拦截） |
| 🧱 注入检测 | SQL 注入 / XSS / 路径穿越与敏感路径探测 / 命令注入；逐项动作（关 / 监控 / 拦截），双重 URL 解码防绕过 |
| 🌐 跨站来源校验 | 非安全方法校验 `Sec-Fetch-Site` / `Origin`；**先于回环豁免**（防 localhost 面板被恶意网页盲发） |
| 🚫 IP 名单 | 白名单（优先放行）/ 黑名单；精确、CIDR、通配符、文件 |
| ⏱️ CC 限速 | 每 IP「首次命中起 60 秒」窗口；放行类机器人豁免；静态资源不计数 |
| 🚦 接口级限流 | 对齐 C# `DH.RateLimter`：方法 + 路径规则，7 种策略，多阀门优先级，`WhenNull`，429 多格式 |
| 📜 规则引擎 | 与 C# `Pek.WAF` 的 Ruleset JSON 同格式（同一份规则可双端共用），新增 `IsBotKind` |
| ♻️ 热重载 | `Config/Waf.toml` 修改后 ≤10 秒自动生效（mtime 检查）；解析失败保留旧配置 |
| 📊 运行统计 | 拦截数 / 请求数 / 拦截率 / 近 1 分钟与 5 分钟 / 按原因 / Top 来源 IP（全原子计数，零轮询） |
| 🔓 回环豁免 | `127.0.0.1` / `::1` 默认豁免（保护本地工具与冒烟脚本；生产可关） |
| ⚡ 早拒 | `ServerGuard` 在**路由匹配与读取 body 之前**拒绝（路径探测 `/.env`、`/x.php` 也拦得住） |

## 快速接入（三步）

```zig
const std = @import("std");
const zzig = @import("zzig");
const pek_zwaf = @import("pek_zwaf");

var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
const io = threaded.io();

// 1. 加载配置（读 {base}/Config/Waf.toml；首启自动生成模板）
const waf = try pek_zwaf.Waf.load(std.heap.page_allocator, io, base_dir);
defer waf.deinit();

// 2. 路由中间件（首行注册，已匹配路由全部生效）
var app = try zzig.web.App.init(std.heap.page_allocator, io, .{});
defer app.deinit();
try app.useMiddleware(waf.middleware());

// 3. HTTP 层早拒（可选但强烈建议：路由中间件管不到未匹配的路径）
var srv = app.makeServer(.{});
var guard = pek_zwaf.ServerGuard.init(waf, srv.ctx, srv.handler);
defer guard.deinit(std.heap.page_allocator);
guard.install(&srv);
try srv.run("127.0.0.1", 8080);
```

被拦截返回 `403`（限速 `429` + `Retry-After`），响应头带 `X-WAF-Blocked: 1`，
拦截原因（IP / UA / 路径）写入 zzig 日志（`[WAF] 拦截 ...`）。

`zig build demo` 可起一个演示站点（`127.0.0.1:18080`）用 curl 验证拦截效果。

## 站点模式预设

| 配置项 | `publicSite()`（前台） | `adminApi()`（管理端，默认） |
| --- | --- | --- |
| 搜索引擎 / GEO-AI / 社交预览 | 放行 | 全部拦截 |
| `/admin` 等敏感前缀 | 禁止一切机器人 + 攻击监控升级为拦截 | —（全站从严） |
| SQL 注入 / 路径探测 | 拦截 | 拦截 |
| XSS / 命令注入 | 仅记录（表单易误报） | 拦截 |
| CC 限速 | 600 次/分钟 | 300 次/分钟 |
| 请求体全类型扫描 | 关 | 开 |

首启生成的 `Config/Waf.toml` 用 `adminApi()`；前台项目改成：

```toml
mode = "publicSite"
allowSearchBots = true
allowAiBots = true
allowSocialPreviews = true
sensitivePrefixes = ["/admin"]
```

## 爬虫分级（核心）

**放行**：`Googlebot` `Bingbot` `Baiduspider` `Sogou` `Applebot`…（27 项）；
`GPTBot` `ClaudeBot` `PerplexityBot` `Google-Extended` `CCBot`…（18 项 AI/GEO 抓取）；
`facebookexternalhit` `Twitterbot` `Slackbot`…（社交预览）。

**拦截**：`MJ12bot` `SemrushBot` `AhrefsBot` 等 SEO 采集；`sqlmap` `nikto` `nmap` `dirbuster` 等扫描器；
`Censys` `Shodan` 等测绘；`python-requests` `curl/` `wget/` `go-http-client` 等脚本默认 UA
（**自家工具请走 IP 白名单或回环**）。

**记录并限速**：`Bytespider` `Scrapy` `axios/` `okhttp` 等灰色 UA。

**自定义**：`extraAllowBots` / `extraBlockBots`（UA 子串，大小写不敏感；放行优先）。

> 机器对机器接口用 `skipBotPrefixes = ["/api"]`（只跳过 bot 判定，攻击特征/IP/CC 仍然生效）；
> 已有 HMAC 签名的项目可用 `waf.setTrustedSecret(secret)` 复用该签名体系，无需新增凭据。

## 配置参考（`Config/Waf.toml`，camelCase）

| 字段 | 默认（adminApi） | 说明 |
| --- | --- | --- |
| `enable` | `true` | 总开关 |
| `mode` | `"adminApi"` | 语义标记（`publicSite` / `adminApi`） |
| `blockEmptyUa` | `false` | 拦截空 User-Agent（服务间调用常无 UA） |
| `loopbackBypass` | `true` | 回环地址全豁免 |
| `ipWhitelist` / `ipBlacklist` | `[]` | IP 名单（白名单优先） |
| `extraAllowBots` / `extraBlockBots` | `[]` | 自定义 UA 子串 |
| `allowSearchBots` / `allowAiBots` / `allowSocialPreviews` | `false` | 放行三类正常抓取 |
| `blockMaliciousBots` | `true` | 拦截恶意爬虫 |
| `sensitivePrefixes` | `[]` | 敏感前缀（禁一切机器人 + 攻击监控升级拦截） |
| `skipAttackPrefixes` | `[]` | 跳过攻击检测（在线 SQL / 文件管理等端点） |
| `skipBotPrefixes` | `[]` | 跳过机器人拦截（机器对机器 API） |
| `csrfGuard` | `true` | 跨站来源校验 |
| `sqliAction` / `xssAction` / `pathAction` / `cmdAction` | `"block"` | 逐项动作：`off` / `monitor` / `block` |
| `rateLimitPerMin` | `300` | CC 限速（0 = 关） |
| `logBlocked` / `verbose` | `true` / `false` | 拦截日志 / 详细日志 |
| `bodyScanLimit` | `65536` | 请求体扫描上限（字节；0 → 16 KB） |
| `bodyScanAllTypes` | `true` | 非文本 Content-Type 也扫（防改 `Content-Type` 绕过） |
| `trustForwardedFor` | `false` | 直连对端是回环时采纳 `X-Forwarded-For`（**取末段**） |
| `rulesetFile` | `""` | C# 兼容规则集 JSON 路径（相对基础目录） |

## 规则引擎（C# 兼容）

```json
{
  "Operator": "OrElse",
  "Rules": [
    { "MemberName": "Path", "Operator": "EndsWith", "Inputs": [".php", ".env", ".git"] },
    { "MemberName": "UserAgent", "Operator": "IsBotKind", "TargetValue": "Malicious" },
    { "MemberName": "RemoteIp", "Operator": "InSubnet", "Inputs": ["10.0.0.0", 8] },
    { "MemberName": "Path", "Operator": "IsMatch", "TargetValue": "^/admin", "Negate": true }
  ]
}
```

- 逻辑：`OrElse` / `AndAlso`，可任意嵌套；`Negate` 取反；
- 成员：`Path` / `Method` / `UserAgent` / `RemoteIp`(`IpAddress`) / `QueryString` / `ContentType`；
- 操作符：`EndsWith` `StartsWith` `Contains` `Equals` `IsMatch`(正则) `IsInInput` `IsInteger` `IsDouble`
  `IsSingle` `IsDecimal` `IsInIpList` `IsNotInIpList` `InSubnet` `IpInFile` `ContainsUserAgent`
  `NotContainsUserAgent` `IsInUserAgentList` `IsNotInUserAgentList` `UserAgentStartsWith`
  `UserAgentIsEmpty` `UserAgentIsNotEmpty` **`IsBotKind`**；
- `IpCountry` 需外部 GeoIP 数据（未内置，恒不命中）。

## 接口级限流（`Config/Throttle.json`）

```json
{
  "enable": true, "keyPrefix": "dh", "logBlocked": true, "trustForwardedFor": false,
  "skipPaths": ["/assets/"],
  "rules": [
    { "name": "POST /api/auth/login", "method": "POST", "path": "/api/auth/login",
      "valves": [
        { "policy": "ip", "limit": 5, "duration": 60, "whenNull": "pass", "priority": 1, "returnType": "jsonDResult" },
        { "policy": "header", "policyKey": "X-Api-Key", "limit": 100, "duration": 3600, "whenNull": "intercept", "priority": 2 }
      ] }
  ]
}
```

```zig
const throttle = try pek_zwaf.Throttle.load(gpa, io, base_dir);
defer throttle.deinit();
try app.useMiddleware(waf.middleware());      // WAF 放最外层
try app.useMiddleware(throttle.middleware());  // 限流放其后
```

> **IP 策略前提**：CC 限速与 `throttle` 的 `ip` / `whenNull=intercept` 都需要对端地址。
> 直接调用 `Waf.checkRouteRequest` / `Throttle.check` 并显式传 `remote_addr` 时生效；
> 经 `zzig.web.App` 接入时，`zzig.http_server.RequestView` 目前不带对端地址
> （`Request.remote_addr` 为空），因此 IP 维度不生效——见 `docs/设计说明.md` §9。

## 性能基准（100 万口径）

```powershell
zig build bench -Doptimize=ReleaseFast
```

本机 Windows / Zig 0.17.1 实测（100 万次判定，详见 `docs/设计说明.md` §8）：

| 场景 | 耗时 |
| --- | --- |
| 放行：浏览器 GET | **365.6 ns/次** |
| 拦截：SQL 注入查询串 | **510.5 ns/次** |
| 拦截：恶意 UA（早拦） | 247.0 ns/次 |
| 放行：静态资源 | 272.0 ns/次 |
| 放行：POST 8 KB body | 23.98 µs/次 |
| 100 万条 IP 黑名单（未命中） | 204.5 ns/次 |
| 1000 条自定义规则（未命中） | 3.20 µs/次 |

特征共 82 条（SQLi 30 / XSS 13 / 路径 28 / 命令 11），命中检测是**单遍扫描**
（首字节桶 + 第二字节过滤），不再是对每个特征各做一次 `indexOf`。

## 运行验证

```powershell
zig build test     # 单元测试（基线 52 项）
zig build demo     # 启动演示服务后按 examples/waf_demo.zig 顶部注释用 curl 验证
```

## 目录

```
src/
  root.zig      公共导出
  waf.zig       门面（决策链）、路由中间件、ServerGuard 早拒、CSRF、可信签名
  config.zig    Config/Waf.toml 读写（TOML 解析复用 zzig）
  bots.zig      爬虫分级（130+ 关键词）
  attack.zig    攻击特征（规范化 + 双重解码 + 四类名单）
  rules.zig     C# 兼容规则引擎
  throttle.zig  接口级限流（7 策略 / 多阀门 / 429 多格式）
  ratelimit.zig 固定窗口计数引擎
  stats.zig     运行统计（原子计数 + 固定容量 Top 表）
  wafreq.zig    请求视图 + IP 匹配（CIDR / 通配符 / 文件 / 预编译 IpSet）
  gen.zig       引用计数的配置代（热重载安全替换）
  clock.zig     墙钟（复用 zzig.compat）
  regex.zig     正则薄封装（vendor 自生态既有实现）
  vendor/regex.zig  ZZUI 回溯正则引擎（字节级拷贝，见 docs/设计说明.md）
bench/waf_bench.zig    性能基准（100 万次判定 / 100 万条名单）
examples/waf_demo.zig  端到端演示
docs/设计说明.md        移植对照与决策记录
```
