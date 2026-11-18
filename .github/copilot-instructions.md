# Pek.ZWaf · 项目指令（Copilot 必读）

> 通用协议见用户级《跨项目接续协议》（`%APPDATA%\Code\User\prompts\跨项目接续协议.instructions.md`）。
> 本文只写**本项目特有**的口径；开工先读顺序见 `docs/项目接续指南.md`。

## 1. 项目定位

- 目录：`G:\Code\Zig\Pek.ZWaf`；远端：`https://github.com/RemoteAll/Pek.ZWaf.git`（`origin/main`）。
- 定位：**Zig 版 Web 应用防火墙公共库**，功能对齐两个参考实现：
  - Rust `G:\Code\Rust\Pek.RWaf`（决策链 / 爬虫分级 / 攻击特征 / CC 限速 / 接口级限流 / 统计）——**功能以它为准**；
  - C# `G:\Code\Pek.FrameWork\Pek.WAF`（Ruleset JSON 规则格式）——**规则格式以它为准**（同一份规则双端共用）。
- 消费方：任意基于 `G:\Code\Zig\zzig` 的 HTTP 服务（`zzig.web.App` + `zzig.http_server`）。
- 逐项移植对照、有意差异、Zig 0.17 迁移坑：`docs/设计说明.md`（改行为前必看）。

## 2. 工具链与命令

```powershell
zig version            # 0.17.0（WinGet）或 0.17.1（VS Code Zig 扩展托管），两者均已验证
zig build test         # 单元测试（基线 52 项，必须全绿）
zig build              # 编译库 + 示例
zig build demo         # 起演示站点 127.0.0.1:18080（用 examples/waf_demo.zig 顶部注释的 curl 验证）
zig build bench -Doptimize=ReleaseFast   # 性能基准（100 万次判定 / 100 万条名单）
```

依赖：`build.zig.zon` 里 `zzig = { .path = "../zzig" }`（`G:\Code\Zig\zzig`）。
**改 zzig 后必须连带跑** `cd ..\zzig; zig build test` 确认没打破公共库。

## 3. 目录

| 路径 | 内容 |
| --- | --- |
| `src/waf.zig` | 门面：决策链、路由中间件、`ServerGuard` 早拒、CSRF、可信签名、日志去重 |
| `src/config.zig` | `Config/Waf.toml` 读写（TOML 解析复用 `zzig.config.toml`） |
| `src/bots.zig` / `attack.zig` / `wafreq.zig` | 爬虫分级 / 攻击特征 / 请求视图 + IP 匹配 |
| `src/rules.zig` | C# 兼容规则引擎（`IsMatch` 走 vendor 正则） |
| `src/throttle.zig` | 接口级限流（`Config/Throttle.json`） |
| `src/ratelimit.zig` / `stats.zig` / `gen.zig` / `clock.zig` | 计数引擎 / 统计 / 配置代 / 墙钟 |
| `src/vendor/regex.zig` | 生态既有正则引擎（`ZZUI/src/regex.zig` 字节级拷贝，见设计说明 §5） |
| `examples/waf_demo.zig` | 端到端演示（中间件 + 早拒 + 统计端点） |
| `docs/` | 接续指南、用户档案、项目记忆、决策记录、设计说明 |

## 4. 硬性约定（本项目特有）

1. **复用优先**：写码前先检索 `zzig`（TOML/日志/compat/路由/HTTP 服务）→ 兄弟项目 → 本仓库。
   不复用公共库要在注释与 `docs/设计说明.md` 写明理由（已有先例：`zzig.Net.parseCidr` 在 `/0` 上 panic、
   `zzig.url.decode` 非法转义报错、`zzig.config.toml.decode` 会清空调用方预设）。
2. **Zig 0.17 API 约束**（踩过，见设计说明 §6）：`std.Thread.Mutex`→`zzig.compat.Mutex`；
   `std.time.timestamp`→`zzig.compat.nanoTimestamp`；文件 IO 一律要 `Io`；`ArrayList.writer` 不存在（用 `print(gpa, ...)`）；
   `std.fmt.fmtSliceHexLower`→`std.fmt.bytesToHex`；字符串重复不能用 `**`。
3. **配置不能丢预设**：加载用「以调用方预设为起点、逐键覆盖」，禁止依赖 `toml.decode`（会静默清空 `publicSite()`
   与项目传入的 `skipBotPrefixes`，Rust 侧 2026-10-21 踩过）。
4. **JSON 解析文本必须分配在 arena**：`std.json` 返回的字符串别名输入文本，用 gpa 分配再释放会让规则名变乱码。
5. **热重载必须走 `gen.zig` 引用计数**：检查期间持有配置代，替换时 `unref`，禁止直接释放旧 arena（切片悬空）。
6. **热路径零分配**：`WafRequest` 全是借用切片；扫描/规范化用 `attack.Scratch` 复用缓冲。
7. **失败日志三要素**：做什么 + 为什么失败 + 关键上下文（路径/端口/错误名/片段）；禁止只写「操作失败」。
8. **两类接入层边界**（不要混用）：路由中间件只覆盖**已匹配路由**；未匹配路径（`/.env`、`/x.php`）靠 `ServerGuard` 早拒。
   早拒层拿不到对端地址（zzig 视图限制）→ IP 名单/CC 在路由层做，`ip==""` 时不做 CC 计数。
9. **验证门槛**：改动后 `zig build test` 必须全绿（通过数不得低于基线 52）；行为改动同时更新 `docs/设计说明.md` 的对照表。
10. **提交信息一律中文**，用 `git commit -F <UTF-8 文件>`（不要 `-m`，PS 5.1 会转 GBK）；
    GitHub 直连超时用 `git -c http.curloptResolve=github.com:443:140.82.112.3 <cmd>`。

## 5. 每轮收尾（缺一不可）

1. `docs/决策记录.md` 新增一节（含**用户原话** + 结论 + 验证数字）；
2. 本机记忆 → `docs/项目记忆.md`：`powershell -NoProfile -ExecutionPolicy Bypass -File tools/continuity/sync-memory.ps1`；
3. 跑回归 `zig build test`，汇报贴实际输出（通过数/退出码）。
