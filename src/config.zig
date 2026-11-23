//! WAF 配置：`Config/Waf.toml`（首启自动生成模板；mtime 变化热重载）。
//!
//! ## 与 Rust 版的差异（有意为之）
//! - **TOML 解析复用 `zzig.config.toml`**（不重复实现解析器）；
//! - 但**应用配置不用 `toml.decode`**：`decode` 从「类型默认值」起步，会把调用方预设
//!   （如 `publicSite()` / 项目的 `skipBotPrefixes`）静默清空——Rust 版踩过这个坑
//!   （2026-10-21 直连 RestSharp UA 被误拦）。这里改为「以预设为起点、逐键覆盖」。
//! - 规则集（C# `Pek.WAF` 兼容 Ruleset）不再塞进 TOML：`rulesetFile` 指向一个 JSON 文件。
//!   这样同一份 JSON 可以与 C# 端**字节级共用**（C# 本来就从 appsettings JSON 读），
//!   也避开 TOML 内联表/数组表表达规则树的麻烦。

const std = @import("std");
const zzig = @import("zzig");

/// 配置文件相对基础目录的路径。
pub const CONFIG_REL = "Config/Waf.toml";

/// 站点模式（语义标记；策略由具体开关决定）。
pub const Mode = enum { public_site, admin_api };

/// 单项防护动作。
pub const Action = enum { off, monitor, block };

/// 解析动作字符串（`off` / `monitor` / `block`；未知值落回 `block`——失败朝安全）。
pub fn actionOf(text: []const u8) Action {
    if (eq(text, "off")) return .off;
    if (eq(text, "monitor")) return .monitor;
    return .block;
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

/// WAF 配置（字段名即 TOML 键名，camelCase；缺省键保留调用方预设）。
pub const WafConfig = struct {
    /// 总开关
    enable: bool = true,
    /// 模式（`publicSite` / `adminApi`）
    mode: []const u8 = "adminApi",
    /// 拦截空 User-Agent（默认关：服务间调用常无 UA）
    blockEmptyUa: bool = false,
    /// 回环地址（127.0.0.1/::1）豁免全部检查
    loopbackBypass: bool = true,
    /// IP 白名单（精确 / CIDR / 通配符）
    ipWhitelist: []const []const u8 = &.{},
    /// IP 黑名单
    ipBlacklist: []const []const u8 = &.{},
    /// 自定义放行 UA 子串（优先于全部恶意判定）
    extraAllowBots: []const []const u8 = &.{},
    /// 自定义拦截 UA 子串（先于名单分类）
    extraBlockBots: []const []const u8 = &.{},
    /// 放行搜索引擎蜘蛛
    allowSearchBots: bool = false,
    /// 放行 GEO / AI 抓取器
    allowAiBots: bool = false,
    /// 放行社交平台链接预览
    allowSocialPreviews: bool = false,
    /// 拦截恶意爬虫 / 扫描器
    blockMaliciousBots: bool = true,
    /// 敏感前缀（禁止一切机器人；攻击监控项升级为拦截）
    sensitivePrefixes: []const []const u8 = &.{},
    /// 跳过攻击特征检测的路径前缀（本体即执行 SQL / 传文件的管理端点）
    skipAttackPrefixes: []const []const u8 = &.{},
    /// 跳过机器人拦截的路径前缀（机器对机器 API）
    skipBotPrefixes: []const []const u8 = &.{},
    /// 跨站来源校验（CSRF）：非安全方法校验 `Sec-Fetch-Site` / `Origin`
    csrfGuard: bool = true,
    /// SQL 注入动作
    sqliAction: []const u8 = "block",
    /// XSS 动作
    xssAction: []const u8 = "block",
    /// 路径穿越 / 敏感路径探测动作
    pathAction: []const u8 = "block",
    /// 命令注入动作
    cmdAction: []const u8 = "block",
    /// CC 限速（每 IP 首次命中起 60 秒窗口内的请求数；0 = 关闭）
    rateLimitPerMin: u32 = 300,
    /// 拦截日志
    logBlocked: bool = true,
    /// 详细日志（记录放行/监控命中）
    verbose: bool = false,
    /// 请求体扫描上限（字节；0 回退 16 KB）
    bodyScanLimit: usize = 64 * 1024,
    /// 对非文本 Content-Type 的请求体也做扫描
    bodyScanAllTypes: bool = true,
    /// 直连对端是回环时采纳 `X-Forwarded-For`（反代后取真实 IP）
    /// 是否采纳反代转发头（`x-real-ip` / `x-forwarded-for` 末段）当客户端 IP。
    ///
    /// **默认开**：应用绝大多数跑在 nginx 之后；`resolveClientIp` 只在 TCP 对端是回环时才采纳，
    /// 直连公网时对端不是回环 → 转发头一律忽略，所以默认开不降低安全性。
    /// 如果反代与程序**不在同一主机**（容器 / 旁路部署），对端不是回环，需配 `trustedProxyPrefixes`。
    trustForwardedFor: bool = true,
    /// C# 兼容规则集 JSON 文件（相对基础目录；空 = 不启用）
    rulesetFile: []const u8 = "",

    // ————— 协议层硬限制（按 Web 规范给的默认值；**0 / 空 = 不限制**）—————
    /// 允许的 HTTP 方法（**大小写敏感**，HTTP 规范如此）。不在表内一律 405。
    ///
    /// 默认不包含 `TRACE` / `TRACK`（XST 跨站追踪攻击）、`PROPFIND` 等 WebDAV 方法。
    /// 默认含 `OPTIONS`：CORS 预检与部分反代探活要用。
    allowedMethods: []const []const u8 = &.{ "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS" },
    /// URL（path + `?` + query）长度上限；超限 414。浏览器与反代普遍 8 KB，取 4 KB 有余量
    maxUrlLength: usize = 4096,
    /// 非上传路径的 `Content-Length` 上限（字节）；超限 413。
    ///
    /// 取 1 MB 而非规范推荐的 256 KB：生态里后台富文本/设置提交可能到几百 KB，
    /// 256 KB 会在正常使用下误伤。真正的大文件走 `uploadPrefixes`（受服务端 `max_body` 约束）。
    maxBodyNormal: usize = 1024 * 1024,
    /// 上传路径前缀（不做 `maxBodyNormal` 限制，交给服务端全局 `max_body`）
    uploadPrefixes: []const []const u8 = &.{ "/upload", "/fileuploader", "/api/upload" },

    pub fn modeKind(self: WafConfig) Mode {
        return if (eq(self.mode, "publicSite")) .public_site else .admin_api;
    }

    pub fn sqli(self: WafConfig) Action {
        return actionOf(self.sqliAction);
    }
    pub fn xss(self: WafConfig) Action {
        return actionOf(self.xssAction);
    }
    pub fn path(self: WafConfig) Action {
        return actionOf(self.pathAction);
    }
    pub fn cmd(self: WafConfig) Action {
        return actionOf(self.cmdAction);
    }
    pub fn bodyLimit(self: WafConfig) usize {
        return if (self.bodyScanLimit == 0) 16 * 1024 else self.bodyScanLimit;
    }

    /// 管理端 / API 预设：不放行任何机器人；全站从严（XSS/命令注入也拦截）。
    pub fn adminApi() WafConfig {
        return .{};
    }

    /// 前台公开站点预设：正常搜索引擎 / GEO-AI / 社交预览放行；`/admin` 从严。
    pub fn publicSite() WafConfig {
        return .{
            .mode = "publicSite",
            .allowSearchBots = true,
            .allowAiBots = true,
            .allowSocialPreviews = true,
            .sensitivePrefixes = &.{"/admin"},
            .xssAction = "monitor",
            .cmdAction = "monitor",
            .rateLimitPerMin = 600,
            .bodyScanAllTypes = false,
        };
    }
};

/// 加载结果：配置 + 持有配置字符串的 arena。
pub const Loaded = struct {
    arena: std.heap.ArenaAllocator,
    config: WafConfig,
    moved: bool = false,

    pub fn deinit(self: *Loaded) void {
        if (self.moved) return;
        self.arena.deinit();
    }

    /// 转移 arena 所有权（调用方接管后本对象 `deinit` 变成空操作）。
    pub fn take(self: *Loaded) std.heap.ArenaAllocator {
        self.moved = true;
        return self.arena;
    }
};

fn dupeStr(a: std.mem.Allocator, s: []const u8) ![]const u8 {
    return a.dupe(u8, s);
}

fn dupeList(a: std.mem.Allocator, list: []const []const u8) ![]const []const u8 {
    if (list.len == 0) return &.{};
    const out = try a.alloc([]const u8, list.len);
    for (list, 0..) |item, i| out[i] = try dupeStr(a, item);
    return out;
}

/// 深拷贝配置到 `a`（面板保存 / 内存态配置用：调用方切片可能随时失效）。
pub fn clone(a: std.mem.Allocator, cfg: WafConfig) !WafConfig {
    var out = cfg;
    out.mode = try dupeStr(a, cfg.mode);
    out.ipWhitelist = try dupeList(a, cfg.ipWhitelist);
    out.ipBlacklist = try dupeList(a, cfg.ipBlacklist);
    out.extraAllowBots = try dupeList(a, cfg.extraAllowBots);
    out.extraBlockBots = try dupeList(a, cfg.extraBlockBots);
    out.sensitivePrefixes = try dupeList(a, cfg.sensitivePrefixes);
    out.skipAttackPrefixes = try dupeList(a, cfg.skipAttackPrefixes);
    out.skipBotPrefixes = try dupeList(a, cfg.skipBotPrefixes);
    out.sqliAction = try dupeStr(a, cfg.sqliAction);
    out.xssAction = try dupeStr(a, cfg.xssAction);
    out.pathAction = try dupeStr(a, cfg.pathAction);
    out.cmdAction = try dupeStr(a, cfg.cmdAction);
    out.rulesetFile = try dupeStr(a, cfg.rulesetFile);
    return out;
}

/// 剥 UTF-8 BOM。**Windows 记事本、PowerShell 5.1 的 `Set-Content -Encoding utf8`
/// 都会在文件开头写 `EF BB BF`**，不剥会解析失败。
///
/// 2026-11-23 实测踩到：手工把 `loopbackBypass` 改成 `false` 时被写进 BOM，
/// 热重载报 `InvalidToml` 并**保留旧配置**，于是「以为关掉了回环放行，其实没关」，
/// 一整轮 WAF 测试全部假放行（空 UA / sqlmap 都返回 200）。
fn stripBom(text: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, text, "\xEF\xBB\xBF")) text[3..] else text;
}

/// 从 `path` 加载；文件不存在时按 `preset` 生成模板并返回预设。
pub fn loadOrCreate(io: std.Io, gpa: std.mem.Allocator, path: []const u8, preset: WafConfig) !Loaded {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const text = stripBom(std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(1024 * 1024)) catch |err| switch (err) {
        error.FileNotFound => {
            const cfg = preset;
            save(io, a, path, cfg) catch {};
            return .{ .arena = arena, .config = cfg };
        },
        else => return err,
    });

    const table = zzig.config.toml.parse(a, text) catch {
        // 解析失败：保留调用方预设（不静默清空），由门面负责告警
        return .{ .arena = arena, .config = preset };
    };

    var cfg = preset;
    try applyTable(a, &cfg, table);
    return .{ .arena = arena, .config = cfg };
}

/// 读取已存在的配置（不存在则报错；热重载用）。
pub fn loadExisting(io: std.Io, gpa: std.mem.Allocator, path: []const u8, preset: WafConfig) !Loaded {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    const text = stripBom(try std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(1024 * 1024)));
    const table = try zzig.config.toml.parse(a, text);
    var cfg = preset;
    try applyTable(a, &cfg, table);
    return .{ .arena = arena, .config = cfg };
}

/// 以**预设为起点**逐键覆盖（不用 `toml.decode`：它会从类型默认值起步，把调用方预设清空）。
/// 取值助手统一用 `zzig.config.toml.get*`（大小写不敏感，键名写错大小写也能读到）。
fn applyTable(a: std.mem.Allocator, cfg: *WafConfig, table: *zzig.config.toml.Table) !void {
    if (zzig.config.toml.getBool(table, "enable")) |v| cfg.enable = v;
    if (zzig.config.toml.getStr(table, "mode")) |v| cfg.mode = v;
    if (zzig.config.toml.getBool(table, "blockEmptyUa")) |v| cfg.blockEmptyUa = v;
    if (zzig.config.toml.getBool(table, "loopbackBypass")) |v| cfg.loopbackBypass = v;
    if (try zzig.config.toml.getStrList(a, table, "ipWhitelist")) |v| cfg.ipWhitelist = v;
    if (try zzig.config.toml.getStrList(a, table, "ipBlacklist")) |v| cfg.ipBlacklist = v;
    if (try zzig.config.toml.getStrList(a, table, "extraAllowBots")) |v| cfg.extraAllowBots = v;
    if (try zzig.config.toml.getStrList(a, table, "extraBlockBots")) |v| cfg.extraBlockBots = v;
    if (zzig.config.toml.getBool(table, "allowSearchBots")) |v| cfg.allowSearchBots = v;
    if (zzig.config.toml.getBool(table, "allowAiBots")) |v| cfg.allowAiBots = v;
    if (zzig.config.toml.getBool(table, "allowSocialPreviews")) |v| cfg.allowSocialPreviews = v;
    if (zzig.config.toml.getBool(table, "blockMaliciousBots")) |v| cfg.blockMaliciousBots = v;
    if (try zzig.config.toml.getStrList(a, table, "sensitivePrefixes")) |v| cfg.sensitivePrefixes = v;
    if (try zzig.config.toml.getStrList(a, table, "skipAttackPrefixes")) |v| cfg.skipAttackPrefixes = v;
    if (try zzig.config.toml.getStrList(a, table, "skipBotPrefixes")) |v| cfg.skipBotPrefixes = v;
    if (zzig.config.toml.getBool(table, "csrfGuard")) |v| cfg.csrfGuard = v;
    if (zzig.config.toml.getStr(table, "sqliAction")) |v| cfg.sqliAction = v;
    if (zzig.config.toml.getStr(table, "xssAction")) |v| cfg.xssAction = v;
    if (zzig.config.toml.getStr(table, "pathAction")) |v| cfg.pathAction = v;
    if (zzig.config.toml.getStr(table, "cmdAction")) |v| cfg.cmdAction = v;
    if (zzig.config.toml.getInt(table, "rateLimitPerMin")) |v| {
        if (v >= 0) cfg.rateLimitPerMin = @intCast(@min(v, std.math.maxInt(u32)));
    }
    if (zzig.config.toml.getBool(table, "logBlocked")) |v| cfg.logBlocked = v;
    if (zzig.config.toml.getBool(table, "verbose")) |v| cfg.verbose = v;
    if (zzig.config.toml.getInt(table, "bodyScanLimit")) |v| {
        if (v >= 0) cfg.bodyScanLimit = @intCast(@min(v, std.math.maxInt(u32)));
    }
    if (zzig.config.toml.getBool(table, "bodyScanAllTypes")) |v| cfg.bodyScanAllTypes = v;
    if (zzig.config.toml.getBool(table, "trustForwardedFor")) |v| cfg.trustForwardedFor = v;
    if (zzig.config.toml.getStr(table, "rulesetFile")) |v| cfg.rulesetFile = v;
    if (try zzig.config.toml.getStrList(a, table, "allowedMethods")) |v| cfg.allowedMethods = v;
    if (zzig.config.toml.getInt(table, "maxUrlLength")) |v| {
        if (v >= 0) cfg.maxUrlLength = @intCast(@min(v, std.math.maxInt(u32)));
    }
    if (zzig.config.toml.getInt(table, "maxBodyNormal")) |v| {
        if (v >= 0) cfg.maxBodyNormal = @intCast(@min(v, std.math.maxInt(u32)));
    }
    if (try zzig.config.toml.getStrList(a, table, "uploadPrefixes")) |v| cfg.uploadPrefixes = v;
}

/// 保存配置（自动建目录、写临时文件后 rename；内容带注释头）。
pub fn save(io: std.Io, allocator: std.mem.Allocator, path: []const u8, cfg: WafConfig) !void {
    const cwd = std.Io.Dir.cwd();
    const dir_path = std.fs.path.dirname(path) orelse ".";
    try cwd.createDirPath(io, dir_path);
    const text = try renderTemplate(allocator, cfg);
    defer allocator.free(text);

    const tmp = try std.fmt.allocPrint(allocator, "{s}.tmp", .{path});
    defer allocator.free(tmp);
    {
        const file = try cwd.createFile(io, tmp, .{ .truncate = true });
        defer file.close(io);
        try file.writeStreamingAll(io, text);
    }
    cwd.rename(tmp, cwd, path, io) catch {
        // rename 失败（跨盘/被占用）：退化为直写
        const file = try cwd.createFile(io, path, .{ .truncate = true });
        defer file.close(io);
        try file.writeStreamingAll(io, text);
    };
}

fn appendStrList(out: *std.ArrayList(u8), a: std.mem.Allocator, key: []const u8, list: []const []const u8) !void {
    try out.appendSlice(a, key);
    try out.appendSlice(a, " = [");
    for (list, 0..) |item, i| {
        if (i > 0) try out.appendSlice(a, ", ");
        try out.append(a, '"');
        try out.appendSlice(a, item);
        try out.append(a, '"');
    }
    try out.appendSlice(a, "]\n");
}

/// 渲染带注释头的 TOML 模板（字段齐全）。
pub fn renderTemplate(a: std.mem.Allocator, cfg: WafConfig) ![]u8 {
    const t = zzig.config.toml_template;
    // 声明表驱动：注释与键值写在**同一条记录**里，渲染规则（`# ` 前缀、分组空行、
    // 列表格式、字符串转义）统一由 `zzig.config.toml_template` 负责。
    // 新增字段时只要在这张表里加一条，注释忘写会一眼看出来。
    const items = [_]t.Item{
        .{ .key = "enable", .doc = &.{"总开关（false = 完全旁路，仅调试用；生产保持 true）"}, .value = .{ .boolean = cfg.enable } },
        .{ .key = "mode", .doc = &.{"预设模式：adminApi（后台/API 从严）| publicSite（公开站点，放行搜索与 AI 抓取）"}, .value = .{ .string = cfg.mode } },
        .{ .key = "blockEmptyUa", .doc = &.{"空 User-Agent 是否拦截（扫描器常用空 UA；探活脚本请配 ipWhitelist）"}, .value = .{ .boolean = cfg.blockEmptyUa } },
        .{ .key = "loopbackBypass", .doc = &.{
            "对端是回环（127.0.0.1 / ::1）时整体放行。",
            "生产建议 true（本机脚本/探活免检）；写 WAF 测试时必须置 false，否则回环用例等于没测",
        }, .value = .{ .boolean = cfg.loopbackBypass } },
        .{ .key = "ipWhitelist", .doc = &.{"IP 白名单（精确 IP 或前缀，如 \"10.0.\"）"}, .value = .{ .string_list = cfg.ipWhitelist } },
        .{ .key = "ipBlacklist", .doc = &.{"IP 黑名单（同上格式；命中直接 403）"}, .value = .{ .string_list = cfg.ipBlacklist } },
        .{ .key = "extraAllowBots", .doc = &.{"额外放行的机器人标识（匹配 User-Agent 子串）"}, .value = .{ .string_list = cfg.extraAllowBots } },
        .{ .key = "extraBlockBots", .doc = &.{"额外拦截的机器人标识（匹配 User-Agent 子串）"}, .value = .{ .string_list = cfg.extraBlockBots } },
        .{ .key = "allowSearchBots", .doc = &.{"放行搜索引擎抓取（公开站点通常开；百度/Google/Bing 等）"}, .value = .{ .boolean = cfg.allowSearchBots } },
        .{ .key = "allowAiBots", .doc = &.{"放行 GEO-AI 抓取器（GPTBot / ClaudeBot / PerplexityBot 等）"}, .value = .{ .boolean = cfg.allowAiBots } },
        .{ .key = "allowSocialPreviews", .doc = &.{"放行社交链接预览（微信 / 飞书 / Telegram / Slack 等）"}, .value = .{ .boolean = cfg.allowSocialPreviews } },
        .{ .key = "blockMaliciousBots", .doc = &.{"拦截恶意爬虫与扫描器（sqlmap / nikto 等 UA 特征）"}, .value = .{ .boolean = cfg.blockMaliciousBots } },
        .{ .key = "sensitivePrefixes", .doc = &.{"敏感路径前缀：该前缀下禁止一切机器人，且攻击「监控」项自动升级为「拦截」（如 \"/admin\"）"}, .value = .{ .string_list = cfg.sensitivePrefixes } },
        .{ .key = "skipAttackPrefixes", .doc = &.{"跳过攻击特征检测的路径前缀（本体就执行 SQL / 接收文件的管理端点）"}, .value = .{ .string_list = cfg.skipAttackPrefixes } },
        .{ .key = "skipBotPrefixes", .doc = &.{"跳过机器人拦截的路径前缀（机器对机器 API，调用方 UA 常是 curl / python-requests）"}, .value = .{ .string_list = cfg.skipBotPrefixes } },
        .{ .key = "allowedMethods", .doc = &.{
            "允许的 HTTP 方法（大小写敏感）；不在表内一律 405。",
            "默认不含 TRACE / TRACK（XST 跨站追踪）与 WebDAV 系方法；空数组 = 不限制。",
        }, .value = .{ .string_list = cfg.allowedMethods } },
        .{ .key = "maxUrlLength", .doc = &.{"URL（path + query）长度上限，超限 414；0 = 不限制"}, .value = .{ .integer = @intCast(cfg.maxUrlLength) } },
        .{ .key = "maxBodyNormal", .doc = &.{
            "非上传路径的 Content-Length 上限（字节），超限 413（早拒，不读 body）；0 = 不限制。",
            "取 1 MB：后台富文本/设置提交可能到几百 KB，256 KB 会误伤。",
        }, .value = .{ .integer = @intCast(cfg.maxBodyNormal) } },
        .{ .key = "uploadPrefixes", .doc = &.{"上传路径前缀：不受 maxBodyNormal 限制，由服务端全局 max_body 约束"}, .value = .{ .string_list = cfg.uploadPrefixes } },
        .{ .key = "csrfGuard", .doc = &.{"跨站来源校验（CSRF）：非安全方法校验 Sec-Fetch-Site / Origin"}, .value = .{ .boolean = cfg.csrfGuard } },
        .{ .key = "sqliAction", .doc = &.{"SQL 注入动作：block（拦截）| monitor（只记录）| off（不检测）"}, .value = .{ .string = cfg.sqliAction } },
        .{ .key = "xssAction", .doc = &.{"XSS 动作（同上取值）"}, .value = .{ .string = cfg.xssAction } },
        .{ .key = "pathAction", .doc = &.{"路径穿越动作（同上取值）"}, .value = .{ .string = cfg.pathAction } },
        .{ .key = "cmdAction", .doc = &.{"命令注入动作（同上取值）"}, .value = .{ .string = cfg.cmdAction } },
        .{ .key = "rateLimitPerMin", .doc = &.{
            "全站 CC 限速（每 IP 首次命中起 60 秒窗口内的请求数；0 = 关闭）。",
            "阈值过小会误伤缓存命中的高频正常调用 —— 定值前先算业务峰值。",
            "逐接口限流不在这里：用 Pek.ZWaf 的 Throttle（对齐 C# [RateValve]）在路由上挂。",
        }, .value = .{ .integer = @intCast(cfg.rateLimitPerMin) } },
        .{ .key = "logBlocked", .doc = &.{"拦截日志（同一 IP + 原因 1 秒内去重；高频攻击不刷屏）"}, .value = .{ .boolean = cfg.logBlocked } },
        .{ .key = "verbose", .doc = &.{"详细日志（放行与监控命中，排障用；生产建议关）"}, .value = .{ .boolean = cfg.verbose } },
        .{ .key = "bodyScanLimit", .doc = &.{"请求体扫描上限（字节；0 回退 16 KB）"}, .value = .{ .integer = @intCast(cfg.bodyScanLimit) } },
        .{ .key = "bodyScanAllTypes", .doc = &.{"非文本 Content-Type 的请求体也扫描（只有 JSON/表单的服务必须开，否则改个 Type 就绕过）"}, .value = .{ .boolean = cfg.bodyScanAllTypes } },
        .{ .key = "trustForwardedFor", .doc = &.{
            "对端是回环时是否采纳 X-Real-IP / X-Forwarded-For（末段）作为客户端 IP。",
            "反代后必须为 true，否则 WAF 看到的是 127.0.0.1：黑名单、Top IP、CC 全部失真",
        }, .value = .{ .boolean = cfg.trustForwardedFor } },
        .{ .key = "rulesetFile", .doc = &.{"自定义规则集文件（JSON；留空 = 不使用）"}, .value = .{ .string = cfg.rulesetFile } },
    };
    return t.render(a, .{ .header = &.{
        "Pek.ZWaf 配置（TOML；保存后自动热生效，改文件约 2 秒内加载）",
        "字段含义见 Pek.ZWaf README / docs/设计说明.md；可手工修改后保存。",
        "规则集（C# Pek.WAF 兼容）放在 rulesetFile 指向的 JSON 文件里。",
    } }, &items);
}

/// 测试用临时目录路径（相对构建根目录；调用方负责 free + deleteTree）。
fn tempDir(a: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(a, ".zig-cache{c}pek-zwaf-test-{d}", .{ std.fs.path.sep, zzig.compat.nanoTimestamp() });
}

test "预设与动作解析" {
    const t = std.testing;
    const admin = WafConfig.adminApi();
    try t.expectEqual(Mode.admin_api, admin.modeKind());
    try t.expectEqual(Action.block, admin.xss());
    const pub_site = WafConfig.publicSite();
    try t.expectEqual(Mode.public_site, pub_site.modeKind());
    try t.expectEqual(Action.monitor, pub_site.xss());
    try t.expect(pub_site.allowSearchBots);
    try t.expectEqualStrings("/admin", pub_site.sensitivePrefixes[0]);
    try t.expectEqual(Action.off, actionOf("OFF"));
    try t.expectEqual(Action.block, actionOf("unknown-value"));
}

test "往返保存与读取（缺键继承预设）" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const cwd = std.Io.Dir.cwd();
    const base = try tempDir(a);
    defer a.free(base);
    defer cwd.deleteTree(io, base) catch {};
    try cwd.createDirPath(io, base);

    const path = try std.fs.path.join(a, &.{ base, CONFIG_REL });
    defer a.free(path);

    var preset = WafConfig.adminApi();
    preset.skipBotPrefixes = &.{"/api"};
    preset.skipAttackPrefixes = &.{"/api"};

    var loaded = try loadOrCreate(io, a, path, preset);
    defer loaded.deinit();
    try std.testing.expect(loaded.config.enable);

    // 落盘后手工写一份「旧文件」：只含两个键
    {
        const file = try cwd.createFile(io, path, .{ .truncate = true });
        defer file.close(io);
        try file.writeStreamingAll(io, "enable = true\nblockMaliciousBots = true\n");
    }

    var again = try loadExisting(io, a, path, preset);
    defer again.deinit();
    // 文件里有的键优先
    try std.testing.expect(again.config.blockMaliciousBots);
    // 文件缺失的键继承预设（不能被静默清空）
    try std.testing.expectEqualStrings("/api", again.config.skipBotPrefixes[0]);
    try std.testing.expectEqualStrings("/api", again.config.skipAttackPrefixes[0]);

    // 显式空数组时尊重文件
    {
        const file2 = try cwd.createFile(io, path, .{ .truncate = true });
        defer file2.close(io);
        try file2.writeStreamingAll(io, "skipBotPrefixes = []\n");
    }
    var third = try loadExisting(io, a, path, preset);
    defer third.deinit();
    try std.testing.expectEqual(@as(usize, 0), third.config.skipBotPrefixes.len);
}

test "读入时剥 UTF-8 BOM（Windows 记事本 / PS 5.1 会写 BOM）" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const cwd = std.Io.Dir.cwd();
    const base = try tempDir(a);
    defer a.free(base);
    defer cwd.deleteTree(io, base) catch {};
    try cwd.createDirPath(io, base);

    const path = try std.fs.path.join(a, &.{ base, CONFIG_REL });
    defer a.free(path);
    try cwd.createDirPath(io, std.fs.path.dirname(path).?);

    // 文件头 EF BB BF + 一行真实配置：BOM 不剥会 parse 失败 → 静默保留预设（测试会红）
    {
        const file = try cwd.createFile(io, path, .{ .truncate = true });
        defer file.close(io);
        try file.writeStreamingAll(io, "\xEF\xBB\xBFenable = true\nloopbackBypass = false\n");
    }

    var preset = WafConfig.adminApi();
    preset.loopbackBypass = true; // 预设与文件相反：读到 false 才证明文件生效
    var loaded = try loadExisting(io, a, path, preset);
    defer loaded.deinit();
    try std.testing.expect(loaded.config.enable);
    try std.testing.expect(!loaded.config.loopbackBypass);
}

test "模板渲染可被解析回同样配置" {
    const a = std.testing.allocator;
    var cfg = WafConfig.publicSite();
    cfg.rulesetFile = "Config/WafRules.json";
    cfg.ipWhitelist = &.{ "127.0.0.1", "10.0.0.0/8" };
    const text = try renderTemplate(a, cfg);
    defer a.free(text);

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const table = try zzig.config.toml.parse(arena.allocator(), text);
    var back = WafConfig.adminApi();
    try applyTable(arena.allocator(), &back, table);
    try std.testing.expectEqualStrings("publicSite", back.mode);
    try std.testing.expectEqual(@as(u32, 600), back.rateLimitPerMin);
    try std.testing.expectEqualStrings("Config/WafRules.json", back.rulesetFile);
    try std.testing.expectEqual(@as(usize, 2), back.ipWhitelist.len);
}
