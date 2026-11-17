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
    trustForwardedFor: bool = false,
    /// C# 兼容规则集 JSON 文件（相对基础目录；空 = 不启用）
    rulesetFile: []const u8 = "",

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

/// 从 `path` 加载；文件不存在时按 `preset` 生成模板并返回预设。
pub fn loadOrCreate(io: std.Io, gpa: std.mem.Allocator, path: []const u8, preset: WafConfig) !Loaded {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const text = std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(1024 * 1024)) catch |err| switch (err) {
        error.FileNotFound => {
            const cfg = preset;
            save(io, a, path, cfg) catch {};
            return .{ .arena = arena, .config = cfg };
        },
        else => return err,
    };

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
    const text = try std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(1024 * 1024));
    const table = try zzig.config.toml.parse(a, text);
    var cfg = preset;
    try applyTable(a, &cfg, table);
    return .{ .arena = arena, .config = cfg };
}

fn getBool(table: *zzig.config.toml.Table, key: []const u8) ?bool {
    const v = table.get(key) orelse return null;
    return switch (v) {
        .boolean => |b| b,
        else => null,
    };
}

fn getInt(table: *zzig.config.toml.Table, key: []const u8) ?i64 {
    const v = table.get(key) orelse return null;
    return switch (v) {
        .integer => |i| i,
        else => null,
    };
}

fn getStr(table: *zzig.config.toml.Table, key: []const u8) ?[]const u8 {
    const v = table.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn getStrList(a: std.mem.Allocator, table: *zzig.config.toml.Table, key: []const u8) !?[]const []const u8 {
    const v = table.get(key) orelse return null;
    return switch (v) {
        .array => |items| blk: {
            const out = try a.alloc([]const u8, items.len);
            for (items, 0..) |item, i| {
                out[i] = switch (item) {
                    .string => |s| s,
                    else => "",
                };
            }
            break :blk out;
        },
        else => null,
    };
}

fn applyTable(a: std.mem.Allocator, cfg: *WafConfig, table: *zzig.config.toml.Table) !void {
    if (getBool(table, "enable")) |v| cfg.enable = v;
    if (getStr(table, "mode")) |v| cfg.mode = v;
    if (getBool(table, "blockEmptyUa")) |v| cfg.blockEmptyUa = v;
    if (getBool(table, "loopbackBypass")) |v| cfg.loopbackBypass = v;
    if (try getStrList(a, table, "ipWhitelist")) |v| cfg.ipWhitelist = v;
    if (try getStrList(a, table, "ipBlacklist")) |v| cfg.ipBlacklist = v;
    if (try getStrList(a, table, "extraAllowBots")) |v| cfg.extraAllowBots = v;
    if (try getStrList(a, table, "extraBlockBots")) |v| cfg.extraBlockBots = v;
    if (getBool(table, "allowSearchBots")) |v| cfg.allowSearchBots = v;
    if (getBool(table, "allowAiBots")) |v| cfg.allowAiBots = v;
    if (getBool(table, "allowSocialPreviews")) |v| cfg.allowSocialPreviews = v;
    if (getBool(table, "blockMaliciousBots")) |v| cfg.blockMaliciousBots = v;
    if (try getStrList(a, table, "sensitivePrefixes")) |v| cfg.sensitivePrefixes = v;
    if (try getStrList(a, table, "skipAttackPrefixes")) |v| cfg.skipAttackPrefixes = v;
    if (try getStrList(a, table, "skipBotPrefixes")) |v| cfg.skipBotPrefixes = v;
    if (getBool(table, "csrfGuard")) |v| cfg.csrfGuard = v;
    if (getStr(table, "sqliAction")) |v| cfg.sqliAction = v;
    if (getStr(table, "xssAction")) |v| cfg.xssAction = v;
    if (getStr(table, "pathAction")) |v| cfg.pathAction = v;
    if (getStr(table, "cmdAction")) |v| cfg.cmdAction = v;
    if (getInt(table, "rateLimitPerMin")) |v| {
        if (v >= 0) cfg.rateLimitPerMin = @intCast(@min(v, std.math.maxInt(u32)));
    }
    if (getBool(table, "logBlocked")) |v| cfg.logBlocked = v;
    if (getBool(table, "verbose")) |v| cfg.verbose = v;
    if (getInt(table, "bodyScanLimit")) |v| {
        if (v >= 0) cfg.bodyScanLimit = @intCast(@min(v, std.math.maxInt(u32)));
    }
    if (getBool(table, "bodyScanAllTypes")) |v| cfg.bodyScanAllTypes = v;
    if (getBool(table, "trustForwardedFor")) |v| cfg.trustForwardedFor = v;
    if (getStr(table, "rulesetFile")) |v| cfg.rulesetFile = v;
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
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);

    try out.appendSlice(a,
        \\# Pek.ZWaf 配置（TOML；保存后自动热生效）
        \\# 字段含义见 Pek.ZWaf README / docs/设计说明.md；可手工修改后保存。
        \\# 规则集（C# Pek.WAF 兼容）放在 rulesetFile 指向的 JSON 文件里。
        \\
        \\
    );
    try out.print(a, "enable = {}\n", .{cfg.enable});
    try out.print(a, "mode = \"{s}\"\n", .{cfg.mode});
    try out.print(a, "blockEmptyUa = {}\n", .{cfg.blockEmptyUa});
    try out.print(a, "loopbackBypass = {}\n", .{cfg.loopbackBypass});
    try appendStrList(&out, a, "ipWhitelist", cfg.ipWhitelist);
    try appendStrList(&out, a, "ipBlacklist", cfg.ipBlacklist);
    try appendStrList(&out, a, "extraAllowBots", cfg.extraAllowBots);
    try appendStrList(&out, a, "extraBlockBots", cfg.extraBlockBots);
    try out.print(a, "allowSearchBots = {}\n", .{cfg.allowSearchBots});
    try out.print(a, "allowAiBots = {}\n", .{cfg.allowAiBots});
    try out.print(a, "allowSocialPreviews = {}\n", .{cfg.allowSocialPreviews});
    try out.print(a, "blockMaliciousBots = {}\n", .{cfg.blockMaliciousBots});
    try appendStrList(&out, a, "sensitivePrefixes", cfg.sensitivePrefixes);
    try appendStrList(&out, a, "skipAttackPrefixes", cfg.skipAttackPrefixes);
    try appendStrList(&out, a, "skipBotPrefixes", cfg.skipBotPrefixes);
    try out.print(a, "csrfGuard = {}\n", .{cfg.csrfGuard});
    try out.print(a, "sqliAction = \"{s}\"\n", .{cfg.sqliAction});
    try out.print(a, "xssAction = \"{s}\"\n", .{cfg.xssAction});
    try out.print(a, "pathAction = \"{s}\"\n", .{cfg.pathAction});
    try out.print(a, "cmdAction = \"{s}\"\n", .{cfg.cmdAction});
    try out.print(a, "rateLimitPerMin = {d}\n", .{cfg.rateLimitPerMin});
    try out.print(a, "logBlocked = {}\n", .{cfg.logBlocked});
    try out.print(a, "verbose = {}\n", .{cfg.verbose});
    try out.print(a, "bodyScanLimit = {d}\n", .{cfg.bodyScanLimit});
    try out.print(a, "bodyScanAllTypes = {}\n", .{cfg.bodyScanAllTypes});
    try out.print(a, "trustForwardedFor = {}\n", .{cfg.trustForwardedFor});
    try out.print(a, "rulesetFile = \"{s}\"\n", .{cfg.rulesetFile});
    return out.toOwnedSlice(a);
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
