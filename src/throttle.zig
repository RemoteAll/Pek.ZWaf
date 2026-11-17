//! 接口级限流（对齐 C# `DH.RateLimter` 与 Rust `Pek.RWaf::throttle`）。
//!
//! 与 WAF 的 CC 限速（`rateLimitPerMin`，全站每 IP）不同：这里是**按接口 + 多策略**的业务限流，
//! 两者可同时启用：
//! - 七种策略：`ip` / `userIdentity` / `header` / `query` / `requestPath` / `cookie` / `form`；
//! - 一条规则可挂多个阀门（按 `priority` 从高到低执行，首个超限即拒绝）；
//! - `whenNull`：`pass`（值为空跳过该阀门）/ `intercept`（值为空按客户端 IP 计数）；
//! - 429 三种返回体（`text` / `jsonDResult` / `jsonDgResult`）+ `Api-Throttle-Status` 头。
//!
//! ## 与 Rust 版的差异（有意为之，均已在 README「移植对照」注明）
//! - **规则文件用 JSON**（`Config/Throttle.json`）：规则是「规则数组 → 阀门数组」两层结构，
//!   TOML 的数组表表达力差且易写错；WAF 主配置仍是 TOML。
//! - `whenNull=intercept` 的空值标识直接用客户端 IP（Rust 侧是 `empty_value_<md5_short(ip)>`）：
//!   目的相同（同一 IP 共用计数），少一次哈希。
//! - `jsonDgResult` 省略动态的 `operationTime` / `id` 字段（宿主如需可自行覆盖）。

const std = @import("std");
const zzig = @import("zzig");

const clock = @import("clock.zig");
const gen = @import("gen.zig");
const ratelimit = @import("ratelimit.zig");
const wafreq = @import("wafreq.zig");

/// 状态头（限流器写入）。
pub const HEADER_STATUS = "Api-Throttle-Status";
/// 规则文件相对基础目录的路径。
pub const CONFIG_REL = "Config/Throttle.json";

/// 限流策略。
pub const Policy = enum {
    ip,
    user_identity,
    header,
    query,
    request_path,
    cookie,
    form,

    pub fn asKey(self: Policy) []const u8 {
        return switch (self) {
            .ip => "ip",
            .user_identity => "userIdentity",
            .header => "header",
            .query => "query",
            .request_path => "requestPath",
            .cookie => "cookie",
            .form => "form",
        };
    }

    pub fn fromKey(s: []const u8) ?Policy {
        if (std.ascii.eqlIgnoreCase(s, "ip")) return .ip;
        if (std.ascii.eqlIgnoreCase(s, "userIdentity")) return .user_identity;
        if (std.ascii.eqlIgnoreCase(s, "header")) return .header;
        if (std.ascii.eqlIgnoreCase(s, "query")) return .query;
        if (std.ascii.eqlIgnoreCase(s, "requestPath")) return .request_path;
        if (std.ascii.eqlIgnoreCase(s, "cookie")) return .cookie;
        if (std.ascii.eqlIgnoreCase(s, "form")) return .form;
        return null;
    }
};

/// 值为空时的处理方式。
pub const WhenNull = enum {
    /// 跳过该阀门
    pass,
    /// 按客户端 IP 生成空值标识继续计数
    intercept,
};

/// 超限返回体格式。
pub const ReturnType = enum {
    /// `{"code":429,"msg":"..."}`
    json_d_result,
    /// `{"code":429,"errCode":0,"message":"...","data":null,"extData":null}`
    json_dg_result,
    /// 纯文本
    text,

    pub fn fromKey(s: []const u8) ReturnType {
        if (std.ascii.eqlIgnoreCase(s, "text")) return .text;
        if (std.ascii.eqlIgnoreCase(s, "jsonDgResult")) return .json_dg_result;
        return .json_d_result;
    }
};

/// 限流阀门。
pub const RateValve = struct {
    policy: Policy = .ip,
    /// 策略键（`header` / `query` / `cookie` / `form` 用）
    policyKey: []const u8 = "",
    /// 窗口内允许次数（0 = 阀门无效）
    limit: u64 = 0,
    /// 窗口时长（秒）
    duration: u64 = 60,
    whenNull: WhenNull = .pass,
    priority: i32 = 0,
    returnType: ReturnType = .json_d_result,

    pub fn ip(limit: u64, duration: u64) RateValve {
        return .{ .policy = .ip, .limit = limit, .duration = duration };
    }

    pub fn userIdentity(limit: u64, duration: u64) RateValve {
        return .{ .policy = .user_identity, .limit = limit, .duration = duration };
    }

    pub fn header(key: []const u8, limit: u64, duration: u64) RateValve {
        return .{ .policy = .header, .policyKey = key, .limit = limit, .duration = duration };
    }

    pub fn query(key: []const u8, limit: u64, duration: u64) RateValve {
        return .{ .policy = .query, .policyKey = key, .limit = limit, .duration = duration };
    }

    pub fn requestPath(limit: u64, duration: u64) RateValve {
        return .{ .policy = .request_path, .limit = limit, .duration = duration };
    }

    pub fn cookie(key: []const u8, limit: u64, duration: u64) RateValve {
        return .{ .policy = .cookie, .policyKey = key, .limit = limit, .duration = duration };
    }

    pub fn form(key: []const u8, limit: u64, duration: u64) RateValve {
        return .{ .policy = .form, .policyKey = key, .limit = limit, .duration = duration };
    }

    /// 有效阀门（次数与时长都必须 > 0）。
    pub fn effective(self: RateValve) bool {
        return self.limit > 0 and self.duration > 0;
    }
};

/// 一条限流规则（「方法 + 路径」）。
pub const ThrottleRule = struct {
    name: []const u8 = "",
    /// 方法（空 / `*` = 任意）
    method: []const u8 = "",
    /// 路径模式（支持 `{param}` 占位与 `*` 尾缀）
    path: []const u8 = "",
    enable: bool = true,
    /// 阀门（**按 priority 降序**；加载/注册时会自动排序）
    valves: []const RateValve = &.{},

    pub fn new(method: []const u8, path: []const u8, valves: []const RateValve) ThrottleRule {
        return .{ .method = method, .path = path, .valves = valves };
    }
};

/// 限流配置（`Config/Throttle.json`）。
pub const ThrottleConfig = struct {
    enable: bool = true,
    keyPrefix: []const u8 = "dh",
    logBlocked: bool = true,
    trustForwardedFor: bool = false,
    skipPaths: []const []const u8 = &.{},
    rules: []const ThrottleRule = &.{},
};

/// 超限详情（**值类型**：不含借用切片，可在 `check` 返回后安全使用）。
pub const LimitInfo = struct {
    name_buf: [96]u8 = @splat(0),
    name_len: usize = 0,
    ip_buf: [46]u8 = @splat(0),
    ip_len: usize = 0,
    policy: Policy = .ip,
    limit: u64 = 0,
    duration: u64 = 0,
    count: u64 = 0,
    reset_in_ms: u64 = 0,
    returnType: ReturnType = .json_d_result,

    pub fn name(self: *const LimitInfo) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    pub fn ipText(self: *const LimitInfo) []const u8 {
        return self.ip_buf[0..self.ip_len];
    }
};

/// 判定结果。
pub const ThrottleVerdict = union(enum) {
    allow,
    limited: LimitInfo,

    pub fn isAllow(self: ThrottleVerdict) bool {
        return self == .allow;
    }
};

const ThrottlePayload = struct {
    cfg: ThrottleConfig,
    rules: []const ThrottleRule = &.{},
};

const Gen = gen.Gen(ThrottlePayload);

/// 限流引擎（线程安全）。
pub const Throttle = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    gen: *Gen,
    gen_lock: zzig.compat.Mutex = .{},
    limiter: ratelimit.WindowLimiter,
    file_path: ?[]const u8 = null,
    user_identity_hook: ?*const fn (*const zzig.web.router.Ctx) ?[]const u8 = null,
    client_ip_hook: ?*const fn (zzig.web.router.Request) []const u8 = null,

    /// 以内存配置构建（规则写在代码里；无文件热重载）。
    pub fn init(gpa: std.mem.Allocator, io: std.Io, cfg: ThrottleConfig) !*Throttle {
        var loaded = try makeLoaded(gpa, cfg);
        defer loaded.deinit();
        return newSelf(gpa, io, &loaded, null);
    }

    /// 从 `{base}/Config/Throttle.json` 加载（不存在则写模板并启用默认策略）。
    pub fn load(gpa: std.mem.Allocator, io: std.Io, base_dir: []const u8) !*Throttle {
        const path = try std.fs.path.join(gpa, &.{ base_dir, CONFIG_REL });
        defer gpa.free(path);

        var loaded = loadFile(io, gpa, path) catch |err| blk: {
            zzig.Logger.warn("[Throttle] 配置加载失败，使用默认（不限流）：{s}", .{@errorName(err)});
            break :blk try makeLoaded(gpa, .{});
        };
        defer loaded.deinit();
        return newSelf(gpa, io, &loaded, path);
    }

    fn newSelf(gpa: std.mem.Allocator, io: std.Io, loaded: *Loaded, file_path: ?[]const u8) !*Throttle {
        const self = try gpa.create(Throttle);
        errdefer gpa.destroy(self);
        const file_copy: ?[]const u8 = if (file_path) |p| try gpa.dupe(u8, p) else null;
        errdefer if (file_copy) |p| gpa.free(p);

        const payload = ThrottlePayload{ .cfg = loaded.config, .rules = loaded.rules };
        const first_gen = try Gen.create(gpa, loaded.take(), payload);
        errdefer first_gen.unref(gpa);

        self.* = .{
            .gpa = gpa,
            .io = io,
            .gen = first_gen,
            .limiter = ratelimit.WindowLimiter.init(gpa),
            .file_path = file_copy,
        };
        return self;
    }

    pub fn deinit(self: *Throttle) void {
        self.gen.unref(self.gpa);
        self.limiter.deinit();
        if (self.file_path) |p| self.gpa.free(p);
        self.gpa.destroy(self);
    }

    /// 自定义「用户身份」取值（默认读 `Ctx.state` 的 `user_id`/`userId`/`userid`/`user`/`username`/`sub`）。
    pub fn setUserIdentity(self: *Throttle, f: *const fn (*const zzig.web.router.Ctx) ?[]const u8) void {
        self.user_identity_hook = f;
    }

    /// 自定义「客户端 IP」取值（默认取 `remote_addr`；开启 `trustForwardedFor` 时取 XFF 末段）。
    pub fn setClientIp(self: *Throttle, f: *const fn (zzig.web.router.Request) []const u8) void {
        self.client_ip_hook = f;
    }

    /// 当前生效配置（面板展示用；切片借用当前代）。
    pub fn currentConfig(self: *Throttle) ThrottleConfig {
        const g = self.acquire();
        defer g.unref(self.gpa);
        return g.payload.cfg;
    }

    /// 手动重载（失败保留旧配置）。
    pub fn reload(self: *Throttle) void {
        const path = self.file_path orelse return;
        var loaded = loadFile(self.io, self.gpa, path) catch |err| {
            zzig.Logger.warn("[Throttle] 配置热重载失败（保留旧配置）：{s}", .{@errorName(err)});
            return;
        };
        defer loaded.deinit();
        const payload = ThrottlePayload{ .cfg = loaded.config, .rules = loaded.rules };
        const g = Gen.create(self.gpa, loaded.take(), payload) catch return;
        const old = self.swap(g);
        old.unref(self.gpa);
        self.limiter.clear();
    }

    fn swap(self: *Throttle, g: *Gen) *Gen {
        self.gen_lock.lock();
        defer self.gen_lock.unlock();
        const old = self.gen;
        self.gen = g;
        return old;
    }

    fn acquire(self: *Throttle) *Gen {
        self.gen_lock.lock();
        defer self.gen_lock.unlock();
        self.gen.ref();
        return self.gen;
    }

    /// 清空计数（改配置后调用）。
    pub fn clearCounters(self: *Throttle) void {
        self.limiter.clear();
    }

    /// 对一次请求判定。
    pub fn check(self: *Throttle, c: *const zzig.web.router.Ctx) ThrottleVerdict {
        const g = self.acquire();
        defer g.unref(self.gpa);
        const cfg = g.payload.cfg;
        if (!cfg.enable) return .allow;
        if (prefixHit(cfg.skipPaths, c.req.path)) return .allow;

        const ip = self.clientIp(c);
        for (g.payload.rules) |*rule| {
            if (!rule.enable) continue;
            if (!ruleMatches(rule, c.req.method, c.req.path)) continue;
            if (self.checkRule(cfg, rule, c, ip)) |info| return .{ .limited = info };
        }
        return .allow;
    }

    fn checkRule(
        self: *Throttle,
        cfg: ThrottleConfig,
        rule: *const ThrottleRule,
        c: *const zzig.web.router.Ctx,
        ip: []const u8,
    ) ?LimitInfo {
        for (rule.valves) |valve| {
            if (!valve.effective()) continue;
            const value = self.effectiveValue(c, valve, ip) orelse continue;

            var key_buf: [512]u8 = undefined;
            const key = std.fmt.bufPrint(&key_buf, "{s}:{s}:{s}:{s}:{s}", .{
                if (cfg.keyPrefix.len == 0) "dh" else cfg.keyPrefix,
                displayRule(rule),
                valve.policy.asKey(),
                valve.policyKey,
                value,
            }) catch continue;

            const d = self.limiter.hit(key, valve.limit, valve.duration * 1000);
            if (d.allowed) continue;

            var info = LimitInfo{
                .policy = valve.policy,
                .limit = valve.limit,
                .duration = valve.duration,
                .count = d.count,
                .reset_in_ms = d.reset_in_ms,
                .returnType = valve.returnType,
            };
            const name = displayRule(rule);
            info.name_len = @min(name.len, info.name_buf.len);
            @memcpy(info.name_buf[0..info.name_len], name[0..info.name_len]);
            info.ip_len = @min(ip.len, info.ip_buf.len);
            @memcpy(info.ip_buf[0..info.ip_len], ip[0..info.ip_len]);

            if (cfg.logBlocked) {
                zzig.Logger.warn("[RateLimiter] 触发限流! API={s} Policy={s} IP={s} Count={d} Limit={d} Duration={d}s", .{
                    info.name(), valve.policy.asKey(), info.ipText(), info.count, info.limit, info.duration,
                });
            }
            return info;
        }
        return null;
    }

    fn clientIp(self: *Throttle, c: *const zzig.web.router.Ctx) []const u8 {
        if (self.client_ip_hook) |f| return f(c.req);
        const peer = wafreq.stripPort(c.req.remote_addr orelse "");
        if (self.trustForwardedFor()) {
            if (c.req.header("x-forwarded-for")) |xff| {
                var last: []const u8 = "";
                var it = std.mem.splitScalar(u8, xff, ',');
                while (it.next()) |seg| {
                    const t = std.mem.trim(u8, seg, " \t");
                    if (t.len > 0) last = t;
                }
                if (last.len > 0) return wafreq.stripPort(last);
            }
        }
        return peer;
    }

    fn trustForwardedFor(self: *Throttle) bool {
        const g = self.acquire();
        defer g.unref(self.gpa);
        return g.payload.cfg.trustForwardedFor;
    }

    fn userIdentity(self: *Throttle, c: *const zzig.web.router.Ctx) ?[]const u8 {
        if (self.user_identity_hook) |f| return f(c);
        const keys = [_][]const u8{ "user_id", "userId", "userid", "user", "username", "sub" };
        for (keys) |k| {
            if (c.stateValue(k)) |v| {
                if (v.len > 0) return v;
            }
        }
        return null;
    }

    fn policyValue(self: *Throttle, c: *const zzig.web.router.Ctx, valve: RateValve, ip: []const u8) ?[]const u8 {
        const v: ?[]const u8 = switch (valve.policy) {
            .ip => if (ip.len > 0) ip else null,
            .user_identity => self.userIdentity(c),
            .header => c.header(valve.policyKey),
            .query => c.queryValue(valve.policyKey),
            .request_path => c.req.path,
            .cookie => cookieValue(c.req, valve.policyKey),
            .form => c.formValue(valve.policyKey),
        };
        if (v) |value| {
            if (value.len > 0) return value;
        }
        return null;
    }

    fn effectiveValue(self: *Throttle, c: *const zzig.web.router.Ctx, valve: RateValve, ip: []const u8) ?[]const u8 {
        if (self.policyValue(c, valve, ip)) |v| return v;
        return switch (valve.whenNull) {
            .pass => null,
            // 空值按客户端 IP 计数（同一来源共用计数；IP 也没有时退化为 unknown）
            .intercept => if (ip.len > 0) ip else "unknown",
        };
    }

    /// 生成超限响应（429 + 对应返回体 + 限流头）。
    pub fn limitedResponse(self: *Throttle, info: LimitInfo, arena: std.mem.Allocator) !zzig.web.router.Response {
        _ = self;
        const message = limit_message;
        var headers_buf: [5]std.http.Header = undefined;
        var n: usize = 0;
        headers_buf[n] = .{ .name = HEADER_STATUS, .value = "0" };
        n += 1;
        headers_buf[n] = .{ .name = "Cache-Control", .value = "no-store" };
        n += 1;
        headers_buf[n] = .{ .name = "X-RateLimit-Remaining", .value = "0" };
        n += 1;
        const retry = try std.fmt.allocPrint(arena, "{d}", .{@max(1, (info.reset_in_ms + 999) / 1000)});
        headers_buf[n] = .{ .name = "Retry-After", .value = retry };
        n += 1;
        const limit_text = try std.fmt.allocPrint(arena, "{d}", .{info.limit});
        headers_buf[n] = .{ .name = "X-RateLimit-Limit", .value = limit_text };
        n += 1;

        const hdrs = try arena.dupe(std.http.Header, headers_buf[0..n]);
        const body = switch (info.returnType) {
            .text => try arena.dupe(u8, message),
            .json_d_result => try std.fmt.allocPrint(arena, "{{\"code\":429,\"msg\":\"{s}\"}}", .{message}),
            .json_dg_result => try std.fmt.allocPrint(arena, "{{\"code\":429,\"errCode\":0,\"message\":\"{s}\",\"data\":null,\"extData\":null}}", .{message}),
        };
        const content_type = switch (info.returnType) {
            .text => "text/plain; charset=utf-8",
            else => "application/json; charset=utf-8",
        };
        return .{ .status = .too_many_requests, .body = body, .content_type = content_type, .headers = hdrs };
    }

    /// 生成 zzig 路由中间件（WAF 放最外层，本中间件放其后）。
    pub fn middleware(self: *Throttle) zzig.web.router.Middleware {
        return .{ .ctx = @ptrCast(self), .call = middlewareInvoke };
    }

    /// 包裹单个路由处理器（规则写在代码里，不必进配置文件）。
    ///
    /// 返回的 `Handler` 内部持有一份规则副本（用 `gpa` 分配），
    /// 不再使用时调用 [`Guard.free`] 释放。
    pub fn guard(self: *Throttle, rule: ThrottleRule, handler: zzig.web.router.Handler) !zzig.web.router.Handler {
        const g = try self.gpa.create(Guard);
        errdefer self.gpa.destroy(g);
        g.* = .{ .throttle = self, .rule = try dupRule(self.gpa, rule), .handler = handler };
        return .{ .ctx = g, .call = guardInvoke };
    }
};

/// `guard` 的上下文。
pub const Guard = struct {
    throttle: *Throttle,
    rule: ThrottleRule,
    handler: zzig.web.router.Handler,

    /// 释放（规则副本归 gpa）。
    pub fn free(self: *Guard) void {
        const gpa = self.throttle.gpa;
        freeRule(gpa, self.rule);
        gpa.destroy(self);
    }
};

fn guardInvoke(ctx: ?*anyopaque, c: *zzig.web.router.Ctx) anyerror!zzig.web.router.Response {
    const g: *Guard = @ptrCast(@alignCast(ctx orelse return error.InvalidGuard));
    const t = g.throttle;
    const payload = t.acquire();
    defer payload.unref(t.gpa);
    const ip = t.clientIp(c);
    if (t.checkRule(payload.payload.cfg, &g.rule, c, ip)) |info| {
        return t.limitedResponse(info, c.arena);
    }
    return g.handler.invoke(c);
}

fn middlewareInvoke(ctx: ?*anyopaque, c: *zzig.web.router.Ctx, next: zzig.web.router.Next) anyerror!zzig.web.router.Response {
    const t: *Throttle = @ptrCast(@alignCast(ctx orelse return error.InvalidMiddleware));
    switch (t.check(c)) {
        .allow => {
            // 放行：状态写进链路状态，供业务/诊断读取（与 Rust 版的请求头同语义）
            try c.setState(HEADER_STATUS, "1");
            return next.run(c);
        },
        .limited => |info| return t.limitedResponse(info, c.arena),
    }
}

fn cookieValue(req: zzig.web.router.Request, name: []const u8) ?[]const u8 {
    const raw = req.header("cookie") orelse return null;
    var it = std.mem.splitScalar(u8, raw, ';');
    while (it.next()) |part| {
        const t = std.mem.trim(u8, part, " \t");
        const eq = std.mem.indexOfScalar(u8, t, '=') orelse continue;
        if (std.ascii.eqlIgnoreCase(t[0..eq], name)) {
            const v = std.mem.trim(u8, t[eq + 1 ..], " \t");
            return if (v.len == 0) null else v;
        }
    }
    return null;
}

fn displayRule(rule: *const ThrottleRule) []const u8 {
    if (rule.name.len > 0) return rule.name;
    // 未命名：用「方法 + 路径」作为标识（借用规则切片，生命周期随配置代）
    return if (rule.path.len > 0) rule.path else rule.method;
}

fn ruleMatches(rule: *const ThrottleRule, method: []const u8, path: []const u8) bool {
    if (rule.method.len > 0 and !std.mem.eql(u8, rule.method, "*")) {
        if (!std.ascii.eqlIgnoreCase(rule.method, method)) return false;
    }
    return pathMatches(rule.path, path);
}

/// 路径模式匹配：支持 `{param}` 占位与 `*` 尾缀通配（其余按字面比较，大小写不敏感）。
pub fn pathMatches(pattern: []const u8, path: []const u8) bool {
    if (pattern.len == 0 or std.mem.eql(u8, pattern, "*")) return true;
    if (std.mem.endsWith(u8, pattern, "*")) {
        const prefix = pattern[0 .. pattern.len - 1];
        return startsWithIgnoreCase(path, prefix);
    }

    var pat_it = std.mem.splitScalar(u8, pattern, '/');
    var path_it = std.mem.splitScalar(u8, path, '/');
    while (true) {
        const p = pat_it.next();
        const q = path_it.next();
        if (p == null and q == null) return true;
        if (p == null or q == null) return false;
        const ps = p.?;
        if (ps.len >= 2 and ps[0] == '{' and ps[ps.len - 1] == '}') {
            if (q.?.len == 0) return false; // 占位段必须有值
            continue;
        }
        if (!std.ascii.eqlIgnoreCase(ps, q.?)) return false;
    }
}

fn startsWithIgnoreCase(hay: []const u8, prefix: []const u8) bool {
    if (prefix.len > hay.len) return false;
    return std.ascii.eqlIgnoreCase(hay[0..prefix.len], prefix);
}

fn prefixHit(prefixes: []const []const u8, path: []const u8) bool {
    for (prefixes) |p| {
        if (p.len > 0 and std.mem.startsWith(u8, path, p)) return true;
    }
    return false;
}

// ————— 配置加载（JSON） —————

const RawValve = struct {
    policy: []const u8 = "ip",
    policyKey: []const u8 = "",
    limit: u64 = 0,
    duration: u64 = 60,
    whenNull: []const u8 = "pass",
    priority: i32 = 0,
    returnType: []const u8 = "jsonDResult",
};

const RawRule = struct {
    name: []const u8 = "",
    method: []const u8 = "",
    path: []const u8 = "",
    enable: bool = true,
    valves: []const RawValve = &.{},
};

const RawConfig = struct {
    enable: bool = true,
    keyPrefix: []const u8 = "dh",
    logBlocked: bool = true,
    trustForwardedFor: bool = false,
    skipPaths: []const []const u8 = &.{},
    rules: []const RawRule = &.{},
};

const Loaded = struct {
    arena: std.heap.ArenaAllocator,
    config: ThrottleConfig,
    rules: []const ThrottleRule,
    moved: bool = false,

    pub fn deinit(self: *Loaded) void {
        if (self.moved) return;
        self.arena.deinit();
    }

    pub fn take(self: *Loaded) std.heap.ArenaAllocator {
        self.moved = true;
        return self.arena;
    }
};

fn makeLoaded(gpa: std.mem.Allocator, cfg: ThrottleConfig) !Loaded {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    var out = ThrottleConfig{
        .enable = cfg.enable,
        .keyPrefix = try a.dupe(u8, cfg.keyPrefix),
        .logBlocked = cfg.logBlocked,
        .trustForwardedFor = cfg.trustForwardedFor,
        .skipPaths = try dupList(a, cfg.skipPaths),
    };
    const rules = try a.alloc(ThrottleRule, cfg.rules.len);
    for (cfg.rules, 0..) |r, i| rules[i] = try dupRule(a, r);
    out.rules = rules;
    return .{ .arena = arena, .config = out, .rules = rules };
}

fn dupList(a: std.mem.Allocator, list: []const []const u8) ![]const []const u8 {
    if (list.len == 0) return &.{};
    const out = try a.alloc([]const u8, list.len);
    for (list, 0..) |item, i| out[i] = try a.dupe(u8, item);
    return out;
}

/// 复制规则（字符串与阀门数组全部深拷到 `a`），并按 priority 降序排列阀门。
pub fn dupRule(a: std.mem.Allocator, rule: ThrottleRule) !ThrottleRule {
    var out = ThrottleRule{
        .name = try a.dupe(u8, rule.name),
        .method = try a.dupe(u8, rule.method),
        .path = try a.dupe(u8, rule.path),
        .enable = rule.enable,
        .valves = &.{},
    };
    const valves = try a.alloc(RateValve, rule.valves.len);
    for (rule.valves, 0..) |v, i| {
        valves[i] = .{
            .policy = v.policy,
            .policyKey = try a.dupe(u8, v.policyKey),
            .limit = v.limit,
            .duration = v.duration,
            .whenNull = v.whenNull,
            .priority = v.priority,
            .returnType = v.returnType,
        };
    }
    sortValves(valves);
    out.valves = valves;
    return out;
}

fn freeRule(gpa: std.mem.Allocator, rule: ThrottleRule) void {
    gpa.free(rule.name);
    gpa.free(rule.method);
    gpa.free(rule.path);
    for (rule.valves) |v| gpa.free(v.policyKey);
    gpa.free(rule.valves);
}

/// 阀门按 priority 降序排序（同优先级保持原有顺序）。
pub fn sortValves(valves: []RateValve) void {
    std.mem.sort(RateValve, valves, {}, struct {
        fn lt(_: void, a: RateValve, b: RateValve) bool {
            return a.priority > b.priority;
        }
    }.lt);
}

fn loadFile(io: std.Io, gpa: std.mem.Allocator, path: []const u8) !Loaded {
    const cwd = std.Io.Dir.cwd();

    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    // 文本**必须**分配在 arena 上：`std.json` 解析出的字符串切片别名到输入文本，
    // 用 gpa 分配再释放会让规则的 name/path 变成悬空指针（实测表现为乱码）。
    const text = cwd.readFileAlloc(io, path, a, .limited(4 * 1024 * 1024)) catch |err| {
        if (err == error.FileNotFound) {
            saveTemplate(io, path) catch {};
            return .{ .arena = arena, .config = .{}, .rules = &.{} };
        }
        return err;
    };

    const raw = std.json.parseFromSliceLeaky(RawConfig, a, text, .{ .ignore_unknown_fields = true }) catch
        return error.InvalidJson;

    var config = ThrottleConfig{
        .enable = raw.enable,
        .keyPrefix = raw.keyPrefix,
        .logBlocked = raw.logBlocked,
        .trustForwardedFor = raw.trustForwardedFor,
        .skipPaths = raw.skipPaths,
    };
    const rules = try a.alloc(ThrottleRule, raw.rules.len);
    for (raw.rules, 0..) |r, i| {
        const valves = try a.alloc(RateValve, r.valves.len);
        for (r.valves, 0..) |v, j| {
            valves[j] = .{
                .policy = Policy.fromKey(v.policy) orelse .ip,
                .policyKey = v.policyKey,
                .limit = v.limit,
                .duration = v.duration,
                .whenNull = if (std.ascii.eqlIgnoreCase(v.whenNull, "intercept")) .intercept else .pass,
                .priority = v.priority,
                .returnType = ReturnType.fromKey(v.returnType),
            };
        }
        sortValves(valves);
        rules[i] = .{
            .name = r.name,
            .method = r.method,
            .path = r.path,
            .enable = r.enable,
            .valves = valves,
        };
    }
    config.rules = rules;
    return .{ .arena = arena, .config = config, .rules = rules };
}

const template_json =
    \\{
    \\  "enable": true,
    \\  "keyPrefix": "dh",
    \\  "logBlocked": true,
    \\  "trustForwardedFor": false,
    \\  "skipPaths": [],
    \\  "rules": []
    \\}
    \\
;

fn saveTemplate(io: std.Io, path: []const u8) !void {
    const dir_path = std.fs.path.dirname(path) orelse ".";
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, dir_path);
    const file = try cwd.createFile(io, path, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, template_json);
}

/// 被拦响应体消息。
const limit_message = "访问过于频繁，请稍后重试！";

// ————— 测试 —————

const testing = std.testing;

fn testThrottle(cfg: ThrottleConfig) !*Throttle {
    return Throttle.init(testing.allocator, testing.io, cfg);
}

fn buildCtx(arena: std.mem.Allocator, method: []const u8, path: []const u8, ip: []const u8, headers: []const std.http.Header) !zzig.web.router.Ctx {
    const req = zzig.web.router.Request{
        .method = method,
        .path = path,
        .query = "",
        .headers = headers,
        .remote_addr = ip,
    };
    return zzig.web.router.Ctx.build(arena, req);
}

test "IP 策略限流与 429 返回体" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const rule = ThrottleRule.new("POST", "/api/auth/login", &.{RateValve.ip(2, 60)});
    const throttle = try testThrottle(.{ .rules = &.{rule} });
    defer throttle.deinit();

    var i: usize = 0;
    while (i < 2) : (i += 1) {
        var c = try buildCtx(a, "POST", "/api/auth/login", "1.2.3.4:5555", &.{});
        defer c.deinit();
        try testing.expect((throttle.check(&c)).isAllow());
    }
    var c = try buildCtx(a, "POST", "/api/auth/login", "1.2.3.4:5555", &.{});
    defer c.deinit();
    const v = throttle.check(&c);
    try testing.expect(!v.isAllow());
    try testing.expectEqual(@as(u64, 2), v.limited.limit);

    const resp = try throttle.limitedResponse(v.limited, a);
    try testing.expectEqual(@as(u16, 429), @backingInt(resp.status));
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"code\":429") != null);
    // 头：Api-Throttle-Status = 0
    var found = false;
    for (resp.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, HEADER_STATUS)) {
            try testing.expectEqualStrings("0", h.value);
            found = true;
        }
    }
    try testing.expect(found);
}

test "方法与路径匹配" {
    try testing.expect(pathMatches("/api/auth/login", "/api/auth/login"));
    try testing.expect(!pathMatches("/api/auth/login", "/api/auth/logout"));
    try testing.expect(pathMatches("/api/cards/{id}", "/api/cards/42"));
    try testing.expect(!pathMatches("/api/cards/{id}", "/api/cards/"));
    try testing.expect(pathMatches("/assets/*", "/assets/app.js"));

    var rule = ThrottleRule.new("POST", "/x", &.{});
    try testing.expect(ruleMatches(&rule, "post", "/x"));
    try testing.expect(!ruleMatches(&rule, "GET", "/x"));
    rule.method = "*";
    try testing.expect(ruleMatches(&rule, "GET", "/x"));
}

test "whenNull：pass 跳过、intercept 按 IP 计数" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var v_pass = RateValve.header("X-Api-Key", 1, 60);
    v_pass.whenNull = .pass;
    var v_int = RateValve.query("token", 1, 60);
    v_int.whenNull = .intercept;

    const rule = ThrottleRule.new("GET", "/api/x", &.{ v_pass, v_int });
    const throttle = try testThrottle(.{ .rules = &.{rule} });
    defer throttle.deinit();

    // 缺值：pass 阀门跳过；intercept 阀门按 IP 计数（第 1 次放行）
    var c = try buildCtx(a, "GET", "/api/x", "5.5.5.5", &.{});
    defer c.deinit();
    try testing.expect((throttle.check(&c)).isAllow());
    // 第 2 次同 IP → intercept 阀门超限
    const v = throttle.check(&c);
    try testing.expect(!v.isAllow());
    try testing.expectEqual(Policy.query, v.limited.policy);
}

test "多阀门按 priority 降序" {
    var valves = [_]RateValve{
        .{ .policy = .ip, .limit = 100, .priority = 1 },
        .{ .policy = .header, .policyKey = "X-Key", .limit = 1, .priority = 2 },
    };
    sortValves(&valves);
    try testing.expectEqual(@as(i32, 2), valves[0].priority);
    try testing.expectEqual(Policy.header, valves[0].policy);
}

test "配置加载与热重载" {
    const gpa = testing.allocator;
    const io = testing.io;
    const cwd = std.Io.Dir.cwd();
    const base = try std.fmt.allocPrint(gpa, ".zig-cache/pek-zwaf-throttle-{d}", .{zzig.compat.nanoTimestamp()});
    defer gpa.free(base);
    defer cwd.deleteTree(io, base) catch {};
    try cwd.createDirPath(io, base);

    const throttle = try Throttle.load(gpa, io, base);
    defer throttle.deinit();
    const cfg = throttle.currentConfig();
    try testing.expect(cfg.enable);
    try testing.expectEqualStrings("dh", cfg.keyPrefix);

    const path = try std.fs.path.join(gpa, &.{ base, CONFIG_REL });
    defer gpa.free(path);
    const json =
        \\{ "enable": true, "rules": [
        \\  { "name": "POST /api/login", "method": "POST", "path": "/api/login",
        \\    "valves": [{ "policy": "ip", "limit": 1, "duration": 60 }] }
        \\] }
    ;
    {
        const f = try cwd.createFile(io, path, .{ .truncate = true });
        defer f.close(io);
        try f.writeStreamingAll(io, json);
    }
    throttle.reload();
    const cfg2 = throttle.currentConfig();
    try testing.expectEqual(@as(usize, 1), cfg2.rules.len);
    try testing.expectEqualStrings("POST /api/login", cfg2.rules[0].name);
}

test "guard 包裹单个处理器" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const throttle = try testThrottle(.{});
    defer throttle.deinit();

    const handler = zzig.web.router.handler(struct {
        fn h(_: *zzig.web.router.Ctx) anyerror!zzig.web.router.Response {
            return .{ .body = "{\"ok\":true}" };
        }
    }.h);
    const wrapped = try throttle.guard(ThrottleRule.new("GET", "/g", &.{RateValve.ip(1, 60)}), handler);
    const g: *Guard = @ptrCast(@alignCast(wrapped.ctx.?));
    defer g.free();

    var c = try buildCtx(a, "GET", "/g", "7.7.7.7", &.{});
    defer c.deinit();
    const first = try wrapped.invoke(&c);
    try testing.expectEqualStrings("{\"ok\":true}", first.body);
    const second = try wrapped.invoke(&c);
    try testing.expectEqual(@as(u16, 429), @backingInt(second.status));
}
