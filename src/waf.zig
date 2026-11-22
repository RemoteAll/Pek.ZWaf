//! WAF 核心：`Waf` 门面（决策链）、zzig 中间件装配、`Config/Waf.toml` 热重载。
//!
//! 检查顺序（首个命中短路，与 Rust `Pek.RWaf` 完全一致）：
//! 1. 可信签名 → 总开关 → 回环豁免 → IP 黑名单 → IP 白名单
//! 2. 自定义拦截 UA → 空 UA → 爬虫分类（恶意拦 / 敏感前缀全禁机器人 / 放行类豁免限速）
//! 3. 攻击特征（SQL 注入 / 路径探测 / 命令注入 / XSS——按各自动作，敏感前缀下 Monitor 升级为 Block）
//! 4. 自定义规则集（命中即拦）
//! 5. CC 限速（每 IP 首次命中起 60 秒窗口；放行类机器人豁免；静态资源不计数）
//!
//! 接入方式：
//! ```zig
//! const waf = try pek_zwaf.Waf.load(gpa, io, base_dir);   // 读 {base}/Config/Waf.toml（首启生成）
//! defer waf.deinit();
//! try router.useMiddleware(waf.middleware());               // 首行注册，全部路由生效
//! ```

const std = @import("std");
const zzig = @import("zzig");

const attack = @import("attack.zig");
const bots = @import("bots.zig");
const config = @import("config.zig");
const clock = @import("clock.zig");
const gen = @import("gen.zig");
const ratelimit = @import("ratelimit.zig");
const rules = @import("rules.zig");
const stats = @import("stats.zig");
const wafreq = @import("wafreq.zig");

const Action = config.Action;
const WafConfig = config.WafConfig;
const WafRequest = wafreq.WafRequest;

/// 热重载检查间隔（毫秒）。
const RELOAD_CHECK_INTERVAL_MS: i64 = 10_000;

/// 判定结果。
pub const Verdict = union(enum) {
    allow,
    blocked: Blocked,

    pub const Blocked = struct {
        /// HTTP 状态码（403 常规拦截 / 429 限速）
        status: u16,
        /// 拦截原因分类（统计用）
        kind: stats.BlockKind,
        /// 原因文本（**只在本次检查的 `Stage` 下次被覆写前有效**）
        reason: []const u8,
    };

    pub fn isAllow(self: Verdict) bool {
        return self == .allow;
    }
};

/// 每请求复用缓冲（跨请求复用时稳态零分配）。
///
/// 生命周期：`Stage` 与 `check` 返回的 `reason` 绑定；**调用方必须保证
/// `check` 期间与日志输出期间 Stage 有效**（中间件里用 `defer deinit` 即可）。
pub const Stage = struct {
    attack_scratch: attack.Scratch = .{},
    reason: std.ArrayList(u8) = .empty,

    pub fn deinit(self: *Stage, allocator: std.mem.Allocator) void {
        self.attack_scratch.deinit(allocator);
        self.reason.deinit(allocator);
    }

    fn setReason(self: *Stage, a: std.mem.Allocator, comptime fmt: []const u8, args: anytype) []const u8 {
        self.reason.clearRetainingCapacity();
        self.reason.print(a, fmt, args) catch return "blocked";
        return self.reason.items;
    }
};

/// 配置负载：热重载时整体替换（由 [`gen.Gen`] 做引用计数）。
const WafPayload = struct {
    cfg: WafConfig,
    compiled: []const rules.Compiled = &.{},
    /// 预编译 IP 名单（精确走 u32 哈希、CIDR 走预解析网段；按 100 万条规模设计）
    ip_allow: wafreq.IpSet = .{},
    ip_block: wafreq.IpSet = .{},
};

/// 配置代（引用计数：检查期间持有，热重载时整体替换）。
const Gen = gen.Gen(WafPayload);

fn makeGen(gpa: std.mem.Allocator, loaded: *config.Loaded) !*Gen {
    const g = try Gen.create(gpa, loaded.take(), .{ .cfg = loaded.config });
    errdefer g.unref(gpa);
    // 名单只在配置期解析一次；arena 随本配置代释放
    const a = g.arena.allocator();
    g.payload.ip_allow = wafreq.IpSet.build(a, loaded.config.ipWhitelist) catch wafreq.IpSet{};
    g.payload.ip_block = wafreq.IpSet.build(a, loaded.config.ipBlacklist) catch wafreq.IpSet{};
    return g;
}

/// 拦截日志去重器：同「IP + 原因」在 1 秒窗口内只放行一条日志。
///
/// 目的：攻击洪峰时每个被拦请求都写一条 warn 会把日志 IO 放大成瓶颈；
/// **计数与统计不受影响**（统计是原子计数，与日志无关）。
const LogThrottle = struct {
    mutex: zzig.compat.Mutex = .{},
    map: std.AutoHashMapUnmanaged(u64, i64) = .empty,

    fn allow(self: *LogThrottle, gpa: std.mem.Allocator, ip: []const u8, reason: []const u8) bool {
        var h = std.hash.Wyhash.init(0);
        h.update(ip);
        h.update(&[1]u8{0});
        h.update(reason);
        const key = h.final();
        const now = clock.nowMillis();

        self.mutex.lock();
        defer self.mutex.unlock();

        // 容量保护：条目过多时清掉 60 秒前的旧记录（Top 攻击源数量有界）
        if (self.map.count() > 512) {
            var it = self.map.iterator();
            var drop: std.ArrayList(u64) = .empty;
            defer drop.deinit(gpa);
            while (it.next()) |kv| {
                if (now - kv.value_ptr.* >= 60_000) drop.append(gpa, kv.key_ptr.*) catch break;
            }
            for (drop.items) |k| _ = self.map.remove(k);
        }
        if (self.map.get(key)) |t| {
            if (now - t < 1000) return false;
        }
        self.map.put(gpa, key, now) catch return true;
        return true;
    }

    fn deinit(self: *LogThrottle, gpa: std.mem.Allocator) void {
        self.map.deinit(gpa);
    }
};

/// `Stage` 有界对象池。
///
/// 为什么需要：中间件每请求都要一份临时缓冲，`var stage = Stage{}` + `deinit`
/// 会让两个 `ArrayList` 次次重新分配/扩容。池化后稳态零系统分配。
///
/// 为什么不用 `threadlocal`：zzig 服务端是 thread-per-connection，线程退出时
/// 堆缓冲不会自动释放，等于每连接泄漏一份；这里用全局锁保护的小池（容量有界）。
const StagePool = struct {
    mutex: zzig.compat.Mutex = .{},
    free: std.ArrayListUnmanaged(*Stage) = .empty,
    max: usize = 64,

    fn acquire(self: *StagePool, gpa: std.mem.Allocator) ?*Stage {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.free.pop()) |s| return s;
        const s = gpa.create(Stage) catch return null;
        s.* = .{};
        return s;
    }

    fn release(self: *StagePool, gpa: std.mem.Allocator, s: *Stage) void {
        self.mutex.lock();
        if (self.free.items.len < self.max) {
            self.free.append(gpa, s) catch {
                self.mutex.unlock();
                s.deinit(gpa);
                gpa.destroy(s);
                return;
            };
            self.mutex.unlock();
            return;
        }
        self.mutex.unlock();
        // 池满：直接释放（不无限缓存）
        s.deinit(gpa);
        gpa.destroy(s);
    }

    fn deinit(self: *StagePool, gpa: std.mem.Allocator) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.free.items) |s| {
            s.deinit(gpa);
            gpa.destroy(s);
        }
        self.free.deinit(gpa);
        self.free = .empty;
    }
};

/// WAF 门面（线程安全）。
pub const Waf = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    io_lock: zzig.compat.Mutex = .{},

    gen: *Gen,
    gen_lock: zzig.compat.Mutex = .{},

    /// 项目基础目录（`base_dir` 的拷贝，`deinit` 释放）
    base_dir: []const u8,
    /// 配置文件路径（`null` = 内存配置，无热重载）
    file_path: ?[]const u8,
    /// 首启/回退预设（调用方保证生命周期 ≥ Waf）
    preset: WafConfig,

    limiter: ratelimit.WindowLimiter,
    stats: stats.WafStats,
    log_throttle: LogThrottle = .{},
    /// 每请求 Stage 复用池（稳态避免 ArrayList 反复分配/扩容）
    stages: StagePool = .{},

    /// 可信业务请求签名密钥（内存态，不落配置文件）
    trusted_secret: ?[]const u8 = null,
    /// 强制跳过机器人拦截的路径前缀（内存态，配置保存不会清掉）
    forced_skip_bot: []const []const u8 = &.{},
    /// 强制跳过攻击特征检测的路径前缀（内存态）
    forced_skip_attack: []const []const u8 = &.{},
    /// 内存态接口级限流规则（优先于配置文件里的 `routeLimits`；面板保存配置不会清掉）。
    forced_route_limits: []const config.RouteLimit = &.{},
    /// 是否在「直连对端是回环」时采纳 `X-Forwarded-For`
    trust_forwarded_for: bool = false,

    last_check_ms: i64 = 0,
    last_mtime_ns: i96 = 0,

    /// 以内存配置构建（无文件热重载）。
    pub fn init(gpa: std.mem.Allocator, io: std.Io, cfg: WafConfig) !*Waf {
        var loaded = try makeLoaded(gpa, cfg);
        defer loaded.deinit();
        const waf_ptr = try newSelf(gpa, io, &loaded, null, cfg);
        errdefer waf_ptr.destroy();
        waf_ptr.compileRules(waf_ptr.gen);
        return waf_ptr;
    }

    /// 从项目基础目录加载 `{base}/Config/Waf.toml`（不存在则按 `adminApi()` 预设生成）。
    pub fn load(gpa: std.mem.Allocator, io: std.Io, base_dir: []const u8) !*Waf {
        return loadWithPreset(gpa, io, base_dir, WafConfig.adminApi());
    }

    /// 同 [`load`]，但首启生成的模板使用指定预设（前台站点用 [`WafConfig.publicSite`]）。
    pub fn loadWithPreset(gpa: std.mem.Allocator, io: std.Io, base_dir: []const u8, preset: WafConfig) !*Waf {
        const path = try std.fs.path.join(gpa, &.{ base_dir, config.CONFIG_REL });
        errdefer gpa.free(path);

        var loaded = config.loadOrCreate(io, gpa, path, preset) catch |err| blk: {
            // 读/解析失败：用预设继续（不静默改用户文件），但要留痕
            zzig.Logger.warn("[WAF] 配置加载失败，使用预设策略：{s}", .{@errorName(err)});
            break :blk try makeLoaded(gpa, preset);
        };
        defer loaded.deinit();

        const waf_ptr = try newSelf(gpa, io, &loaded, path, preset);
        errdefer waf_ptr.destroy();
        waf_ptr.compileRules(waf_ptr.gen);
        return waf_ptr;
    }

    fn makeLoaded(gpa: std.mem.Allocator, cfg: WafConfig) !config.Loaded {
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const cfg_copy = try config.clone(arena.allocator(), cfg);
        return .{ .arena = arena, .config = cfg_copy };
    }

    fn newSelf(gpa: std.mem.Allocator, io: std.Io, loaded: *config.Loaded, file_path: ?[]const u8, preset: WafConfig) !*Waf {
        const self = try gpa.create(Waf);
        errdefer gpa.destroy(self);

        const base_src = if (file_path) |p| std.fs.path.dirname(p) orelse "." else ".";
        const base_dir = try gpa.dupe(u8, base_src);
        errdefer gpa.free(base_dir);
        const file_copy: ?[]const u8 = if (file_path) |p| try gpa.dupe(u8, p) else null;
        errdefer if (file_copy) |p| gpa.free(p);

        // 全部可能失败的分配做完后才移动 arena 所有权
        const first_gen = try makeGen(gpa, loaded);
        errdefer first_gen.unref(gpa);

        self.* = .{
            .gpa = gpa,
            .io = io,
            .gen = first_gen,
            .base_dir = base_dir,
            .file_path = file_copy,
            .preset = preset,
            .limiter = ratelimit.WindowLimiter.init(gpa),
            .stats = stats.WafStats.init(),
        };
        if (self.file_path) |p| self.stampMtime(p);
        return self;
    }

    fn destroy(self: *Waf) void {
        self.gen.unref(self.gpa);
        self.limiter.deinit();
        self.log_throttle.deinit(self.gpa);
        self.stages.deinit(self.gpa);
        if (self.file_path) |p| self.gpa.free(p);
        self.gpa.free(self.base_dir);
        if (self.forced_skip_bot.len > 0) self.gpa.free(self.forced_skip_bot);
        if (self.forced_skip_attack.len > 0) self.gpa.free(self.forced_skip_attack);
        if (self.forced_route_limits.len > 0) self.gpa.free(self.forced_route_limits);
        if (self.trusted_secret) |s| self.gpa.free(s);
        self.gpa.destroy(self);
    }

    pub fn deinit(self: *Waf) void {
        self.destroy();
    }

    fn compileRules(self: *Waf, g: *Gen) void {
        if (g.payload.cfg.rulesetFile.len == 0) return;
        const a = g.arena.allocator();
        const path = if (std.fs.path.isAbsolute(g.payload.cfg.rulesetFile))
            g.payload.cfg.rulesetFile
        else
            std.fs.path.join(a, &.{ self.base_dir, g.payload.cfg.rulesetFile }) catch return;

        var rule = rules.parseFile(self.io, a, path) catch |err| {
            zzig.Logger.warn("[WAF] 规则文件读取/解析失败（本次不启用规则）：{s}（{s}）", .{ path, @errorName(err) });
            return;
        };
        const compiled = rules.compile(a, &rule, self.io, self.base_dir) catch |err| {
            zzig.Logger.warn("[WAF] 规则编译失败（本次不启用规则）：{s}（{s}）", .{ path, @errorName(err) });
            return;
        };
        const list = a.alloc(rules.Compiled, 1) catch return;
        list[0] = compiled;
        g.payload.compiled = list;
    }

    /// 运行统计快照（面板 / `-status` 读取；零磁盘、零网络）。
    pub fn snapshot(self: *Waf) stats.Snapshot {
        return self.stats.snapshot();
    }

    /// 当前生效配置副本（面板展示用；字符串借用当前代，热重载后失效）。
    pub fn currentConfig(self: *Waf) WafConfig {
        const g = self.acquire();
        defer g.unref(self.gpa);
        return g.payload.cfg;
    }

    /// 设置可信业务请求签名密钥（内存态，不写配置文件；空串 = 关闭）。
    pub fn setTrustedSecret(self: *Waf, secret: []const u8) void {
        if (self.trusted_secret) |old| self.gpa.free(old);
        const t = std.mem.trim(u8, secret, " \t\r\n");
        self.trusted_secret = if (t.len == 0) null else (self.gpa.dupe(u8, t) catch null);
    }

    /// 强制跳过机器人拦截的路径前缀（内存态；面板保存配置不会清掉）。
    pub fn setForcedSkipBotPrefixes(self: *Waf, prefixes: []const []const u8) !void {
        const copy = try self.gpa.dupe([]const u8, prefixes);
        if (self.forced_skip_bot.len > 0) self.gpa.free(self.forced_skip_bot);
        self.forced_skip_bot = copy;
    }

    /// 强制跳过攻击特征检测的路径前缀（内存态）。
    pub fn setForcedSkipAttackPrefixes(self: *Waf, prefixes: []const []const u8) !void {
        const copy = try self.gpa.dupe([]const u8, prefixes);
        if (self.forced_skip_attack.len > 0) self.gpa.free(self.forced_skip_attack);
        self.forced_skip_attack = copy;
    }

    /// 强制接口级限流规则（内存态；优先于配置文件的 `routeLimits`）。
    ///
    /// 用 `setForced*` 而不是只写配置：面板保存会把配置写全字段，容易把加固清掉；
    /// 内存态规则让「关键接口限流」始终在位。
    ///
    /// 存入时按 **前缀长度降序**预排序：请求到来时只要命中第一条最长前缀就返回，
    /// 不需要每次遍历全部规则去找「最长前缀」。
    pub fn setForcedRouteLimits(self: *Waf, list: []const config.RouteLimit) !void {
        if (self.forced_route_limits.len > 0) self.gpa.free(self.forced_route_limits);
        self.forced_route_limits = &.{};
        if (list.len == 0) return;
        const copy = try self.gpa.alloc(config.RouteLimit, list.len);
        for (list, 0..) |rule, i| {
            copy[i] = .{
                .prefix = try self.gpa.dupe(u8, rule.prefix),
                .limit = rule.limit,
                .window_ms = rule.window_ms,
            };
        }
        const Less = struct {
            fn less(_: void, a: config.RouteLimit, b: config.RouteLimit) bool {
                return a.prefix.len > b.prefix.len;
            }
        };
        std.mem.sort(config.RouteLimit, copy, {}, Less.less);
        self.forced_route_limits = copy;
    }

    /// 是否在「直连对端是回环」时采纳 `X-Forwarded-For`（内存态）。
    pub fn setTrustForwardedFor(self: *Waf, trust: bool) void {
        self.trust_forwarded_for = trust;
    }

    /// 面板保存入口：写配置文件（有路径时）并立即生效（规则重编译、限速计数清零）。
    pub fn applyConfig(self: *Waf, cfg: WafConfig) !void { // 先落盘（失败即不应用，避免「内存已改、重启丢失」）
        if (self.file_path) |path| try config.save(self.io, self.gpa, path, cfg);

        var loaded = try makeLoaded(self.gpa, cfg);
        defer loaded.deinit();
        const g = try makeGen(self.gpa, &loaded);
        errdefer g.unref(self.gpa);
        self.compileRules(g);

        const old = self.swapGen(g);
        old.unref(self.gpa);
        self.limiter.clear();
        if (self.file_path) |path| self.stampMtime(path);
    }

    /// 手动重载配置与规则（校验失败保留旧配置）。
    pub fn reload(self: *Waf) void {
        const path = self.file_path orelse return;
        var loaded = config.loadExisting(self.io, self.gpa, path, self.preset) catch |err| {
            if (err == error.FileNotFound) {
                // 文件被删除：以当前内存配置重建（预设可能不是库默认值）
                const current = self.currentConfig();
                config.save(self.io, self.gpa, path, current) catch {};
                return;
            }
            zzig.Logger.warn("[WAF] 配置热重载失败（保留旧配置）：{s}", .{@errorName(err)});
            return;
        };
        defer loaded.deinit();

        const g = makeGen(self.gpa, &loaded) catch |err| {
            zzig.Logger.warn("[WAF] 配置热重载失败（保留旧配置）：{s}", .{@errorName(err)});
            return;
        };
        self.compileRules(g);
        const old = self.swapGen(g);
        old.unref(self.gpa);
        self.limiter.clear();
        self.stampMtime(path);
    }

    fn swapGen(self: *Waf, g: *Gen) *Gen {
        self.gen_lock.lock();
        defer self.gen_lock.unlock();
        const old = self.gen;
        self.gen = g;
        return old;
    }

    fn acquire(self: *Waf) *Gen {
        self.gen_lock.lock();
        defer self.gen_lock.unlock();
        self.gen.ref();
        return self.gen;
    }

    fn stampMtime(self: *Waf, path: []const u8) void {
        const st = std.Io.Dir.cwd().statFile(self.io, path, .{}) catch return;
        self.last_mtime_ns = st.mtime.nanoseconds;
        self.last_check_ms = clock.nowMillis();
    }

    fn maybeReload(self: *Waf) void {
        const path = self.file_path orelse return;
        const now = clock.nowMillis();
        if (now - self.last_check_ms < RELOAD_CHECK_INTERVAL_MS) return;
        self.last_check_ms = now;

        const st = std.Io.Dir.cwd().statFile(self.io, path, .{}) catch {
            self.reload();
            return;
        };
        if (st.mtime.nanoseconds == self.last_mtime_ns) return;
        self.reload();
    }

    /// 解析真实客户端 IP：仅当「对端是回环」且开了 `trustForwardedFor` 时采纳 XFF，
    /// 且取**最后一跳**（末段）——首段完全由客户端控制，取首段等于允许伪造 IP
    /// 绕过黑名单/限流（与 `dhrust::net::panel_auth::client_ip_behind_proxy` 同口径）。
    pub fn resolveClientIp(self: *Waf, peer: []const u8, xff: ?[]const u8) []const u8 {
        const peer_ip = wafreq.stripPort(peer);
        if (!self.trust_forwarded_for or !wafreq.isLoopback(peer_ip)) return peer_ip;
        const raw = xff orelse return peer_ip;
        var last: []const u8 = "";
        var it = std.mem.splitScalar(u8, raw, ',');
        while (it.next()) |seg| {
            const t = std.mem.trim(u8, seg, " \t");
            if (t.len > 0) last = t;
        }
        if (last.len == 0) return peer_ip;
        const ip = wafreq.stripPort(last);
        return if (ip.len == 0) peer_ip else ip;
    }

    /// 请求是否带当前可信业务签名（`TimeStamp` / `Nonce` / `Signature` 三头）。
    fn trustedSigned(self: *Waf, headers: []const std.http.Header) bool {
        const secret = self.trusted_secret orelse return false;

        // 一次遍历取三个头（原来三次 headerOf，等于扫三遍 header 列表）
        var timestamp: []const u8 = "";
        var nonce: []const u8 = "";
        var signature: []const u8 = "";
        for (headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "TimeStamp")) {
                timestamp = std.mem.trim(u8, h.value, " \t");
            } else if (std.ascii.eqlIgnoreCase(h.name, "Nonce")) {
                nonce = std.mem.trim(u8, h.value, " \t");
            } else if (std.ascii.eqlIgnoreCase(h.name, "Signature")) {
                signature = std.mem.trim(u8, h.value, " \t");
            }
        }
        if (timestamp.len == 0 or nonce.len == 0 or signature.len == 0) return false;

        // 与 C# / dhrust 一致：三段升序排列后拼接，SHA1，小写 hex
        var parts = [3][]const u8{ timestamp, nonce, secret };
        std.mem.sort([]const u8, &parts, {}, struct {
            fn lt(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.lt);
        var hasher = std.crypto.hash.Sha1.init(.{});
        for (parts) |p| hasher.update(p);
        var digest: [20]u8 = undefined;
        hasher.final(&digest);
        var expected: [40]u8 = undefined;
        expected = std.fmt.bytesToHex(digest, .lower);

        // 等长常量时间比较（复用 zzig 实现，不再手写一份）
        return zzig.hash.constantTimeEql(expected[0..], signature);
    }

    // ————— 对外检查入口 —————

    /// 完整检查一个 zzig 路由请求（中间件内部用；`Ctx` 已解析查询串与表单）。
    pub fn checkCtx(self: *Waf, c: *const zzig.web.router.Ctx, stage: *Stage) Verdict {
        return self.checkRouteRequest(c.req, stage);
    }

    /// 完整检查一个 zzig 路由请求（不带 `Ctx` 的调用方用）。
    ///
    /// 全程只持有**一**份配置代（引用计数），因此热重载并发时不会读到悬空切片。
    pub fn checkRouteRequest(self: *Waf, req: zzig.web.router.Request, stage: *Stage) Verdict {
        self.maybeReload();
        const g = self.acquire();
        defer g.unref(self.gpa);
        const cfg = g.payload.cfg;

        // 可信签名最优先：已签名请求不因 UA/特征被误拦（业务层仍会验时间窗/重放/权限）
        if (self.trustedSigned(req.headers)) return .allow;

        var view = WafRequest.fromRouterRequest(req);
        view.remote_ip = self.resolveClientIp(req.remote_addr orelse "", req.header("x-forwarded-for"));

        // 跨站来源校验（CSRF）先于回环豁免：浏览器跨站请求的源 IP 恰是回环
        if (cfg.enable and cfg.csrfGuard) {
            if (csrfReason(view.method, req.header("sec-fetch-site") orelse "", req.header("origin") orelse "", req.header("host") orelse "")) |reason| {
                return self.blockedWith(g, &view, stage, 403, .csrf, "{s}", .{reason});
            }
        }

        // body 预览：只扫文本类（或配置强制全类型），且只取前 N 字节
        // 无 body 的请求（GET/HEAD 等）不必查 Content-Type
        if (req.body.len > 0 and !self.skipsAttack(&cfg, view.path)) {
            const is_text = wafreq.isTextContentType(view.content_type);
            if (cfg.bodyScanAllTypes or is_text) {
                view = view.withBodyPreview(req.body, cfg.bodyLimit());
            }
        }
        return self.decide(g, &view, stage, true);
    }

    /// **头阶段**检查（还没读 body 时调）：与完整检查同规则，但
    /// - **不**累加请求总数（避免「早拒放行 → 路由层完整检查」重复计数）；
    /// - **拦截时补记一次总数**：该请求不会再进路由层，不记就无法算拦截率
    ///   （demo 实测曾有 `blockedRatio = 1.5` 的口径缺陷）；
    /// - 只能看路径 / 查询串 / UA / IP / 头（`body_text` 为空）。
    ///
    /// 挂到 HTTP 层早拒钩子后，UA / IP / 路径 / 查询串命中特征时可以**不收 body 就拒绝**。
    pub fn checkHead(self: *Waf, head: HeadInput, stage: *Stage) Verdict {
        self.maybeReload();
        const g = self.acquire();
        defer g.unref(self.gpa);
        const cfg = g.payload.cfg;

        if (self.trustedSigned(head.headers)) return .allow;

        const view = WafRequest{
            .path = head.path,
            .method = head.method,
            .query = head.query,
            .user_agent = headerOf(head.headers, "user-agent") orelse "",
            .remote_ip = self.resolveClientIp(head.remote_addr orelse "", headerOf(head.headers, "x-forwarded-for")),
            .content_type = headerOf(head.headers, "content-type") orelse "",
            .headers = head.headers,
        };

        const verdict = blk: {
            if (cfg.enable and cfg.csrfGuard) {
                if (csrfReason(view.method, headerOf(head.headers, "sec-fetch-site") orelse "", headerOf(head.headers, "origin") orelse "", headerOf(head.headers, "host") orelse "")) |reason| {
                    break :blk self.blockedWith(g, &view, stage, 403, .csrf, "{s}", .{reason});
                }
            }
            break :blk self.decide(g, &view, stage, false);
        };
        if (!verdict.isAllow()) self.stats.recordRequest();
        return verdict;
    }

    /// 便捷：从 zzig HTTP 服务端请求视图做头阶段检查。
    ///
    /// `zzig` 的 `RequestView.remote_addr` 已是**纯 IP**（如果是反代场景，已被 `trust_forwarded_for`
    /// 换成了真实客户端 IP），所以 IP 名单 / CC 限速 / 回环豁免在这一层同样生效。
    pub fn checkHeadView(self: *Waf, view: zzig.http_server.RequestView, stage: *Stage) Verdict {
        return self.checkHead(.{
            .method = @tagName(view.method),
            .path = view.path,
            .query = view.query,
            .headers = view.headers,
            .remote_addr = view.remote_addr,
        }, stage);
    }

    fn skipsAttack(self: *Waf, cfg: *const WafConfig, path: []const u8) bool {
        if (matchesAnyPrefix(cfg.skipAttackPrefixes, path)) return true;
        return matchesAnyPrefix(self.forced_skip_attack, path);
    }

    fn skipsBot(self: *Waf, cfg: *const WafConfig, path: []const u8) bool {
        if (matchesAnyPrefix(cfg.skipBotPrefixes, path)) return true;
        return matchesAnyPrefix(self.forced_skip_bot, path);
    }

    /// 便捷入口（测试/内部）：自带引用计数。
    fn run(self: *Waf, req: *const WafRequest, stage: *Stage, count_request: bool) Verdict {
        if (count_request) self.maybeReload();
        const g = self.acquire();
        defer g.unref(self.gpa);
        return self.decide(g, req, stage, count_request);
    }

    /// 决策链（`count_request` = false 表示头阶段，不累加请求总数）。
    fn decide(self: *Waf, g: *const Gen, req: *const WafRequest, stage: *Stage, count_request: bool) Verdict {
        const cfg = g.payload.cfg;

        if (count_request) self.stats.recordRequest();
        if (!cfg.enable) return .allow;

        const ip = std.mem.trim(u8, req.remote_ip, " \t");

        // —— 回环豁免（保护本地工具/冒烟脚本）——
        if (cfg.loopbackBypass and wafreq.isLoopback(ip)) return .allow;

        // —— IP 白名单（显式信任，优先于一切）→ IP 黑名单 ——
        // 名单在配置代里已预编译：匹配只解析请求 IP 一次，不再逐条解析规则字符串。
        if (!g.payload.ip_allow.isEmpty() and g.payload.ip_allow.matches(ip)) return .allow;
        if (g.payload.ip_block.matches(ip)) {
            return self.blockedWith(g, req, stage, 403, .ip, "IP 黑名单：{s}", .{ip});
        }

        const ua = std.mem.trim(u8, req.user_agent, " \t\r\n");

        // —— 自定义 UA 规则 ——
        for (cfg.extraBlockBots) |k| {
            if (wafreq.containsIgnoreCase(ua, std.mem.trim(u8, k, " \t\r\n"))) {
                return self.blockedWith(g, req, stage, 403, .rule, "自定义拦截 UA", .{});
            }
        }
        if (cfg.blockEmptyUa and ua.len == 0) {
            return self.blockedWith(g, req, stage, 403, .rule, "空 User-Agent", .{});
        }
        var extra_allowed = false;
        for (cfg.extraAllowBots) |k| {
            if (wafreq.containsIgnoreCase(ua, std.mem.trim(u8, k, " \t\r\n"))) {
                extra_allowed = true;
                break;
            }
        }

        const sensitive = matchesAnyPrefix(cfg.sensitivePrefixes, req.path);
        const skip_bot = self.skipsBot(&cfg, req.path);

        // —— 爬虫分类 ——
        var friendly_bot = false;
        if (!extra_allowed and !skip_bot) {
            if (bots.classifyCached(req.user_agent)) |kind| {
                switch (kind) {
                    .malicious => {
                        if (cfg.blockMaliciousBots) {
                            var buf: [96]u8 = undefined;
                            return self.blockedWith(g, req, stage, 403, .bot, "恶意爬虫/扫描器：{s}", .{brief(&buf, req.user_agent)});
                        }
                    },
                    .search_engine, .ai_crawler, .social_preview => {
                        if (sensitive) {
                            return self.blockedWith(g, req, stage, 403, .bot, "敏感路径禁止机器人（{s}）", .{kind.nameCn()});
                        }
                        const allowed = switch (kind) {
                            .search_engine => cfg.allowSearchBots,
                            .ai_crawler => cfg.allowAiBots,
                            else => cfg.allowSocialPreviews,
                        };
                        if (allowed) {
                            friendly_bot = true;
                            if (cfg.verbose) {
                                var buf: [96]u8 = undefined;
                                zzig.Logger.info("[WAF] 放行 {s}：{s} {s}（{s}）", .{ kind.nameCn(), req.method, req.path, brief(&buf, req.user_agent) });
                            }
                        } else {
                            return self.blockedWith(g, req, stage, 403, .bot, "未放行的机器人：{s}", .{kind.nameCn()});
                        }
                    },
                    .monitor, .unknown => {
                        if (sensitive) {
                            return self.blockedWith(g, req, stage, 403, .bot, "敏感路径禁止机器人（{s}）", .{kind.nameCn()});
                        }
                        if (cfg.verbose) {
                            var buf: [96]u8 = undefined;
                            zzig.Logger.info("[WAF] {s}：{s} {s}（{s}）", .{ kind.nameCn(), req.method, req.path, brief(&buf, req.user_agent) });
                        }
                    },
                }
            }
        }

        // —— 攻击特征 ——
        if (!self.skipsAttack(&cfg, req.path)) {
            const is_static = wafreq.isStaticAsset(req.path);
            // 动作 `off` 的类别不参与扫描（旧实现无条件全扫，`off` 只是不拦，白扫 82 条）
            var mask: u8 = 0;
            if (cfg.path() != .off) mask |= attack.K_PATH;
            if (!is_static) {
                if (cfg.sqli() != .off) mask |= attack.K_SQLI;
                if (cfg.cmd() != .off) mask |= attack.K_CMD;
                if (cfg.xss() != .off) mask |= attack.K_XSS;
            }

            if (mask != 0) {
                const parts: []const []const u8 = if (is_static or req.body_text.len == 0)
                    &.{ req.path, "?", req.query }
                else
                    &.{ req.path, "?", req.query, " ", req.body_text };
                const bits = attack.scanBitsWith(self.gpa, &stage.attack_scratch, parts, mask) catch 0;

                var kinds: [4]attack.AttackKind = undefined;
                const n = attack.kindsFromBits(bits, &kinds);
                for (kinds[0..n]) |kind| {
                    var action: Action = switch (kind) {
                        .sqli => cfg.sqli(),
                        .xss => cfg.xss(),
                        .path => cfg.path(),
                        .cmd => cfg.cmd(),
                    };
                    if (sensitive and action == .monitor) action = .block;
                    switch (action) {
                        .off => {},
                        .monitor => {
                            if (cfg.verbose) {
                                zzig.Logger.info("[WAF] 监控命中 {s}：{s} {s}", .{ kind.nameCn(), req.method, req.path });
                            }
                        },
                        .block => {
                            const block_kind: stats.BlockKind = switch (kind) {
                                .sqli => .sqli,
                                .xss => .xss,
                                .path => .path,
                                .cmd => .cmd,
                            };
                            var buf: [96]u8 = undefined;
                            return self.blockedWith(g, req, stage, 403, block_kind, "{s} 特征：{s}", .{ kind.nameCn(), brief(&buf, req.path) });
                        },
                    }
                }
            }
        }

        // —— 自定义规则集（命中即拦）——
        for (g.payload.compiled) |*rule| {
            if (rules.eval(rule, req)) {
                var label_buf: [256]u8 = undefined;
                var fba = std.heap.FixedBufferAllocator.init(&label_buf);
                const label = rules.label(rule, fba.allocator());
                return self.blockedWith(g, req, stage, 403, .rule, "自定义规则：{s}", .{label});
            }
        }

        // —— CC 限速（放行类机器人豁免；静态资源不计数）——
        // 客户端 IP 未知时**不计数**：否则所有未知来源共用一个桶，一个客户端就能把全站配额打满
        // （zzig `http_server` 的请求视图目前不带对端地址，走 `App` 集成时会遇到这种情况）。
        if (cfg.rateLimitPerMin > 0 and ip.len > 0 and !friendly_bot and !wafreq.isStaticAsset(req.path)) {
            const d = self.limiter.hit(ip, cfg.rateLimitPerMin, 60_000);
            if (!d.allowed) {
                return self.blockedWith(g, req, stage, 429, .cc, "请求频率超限（{d} 次/分钟）", .{cfg.rateLimitPerMin});
            }
        }

        // —— 接口级限流（按 IP + 路由前缀；对齐 C# `[RateValve(Policy = Policy.Ip, Limit, Duration)]`）——
        // 与上面的全站 CC 互补：这里可以给单个接口定更严的阀值（登录 10 次/分、校验 20 次/分……）。
        // 内存态 `forcedRouteLimits` 优先于配置文件；多规则命中时**最长前缀优先**
        // （`/api/client-ip/check` 的规则先于 `/api/client-ip` 生效）。
        if (count_request and ip.len > 0 and !wafreq.isStaticAsset(req.path)) {
            if (self.checkRouteLimit(&cfg, ip, req.path)) |rule| {
                return self.blockedWith(
                    g,
                    req,
                    stage,
                    429,
                    .route_rate,
                    "接口请求频率超限（{s} 每 {d} 秒 {d} 次）",
                    .{ rule.prefix, rule.window_ms / 1000, rule.limit },
                );
            }
        }

        return .allow;
    }

    /// 接口级限流：内存态规则优先于配置文件规则；命中且超限时返回该规则（用于生成 429 文案）。
    fn checkRouteLimit(self: *Waf, cfg: *const config.WafConfig, ip: []const u8, path: []const u8) ?config.RouteLimit {
        const rule = pickRouteLimit(self.forced_route_limits, path) orelse
            pickRouteLimit(cfg.routeLimits, path) orelse return null;
        var key_buf: [512]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "{s}|{s}", .{ ip, rule.prefix }) catch ip;
        const d = self.limiter.hit(key, rule.limit, rule.window_ms);
        return if (d.allowed) null else rule;
    }

    /// 在规则集里挑一条（规则已按前缀长度**降序**存好：首个命中即最长前缀，O(1) 典型）。
    fn pickRouteLimit(list: []const config.RouteLimit, path: []const u8) ?config.RouteLimit {
        for (list) |rule| {
            if (rule.limit == 0 or rule.prefix.len == 0) continue;
            if (std.mem.startsWith(u8, path, rule.prefix)) return rule;
        }
        return null;
    }

    fn blockedWith(
        self: *Waf,
        g: *const Gen,
        req: *const WafRequest,
        stage: *Stage,
        status: u16,
        kind: stats.BlockKind,
        comptime fmt: []const u8,
        args: anytype,
    ) Verdict {
        const reason = stage.setReason(self.gpa, fmt, args);
        self.stats.recordBlock(kind, req.remote_ip);

        if (g.payload.cfg.logBlocked and self.log_throttle.allow(self.gpa, req.remote_ip, reason)) {
            var ua_buf: [96]u8 = undefined;
            zzig.Logger.warn("[WAF] 拦截 {s} {s} 状态={d} IP={s} UA={s} 原因={s}", .{
                req.method,
                req.path,
                status,
                req.remote_ip,
                brief(&ua_buf, req.user_agent),
                reason,
            });
        }
        return .{ .blocked = .{ .status = status, .kind = kind, .reason = reason } };
    }

    /// 生成 zzig 路由中间件（`router.useMiddleware(waf.middleware())`）。
    pub fn middleware(self: *Waf) zzig.web.router.Middleware {
        return .{ .ctx = @ptrCast(self), .call = middlewareInvoke };
    }
};

/// 头阶段输入（早拒钩子用；`remote_addr` 可为空）。
pub const HeadInput = struct {
    method: []const u8 = "GET",
    path: []const u8 = "/",
    query: []const u8 = "",
    headers: []const std.http.Header = &.{},
    remote_addr: ?[]const u8 = null,
};

/// HTTP 层早拒包装（对齐 Rust 版 `HttpServerOptions.early_guard`）。
///
/// 为什么需要：**路由中间件只对「已匹配的路由」生效**——`/.env`、`/wp-login.php` 这类
/// 路径探测请求会直接 404，压根进不了 WAF。把本包装挂到 `http_server.Server.handler`
/// 之后，UA / 路径 / 查询串 / CSRF 命中时会**在读取业务请求体之前**就拒绝。
///
/// 用法：
/// ```zig
/// var srv = app.makeServer(.{});
/// var guard = pek_zwaf.waf.ServerGuard.init(waf, srv.ctx, srv.handler);
/// defer guard.deinit(gpa);
/// guard.install(&srv);
/// try srv.run("127.0.0.1", 8080);
/// ```
///
/// 局限：`http_server.RequestView` 不带对端地址，因此 IP 名单 / CC 限速在这一层不生效，
/// 由路由中间件（完整检查）补齐；请求体级规则同理。
pub const ServerGuard = struct {
    waf: *Waf,
    inner_ctx: *anyopaque,
    inner: zzig.http_server.HandlerFn,

    pub fn init(waf: *Waf, inner_ctx: *anyopaque, inner: zzig.http_server.HandlerFn) ServerGuard {
        return .{ .waf = waf, .inner_ctx = inner_ctx, .inner = inner };
    }

    pub fn deinit(self: *ServerGuard, gpa: std.mem.Allocator) void {
        _ = self;
        _ = gpa;
    }

    /// 把自己装进 zzig HTTP 服务端（替换 ctx/handler）。
    pub fn install(self: *ServerGuard, srv: *zzig.http_server.Server) void {
        srv.ctx = @ptrCast(self);
        srv.handler = invoke;
    }

    fn invoke(raw: *anyopaque, req: zzig.http_server.RequestView, arena: std.mem.Allocator) anyerror!zzig.http_server.Reply {
        const self: *ServerGuard = @ptrCast(@alignCast(raw));
        // 池化复用（分配失败时降级为栈上 Stage，不影响拦截）
        const stage = self.waf.stages.acquire(self.waf.gpa) orelse return self.invokeWith(req, arena, null);
        defer self.waf.stages.release(self.waf.gpa, stage);
        return self.invokeWith(req, arena, stage);
    }

    fn invokeWith(self: *ServerGuard, req: zzig.http_server.RequestView, arena: std.mem.Allocator, pooled: ?*Stage) anyerror!zzig.http_server.Reply {
        var local = Stage{};
        const stage: *Stage = blk: {
            if (pooled) |s| break :blk s;
            break :blk &local;
        };
        defer if (pooled == null) local.deinit(self.waf.gpa);

        switch (self.waf.checkHeadView(req, stage)) {
            .allow => return self.inner(self.inner_ctx, req, arena),
            .blocked => |b| {
                const status: std.http.Status = if (b.status == 429) .too_many_requests else .forbidden;
                return .{
                    .status = status,
                    .body = if (b.status == 429) "请求过于频繁，请稍后再试" else "请求被安全策略拦截",
                    .content_type = "text/plain; charset=utf-8",
                    .headers = if (b.status == 429) &limited_headers else &blocked_headers,
                };
            },
        }
    }
};

/// 被拦响应的固定头（静态存储：响应可能在中间件返回后才被发送）。
const blocked_headers = [_]std.http.Header{
    .{ .name = "X-WAF-Blocked", .value = "1" },
    .{ .name = "Cache-Control", .value = "no-store" },
};
const limited_headers = [_]std.http.Header{
    .{ .name = "X-WAF-Blocked", .value = "1" },
    .{ .name = "Cache-Control", .value = "no-store" },
    .{ .name = "Retry-After", .value = "60" },
};

fn middlewareInvoke(
    ctx: ?*anyopaque,
    c: *zzig.web.router.Ctx,
    next: zzig.web.router.Next,
) anyerror!zzig.web.router.Response {
    const waf: *Waf = @ptrCast(@alignCast(ctx orelse return error.InvalidMiddleware));
    // 池化复用（分配失败时降级为栈上 Stage，不影响拦截）
    const stage = waf.stages.acquire(waf.gpa) orelse return middlewareWith(waf, c, next, null);
    defer waf.stages.release(waf.gpa, stage);
    return middlewareWith(waf, c, next, stage);
}

fn middlewareWith(
    waf: *Waf,
    c: *zzig.web.router.Ctx,
    next: zzig.web.router.Next,
    pooled: ?*Stage,
) anyerror!zzig.web.router.Response {
    var local = Stage{};
    const stage: *Stage = blk: {
        if (pooled) |s| break :blk s;
        break :blk &local;
    };
    defer if (pooled == null) local.deinit(waf.gpa);

    switch (waf.checkCtx(c, stage)) {
        .allow => return next.run(c),
        .blocked => |b| {
            if (b.status == 429) {
                return .{
                    .status = .too_many_requests,
                    .body = "请求过于频繁，请稍后再试",
                    .content_type = "text/plain; charset=utf-8",
                    .headers = &limited_headers,
                };
            }
            return .{
                .status = .forbidden,
                .body = "请求被安全策略拦截",
                .content_type = "text/plain; charset=utf-8",
                .headers = &blocked_headers,
            };
        },
    }
}

fn headerOf(headers: []const std.http.Header, name: []const u8) ?[]const u8 {
    // 单一实现：转调 `wafreq.headerOf`（本文件曾与它各写一份遍历）
    return wafreq.headerOf(headers, name);
}

fn matchesAnyPrefix(prefixes: []const []const u8, path: []const u8) bool {
    for (prefixes) |p| {
        if (p.len > 0 and std.mem.startsWith(u8, path, p)) return true;
    }
    return false;
}

/// UTF-8 安全截断（日志用：80 字节上限，回退到字符边界）。
fn brief(buf: []u8, s: []const u8) []const u8 {
    const limit = @min(80, buf.len);
    if (s.len <= limit) return s;
    var end = limit;
    while (end > 0 and (s[end] & 0xC0) == 0x80) end -= 1;
    @memcpy(buf[0..end], s[0..end]);
    return buf[0..end];
}

/// 跨站来源校验（CSRF）：返回拦截原因（`null` = 放行）。
///
/// 判定顺序（仅非安全方法）：
/// 1. `Sec-Fetch-Site: cross-site` → 拒绝（现代浏览器）；
/// 2. 无 Sec-Fetch-Site 但有 `Origin`：与请求 `Host` 同源才放行（`null` 视作跨站拒绝）；
/// 3. 两类头均无（curl / 服务间调用）→ 放行。
pub fn csrfReason(method: []const u8, sec_fetch_site: []const u8, origin: []const u8, host: []const u8) ?[]const u8 {
    if (!(std.ascii.eqlIgnoreCase(method, "POST") or
        std.ascii.eqlIgnoreCase(method, "PUT") or
        std.ascii.eqlIgnoreCase(method, "PATCH") or
        std.ascii.eqlIgnoreCase(method, "DELETE"))) return null;

    const site = std.mem.trim(u8, sec_fetch_site, " \t");
    if (site.len > 0) {
        return if (std.ascii.eqlIgnoreCase(site, "cross-site")) "跨站请求（Sec-Fetch-Site: cross-site）" else null;
    }

    const o = std.mem.trim(u8, origin, " \t");
    if (o.len == 0) return null;
    if (std.ascii.eqlIgnoreCase(o, "null")) return "跨站来源（Origin: null——file:// 或沙盒页面）";

    const h = std.mem.trim(u8, host, " \t");
    const origin_host = if (std.mem.indexOf(u8, o, "://")) |i| o[i + 3 ..] else o;
    if (h.len > 0 and !std.ascii.eqlIgnoreCase(origin_host, h)) {
        return "跨站来源（Origin 与 Host 不一致）";
    }
    return null;
}

// ————— 测试 —————

const testing = std.testing;

fn testWaf(arena: *std.heap.ArenaAllocator, cfg: WafConfig) !*Waf {
    return Waf.init(arena.allocator(), testing.io, cfg);
}

fn reqOf(path: []const u8, ua: []const u8, ip: []const u8) WafRequest {
    return .{ .path = path, .method = "GET", .user_agent = ua, .remote_ip = ip };
}

test "管理端默认从严：恶意爬虫拦、普通浏览器放" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const waf = try testWaf(&arena, WafConfig.adminApi());
    defer waf.deinit();

    var stage = Stage{};
    defer stage.deinit(waf.gpa);

    var r = reqOf("/api/x", "sqlmap/1.7", "8.8.8.8");
    try testing.expect(waf.run(&r, &stage, false).isAllow() == false);

    r = reqOf("/api/x", "Mozilla/5.0 (Windows NT 10.0) Chrome/126", "8.8.8.8");
    try testing.expect(waf.run(&r, &stage, false).isAllow());
}

test "回环豁免与 IP 名单优先级" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var cfg = WafConfig.adminApi();
    cfg.ipBlacklist = &.{"8.8.8.8"};
    cfg.ipWhitelist = &.{"10.0.0.0/8"};
    const waf = try testWaf(&arena, cfg);
    defer waf.deinit();

    var stage = Stage{};
    defer stage.deinit(waf.gpa);

    // 回环豁免优先
    try testing.expect(waf.run(&reqOf("/x", "sqlmap/1.7", "127.0.0.1"), &stage, false).isAllow());
    // 白名单优先于黑名单/检查
    try testing.expect(waf.run(&reqOf("/x", "sqlmap/1.7", "10.1.2.3"), &stage, false).isAllow());
    // 黑名单命中
    const v = waf.run(&reqOf("/x", "Mozilla/5.0", "8.8.8.8"), &stage, false);
    try testing.expect(!v.isAllow());
    try testing.expectEqual(@as(u16, 403), v.blocked.status);
}

test "攻击特征拦截与敏感前缀升级" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var cfg = WafConfig.publicSite();
    cfg.xssAction = "monitor";
    const waf = try testWaf(&arena, cfg);
    defer waf.deinit();

    var stage = Stage{};
    defer stage.deinit(waf.gpa);

    // SQL 注入默认拦截
    var r = WafRequest{ .path = "/cards", .method = "GET", .query = "q=1' or 1=1--", .user_agent = "Mozilla/5.0", .remote_ip = "8.8.8.8" };
    try testing.expect(!waf.run(&r, &stage, false).isAllow());

    // XSS 在公开站点是 monitor → 放行
    r = WafRequest{ .path = "/cards", .method = "GET", .query = "q=<script>alert(1)</script>", .user_agent = "Mozilla/5.0", .remote_ip = "8.8.8.8" };
    try testing.expect(waf.run(&r, &stage, false).isAllow());

    // 但 /admin 敏感前缀下 monitor 升级为 block
    r.path = "/admin/cards";
    try testing.expect(!waf.run(&r, &stage, false).isAllow());
}

test "跳过前缀：bot 与攻击检测各自独立" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var cfg = WafConfig.adminApi();
    cfg.skipBotPrefixes = &.{"/api"};
    const waf = try testWaf(&arena, cfg);
    defer waf.deinit();

    var stage = Stage{};
    defer stage.deinit(waf.gpa);

    // /api 下脚本 UA 不再被当扫描器
    try testing.expect(waf.run(&reqOf("/api/x", "python-requests/2.31", "8.8.8.8"), &stage, false).isAllow());
    // 但攻击特征仍然生效
    var r = WafRequest{ .path = "/api/x", .method = "GET", .query = "q=1 union select 1", .user_agent = "python-requests/2.31", .remote_ip = "8.8.8.8" };
    try testing.expect(!waf.run(&r, &stage, false).isAllow());

    // 强制豁免（内存态）同样生效
    try waf.setForcedSkipBotPrefixes(&.{"/api"});
    try testing.expect(waf.run(&reqOf("/api/y", "curl/8.0", "8.8.8.8"), &stage, false).isAllow());
}

test "接口级限流：按 IP + 路由前缀（最长前缀优先），超限 429" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var cfg = WafConfig.adminApi();
    cfg.rateLimitPerMin = 0; // 关掉全站 CC，单独验证接口级
    cfg.routeLimits = &.{
        // 注意顺序：`pickRouteLimit` 依赖「前缀长度降序」（配置文件解析时已排好；
        // 代码里手工构造时也要按降序写）
        .{ .prefix = "/api/client-ip/check", .limit = 2, .window_ms = 60_000 },
        .{ .prefix = "/api/client-ip", .limit = 10, .window_ms = 60_000 },
    };
    const waf = try testWaf(&arena, cfg);
    defer waf.deinit();

    var stage = Stage{};
    defer stage.deinit(waf.gpa);

    // `/api/client-ip/check` 命中更严的 2 次/分（最长前缀优先）。
    // 第三参数 `true` = 请求层（会计数）；头阶段调用传 `false`，限流**不在那一层计数**（避免双计）。
    try testing.expect(waf.run(&reqOf("/api/client-ip/check", "Mozilla/5.0", "7.7.7.7"), &stage, true).isAllow());
    try testing.expect(waf.run(&reqOf("/api/client-ip/check", "Mozilla/5.0", "7.7.7.7"), &stage, true).isAllow());
    const v = waf.run(&reqOf("/api/client-ip/check", "Mozilla/5.0", "7.7.7.7"), &stage, true);
    try testing.expectEqual(@as(u16, 429), v.blocked.status);

    // 头阶段（`count_request = false`）不计数：同一 IP 再走 5 次仍放行
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        try testing.expect(waf.run(&reqOf("/api/client-ip/check", "Mozilla/5.0", "7.7.7.7"), &stage, false).isAllow());
    }

    // 父前缀 `/api/client-ip`（10 次/分）不受子规则已用次数影响
    var j: usize = 0;
    while (j < 5) : (j += 1) {
        try testing.expect(waf.run(&reqOf("/api/client-ip", "Mozilla/5.0", "7.7.7.7"), &stage, true).isAllow());
    }
    // 按 IP 分桶：另一个 IP 不受前一 IP 的计数影响
    try testing.expect(waf.run(&reqOf("/api/client-ip/check", "Mozilla/5.0", "6.6.6.6"), &stage, true).isAllow());
}

test "CC 限速与静态资源豁免" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var cfg = WafConfig.adminApi();
    cfg.rateLimitPerMin = 2;
    const waf = try testWaf(&arena, cfg);
    defer waf.deinit();

    var stage = Stage{};
    defer stage.deinit(waf.gpa);

    try testing.expect(waf.run(&reqOf("/x", "Mozilla/5.0", "9.9.9.9"), &stage, false).isAllow());
    try testing.expect(waf.run(&reqOf("/x", "Mozilla/5.0", "9.9.9.9"), &stage, false).isAllow());
    const v = waf.run(&reqOf("/x", "Mozilla/5.0", "9.9.9.9"), &stage, false);
    try testing.expectEqual(@as(u16, 429), v.blocked.status);

    // 静态资源不计数
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        try testing.expect(waf.run(&reqOf("/assets/a.js", "Mozilla/5.0", "9.9.9.9"), &stage, false).isAllow());
    }
}

test "CSRF 判定" {
    try testing.expect(csrfReason("GET", "cross-site", "", "") == null);
    try testing.expect(csrfReason("POST", "cross-site", "", "") != null);
    try testing.expect(csrfReason("POST", "same-origin", "", "") == null);
    try testing.expect(csrfReason("POST", "", "null", "example.com") != null);
    try testing.expect(csrfReason("POST", "", "https://example.com", "example.com") == null);
    try testing.expect(csrfReason("POST", "", "https://evil.com", "example.com") != null);
    // 没有来源头（curl / 服务间调用）→ 放行
    try testing.expect(csrfReason("POST", "", "", "") == null);
}

test "可信签名放行与伪造签名拦截" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const waf = try testWaf(&arena, WafConfig.adminApi());
    defer waf.deinit();
    waf.setTrustedSecret("s3cret");

    var stage = Stage{};
    defer stage.deinit(waf.gpa);

    // 计算期望签名：三段升序拼接后 SHA1
    const ts = "1700000000";
    const nonce = "abc";
    var parts = [3][]const u8{ ts, nonce, "s3cret" };
    std.mem.sort([]const u8, &parts, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
    var hasher = std.crypto.hash.Sha1.init(.{});
    for (parts) |p| hasher.update(p);
    var digest: [20]u8 = undefined;
    hasher.final(&digest);
    var sign_buf: [40]u8 = undefined;
    sign_buf = std.fmt.bytesToHex(digest, .lower);
    const sign: []const u8 = &sign_buf;

    const good = [_]std.http.Header{
        .{ .name = "TimeStamp", .value = ts },
        .{ .name = "Nonce", .value = nonce },
        .{ .name = "Signature", .value = sign },
        .{ .name = "User-Agent", .value = "python-requests/2.31" },
    };
    try testing.expect(waf.checkHead(.{ .path = "/api/x", .method = "GET", .headers = &good, .remote_addr = "8.8.8.8" }, &stage).isAllow());

    const bad = [_]std.http.Header{
        .{ .name = "TimeStamp", .value = ts },
        .{ .name = "Nonce", .value = nonce },
        .{ .name = "Signature", .value = "deadbeef" },
        .{ .name = "User-Agent", .value = "python-requests/2.31" },
    };
    try testing.expect(!waf.checkHead(.{ .path = "/api/x", .method = "GET", .headers = &bad, .remote_addr = "8.8.8.8" }, &stage).isAllow());
}

test "XFF 仅在对端回环且开关打开时生效，取末段" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const waf = try testWaf(&arena, WafConfig.adminApi());
    defer waf.deinit();

    // 默认不信任
    try testing.expectEqualStrings("1.2.3.4", waf.resolveClientIp("1.2.3.4", "9.9.9.9"));
    try testing.expectEqualStrings("127.0.0.1", waf.resolveClientIp("127.0.0.1", "9.9.9.9"));

    waf.setTrustForwardedFor(true);
    // 非回环对端：忽略 XFF（防伪造）
    try testing.expectEqualStrings("1.2.3.4", waf.resolveClientIp("1.2.3.4", "9.9.9.9"));
    // 回环对端：取末段
    try testing.expectEqualStrings("9.9.9.9", waf.resolveClientIp("127.0.0.1", "1.1.1.1, 9.9.9.9"));
    try testing.expectEqualStrings("9.9.9.9", waf.resolveClientIp("[::1]:5555", "9.9.9.9"));
}

test "统计：请求计数与拦截计数分别累计" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const waf = try testWaf(&arena, WafConfig.adminApi());
    defer waf.deinit();

    var stage = Stage{};
    defer stage.deinit(waf.gpa);

    _ = waf.run(&reqOf("/x", "Mozilla/5.0", "8.8.8.8"), &stage, true);
    _ = waf.run(&reqOf("/x", "sqlmap/1.7", "8.8.8.8"), &stage, true);
    // 头阶段不累加请求总数
    _ = waf.run(&reqOf("/x", "sqlmap/1.7", "8.8.8.8"), &stage, false);

    const snap = waf.snapshot();
    try testing.expectEqual(@as(u64, 2), snap.total);
    try testing.expectEqual(@as(u64, 2), snap.blocked);
}

test "中间件阻止与放行" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const waf = try testWaf(&arena, WafConfig.adminApi());
    defer waf.deinit();

    const mw = waf.middleware();
    try testing.expectEqual(@as(?*anyopaque, @ptrCast(waf)), mw.ctx);

    // 直接调用中间件入口的包装逻辑（不依赖完整 router 生命周期）
    var req = zzig.web.router.Request{ .path = "/x", .method = "GET" };
    req.headers = &.{.{ .name = "user-agent", .value = "sqlmap/1.7" }};
    req.remote_addr = "8.8.8.8";
    var ctx = try zzig.web.router.Ctx.build(arena.allocator(), req);
    defer ctx.deinit();

    var stage = Stage{};
    defer stage.deinit(waf.gpa);
    const verdict = waf.checkCtx(&ctx, &stage);
    try testing.expect(!verdict.isAllow());
    try testing.expectEqual(@as(u16, 403), verdict.blocked.status);
}

test "早拒拦截补记请求总数（拦截率不超过 1）" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var cfg = WafConfig.adminApi();
    cfg.loopbackBypass = false;
    const waf = try testWaf(&arena, cfg);
    defer waf.deinit();

    var stage = Stage{};
    defer stage.deinit(waf.gpa);

    // 早拒拦截：`/.env` 命中路径特征；该请求不会再进路由层，必须补记总数
    const v = waf.checkHead(.{ .method = "GET", .path = "/.env", .remote_addr = "8.8.8.8" }, &stage);
    try testing.expect(!v.isAllow());
    var snap = waf.snapshot();
    try testing.expectEqual(@as(u64, 1), snap.total);
    try testing.expectEqual(@as(u64, 1), snap.blocked);
    try testing.expect(snap.blocked_ratio <= 1.0);

    // 早拒放行：不累加总数（由路由层完整检查计数，避免重复）
    const ok = waf.checkHead(.{ .method = "GET", .path = "/ping", .remote_addr = "8.8.8.8" }, &stage);
    try testing.expect(ok.isAllow());
    snap = waf.snapshot();
    try testing.expectEqual(@as(u64, 1), snap.total);
}
