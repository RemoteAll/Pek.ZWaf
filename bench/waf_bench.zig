//! 性能基准：**按 100 万口径**量化每条判定路径。
//!
//! 两类 100 万规模：
//! - **100 万次判定**（`iters` 默认 1,000,000）：典型放行 / 恶意 UA / SQLi / 静态资源 / 大 body；
//! - **100 万条名单 / 1000 条规则**：`ipBlacklist` 与 Ruleset 的规模效应（迭代数按单次耗时自动降档）。
//!
//! 运行（必须 ReleaseFast，Debug 数字无参考价值）：
//! ```text
//! zig build bench -Doptimize=ReleaseFast
//! ```
//!
//! 输出英文标签（PS 5.1 控制台按 GBK 解码 UTF-8 会乱码），每行格式：
//! `<场景>  <ns/次>  <万次/秒>  <拦截数/总次数>`

const std = @import("std");
const zzig = @import("zzig");
const pek_zwaf = @import("pek_zwaf");

const NS_PER_ITER_DEFAULT: usize = 1_000_000;

fn nowNs() i128 {
    return zzig.compat.nanoTimestamp();
}

const Case = struct {
    name: []const u8,
    iters: usize = NS_PER_ITER_DEFAULT,
};

fn report(name: []const u8, ns_total: i128, iters: usize, blocked: usize) void {
    const per = @as(f64, @floatFromInt(ns_total)) / @as(f64, @floatFromInt(iters));
    const per_us = per / 1000.0;
    const per_sec = 1e9 / per;
    std.debug.print("{s:<34} {d:>10.1} ns  ({d:>9.3} us)  {d:>12.0} /s  blocked={d}/{d}\n", .{
        name, per, per_us, per_sec, blocked, iters,
    });
}

fn runCase(
    waf: *pek_zwaf.Waf,
    stage: *pek_zwaf.Stage,
    req: *const zzig.web.router.Request,
    case: Case,
) void {
    var warm: usize = 0;
    const warm_iters = @min(case.iters, 20_000);
    while (warm < warm_iters) : (warm += 1) {
        _ = waf.checkRouteRequest(req.*, stage);
    }

    var i: usize = 0;
    var blocked: usize = 0;
    const t0 = nowNs();
    while (i < case.iters) : (i += 1) {
        const v = waf.checkRouteRequest(req.*, stage);
        if (!v.isAllow()) blocked += 1;
    }
    const t1 = nowNs();
    report(case.name, t1 - t0, case.iters, blocked);
}

fn makeWaf(
    gpa: std.mem.Allocator,
    io: std.Io,
    cfg: pek_zwaf.WafConfig,
) !*pek_zwaf.Waf {
    return pek_zwaf.Waf.init(gpa, io, cfg);
}

fn bigIpList(gpa: std.mem.Allocator, n: usize) ![]const []const u8 {
    const arr = try gpa.alloc([]const u8, n);
    for (arr, 0..) |*slot, i| {
        slot.* = try std.fmt.allocPrint(gpa, "10.{d}.{d}.{d}/32", .{
            (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF,
        });
    }
    return arr;
}

fn writeRulesFile(gpa: std.mem.Allocator, io: std.Io, dir: []const u8, n: usize) ![]const u8 {
    std.Io.Dir.cwd().createDirPath(io, dir) catch {};
    const path = try std.fs.path.join(gpa, &.{ dir, "Rules.json" });
    errdefer gpa.free(path);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try out.appendSlice(gpa, "{\"Operator\":\"OrElse\",\"Rules\":[");
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (i > 0) try out.append(gpa, ',');
        try out.print(gpa,
            \\{{"MemberName":"Path","Operator":"EndsWith","Inputs":["/legacy-{d}.php"]}}
        , .{i});
    }
    try out.appendSlice(gpa, "]}");

    var f = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer f.close(io);
    try f.writeStreamingAll(io, out.items);
    return path;
}

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    const io = threaded.io();

    std.debug.print("=== Pek.ZWaf bench (ReleaseFast) ===\n", .{});

    // ————— 场景 1–5：单请求判定路径（100 万次）—————
    {
        var cfg = pek_zwaf.WafConfig.adminApi();
        cfg.loopbackBypass = false;
        cfg.rateLimitPerMin = 0; // 关闭 CC，先量基础判定
        const waf = try makeWaf(gpa, io, cfg);
        defer waf.deinit();
        var stage = pek_zwaf.Stage{};
        defer stage.deinit(waf.gpa);

        const browser_headers = [_]std.http.Header{
            .{ .name = "user-agent", .value = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36" },
            .{ .name = "accept", .value = "application/json, text/plain, */*" },
            .{ .name = "accept-language", .value = "zh-CN,zh;q=0.9,en;q=0.8" },
            .{ .name = "content-type", .value = "application/json" },
        };

        var req = zzig.web.router.Request{
            .method = "GET",
            .path = "/api/orders/12345",
            .query = "page=2&size=20&sort=created_at&keyword=phone",
            .headers = &browser_headers,
            .remote_addr = "203.0.113.42:54321",
        };
        runCase(waf, &stage, &req, .{ .name = "allow: browser GET" });

        req.query = "id=1%27%20or%201%3D1--";
        runCase(waf, &stage, &req, .{ .name = "block: sqli query" });

        const evil = [_]std.http.Header{
            .{ .name = "user-agent", .value = "sqlmap/1.7.12#stable (https://sqlmap.org)" },
        };
        req = .{
            .method = "GET",
            .path = "/api/orders",
            .query = "",
            .headers = &evil,
            .remote_addr = "203.0.113.42:54321",
        };
        runCase(waf, &stage, &req, .{ .name = "block: malicious UA" });

        req = .{
            .method = "GET",
            .path = "/assets/app.2f1a9c.js",
            .query = "",
            .headers = &browser_headers,
            .remote_addr = "203.0.113.42:54321",
        };
        runCase(waf, &stage, &req, .{ .name = "allow: static asset" });

        // 8 KB JSON body（文本类 → 会做 body 预览扫描）
        var body_buf: [8192]u8 = undefined;
        for (&body_buf, 0..) |*b, i| b.* = 'a' + @as(u8, @intCast(i % 26));
        req = .{
            .method = "POST",
            .path = "/api/orders",
            .query = "",
            .body = &body_buf,
            .headers = &browser_headers,
            .remote_addr = "203.0.113.42:54321",
        };
        runCase(waf, &stage, &req, .{ .name = "allow: POST 8KB body" });
    }

    // ————— 场景 6：100 万条 IP 黑名单（线性字符串解析）—————
    {
        const n = 1_000_000;
        const t0 = nowNs();
        const list = try bigIpList(gpa, n);
        const t1 = nowNs();
        defer {
            for (list) |s| gpa.free(s);
            gpa.free(list);
        }
        std.debug.print("build 1M ip rules: {d:.1} ms\n", .{@as(f64, @floatFromInt(t1 - t0)) / 1e6});

        var cfg = pek_zwaf.WafConfig.adminApi();
        cfg.loopbackBypass = false;
        cfg.rateLimitPerMin = 0;
        cfg.ipBlacklist = list;
        const waf = try makeWaf(gpa, io, cfg);
        defer waf.deinit();
        var stage = pek_zwaf.Stage{};
        defer stage.deinit(waf.gpa);

        const headers = [_]std.http.Header{
            .{ .name = "user-agent", .value = "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0.0.0" },
        };
        const req = zzig.web.router.Request{
            .method = "GET",
            .path = "/api/orders",
            .query = "page=1",
            .headers = &headers,
            .remote_addr = "198.51.100.7:1234", // 不在名单（最坏情况：全表扫完）
        };
        runCase(waf, &stage, &req, .{ .name = "1M ip blacklist: miss", .iters = 200 });
    }

    // ————— 场景 7：1000 条自定义规则 —————
    {
        const dir = ".zig-cache/zwaf-bench";
        const path = try writeRulesFile(gpa, io, dir, 1000);
        defer gpa.free(path);

        var cfg = pek_zwaf.WafConfig.adminApi();
        cfg.loopbackBypass = false;
        cfg.rateLimitPerMin = 0;
        cfg.rulesetFile = path;
        const waf = try makeWaf(gpa, io, cfg);
        defer waf.deinit();
        var stage = pek_zwaf.Stage{};
        defer stage.deinit(waf.gpa);

        const headers = [_]std.http.Header{
            .{ .name = "user-agent", .value = "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0.0.0" },
        };
        const req = zzig.web.router.Request{
            .method = "GET",
            .path = "/api/orders",
            .query = "page=1",
            .headers = &headers,
            .remote_addr = "198.51.100.7:1234",
        };
        runCase(waf, &stage, &req, .{ .name = "1000 ruleset: miss", .iters = 100_000 });
    }

    // ————— 场景 8：热重载时间戳轮询成本（file_path 非空时的每请求开销）—————
    {
        const base = ".zig-cache/zwaf-bench-hot";
        std.Io.Dir.cwd().createDirPath(io, base) catch {};
        // 预写配置：关闭回环豁免与 CC（否则 100 万次同 IP 请求会被默认 300/min 限速）
        var cfg0 = pek_zwaf.WafConfig.adminApi();
        cfg0.loopbackBypass = false;
        cfg0.rateLimitPerMin = 0;
        const cfg_path = try std.fs.path.join(gpa, &.{ base, pek_zwaf.config.CONFIG_REL });
        defer gpa.free(cfg_path);
        try pek_zwaf.config.save(io, gpa, cfg_path, cfg0);

        const waf = try pek_zwaf.Waf.load(gpa, io, base);
        defer waf.deinit();
        var stage = pek_zwaf.Stage{};
        defer stage.deinit(waf.gpa);

        const headers = [_]std.http.Header{
            .{ .name = "user-agent", .value = "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0.0.0" },
        };
        const req = zzig.web.router.Request{
            .method = "GET",
            .path = "/api/orders",
            .query = "page=1",
            .headers = &headers,
            .remote_addr = "198.51.100.7:1234",
        };
        runCase(waf, &stage, &req, .{ .name = "allow: with reload poll" });
    }

    // ————— 场景 9：CC 限速（计数开销 + 阈值触发）—————
    {
        const headers = [_]std.http.Header{
            .{ .name = "user-agent", .value = "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0.0.0" },
        };
        const req = zzig.web.router.Request{
            .method = "GET",
            .path = "/api/orders",
            .query = "page=1",
            .headers = &headers,
            .remote_addr = "198.51.100.7:1234",
        };

        // 9a：只量计数开销（阈值调大，避免 warmup 把配额烧掉）
        {
            var cfg = pek_zwaf.WafConfig.adminApi();
            cfg.loopbackBypass = false;
            cfg.rateLimitPerMin = 100_000_000;
            const waf = try makeWaf(gpa, io, cfg);
            defer waf.deinit();
            var stage = pek_zwaf.Stage{};
            defer stage.deinit(waf.gpa);
            runCase(waf, &stage, &req, .{ .name = "allow: CC counting on" });
        }

        // 9b：阈值触发（每 IP 10 次/分钟；第 11 次起应为 429）
        {
            var cfg = pek_zwaf.WafConfig.adminApi();
            cfg.loopbackBypass = false;
            cfg.rateLimitPerMin = 10;
            const waf = try makeWaf(gpa, io, cfg);
            defer waf.deinit();
            var stage = pek_zwaf.Stage{};
            defer stage.deinit(waf.gpa);

            var codes: [12]u16 = undefined;
            var i: usize = 0;
            while (i < 12) : (i += 1) {
                const v = waf.checkRouteRequest(req, &stage);
                codes[i] = switch (v) {
                    .allow => 200,
                    .blocked => |b| b.status,
                };
            }
            std.debug.print("CC threshold (limit=10/min):", .{});
            for (codes) |c| std.debug.print(" {d}", .{c});
            std.debug.print("\n", .{});
        }
    }

    // ————— 场景 10：Stage 复用 vs 每请求新建 —————
    {
        var cfg = pek_zwaf.WafConfig.adminApi();
        cfg.loopbackBypass = false;
        cfg.rateLimitPerMin = 0;
        const waf = try makeWaf(gpa, io, cfg);
        defer waf.deinit();

        const headers = [_]std.http.Header{
            .{ .name = "user-agent", .value = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36" },
            .{ .name = "content-type", .value = "application/json" },
        };
        const req = zzig.web.router.Request{
            .method = "GET",
            .path = "/api/orders/12345",
            .query = "page=2&size=20&sort=created_at&keyword=phone",
            .headers = &headers,
            .remote_addr = "203.0.113.42:54321",
        };

        // 复用（当前中间件路径）
        {
            var stage = pek_zwaf.Stage{};
            defer stage.deinit(waf.gpa);
            runCase(waf, &stage, &req, .{ .name = "allow: reused Stage" });
        }

        // 每请求新建（改造前的中间件路径）
        {
            var warm: usize = 0;
            while (warm < 20_000) : (warm += 1) {
                var stage = pek_zwaf.Stage{};
                defer stage.deinit(waf.gpa);
                _ = waf.checkRouteRequest(req, &stage);
            }
            var i: usize = 0;
            const t0 = nowNs();
            while (i < NS_PER_ITER_DEFAULT) : (i += 1) {
                var stage = pek_zwaf.Stage{};
                defer stage.deinit(waf.gpa);
                _ = waf.checkRouteRequest(req, &stage);
            }
            const t1 = nowNs();
            report("allow: new Stage per request", t1 - t0, NS_PER_ITER_DEFAULT, 0);
        }
    }

    // ————— 场景 11：分片限流器的多线程吞吐（8 线程 × 20 万次，key 分散）—————
    {
        const Threads = struct {
            fn run(l: *pek_zwaf.WindowLimiter, tid: usize, iters: usize) void {
                var buf: [32]u8 = undefined;
                const key = std.fmt.bufPrint(&buf, "10.0.{d}.7", .{tid}) catch "10.0.0.7";
                var i: usize = 0;
                while (i < iters) : (i += 1) {
                    _ = l.hit(key, 100_000_000, 60_000);
                }
            }
        };

        const threads_n = 8;
        const per_thread = 200_000;
        var limiter = pek_zwaf.WindowLimiter.init(gpa);
        defer limiter.deinit();

        var handles: [threads_n]std.Thread = undefined;
        const t0 = nowNs();
        for (&handles, 0..) |*h, i| {
            h.* = try std.Thread.spawn(.{}, Threads.run, .{ &limiter, i, per_thread });
        }
        for (&handles) |*h| h.join();
        const t1 = nowNs();
        report("CC limiter: 8 threads sharded", t1 - t0, threads_n * per_thread, 0);
    }

    std.debug.print("=== done ===\n", .{});
}
