//! 端到端演示：zzig `web.App` + Pek.ZWaf 中间件。
//!
//! 跑起来后可以这样验证（默认监听 127.0.0.1:18080）：
//! ```text
//! curl -i  http://127.0.0.1:18080/ping                                   → 200
//! curl -i -A "sqlmap/1.7" http://127.0.0.1:18080/ping                    → 403（恶意爬虫/扫描器）
//! curl -i "http://127.0.0.1:18080/ping?q=1%27%20or%201=1--"             → 403（SQL 注入）
//! curl -i -X POST -H "Sec-Fetch-Site: cross-site" http://127.0.0.1:18080/echo → 403（跨站）
//! curl -i -A "python-requests/2.31" http://127.0.0.1:18080/ping          → 403（脚本 UA）
//! ```
//!
//! 演示**故意关掉回环豁免**（否则本机 curl 全放行，测不出任何东西）。

const std = @import("std");
const zzig = @import("zzig");
const pek_zwaf = @import("pek_zwaf");

const base_dir = ".zig-cache/zwaf-demo";

/// 演示用全局（真实项目里由你的 App 状态持有）。
var g_waf: ?*pek_zwaf.Waf = null;

fn ping(_: *zzig.web.router.Ctx) anyerror!zzig.web.router.Response {
    return .{ .body = "{\"ok\":true,\"from\":\"pek-zwaf\"}" };
}

fn echo(_: *zzig.web.router.Ctx) anyerror!zzig.web.router.Response {
    return .{ .body = "{\"ok\":true}" };
}

/// 安全统计（面板「安全（WAF）」卡的等价物：拦截数 / 请求数 / 原因 / Top IP）。
fn stats(c: *zzig.web.router.Ctx) anyerror!zzig.web.router.Response {
    const waf = g_waf orelse return .{ .status = .service_unavailable, .body = "{}" };
    const snap = waf.snapshot();
    const a = c.arena;

    var out: std.ArrayList(u8) = .empty;
    try out.print(a, "{{\"uptimeSeconds\":{d},\"total\":{d},\"blocked\":{d},\"blockedRatio\":{d:.4},\"lastMinute\":{d},\"last5Minutes\":{d},\"reasons\":[", .{
        snap.uptime_seconds, snap.total, snap.blocked, snap.blocked_ratio, snap.last_minute, snap.last_5_minutes,
    });
    for (snap.reasonList(), 0..) |r, i| {
        if (i > 0) try out.appendSlice(a, ",");
        try out.print(a, "{{\"code\":\"{s}\",\"label\":\"{s}\",\"count\":{d}}}", .{ r.kind.asStr(), r.kind.labelCn(), r.count });
    }
    try out.appendSlice(a, "],\"topIps\":[");
    for (snap.ipList(), 0..) |ip, i| {
        if (i > 0) try out.appendSlice(a, ",");
        try out.print(a, "{{\"ip\":\"{s}\",\"count\":{d}}}", .{ ip.text(), ip.count });
    }
    try out.appendSlice(a, "]}");
    return .{ .body = out.items };
}

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    const io = threaded.io();

    // 1) 准备演示配置（首启写模板；这里显式关掉回环豁免并压低 CC 阈值）
    var cfg = pek_zwaf.WafConfig.adminApi();
    cfg.loopbackBypass = false;
    cfg.rateLimitPerMin = 10;
    const cfg_path = try std.fs.path.join(gpa, &.{ base_dir, pek_zwaf.config.CONFIG_REL });
    try pek_zwaf.config.save(io, gpa, cfg_path, cfg);
    std.debug.print("[demo] 配置已写入 {s}\n", .{cfg_path});

    // 2) 加载 WAF（读同一个文件）
    const waf = try pek_zwaf.Waf.load(gpa, io, base_dir);
    defer waf.deinit();
    g_waf = waf;

    // 3) zzig Web 应用 + 中间件
    var app = try zzig.web.App.init(gpa, io, .{});
    defer app.deinit();
    try app.useMiddleware(waf.middleware());
    try app.get("/ping", zzig.web.router.handler(ping));
    try app.post("/echo", zzig.web.router.handler(echo));
    try app.get("/__stats", zzig.web.router.handler(stats));

    std.debug.print("[demo] 演示站点 http://127.0.0.1:18080/ping\n", .{});

    // 4) HTTP 层早拒：路由中间件只对已匹配路由生效，`/.env`、`/x.php` 这类探测
    //    请求要靠 ServerGuard 在路由匹配之前拦下。
    var srv = app.makeServer(.{});
    var guard = pek_zwaf.ServerGuard.init(waf, srv.ctx, srv.handler);
    defer guard.deinit(gpa);
    guard.install(&srv);
    try srv.run("127.0.0.1", 18080);
}
