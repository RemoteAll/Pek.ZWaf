//! WAF 运行统计：**只累加被拦请求**（放行路径几乎零开销），用于「当前是否正在被攻击」的判定。
//!
//! 设计约束（对齐「资源与带宽惯例」）：
//! - 全原子计数：每请求 1 次递增；被拦时再按原因 / IP 各 1 次，无锁竞争路径；
//! - **固定容量** Top 表（IP 16 个、原因 9 类）：不随攻击流量膨胀内存；
//! - 分钟窗口只保留 **6 个桶**（近 6 分钟），`O(1)` 累加、`O(6)` 汇总；
//! - 快照 `Snapshot` 是**值类型**（内联固定数组），不写盘、不发网络、无后台线程。

const std = @import("std");
const zzig = @import("zzig");
const clock = @import("clock.zig");

/// Top 表容量（来源 IP 数）。
pub const TOP_IP_CAPACITY: usize = 16;
/// Top 表容量（拦截原因分类数）。
pub const TOP_REASON_CAPACITY: usize = 8;
/// 分钟窗口桶数（近 6 分钟）。
pub const WINDOW_BUCKETS: usize = 6;

/// 拦截原因分类（用于聚合，不参与判定）。
pub const BlockKind = enum {
    sqli,
    xss,
    path,
    cmd,
    bot,
    ip,
    rule,
    csrf,
    cc,

    /// 稳定标识（日志 / 前端展示 / 聚合键）。
    pub fn asStr(self: BlockKind) []const u8 {
        return @tagName(self);
    }

    /// 中文名。
    pub fn labelCn(self: BlockKind) []const u8 {
        return switch (self) {
            .sqli => "SQL 注入",
            .xss => "XSS",
            .path => "路径穿越",
            .cmd => "命令注入",
            .bot => "恶意爬虫/扫描器",
            .ip => "IP 黑名单",
            .rule => "自定义规则",
            .csrf => "跨站请求",
            .cc => "CC 限流",
        };
    }

    pub fn index(self: BlockKind) usize {
        return @backingInt(self);
    }
};

const Bucket = struct {
    minute: u64 = 0,
    count: u64 = 0,
};

/// 固定容量的 IP 键（IP 最长 45 字符，留 1 字节余量）。
pub const IpKey = struct {
    buf: [46]u8 = @splat(0),
    len: usize = 0,
    count: u64 = 0,

    pub fn text(self: *const IpKey) []const u8 {
        return self.buf[0..self.len];
    }
};

/// 原因计数项。
pub const ReasonCount = struct {
    kind: BlockKind = .sqli,
    count: u64 = 0,
};

/// 统计快照（值类型；调用方随便拷贝）。
pub const Snapshot = struct {
    since: i64 = 0,
    uptime_seconds: u64 = 0,
    total: u64 = 0,
    blocked: u64 = 0,
    blocked_ratio: f64 = 0,
    last_minute: u64 = 0,
    last_5_minutes: u64 = 0,
    reasons: [9]ReasonCount = @splat(.{}),
    reason_len: usize = 0,
    ips: [TOP_IP_CAPACITY]IpKey = @splat(.{}),
    ip_len: usize = 0,

    pub fn reasonList(self: *const Snapshot) []const ReasonCount {
        return self.reasons[0..self.reason_len];
    }

    pub fn ipList(self: *const Snapshot) []const IpKey {
        return self.ips[0..self.ip_len];
    }
};

/// 运行统计（进程内、重置即清零）。
pub const WafStats = struct {
    since: i64,
    total: std.atomic.Value(u64) = .init(0),
    blocked: std.atomic.Value(u64) = .init(0),
    by_kind: [9]std.atomic.Value(u64) = @splat(.init(0)),
    mutex: zzig.compat.Mutex = .{},
    window: [WINDOW_BUCKETS]Bucket = @splat(.{}),
    top: [TOP_IP_CAPACITY]IpKey = @splat(.{}),
    top_len: usize = 0,

    pub fn init() WafStats {
        return .{ .since = clock.nowSecs() };
    }

    /// 记录一次请求（放行也算；1 次原子递增）。
    pub fn recordRequest(self: *WafStats) void {
        _ = self.total.fetchAdd(1, .monotonic);
    }

    /// 记录一次拦截：总量 + 原因 + 分钟窗口 + Top IP。
    pub fn recordBlock(self: *WafStats, kind: BlockKind, ip: []const u8) void {
        _ = self.blocked.fetchAdd(1, .monotonic);
        _ = self.by_kind[kind.index()].fetchAdd(1, .monotonic);

        const minute: u64 = @intCast(@divFloor(clock.nowSecs(), 60));
        self.mutex.lock();
        defer self.mutex.unlock();

        // 找当前分钟桶；没有则用最旧的桶覆盖（环形）
        var target: usize = 0;
        for (&self.window, 0..) |*b, i| {
            if (b.minute == minute) {
                target = i;
                break;
            }
            if (b.minute < self.window[target].minute) target = i;
        }
        if (self.window[target].minute != minute) {
            self.window[target] = .{ .minute = minute, .count = 0 };
        }
        self.window[target].count += 1;

        if (ip.len == 0) return;
        const key = ip[0..@min(ip.len, 45)];

        // 已有该 IP：计数 +1
        for (self.top[0..self.top_len]) |*item| {
            if (std.mem.eql(u8, item.text(), key)) {
                item.count += 1;
                return;
            }
        }
        // 未满：追加
        if (self.top_len < TOP_IP_CAPACITY) {
            var item = IpKey{ .len = key.len, .count = 1 };
            @memcpy(item.buf[0..key.len], key);
            self.top[self.top_len] = item;
            self.top_len += 1;
            return;
        }
        // 满了：替换计数最小的（固定容量，内存不随攻击流量增长）
        var idx: usize = 0;
        for (self.top[0..self.top_len], 0..) |item, i| {
            if (item.count < self.top[idx].count) idx = i;
        }
        if (self.top[idx].count <= 1) {
            var item = IpKey{ .len = key.len, .count = 1 };
            @memcpy(item.buf[0..key.len], key);
            self.top[idx] = item;
        }
    }

    /// 快照（面板 / `-status` 读取；只做一次原子读 + 一次短锁）。
    pub fn snapshot(self: *WafStats) Snapshot {
        var snap = Snapshot{};
        snap.since = self.since;
        const now = clock.nowSecs();
        snap.uptime_seconds = if (now > self.since) @intCast(now - self.since) else 0;

        const minute: u64 = @intCast(@divFloor(now, 60));
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            var one: u64 = 0;
            var five: u64 = 0;
            for (self.window) |b| {
                if (b.minute == minute) one += b.count;
                if (b.minute <= minute and b.minute + 5 >= minute) five += b.count;
            }
            snap.last_minute = one;
            snap.last_5_minutes = five;

            for (self.top[0..self.top_len], 0..) |item, i| {
                if (item.len == 0) continue;
                snap.ips[snap.ip_len] = item;
                snap.ip_len += 1;
                _ = i;
            }
        }

        for (0..9) |i| {
            const kind: BlockKind = @fromBackingInt(@intCast(i));
            const count = self.by_kind[i].load(.monotonic);
            if (count == 0) continue;
            snap.reasons[snap.reason_len] = .{ .kind = kind, .count = count };
            snap.reason_len += 1;
        }

        const less = struct {
            fn cmp(_: void, a: ReasonCount, b: ReasonCount) bool {
                return a.count > b.count;
            }
        }.cmp;
        std.mem.sort(ReasonCount, snap.reasons[0..snap.reason_len], {}, less);
        if (snap.reason_len > TOP_REASON_CAPACITY) snap.reason_len = TOP_REASON_CAPACITY;

        const lessIp = struct {
            fn cmp(_: void, a: IpKey, b: IpKey) bool {
                return a.count > b.count;
            }
        }.cmp;
        std.mem.sort(IpKey, snap.ips[0..snap.ip_len], {}, lessIp);
        if (snap.ip_len > TOP_IP_CAPACITY) snap.ip_len = TOP_IP_CAPACITY;

        snap.total = self.total.load(.monotonic);
        snap.blocked = self.blocked.load(.monotonic);
        snap.blocked_ratio = if (snap.total == 0) 0 else @as(f64, @floatFromInt(snap.blocked)) / @as(f64, @floatFromInt(snap.total));
        return snap;
    }
};

test "统计请求、拦截与原因" {
    var stats = WafStats.init();
    for (0..10) |_| stats.recordRequest();
    stats.recordBlock(.bot, "1.1.1.1");
    stats.recordBlock(.bot, "1.1.1.1");
    stats.recordBlock(.sqli, "2.2.2.2");

    const snap = stats.snapshot();
    try std.testing.expectEqual(@as(u64, 10), snap.total);
    try std.testing.expectEqual(@as(u64, 3), snap.blocked);
    try std.testing.expectEqual(@as(u64, 3), snap.last_minute);
    try std.testing.expectEqual(@as(u64, 3), snap.last_5_minutes);
    try std.testing.expectApproxEqAbs(@as(f64, 0.3), snap.blocked_ratio, 0.0001);

    const reasons = snap.reasonList();
    try std.testing.expectEqual(@as(usize, 2), reasons.len);
    try std.testing.expectEqual(BlockKind.bot, reasons[0].kind);
    try std.testing.expectEqual(@as(u64, 2), reasons[0].count);
    try std.testing.expectEqual(BlockKind.sqli, reasons[1].kind);

    const ips = snap.ipList();
    try std.testing.expectEqual(@as(usize, 2), ips.len);
    try std.testing.expectEqualStrings("1.1.1.1", ips[0].text());
    try std.testing.expectEqual(@as(u64, 2), ips[0].count);
    try std.testing.expectEqualStrings("2.2.2.2", ips[1].text());
}

test "Top IP 固定容量不膨胀" {
    var stats = WafStats.init();
    var buf: [32]u8 = undefined;
    for (0..200) |i| {
        const ip = try std.fmt.bufPrint(&buf, "10.0.0.{d}", .{i});
        stats.recordBlock(.bot, ip);
    }
    const snap = stats.snapshot();
    try std.testing.expect(snap.ip_len <= TOP_IP_CAPACITY);
    try std.testing.expectEqual(@as(u64, 200), snap.blocked);
}
