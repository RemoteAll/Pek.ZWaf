//! 固定窗口限流引擎（CC 限速与接口级限流共用）。
//!
//! 口径与 `dhrust::ratelimit::WindowLimiter` 一致：**每个 key 从「首次命中」起算一个窗口**，
//! 窗口内超过上限即拒绝，窗口到期后计数归零。相比「自然分钟边界」的差异：
//! 跨整点不会集中重置，避免整点突发。
//!
//! 内存有界：条目数上限（默认 65536）；超限时先清过期条目，仍满则淘汰最旧的一条
//! （攻击流量下不会无限涨，也不会整表清空造成「限流突然失效」）。

const std = @import("std");
const zzig = @import("zzig");
const clock = @import("clock.zig");

/// 一次计数的判定结果。
pub const Decision = struct {
    allowed: bool,
    count: u64,
    limit: u64,
    /// 窗口剩余毫秒（可直接用于 `Retry-After` 之类）。
    reset_in_ms: u64,
};

const Entry = struct {
    count: u64,
    start_ms: i64,
};

/// 分片数（2 的幂；按 key 哈希低位选片）。
///
/// 为什么分片：CC 限速是**每请求**都要走一次计数（非静态、有 IP、非放行机器人）。
/// 原来全局单锁 + 字符串哈希，高并发下所有线程挤同一把锁；分成 16 片后同一时刻
/// 最多 16 个线程并行，锁冲突概率降一个数量级，而条目上限语义仍保持全局总量。
const SHARD_COUNT: usize = 16;

const Shard = struct {
    mutex: zzig.compat.Mutex = .{},
    map: std.StringHashMapUnmanaged(Entry) = .empty,
    /// 本分片条目上限（`setMaxEntries` 精确分配，总和等于全局上限）
    max_entries: usize = 4096,
};

/// 固定窗口限速器（线程安全；分片锁）。
pub const WindowLimiter = struct {
    allocator: std.mem.Allocator,
    shards: [SHARD_COUNT]Shard = @splat(.{}),

    pub fn init(allocator: std.mem.Allocator) WindowLimiter {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *WindowLimiter) void {
        for (&self.shards) |*s| {
            var it = s.map.keyIterator();
            while (it.next()) |k| self.allocator.free(k.*);
            s.map.deinit(self.allocator);
            s.map = .empty;
        }
    }

    fn shardIndex(key: []const u8) usize {
        return std.hash.Wyhash.hash(0x9e37_79b9_7f4a_7c15, key) & (SHARD_COUNT - 1);
    }

    /// 设置全局条目上限（按分片分配；每片至少 1，总量小于分片数时会被放大到 16）。
    pub fn setMaxEntries(self: *WindowLimiter, total: usize) void {
        const per = @max(1, total / SHARD_COUNT);
        const extra = total % SHARD_COUNT;
        for (&self.shards, 0..) |*s, i| {
            s.max_entries = if (per > 1 and i < extra) per + 1 else per;
        }
    }

    /// 当前条目总数（诊断/测试；逐分片加锁统计）。
    pub fn entryCount(self: *WindowLimiter) usize {
        var total: usize = 0;
        for (&self.shards) |*s| {
            s.mutex.lock();
            defer s.mutex.unlock();
            total += s.map.count();
        }
        return total;
    }

    /// 记一次请求并返回判定。
    pub fn hit(self: *WindowLimiter, key: []const u8, limit: u64, window_ms: u64) Decision {
        if (limit == 0 or window_ms == 0) {
            return .{ .allowed = true, .count = 0, .limit = 0, .reset_in_ms = 0 };
        }
        const now = clock.nowMillis();
        const win: i64 = @intCast(window_ms);
        const s = &self.shards[shardIndex(key)];

        s.mutex.lock();
        defer s.mutex.unlock();

        if (s.map.getPtr(key)) |entry| {
            if (now - entry.start_ms >= win) {
                entry.start_ms = now;
                entry.count = 1;
                return .{ .allowed = true, .count = 1, .limit = limit, .reset_in_ms = window_ms };
            }
            entry.count += 1;
            const elapsed: u64 = @intCast(now - entry.start_ms);
            const reset_in = if (elapsed >= window_ms) 0 else window_ms - elapsed;
            return .{
                .allowed = entry.count <= limit,
                .count = entry.count,
                .limit = limit,
                .reset_in_ms = reset_in,
            };
        }

        // 新 key：容量控制后再插入
        if (s.map.count() >= s.max_entries) evictLocked(self.allocator, s, now, win);
        const owned = self.allocator.dupe(u8, key) catch {
            // 分配失败：失败放行（不因限流器内存不足而拦死业务）
            return .{ .allowed = true, .count = 0, .limit = limit, .reset_in_ms = window_ms };
        };
        s.map.put(self.allocator, owned, .{ .count = 1, .start_ms = now }) catch {
            self.allocator.free(owned);
            return .{ .allowed = true, .count = 0, .limit = limit, .reset_in_ms = window_ms };
        };
        return .{ .allowed = true, .count = 1, .limit = limit, .reset_in_ms = window_ms };
    }

    /// 只判定不计数（诊断用）。
    pub fn peek(self: *WindowLimiter, key: []const u8, limit: u64, window_ms: u64) Decision {
        if (limit == 0 or window_ms == 0) {
            return .{ .allowed = true, .count = 0, .limit = 0, .reset_in_ms = 0 };
        }
        const now = clock.nowMillis();
        const win: i64 = @intCast(window_ms);
        const s = &self.shards[shardIndex(key)];
        s.mutex.lock();
        defer s.mutex.unlock();
        if (s.map.get(key)) |entry| {
            if (now - entry.start_ms >= win) {
                return .{ .allowed = true, .count = 0, .limit = limit, .reset_in_ms = window_ms };
            }
            const elapsed: u64 = @intCast(now - entry.start_ms);
            return .{
                .allowed = entry.count < limit,
                .count = entry.count,
                .limit = limit,
                .reset_in_ms = if (elapsed >= window_ms) 0 else window_ms - elapsed,
            };
        }
        return .{ .allowed = true, .count = 0, .limit = limit, .reset_in_ms = window_ms };
    }

    /// 清空全部计数（热重载时调用；逐分片加锁）。
    pub fn clear(self: *WindowLimiter) void {
        for (&self.shards) |*s| {
            s.mutex.lock();
            var it = s.map.keyIterator();
            while (it.next()) |k| self.allocator.free(k.*);
            s.map.clearRetainingCapacity();
            s.mutex.unlock();
        }
    }
};

/// 分片内清理：先删过期条目，仍满则淘汰最旧的一条（有界内存优先于完整性）。
fn evictLocked(allocator: std.mem.Allocator, s: *Shard, now: i64, window: i64) void {
    var remove: std.ArrayList([]const u8) = .empty;
    defer remove.deinit(allocator);
    var it = s.map.iterator();
    while (it.next()) |kv| {
        if (now - kv.value_ptr.start_ms >= window) {
            remove.append(allocator, kv.key_ptr.*) catch break;
        }
    }
    for (remove.items) |k| {
        if (s.map.fetchRemove(k)) |kv| allocator.free(kv.key);
    }
    if (s.map.count() < s.max_entries) return;

    // 仍然满：淘汰最旧的一条（有界内存优先于完整性）
    var oldest_key: ?[]const u8 = null;
    var oldest_start: i64 = std.math.maxInt(i64);
    var it2 = s.map.iterator();
    while (it2.next()) |kv| {
        if (kv.value_ptr.start_ms < oldest_start) {
            oldest_start = kv.value_ptr.start_ms;
            oldest_key = kv.key_ptr.*;
        }
    }
    if (oldest_key) |k| {
        if (s.map.fetchRemove(k)) |kv| allocator.free(kv.key);
    }
}

test "窗口限速基本语义" {
    var limiter = WindowLimiter.init(std.testing.allocator);
    defer limiter.deinit();

    var i: usize = 0;
    while (i < 3) : (i += 1) {
        try std.testing.expect(limiter.hit("1.2.3.4", 3, 60_000).allowed);
    }
    try std.testing.expect(!limiter.hit("1.2.3.4", 3, 60_000).allowed);
    // 不同 key 独立
    try std.testing.expect(limiter.hit("5.6.7.8", 3, 60_000).allowed);
    // 0 = 关闭
    try std.testing.expect(limiter.hit("1.2.3.4", 0, 60_000).allowed);
    // 清理
    limiter.clear();
    try std.testing.expect(limiter.hit("1.2.3.4", 3, 60_000).allowed);
}

test "窗口到期后重置" {
    var limiter = WindowLimiter.init(std.testing.allocator);
    defer limiter.deinit();
    try std.testing.expect(limiter.hit("k", 1, 30).allowed);
    try std.testing.expect(!limiter.hit("k", 1, 30).allowed);
    zzig.compat.sleep(40 * std.time.ns_per_ms);
    try std.testing.expect(limiter.hit("k", 1, 30).allowed);
}

test "容量上限下不无限增长" {
    var limiter = WindowLimiter.init(std.testing.allocator);
    defer limiter.deinit();
    limiter.setMaxEntries(8);
    var buf: [32]u8 = undefined;
    for (0..200) |i| {
        const key = try std.fmt.bufPrint(&buf, "k-{d}", .{i});
        _ = limiter.hit(key, 10, 60_000);
    }
    try std.testing.expect(limiter.entryCount() <= SHARD_COUNT);
    limiter.clear();
    try std.testing.expectEqual(@as(usize, 0), limiter.entryCount());
}
