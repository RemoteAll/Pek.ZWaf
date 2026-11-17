//! 引用计数的「配置代」（热重载基础设施）。
//!
//! 为什么需要：配置热重载要**整体替换**一份由 arena 持有的配置（含编译后的规则），
//! 而正在处理的请求仍可能持有旧配置的切片。直接释放旧 arena 会造成悬空指针。
//!
//! 做法：检查开始 `ref()`、结束 `unref()`；替换时 `unref()` 旧代，
//! 最后一个持有者退出时才真正释放 arena。与 Rust `Pek.RWaf` 的 `RwLock<WafConfig>`
//! 不同——Zig 侧配置里的字符串是切片，必须保证生命周期覆盖整个检查过程。
//!
//! 消费方：WAF 门面（`Waf`）、接口级限流（`Throttle`），同一份实现不重复写。

const std = @import("std");

/// 泛型配置代：`P` 为负载（通常是 `{ cfg, compiled_rules }`）。
pub fn Gen(comptime P: type) type {
    return struct {
        const Self = @This();

        /// 持有配置字符串与编译产物的 arena（`deinit` 时整体释放）
        arena: std.heap.ArenaAllocator,
        /// 负载（内部所有切片都指向 `arena`）
        payload: P,
        refs: std.atomic.Value(u32),

        /// 新建（引用计数初始为 1，交给创建方）。
        pub fn create(gpa: std.mem.Allocator, arena: std.heap.ArenaAllocator, payload: P) !*Self {
            const self = try gpa.create(Self);
            self.* = .{ .arena = arena, .payload = payload, .refs = .init(1) };
            return self;
        }

        /// 增加引用（并发读路径）。
        pub fn ref(self: *Self) void {
            _ = self.refs.fetchAdd(1, .monotonic);
        }

        /// 减少引用；归零时释放 arena 与自身。
        pub fn unref(self: *Self, gpa: std.mem.Allocator) void {
            if (self.refs.fetchSub(1, .acq_rel) == 1) {
                self.arena.deinit();
                gpa.destroy(self);
            }
        }

        /// 当前引用数（诊断 / 测试用）。
        pub fn refCount(self: *const Self) u32 {
            return self.refs.load(.monotonic);
        }
    };
}

test "引用计数：归零才释放" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    const a = arena.allocator();
    const text = try a.dupe(u8, "payload");

    const G = Gen(struct { text: []const u8 });
    const g = try G.create(std.testing.allocator, arena, .{ .text = text });
    g.ref();
    try std.testing.expectEqual(@as(u32, 2), g.refCount());
    g.unref(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 1), g.refCount());
    try std.testing.expectEqualStrings("payload", g.payload.text);
    g.unref(std.testing.allocator); // 归零 → 释放（testing.allocator 会校验无泄漏）
}
