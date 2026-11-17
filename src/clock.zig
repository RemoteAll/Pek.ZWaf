//! 墙钟时间（Unix 纪元）。
//!
//! Zig 0.17 把 `std.time.timestamp` / `std.time.milliTimestamp` 移出了标准库公开 API，
//! 生态统一走 `zzig.compat.nanoTimestamp()`（Windows 用 `GetSystemTimePreciseAsFileTime`，
//! 其它平台用 `clock_gettime(REALTIME)`）。本模块只是把它换算成秒/毫秒的薄封装，
//! **不重复实现系统调用**。

const std = @import("std");
const zzig = @import("zzig");

/// 当前 Unix 时间（秒）。
pub fn nowSecs() i64 {
    return @intCast(@divFloor(zzig.compat.nanoTimestamp(), std.time.ns_per_s));
}

/// 当前 Unix 时间（毫秒）。
pub fn nowMillis() i64 {
    return @intCast(@divFloor(zzig.compat.nanoTimestamp(), std.time.ns_per_ms));
}

test "时间单调前进" {
    const a = nowMillis();
    zzig.compat.sleep(2 * std.time.ns_per_ms);
    const b = nowMillis();
    try std.testing.expect(b >= a);
    try std.testing.expect(nowSecs() > 1_700_000_000); // 2023-11 之后
}
