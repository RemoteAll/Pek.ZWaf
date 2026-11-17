//! 正则引擎薄封装（供规则引擎 `IsMatch` 使用）。
//!
//! 实现**不是新写的**：`vendor/regex.zig` 是生态内既有实现
//! （`G:\Code\Zig\ZZUI\src\regex.zig`，554 行回溯引擎，支持字面量/转义/字符类/分组/
//! 交替/量词/锚点/`\b`，带步数上限防回溯爆炸）的**字节级拷贝**。
//!
//! 为什么不直接 `@import("zzui")`：ZZUI 是 GUI 工程（拖 Win32 依赖），
//! WAF 不该为一个正则把整套 GUI 拉进服务端进程。
//! **同步纪律**：ZZUI 侧改了 `regex.zig` 要同步拷过来（或后续下沉到 zzig 后改为依赖）。

const impl = @import("vendor/regex.zig");

pub const Match = impl.Match;
pub const Result = impl.Result;
pub const ICASE = impl.ICASE;
pub const MULTILINE = impl.MULTILINE;
pub const DOTALL = impl.DOTALL;

/// 在 `text` 中查找模式（`from` 为起始字节偏移）。
pub fn search(
    pattern: []const u8,
    flags: u32,
    text: []const u8,
    from: usize,
    m: *Match,
    err_text: ?*[]const u8,
) Result {
    return impl.search(pattern, flags, text, from, m, err_text);
}

/// 是否匹配（任意位置命中）。
pub fn isMatch(pattern: []const u8, text: []const u8) bool {
    var m: Match = .{};
    return search(pattern, 0, text, 0, &m, null) == .found;
}

/// 校验模式是否合法（配置期用，避免带病上线）。
pub fn validate(pattern: []const u8) bool {
    var m: Match = .{};
    return search(pattern, 0, "", 0, &m, null) != .invalid_pattern;
}

test "基本匹配与非法模式" {
    try std.testing.expect(isMatch("^/admin", "/admin/users"));
    try std.testing.expect(!isMatch("^/admin", "/api/admin"));
    try std.testing.expect(isMatch("^(curl|python)", "python-requests/2.31"));
    try std.testing.expect(!validate("(unclosed"));
}

const std = @import("std");
