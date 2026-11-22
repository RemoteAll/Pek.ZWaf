//! Pek.ZWaf —— Zig 版 Web 应用防火墙（WAF）。
//!
//! 功能对齐两个参考实现：
//! - Rust `G:\Code\Rust\Pek.RWaf`（决策链、爬虫分级、攻击特征、CC 限速、接口级限流、统计）；
//! - C#  `G:\Code\Pek.FrameWork\Pek.WAF`（Ruleset JSON 规则引擎格式，两边共用同一份规则）。
//!
//! 接入 Zig 项目的形态与 Pek.RWaf 一致：`router.useMiddleware(waf.middleware())` 一行接入；
//! 需要「不收 body 就拒绝」时，用 `waf.checkHead()` 挂到 HTTP 层的早拒钩子。
//!
//! 内存口径：配置与编译后的规则由一个 arena 持有，随 `Waf.deinit` / 热重载整体释放；
//! 请求视图（[`WafRequest`]）全是借用切片，构造零分配。

const std = @import("std");

pub const bots = @import("bots.zig");
pub const attack = @import("attack.zig");
pub const wafreq = @import("wafreq.zig");
pub const config = @import("config.zig");
pub const stats = @import("stats.zig");
pub const ratelimit = @import("ratelimit.zig");
pub const rules = @import("rules.zig");
pub const clock = @import("clock.zig");
pub const regex = @import("regex.zig");
pub const waf = @import("waf.zig");
pub const throttle = @import("throttle.zig");
pub const gen = @import("gen.zig");

pub const BotKind = bots.BotKind;
pub const AttackKind = attack.AttackKind;
pub const WafRequest = wafreq.WafRequest;
pub const WafConfig = config.WafConfig;
pub const RouteLimit = config.RouteLimit;
pub const WafMode = config.Mode;
pub const Action = config.Action;
pub const WafStats = stats.WafStats;
pub const WafStatsSnapshot = stats.Snapshot;
pub const BlockKind = stats.BlockKind;
pub const WindowLimiter = ratelimit.WindowLimiter;
pub const Waf = waf.Waf;
pub const Verdict = waf.Verdict;
pub const Stage = waf.Stage;
pub const HeadInput = waf.HeadInput;
pub const ServerGuard = waf.ServerGuard;
pub const Throttle = throttle.Throttle;
pub const ThrottleConfig = throttle.ThrottleConfig;
pub const ThrottleRule = throttle.ThrottleRule;
pub const RateValve = throttle.RateValve;
pub const ThrottleVerdict = throttle.ThrottleVerdict;
pub const Policy = throttle.Policy;
pub const WhenNull = throttle.WhenNull;

/// 依赖冒烟：确认 zzig 模块可用。
fn smokeDependency() void {
    _ = @import("zzig").web.router;
}

test "zzig 依赖可用" {
    smokeDependency();
    _ = std;
}

test {
    std.testing.refAllDecls(@This());
}
