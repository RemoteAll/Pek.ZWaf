//! 自定义规则引擎：**与 C# `Pek.WAF` 的 Ruleset JSON 格式兼容**
//! （同一份规则文件可双端共用），并在 C# 操作符全集之上新增 `IsBotKind`。
//!
//! 规则 JSON（根/逻辑节点/叶节点一体，`OrElse` 任一命中、`AndAlso` 全部命中；命中即拦截）：
//! ```json
//! { "Operator": "OrElse", "Rules": [
//!   { "MemberName": "Path", "Operator": "EndsWith", "Inputs": [".php"] },
//!   { "MemberName": "UserAgent", "Operator": "IsBotKind", "TargetValue": "Malicious" }
//! ] }
//! ```
//! 支持成员：`Path` / `Method` / `UserAgent` / `RemoteIp`(`IpAddress`) / `QueryString` / `ContentType`；
//! 操作符：`EndsWith`/`StartsWith`/`Contains`/`Equals`/`IsMatch`(正则)/`IsInInput`/`IsInteger`/`IsDouble`/
//! `IsSingle`/`IsDecimal`/`IsInIpList`/`IsNotInIpList`/`InSubnet`/`IpInFile`/`ContainsUserAgent`/
//! `NotContainsUserAgent`/`IsInUserAgentList`/`IsNotInUserAgentList`/`UserAgentStartsWith`/
//! `UserAgentIsEmpty`/`UserAgentIsNotEmpty`/`IsBotKind`；`Negate: true` 取反；
//! `IpCountry` 需外部 GeoIP 数据（未内置，恒不命中）。

const std = @import("std");

const bots = @import("bots.zig");
const regex = @import("regex.zig");
const wafreq = @import("wafreq.zig");
const WafRequest = wafreq.WafRequest;

/// 规则节点（C# 兼容 JSON 形态；字段名即 JSON 键名）。
pub const Rule = struct {
    RuleId: ?[]const u8 = null,
    MemberName: ?[]const u8 = null,
    Operator: ?[]const u8 = null,
    Inputs: ?[]const std.json.Value = null,
    TargetValue: ?[]const u8 = null,
    Negate: bool = false,
    Rules: ?[]const Rule = null,
};

/// 编译后的规则节点。
pub const Compiled = union(enum) {
    /// 逻辑组合（`and_ = true` 为 AndAlso）
    logical: struct {
        and_: bool,
        children: []const Compiled,
    },
    /// 叶子条件
    leaf: struct {
        /// 人类可读描述（日志）
        label: []const u8,
        /// 成员名（原样；求值时大小写不敏感）
        member: []const u8,
        /// 操作符（已小写）
        op: []const u8,
        /// 输入值（已字符串化；IpInFile 已展开为文件内容）
        inputs: []const []const u8,
        /// 目标值
        target: []const u8,
        /// 取反
        negate: bool,
        /// IsMatch 的模式（编译期已校验合法性）
        pattern: ?[]const u8,
    },
};

/// 规则编译错误（调用方负责把「哪个文件、哪个规则」写进日志）。
pub const CompileError = error{
    InvalidRegex,
    IpFileEmpty,
    OutOfMemory,
};

fn lowerEq(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

/// 解析规则 JSON（分配自 `arena`，调用方无需逐个释放）。
pub fn parseJson(arena: std.mem.Allocator, json_text: []const u8) !Rule {
    return std.json.parseFromSliceLeaky(Rule, arena, json_text, .{
        .ignore_unknown_fields = true,
    });
}

/// 从文件解析规则 JSON。
pub fn parseFile(io: std.Io, arena: std.mem.Allocator, path: []const u8) !Rule {
    const text = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(4 * 1024 * 1024));
    return parseJson(arena, text);
}

fn valueToString(arena: std.mem.Allocator, v: std.json.Value) ![]const u8 {
    return switch (v) {
        .string => |s| s,
        .number_string => |s| s,
        .integer => |i| try std.fmt.allocPrint(arena, "{d}", .{i}),
        .float => |f| try std.fmt.allocPrint(arena, "{d}", .{f}),
        .bool => |b| if (b) "true" else "false",
        .null => "",
        else => "",
    };
}

/// 编译规则树（`base_dir` 用于 `IpInFile` 的相对路径解析）。
pub fn compile(arena: std.mem.Allocator, rule: *const Rule, io: std.Io, base_dir: []const u8) CompileError!Compiled {
    return compileInner(arena, rule, io, base_dir);
}

fn compileInner(arena: std.mem.Allocator, rule: *const Rule, io: std.Io, base_dir: []const u8) CompileError!Compiled {
    if (rule.Rules) |children_raw| {
        if (children_raw.len > 0) {
            const and_ = if (rule.Operator) |o| lowerEq(o, "AndAlso") else false;
            const children = try arena.alloc(Compiled, children_raw.len);
            for (children_raw, 0..) |*child, i| {
                children[i] = try compileInner(arena, child, io, base_dir);
            }
            return .{ .logical = .{ .and_ = and_, .children = children } };
        }
    }

    const member = rule.MemberName orelse "";
    const op_raw = rule.Operator orelse "";
    const op = try std.ascii.allocLowerString(arena, op_raw);
    const target = rule.TargetValue orelse "";

    // 输入值 → 字符串列表
    var inputs: []const []const u8 = &.{};
    if (rule.Inputs) |raw| {
        const out = try arena.alloc([]const u8, raw.len);
        for (raw, 0..) |v, i| out[i] = try valueToString(arena, v);
        inputs = out;
    }

    // IpInFile：编译期展开文件内容（热重载时重新编译 → 自动重读）
    if (std.mem.eql(u8, op, "ipinfile") and inputs.len > 0) {
        const file_path = if (std.fs.path.isAbsolute(inputs[0]))
            inputs[0]
        else
            try std.fs.path.join(arena, &.{ base_dir, inputs[0] });
        const lines = wafreq.loadIpFile(io, arena, file_path) catch &.{};
        if (lines.len == 0) return error.IpFileEmpty;
        inputs = lines;
    }

    // IsMatch：编译期校验正则
    var pattern: ?[]const u8 = null;
    if (std.mem.eql(u8, op, "ismatch")) {
        const p = if (target.len > 0) target else if (inputs.len > 0) inputs[0] else "";
        if (!regex.validate(p)) return error.InvalidRegex;
        pattern = p;
    }

    const node_label = if (target.len > 0)
        try std.fmt.allocPrint(arena, "{s}/{s}({s})", .{ member, op_raw, target })
    else
        try std.fmt.allocPrint(arena, "{s}/{s}", .{ member, op_raw });

    return .{ .leaf = .{
        .label = node_label,
        .member = member,
        .op = op,
        .inputs = inputs,
        .target = target,
        .negate = rule.Negate,
        .pattern = pattern,
    } };
}

/// 求值：命中返回 `true`（语义与 C# 一致——true = 拦截）。
pub fn eval(node: *const Compiled, req: *const WafRequest) bool {
    switch (node.*) {
        .logical => |l| {
            if (l.and_) {
                for (l.children) |*c| {
                    if (!eval(c, req)) return false;
                }
                return l.children.len > 0;
            }
            for (l.children) |*c| {
                if (eval(c, req)) return true;
            }
            return false;
        },
        .leaf => |l| {
            const value = req.member(l.member);
            const result = evalLeaf(l, value, req.user_agent);
            return if (l.negate) !result else result;
        },
    }
}

/// 人类可读描述（日志用）。
pub fn label(node: *const Compiled, arena: std.mem.Allocator) []const u8 {
    switch (node.*) {
        .leaf => |l| {
            return if (l.negate)
                std.fmt.allocPrint(arena, "NOT {s}", .{l.label}) catch l.label
            else
                l.label;
        },
        .logical => |l| {
            const op = if (l.and_) "AndAlso" else "OrElse";
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(arena);
            out.appendSlice(arena, op) catch return op;
            out.append(arena, '(') catch return op;
            for (l.children, 0..) |*c, i| {
                if (i > 0) out.appendSlice(arena, ", ") catch {};
                out.appendSlice(arena, label(c, arena)) catch {};
            }
            out.append(arena, ')') catch {};
            return out.toOwnedSlice(arena) catch op;
        },
    }
}

fn hitAny(value: []const u8, inputs: []const []const u8, comptime mode: enum { ends, starts, contains }) bool {
    for (inputs) |i| {
        const matched = switch (mode) {
            .ends => endsWithIgnoreCase(value, i),
            .starts => startsWithIgnoreCase(value, i),
            .contains => wafreq.containsIgnoreCase(value, i),
        };
        if (matched) return true;
    }
    return false;
}

pub fn endsWithIgnoreCase(hay: []const u8, needle: []const u8) bool {
    if (needle.len > hay.len) return false;
    return std.ascii.eqlIgnoreCase(hay[hay.len - needle.len ..], needle);
}

pub fn startsWithIgnoreCase(hay: []const u8, needle: []const u8) bool {
    if (needle.len > hay.len) return false;
    return std.ascii.eqlIgnoreCase(hay[0..needle.len], needle);
}

fn evalLeaf(l: anytype, value: []const u8, user_agent: []const u8) bool {
    const op: []const u8 = l.op;
    if (std.mem.eql(u8, op, "endswith")) return hitAny(value, l.inputs, .ends);
    if (std.mem.eql(u8, op, "startswith")) return hitAny(value, l.inputs, .starts);
    if (std.mem.eql(u8, op, "contains")) return hitAny(value, l.inputs, .contains);
    if (std.mem.eql(u8, op, "equals") or std.mem.eql(u8, op, "equal")) {
        for (l.inputs) |i| {
            if (lowerEq(value, i)) return true;
        }
        return l.target.len > 0 and lowerEq(value, l.target);
    }
    if (std.mem.eql(u8, op, "ismatch")) {
        const p = l.pattern orelse return false;
        return regex.isMatch(p, value);
    }
    if (std.mem.eql(u8, op, "isinput")) {
        for (l.inputs) |i| {
            if (lowerEq(value, i)) return true;
        }
        return false;
    }
    if (std.mem.eql(u8, op, "isinteger")) {
        const t = std.mem.trim(u8, value, " \t\r\n");
        _ = std.fmt.parseInt(i64, t, 10) catch return false;
        return true;
    }
    if (std.mem.eql(u8, op, "isdouble") or std.mem.eql(u8, op, "issingle") or std.mem.eql(u8, op, "isdecimal")) {
        const t = std.mem.trim(u8, value, " \t\r\n");
        _ = std.fmt.parseFloat(f64, t) catch return false;
        return true;
    }
    return evalExt(l, value, user_agent);
}

fn evalExt(l: anytype, value: []const u8, user_agent: []const u8) bool {
    const op: []const u8 = l.op;
    // —— IP 系 ——
    if (std.mem.eql(u8, op, "isiniplist") or std.mem.eql(u8, op, "ipinfile")) {
        for (l.inputs) |i| {
            if (wafreq.ipInList(value, i)) return true;
        }
        return false;
    }
    if (std.mem.eql(u8, op, "isnotiniplist")) {
        for (l.inputs) |i| {
            if (wafreq.ipInList(value, i)) return false;
        }
        return true;
    }
    if (std.mem.eql(u8, op, "insubnet")) {
        if (l.inputs.len == 0) return false;
        const net = l.inputs[0];
        const mask = if (l.inputs.len > 1) l.inputs[1] else "";
        return wafreq.ipInSubnet(value, net, mask);
    }
    // —— UA 系（对 UserAgent 成员操作，忽略大小写）——
    if (std.mem.eql(u8, op, "containsuseragent")) {
        for (l.inputs) |i| {
            if (wafreq.containsIgnoreCase(user_agent, i)) return true;
        }
        return false;
    }
    if (std.mem.eql(u8, op, "notcontainsuseragent")) {
        for (l.inputs) |i| {
            if (wafreq.containsIgnoreCase(user_agent, i)) return false;
        }
        return true;
    }
    if (std.mem.eql(u8, op, "isinuseragentlist")) {
        for (l.inputs) |i| {
            if (lowerEq(user_agent, i)) return true;
        }
        return false;
    }
    if (std.mem.eql(u8, op, "isnotinuseragentlist")) {
        for (l.inputs) |i| {
            if (lowerEq(user_agent, i)) return false;
        }
        return true;
    }
    if (std.mem.eql(u8, op, "useragentstartswith")) {
        for (l.inputs) |i| {
            if (startsWithIgnoreCase(user_agent, i)) return true;
        }
        return false;
    }
    if (std.mem.eql(u8, op, "useragentisempty")) {
        return std.mem.trim(u8, user_agent, " \t\r\n").len == 0;
    }
    if (std.mem.eql(u8, op, "useragentisnotempty")) {
        return std.mem.trim(u8, user_agent, " \t\r\n").len != 0;
    }
    // —— 扩展：按爬虫分类命中 ——
    if (std.mem.eql(u8, op, "isbotkind")) {
        const wanted = if (l.target.len > 0)
            l.target
        else if (l.inputs.len > 0)
            l.inputs[0]
        else
            "";
        const kind = bots.classify(value) orelse return false;
        if (lowerEq(wanted, "any")) return true;
        if (lowerEq(wanted, "friendly")) return kind.isFriendly();
        return lowerEq(wanted, kind.nameEn());
    }
    // 未知操作符：不命中（宽容，避免误拦）
    return false;
}

// —— 测试 ——

fn testReq(ua: []const u8) WafRequest {
    return .{
        .path = "/x.php",
        .method = "GET",
        .query = "",
        .user_agent = ua,
        .remote_ip = "8.8.8.8",
        .content_type = "",
    };
}

fn compileJson(arena: std.mem.Allocator, json: []const u8) !Compiled {
    var rule = try parseJson(arena, json);
    return compile(arena, &rule, std.testing.io, ".");
}

test "C# README 示例规则原样可用" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const json =
        \\{
        \\  "Operator": "OrElse",
        \\  "Rules": [
        \\    { "MemberName": "Path", "Operator": "EndsWith", "Inputs": [".php"] },
        \\    { "MemberName": "Path", "Operator": "EndsWith", "Inputs": [".env"] },
        \\    { "MemberName": "Path", "Operator": "EndsWith", "Inputs": [".git"] }
        \\  ]
        \\}
    ;
    const compiled = try compileJson(a, json);
    const hit = testReq("Mozilla/5.0");
    try std.testing.expect(eval(&compiled, &hit));

    var miss = testReq("Mozilla/5.0");
    miss.path = "/index.html";
    try std.testing.expect(!eval(&compiled, &miss));
}

test "IP 与 UA 操作符 + Negate" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // IsInIpList（CIDR + 通配符混写）
    var ip_rule = try parseJson(a,
        \\{ "MemberName": "RemoteIp", "Operator": "IsInIpList", "Inputs": ["10.0.0.0/8, 192.168.*.*"] }
    );
    const ip_compiled = try compile(a, &ip_rule, std.testing.io, ".");
    var req = testReq("Mozilla/5.0");
    req.remote_ip = "10.1.2.3";
    try std.testing.expect(eval(&ip_compiled, &req));
    req.remote_ip = "8.8.8.8";
    try std.testing.expect(!eval(&ip_compiled, &req));

    // InSubnet（net + mask 两个输入）
    var subnet_rule = try parseJson(a,
        \\{ "MemberName": "RemoteIp", "Operator": "InSubnet", "Inputs": ["192.168.0.0", 16] }
    );
    const subnet_compiled = try compile(a, &subnet_rule, std.testing.io, ".");
    req.remote_ip = "192.168.9.9";
    try std.testing.expect(eval(&subnet_compiled, &req));
    req.remote_ip = "192.169.9.9";
    try std.testing.expect(!eval(&subnet_compiled, &req));

    // IsBotKind
    var bot_rule = try parseJson(a,
        \\{ "MemberName": "UserAgent", "Operator": "IsBotKind", "TargetValue": "Malicious" }
    );
    const bot_compiled = try compile(a, &bot_rule, std.testing.io, ".");
    try std.testing.expect(eval(&bot_compiled, &testReq("MJ12bot/v1.4")));
    try std.testing.expect(!eval(&bot_compiled, &testReq("Googlebot/2.1")));

    // Negate
    var neg_rule = try parseJson(a,
        \\{ "MemberName": "UserAgent", "Operator": "IsBotKind", "TargetValue": "friendly", "Negate": true }
    );
    const neg_compiled = try compile(a, &neg_rule, std.testing.io, ".");
    try std.testing.expect(!eval(&neg_compiled, &testReq("Googlebot/2.1")));
    try std.testing.expect(eval(&neg_compiled, &testReq("curl/8.0")));
}

test "正则与 AndAlso 嵌套" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const json =
        \\{ "Operator": "AndAlso", "Rules": [
        \\  { "MemberName": "Path", "Operator": "StartsWith", "Inputs": ["/admin"] },
        \\  { "MemberName": "UserAgent", "Operator": "IsMatch", "TargetValue": "^(curl|python)" }
        \\] }
    ;
    const compiled = try compileJson(a, json);

    var req = testReq("python-requests/2.31");
    req.path = "/admin/";
    try std.testing.expect(eval(&compiled, &req));
    req.user_agent = "Mozilla/5.0";
    try std.testing.expect(!eval(&compiled, &req));
}

test "非法正则与空 IP 文件报错" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var bad = try parseJson(a,
        \\{ "MemberName": "Path", "Operator": "IsMatch", "TargetValue": "(unclosed" }
    );
    try std.testing.expectError(error.InvalidRegex, compile(a, &bad, std.testing.io, "."));

    var bad_ip = try parseJson(a,
        \\{ "MemberName": "RemoteIp", "Operator": "IpInFile", "Inputs": [".zig-cache/not-exist-ip.txt"] }
    );
    try std.testing.expectError(error.IpFileEmpty, compile(a, &bad_ip, std.testing.io, "."));
}
