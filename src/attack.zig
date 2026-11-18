//! 攻击特征检测：SQL 注入 / XSS / 路径穿越与探测 / 命令注入。
//!
//! 移植自 Rust `Pek.RWaf::attack`（名单、规范化口径、双重编码绕过处理逐项对齐）：
//! 检测对象是「路径 + 查询串 + 表单/JSON 体」经百分号解码（含一次双重解码）后的规范化文本
//! （折叠空白 + ASCII 小写）。
//!
//! 与数据库层参数化查询是纵深关系：本模块是外围第一道，业务层 SQL 参数化是内部根本防线。

const std = @import("std");

/// 攻击类型。
pub const AttackKind = enum {
    sqli,
    path,
    cmd,
    xss,

    /// 中文名（日志用）。
    pub fn nameCn(self: AttackKind) []const u8 {
        return switch (self) {
            .sqli => "SQL 注入",
            .xss => "XSS",
            .path => "路径穿透/敏感路径探测",
            .cmd => "命令注入",
        };
    }
};

/// 类别位（`u8` 是 `Copy`，可直接做 memo 值，不产生分配）。
pub const K_SQLI: u8 = 1;
pub const K_PATH: u8 = 2;
pub const K_CMD: u8 = 4;
pub const K_XSS: u8 = 8;
/// 全部类别。
pub const K_ALL: u8 = K_SQLI | K_PATH | K_CMD | K_XSS;

/// SQL 注入特征（规范化后 `contains` 匹配）。
pub const sqli_patterns = [_][]const u8{
    "' or ",
    "\" or ",
    "'or'",
    "\"or\"",
    " or 1=1",
    " or '1'='1",
    "' or 1=1",
    ") or (",
    "' or (",
    "union select",
    "union all select",
    "select * from",
    "select count(*) from",
    "information_schema",
    "sleep(",
    "benchmark(",
    "waitfor delay",
    "pg_sleep(",
    "dbms_pipe.receive_message",
    "xp_cmdshell",
    "into outfile",
    "load_file(",
    "drop table",
    "truncate table",
    "@@version",
    "convert(int,",
    "'--",
    "';--",
    "\" --",
    "order by 1--",
};

/// XSS 特征。
pub const xss_patterns = [_][]const u8{
    "<script",
    "</script",
    "javascript:",
    "onerror=",
    "onload=",
    "onmouseover=",
    "onfocus=",
    "srcdoc=",
    "<iframe",
    "<svg",
    "document.cookie",
    "eval(",
    "alert(",
};

/// 路径穿越 / 敏感路径探测特征。
pub const path_patterns = [_][]const u8{
    "../",
    "..\\",
    "%2e%2e",
    "..%2f",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self",
    "web.config",
    "phpmyadmin",
    "wp-admin",
    "wp-login",
    "/.env",
    "/.git/",
    "/.svn/",
    "/.aws/",
    "/.ssh/",
    "/actuator/",
    "cgi-bin/",
    "phpunit",
    "phpinfo",
    ".php",
    ".jsp",
    ".asp",
    ".cgi",
    ".env",
    ".git",
    ".sql",
    "/vendor/",
};

/// 命令注入特征（宽松，建议默认 monitor）。
pub const cmd_patterns = [_][]const u8{
    ";cat ",
    "|cat ",
    "&&cat",
    "$(",
    "`cat",
    ";/bin/",
    "&/bin/",
    "wget http",
    "curl http",
    "%0acat",
    "\ncat ",
};

/// 每线程/每请求复用的两片缓冲（解码用 + 规范化用）。
///
/// 与 Rust 版一致：规范化是每请求都要做的事，每次新建缓冲纯属浪费；
/// 复用后稳态零分配。**生命周期规则**：`check` 返回的原因切片、
/// 以及扫描中间结果都只在本对象下次被覆写前有效。
pub const Scratch = struct {
    decoded: std.ArrayList(u8) = .empty,
    norm: std.ArrayList(u8) = .empty,

    pub fn deinit(self: *Scratch, allocator: std.mem.Allocator) void {
        self.decoded.deinit(allocator);
        self.norm.deinit(allocator);
    }
};

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// URL 百分号解码（`+` 视作空格；**非法序列原样保留**）→ 追加到 `out`。
///
/// 与 zzig `url.decode` 的差异（有意为之）：后者遇到非法转义**返回错误**，
/// 适合「严格解析客户端输入」；WAF 需要「容错扫描」——攻击者故意写坏的转义
/// 必须原样进入特征匹配，而不是整段跳过。
pub fn percentDecodeInto(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    input: []const u8,
    plus_as_space: bool,
) !void {
    // 解码后长度必然 ≤ 输入长度（`%XX` 3→1、`+` 1→1）：一次预留，避免逐字节增长
    try out.ensureUnusedCapacity(allocator, input.len);
    var i: usize = 0;
    while (i < input.len) {
        const c = input[i];
        if (c == '+' and plus_as_space) {
            out.appendAssumeCapacity(' ');
            i += 1;
            continue;
        }
        if (c == '%' and i + 2 < input.len) {
            const hi = hexVal(input[i + 1]);
            const lo = hexVal(input[i + 2]);
            if (hi != null and lo != null) {
                out.appendAssumeCapacity((hi.? << 4) | lo.?);
                i += 3;
                continue;
            }
        }
        out.appendAssumeCapacity(c);
        i += 1;
    }
}

/// 百分号解码到新分配切片（便捷版；热路径请用 [`percentDecodeInto`]）。
pub fn percentDecode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try percentDecodeInto(allocator, &out, input, true);
    return out.toOwnedSlice(allocator);
}

fn isUnicodeSpace(cp: u21) bool {
    return switch (cp) {
        0x20, 0x09...0x0D, 0xA0, 0x1680, 0x2000...0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000 => true,
        else => false,
    };
}

/// 折叠空白 + ASCII 小写，多段按顺序直接相连写入 `out`（先清空、容量保留）。
///
/// 语义对齐 `dhrust::text::normalize_lower_bytes_into`：起始不留前导空格、
/// 连续空白折叠为单个空格、非 ASCII 原样保留（仅判空白）。
pub fn normalizeLowerBytes(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    parts: []const []const u8,
) !void {
    out.clearRetainingCapacity();
    // 规范化只会缩短（折叠空白）或等长（小写 / 去重编码）：一次预留总长即可
    var total: usize = 0;
    for (parts) |seg| total += seg.len;
    try out.ensureTotalCapacity(allocator, total);

    var last_space = true;
    for (parts) |seg| {
        var i: usize = 0;
        while (i < seg.len) {
            const b = seg[i];
            if (b < 0x80) {
                if (std.ascii.isWhitespace(b)) {
                    if (!last_space) {
                        out.appendAssumeCapacity(' ');
                        last_space = true;
                    }
                } else {
                    out.appendAssumeCapacity(std.ascii.toLower(b));
                    last_space = false;
                }
                i += 1;
                continue;
            }
            const seq_len = std.unicode.utf8ByteSequenceLength(b) catch 0;
            if (seq_len == 0 or i + seq_len > seg.len) {
                out.appendAssumeCapacity(b);
                last_space = false;
                i += 1;
                continue;
            }
            const cp = std.unicode.utf8Decode(seg[i .. i + seq_len]) catch 0;
            if (cp != 0 and isUnicodeSpace(cp)) {
                if (!last_space) {
                    out.appendAssumeCapacity(' ');
                    last_space = true;
                }
            } else {
                out.appendSliceAssumeCapacity(seg[i .. i + seq_len]);
                last_space = false;
            }
            i += seq_len;
        }
    }
}

/// 单段规范化（便捷版）。
pub fn normalize(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try normalizeLowerBytes(allocator, &list, &.{text});
    return list.toOwnedSlice(allocator);
}

/// 多段规范化（**零拼接**：分隔符由调用方作为独立段给出）。
pub fn normalizeParts(allocator: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    var scratch = Scratch{};
    defer scratch.deinit(allocator);
    try normalizePartsInto(allocator, &scratch, parts);
    return allocator.dupe(u8, scratch.norm.items);
}

/// 多段规范化写入复用缓冲，返回 `scratch.norm.items`（下次覆写前有效）。
pub fn normalizePartsInto(
    allocator: std.mem.Allocator,
    scratch: *Scratch,
    parts: []const []const u8,
) ![]const u8 {
    var needs_decode = false;
    for (parts) |p| {
        if (std.mem.indexOfScalar(u8, p, '%') != null or std.mem.indexOfScalar(u8, p, '+') != null) {
            needs_decode = true;
            break;
        }
    }
    if (!needs_decode) {
        try normalizeLowerBytes(allocator, &scratch.norm, parts);
        return scratch.norm.items;
    }

    scratch.decoded.clearRetainingCapacity();
    for (parts) |p| try percentDecodeInto(allocator, &scratch.decoded, p, true);
    if (std.mem.indexOfScalar(u8, scratch.decoded.items, '%') != null) {
        // 覆盖双重编码：保留「解一次」形态，再追加「解两次」形态（空格分隔防跨段误命中）
        var twice: std.ArrayList(u8) = .empty;
        defer twice.deinit(allocator);
        try percentDecodeInto(allocator, &twice, scratch.decoded.items, true);
        try scratch.decoded.ensureUnusedCapacity(allocator, twice.items.len + 1);
        scratch.decoded.appendAssumeCapacity(' ');
        scratch.decoded.appendSliceAssumeCapacity(twice.items);
    }
    try normalizeLowerBytes(allocator, &scratch.norm, &.{scratch.decoded.items});
    return scratch.norm.items;
}

/// 合并后的特征条目（编译期生成；`kind` 为类别位）。
const PatEntry = struct {
    first: u8,
    second: u8,
    text: []const u8,
    kind: u8,
};

const PAT_TOTAL = sqli_patterns.len + xss_patterns.len + path_patterns.len + cmd_patterns.len;

const pat_entries = blk: {
    @setEvalBranchQuota(20_000);
    var list: [PAT_TOTAL]PatEntry = undefined;
    var n: usize = 0;
    for (sqli_patterns) |p| {
        list[n] = .{ .first = p[0], .second = p[1], .text = p, .kind = K_SQLI };
        n += 1;
    }
    for (xss_patterns) |p| {
        list[n] = .{ .first = p[0], .second = p[1], .text = p, .kind = K_XSS };
        n += 1;
    }
    for (path_patterns) |p| {
        list[n] = .{ .first = p[0], .second = p[1], .text = p, .kind = K_PATH };
        n += 1;
    }
    for (cmd_patterns) |p| {
        list[n] = .{ .first = p[0], .second = p[1], .text = p, .kind = K_CMD };
        n += 1;
    }
    break :blk list;
};

/// 首字节分桶的特征索引：**一次线性扫描**替代 77 次 `indexOf`。
///
/// 为什么：旧实现每类调 `hitAny`，77 个 pattern 各做一次 `std.mem.indexOf`，
/// 每次都对整段文本从头扫（64 字节文本实测约 6.8 µs/请求，几乎全是这部分）。
/// 现在按「首字节 → 桶」把 77 条特征编进表，扫描时每个位置只查一次 256 项小表，
/// 仅当首字节命中且**第二字节**也一致时才做一次等长比较；桶内条目数最多 10 条。
///
/// 与旧实现语义一致：任意位置命中即计入对应类别位；`mask` 限定查哪几类。
const ScanIndex = struct {
    const Range = struct { start: u16, end: u16 };

    const table = blk: {
        @setEvalBranchQuota(50_000);
        var counts: [256]u16 = @splat(0);
        for (pat_entries) |e| counts[e.first] += 1;
        var ranges: [256]Range = undefined;
        var acc: u16 = 0;
        for (0..256) |c| {
            ranges[c] = .{ .start = acc, .end = acc + counts[c] };
            acc += counts[c];
        }
        var cursor: [256]u16 = @splat(0);
        for (0..256) |c| cursor[c] = ranges[c].start;
        var out: [PAT_TOTAL]PatEntry = undefined;
        for (pat_entries) |e| {
            out[cursor[e.first]] = e;
            cursor[e.first] += 1;
        }
        break :blk .{ .entries = out, .ranges = ranges };
    };

    fn scan(text: []const u8, mask: u8) u8 {
        if (text.len < 2) return 0;
        var bits: u8 = 0;
        const last = text.len - 1;
        var i: usize = 0;
        while (i < last) : (i += 1) {
            const r = table.ranges[text[i]];
            if (r.start == r.end) continue;
            const second = text[i + 1];
            var j: usize = r.start;
            while (j < r.end) : (j += 1) {
                const e = table.entries[j];
                if (e.second != second) continue;
                if (e.kind & mask == 0) continue;
                if (e.text.len > text.len - i) continue;
                if (std.mem.startsWith(u8, text[i..], e.text)) {
                    bits |= e.kind;
                    if (bits & mask == mask) return bits;
                }
            }
        }
        return bits;
    }
};

fn bitsOf(text: []const u8, mask: u8) u8 {
    return ScanIndex.scan(text, mask);
}

/// 扫描多段文本，返回命中的类别位（`mask` 限定只查哪几类）。
///
/// 复用 `scratch`（稳态零分配）。
pub fn scanBitsWith(
    allocator: std.mem.Allocator,
    scratch: *Scratch,
    parts: []const []const u8,
    mask: u8,
) !u8 {
    const text = try normalizePartsInto(allocator, scratch, parts);
    return bitsOf(text, mask);
}

/// 扫描多段文本（自带一次性缓冲；非热路径/测试用）。
pub fn scanBits(
    allocator: std.mem.Allocator,
    parts: []const []const u8,
    mask: u8,
) !u8 {
    var scratch = Scratch{};
    defer scratch.deinit(allocator);
    return scanBitsWith(allocator, &scratch, parts, mask);
}

/// 只做「路径穿越 / 敏感路径」检测（静态资源专用）。
pub fn scanPathBitsWith(
    allocator: std.mem.Allocator,
    scratch: *Scratch,
    path: []const u8,
    query: []const u8,
) !u8 {
    return scanBitsWith(allocator, scratch, &.{ path, "?", query }, K_PATH);
}

/// 只做「路径穿越 / 敏感路径」检测（一次性缓冲）。
pub fn scanPathBits(allocator: std.mem.Allocator, path: []const u8, query: []const u8) !u8 {
    return scanBits(allocator, &.{ path, "?", query }, K_PATH);
}

/// 综合扫描（路径 + 查询串 + body）。
pub fn scanAllBitsWith(
    allocator: std.mem.Allocator,
    scratch: *Scratch,
    path: []const u8,
    query: []const u8,
    body: []const u8,
) !u8 {
    return scanBitsWith(allocator, scratch, &.{ path, "?", query, " ", body }, K_ALL);
}

/// 综合扫描（一次性缓冲）。
pub fn scanAllBits(
    allocator: std.mem.Allocator,
    path: []const u8,
    query: []const u8,
    body: []const u8,
) !u8 {
    return scanBits(allocator, &.{ path, "?", query, " ", body }, K_ALL);
}

/// 类别位 → 类别列表（顺序：SQLi、路径、命令、XSS），写入调用方切片，返回实际长度。
pub fn kindsFromBits(bits: u8, out: *[4]AttackKind) usize {
    var n: usize = 0;
    if (bits & K_SQLI != 0) {
        out[n] = .sqli;
        n += 1;
    }
    if (bits & K_PATH != 0) {
        out[n] = .path;
        n += 1;
    }
    if (bits & K_CMD != 0) {
        out[n] = .cmd;
        n += 1;
    }
    if (bits & K_XSS != 0) {
        out[n] = .xss;
        n += 1;
    }
    return n;
}

test "percentDecode 口径" {
    const a = std.testing.allocator;
    const cases = [_]struct { in: []const u8, want: []const u8 }{
        .{ .in = "a%20b", .want = "a b" },
        .{ .in = "a+b", .want = "a b" },
        .{ .in = "%2e%2e%2f", .want = "../" },
        .{ .in = "%E4%B8%AD", .want = "中" },
        .{ .in = "100%", .want = "100%" },
        .{ .in = "%zz", .want = "%zz" },
        // 非法十六进制对不参与解码：`%` 原样保留，`+` 仍按空格处理
        .{ .in = "%+1", .want = "% 1" },
    };
    for (cases) |c| {
        const got = try percentDecode(a, c.in);
        defer a.free(got);
        try std.testing.expectEqualStrings(c.want, got);
    }
}

test "SQL 注入与双重编码绕过" {
    const a = std.testing.allocator;
    try std.testing.expect(0 != try scanAllBits(a, "/api/cards", "q=1' or 1=1--", ""));
    try std.testing.expect(0 != try scanAllBits(a, "/api/x", "id=1 union select password from users", ""));
    try std.testing.expect(0 != try scanAllBits(a, "/api/x", "name=admin'; select sleep(5)--", ""));
    // 双重编码
    try std.testing.expect(0 != try scanAllBits(a, "/api/x", "q=1%2527%20or%201=1", ""));
}

test "正常输入不误报" {
    const a = std.testing.allocator;
    const bits = try scanAllBits(a, "/cards", "q=%E6%8B%9B%E5%95%86%E7%BB%8F%E5%85%B8%E7%99%BD%E9%87%91%E5%8D%A1&page=1", "");
    try std.testing.expectEqual(@as(u8, 0), bits);
    const bits2 = try scanAllBits(a, "/api/my/cardSave", "", "{\"cardTail\":\"8888\",\"alias\":\"我的卡\"}");
    try std.testing.expectEqual(@as(u8, 0), bits2);
}

test "路径与静态资源只查路径穿越" {
    const a = std.testing.allocator;
    try std.testing.expect(0 != try scanPathBits(a, "/a/../../etc/passwd", ""));
    try std.testing.expectEqual(@as(u8, 0), try scanPathBits(a, "/assets/app.js", "v=1"));
    // 内容是脚本片段但路径正常 → 静态资源扫描不误报
    try std.testing.expectEqual(@as(u8, 0), try scanPathBits(a, "/assets/app.js", "q=' or 1=1"));
}

test "空白折叠与大小写" {
    const a = std.testing.allocator;
    const n = try normalize(a, "  A\t\tb \n C  ");
    defer a.free(n);
    try std.testing.expectEqualStrings("a b c ", n);
}

test "Scratch 复用不残留" {
    const a = std.testing.allocator;
    var scratch = Scratch{};
    defer scratch.deinit(a);
    const first = try scanAllBitsWith(a, &scratch, "/x", "q=1' or 1=1--", "");
    try std.testing.expect(first & K_SQLI != 0);
    const second = try scanAllBitsWith(a, &scratch, "/x", "q=hello", "");
    try std.testing.expectEqual(@as(u8, 0), second);
}

/// 对照实现：改造前「每组逐条 indexOf」的语义（只用于测试，保证新扫描器等价）。
fn legacyHitAny(text: []const u8, patterns: []const []const u8) bool {
    for (patterns) |p| {
        if (std.mem.indexOf(u8, text, p) != null) return true;
    }
    return false;
}

fn legacyBitsOf(text: []const u8, mask: u8) u8 {
    var bits: u8 = 0;
    if (mask & K_SQLI != 0 and legacyHitAny(text, sqli_patterns[0..])) bits |= K_SQLI;
    if (mask & K_PATH != 0 and legacyHitAny(text, path_patterns[0..])) bits |= K_PATH;
    if (mask & K_CMD != 0 and legacyHitAny(text, cmd_patterns[0..])) bits |= K_CMD;
    if (mask & K_XSS != 0 and legacyHitAny(text, xss_patterns[0..])) bits |= K_XSS;
    return bits;
}

test "首字节索引扫描与逐条 indexOf 语义等价" {
    const samples = [_][]const u8{
        "",
        "a",
        "/api/orders?page=2&size=20",
        "id=1' or 1=1--",
        "q=1%27%20or%201%3D1--",
        "q=<script>alert(1)</script>",
        "/.env",
        "/assets/app.js",
        "path=../../etc/passwd",
        "x=%2e%2e%2f",
        ";cat /etc/passwd",
        "\ncat /tmp/x",
        "union all select * from users",
        "javascript:alert(1)",
        "select count(*) from t",
        "normal text mentioning union and select separately",
        "a or b",
        "order by 1--",
        "user-agent: Googlebot/2.1",
        "\u{4e2d}\u{6587}\u{6d4b}\u{8bd5}",
    };
    for (samples) |s| {
        try std.testing.expectEqual(legacyBitsOf(s, K_ALL), ScanIndex.scan(s, K_ALL));
        try std.testing.expectEqual(legacyBitsOf(s, K_PATH), ScanIndex.scan(s, K_PATH));
        try std.testing.expectEqual(legacyBitsOf(s, K_SQLI | K_XSS), ScanIndex.scan(s, K_SQLI | K_XSS));
    }
}
