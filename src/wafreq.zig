//! 请求视图与 IP 匹配工具（CIDR / 通配符 / 列表 / 文件）。
//!
//! 与 Rust 版的**结构差异（有意为之）**：Rust 侧把 path/query/UA/IP 复制进 owned `String`
//! 再复用缓冲；Zig 的字符串是切片，因此本视图**全是借用切片**——除了「剥端口」与
//! 「body 预览截断」这类子切片操作，构造请求视图**零分配**。

const std = @import("std");
const zzig = @import("zzig");

/// WAF 请求视图。
///
/// 所有字段都是**借用**（指向原始请求或调用方缓冲）：视图本身不拥有内存、不需要释放。
pub const WafRequest = struct {
    /// 请求路径（不含查询串）
    path: []const u8 = "",
    /// HTTP 方法
    method: []const u8 = "",
    /// 查询串（原始形态，未解码）
    query: []const u8 = "",
    /// User-Agent（缺省为空串）
    user_agent: []const u8 = "",
    /// 客户端 IP（已剥离端口；未知为空串）
    remote_ip: []const u8 = "",
    /// Content-Type（缺省为空串）
    content_type: []const u8 = "",
    /// 请求体文本预览（默认空——由门面在「真要扫 body」时填写）
    body_text: []const u8 = "",
    /// 请求头（供签名校验 / CSRF / 规则引擎取 Origin、Host、Sec-Fetch-Site）
    headers: []const std.http.Header = &.{},

    /// 从 zzig 路由请求构造（零分配）。
    pub fn fromRouterRequest(req: zzig.web.router.Request) WafRequest {
        return .{
            .path = req.path,
            .method = req.method,
            .query = req.query,
            .user_agent = req.header("user-agent") orelse "",
            .remote_ip = stripPort(req.remote_addr orelse ""),
            .content_type = req.header("content-type") orelse "",
            .headers = req.headers,
        };
    }

    /// 从 zzig HTTP 服务端请求视图构造（零分配；早拒钩子用）。
    pub fn fromServerView(view: zzig.http_server.RequestView) WafRequest {
        return .{
            .path = view.path,
            .method = @tagName(view.method),
            .query = view.query,
            .user_agent = headerOf(view.headers, "user-agent") orelse "",
            .remote_ip = "",
            .content_type = headerOf(view.headers, "content-type") orelse "",
            .headers = view.headers,
        };
    }

    /// 取请求头（大小写不敏感）。
    pub fn header(self: WafRequest, name: []const u8) ?[]const u8 {
        return headerOf(self.headers, name);
    }

    /// 用体预览覆写（`limit` 为 0 或 body 为空时清空）。
    pub fn withBodyPreview(self: WafRequest, body: []const u8, limit: usize) WafRequest {
        var out = self;
        out.body_text = if (limit == 0 or body.len == 0) "" else body[0..@min(body.len, limit)];
        return out;
    }

    /// 供规则引擎读取的成员值（对齐 C# `WebRequest` 常用属性；未知成员返回空串）。
    pub fn member(self: WafRequest, name: []const u8) []const u8 {
        if (eqIgnoreCase(name, "Path")) return self.path;
        if (eqIgnoreCase(name, "Method")) return self.method;
        if (eqIgnoreCase(name, "UserAgent")) return self.user_agent;
        if (eqIgnoreCase(name, "RemoteIp") or eqIgnoreCase(name, "IpAddress") or eqIgnoreCase(name, "RemoteIpAddress")) return self.remote_ip;
        if (eqIgnoreCase(name, "QueryString")) return self.query;
        if (eqIgnoreCase(name, "ContentType")) return self.content_type;
        // IpCountry 需外部 GeoIP 数据（未内置）
        return "";
    }
};

fn headerOf(headers: []const std.http.Header, name: []const u8) ?[]const u8 {
    for (headers) |h| {
        if (eqIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

/// 不区分大小写比较（两端都可能存在大小写差异）。
pub fn eqIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

/// 不区分大小写的子串包含。
pub fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    const last = haystack.len - needle.len;
    while (i <= last) : (i += 1) {
        var j: usize = 0;
        while (j < needle.len) : (j += 1) {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(needle[j])) break;
        }
        if (j == needle.len) return true;
    }
    return false;
}

fn trimList(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r\n");
}

/// 剥离 `IP:Port` 中的端口（兼容 `[::1]:123`；裸 IPv6 / 非数字端口原样返回）。
///
/// 与 `dhrust::net::strip_port` 同口径；返回**子切片**，零分配。
pub fn stripPort(addr: []const u8) []const u8 {
    const a = trimList(addr);
    if (a.len == 0) return a;
    if (a[0] == '[') {
        if (std.mem.indexOfScalar(u8, a, ']')) |end| return a[1..end];
        return a;
    }
    var colons: usize = 0;
    for (a) |c| {
        if (c == ':') colons += 1;
    }
    if (colons != 1) return a; // 无端口 / 裸 IPv6 / 非法
    const idx = std.mem.lastIndexOfScalar(u8, a, ':').?;
    const port = a[idx + 1 ..];
    if (port.len == 0) return a;
    for (port) |c| {
        if (!std.ascii.isDigit(c)) return a;
    }
    return a[0..idx];
}

/// 是否回环地址（含 IPv4 映射 `::ffff:127.0.0.1`）。
pub fn isLoopback(ip_in: []const u8) bool {
    const ip = trimList(ip_in);
    const ip2 = if (std.mem.startsWith(u8, ip, "::ffff:")) ip["::ffff:".len..] else ip;
    if (std.mem.eql(u8, ip2, "::1")) return true;
    if (std.mem.eql(u8, ip2, "0:0:0:0:0:0:0:1")) return true;
    if (eqIgnoreCase(ip2, "localhost")) return true;
    return std.mem.startsWith(u8, ip2, "127.");
}

/// 解析 IPv4 为 32 位整数（严格四段、每段 0..255）。
pub fn parseIpv4(ip: []const u8) ?u32 {
    var it = std.mem.splitScalar(u8, trimList(ip), '.');
    var value: u32 = 0;
    var n: usize = 0;
    while (it.next()) |seg| {
        if (n >= 4) return null;
        if (seg.len == 0 or seg.len > 3) return null;
        var b: u32 = 0;
        for (seg) |c| {
            if (!std.ascii.isDigit(c)) return null;
            b = b * 10 + (c - '0');
        }
        if (b > 255) return null;
        value = (value << 8) | b;
        n += 1;
    }
    if (n != 4) return null;
    return value;
}

/// 判断 IP 是否命中单条规则（精确 / CIDR / 通配符 `192.168.*.*` / `*`）。
///
/// CIDR 这里**没有**复用 `zzig.Net.parseCidr`：实测它在 `/0`（`0.0.0.0/0`）上算
/// `@intCast(32 - prefix_len)` 时 panic（u5 装不下 32）——WAF 必须容错而不是崩进程。
/// 已在本地实现等价解析（并正确处理 `/0`、非法前缀退化精确匹配）。
pub fn ipMatch(ip_in: []const u8, rule_in: []const u8) bool {
    const ip = trimList(ip_in);
    const rule = trimList(rule_in);
    if (rule.len == 0 or ip.len == 0) return false;
    if (rule.len == 1 and rule[0] == '*') return true;

    if (std.mem.indexOfScalar(u8, rule, '/') != null) {
        const parsed = parseCidrRule(rule) orelse return eqIgnoreCase(ip, rule);
        const ipv4 = parseIpv4(ip) orelse return false;
        const prefix: u32 = parsed.prefix;
        const mask: u32 = if (prefix == 0) 0 else ~@as(u32, 0) << @intCast(32 - prefix);
        return (ipv4 & mask) == (parsed.network & mask);
    }
    if (std.mem.indexOfScalar(u8, rule, '*') != null) {
        return wildcardMatch(ip, rule);
    }
    return eqIgnoreCase(ip, rule);
}

const CidrRule = struct { network: u32, prefix: u32 };

/// 容错解析 `a.b.c.d/N`（前缀 0..32；非法返回 null）。
fn parseCidrRule(text: []const u8) ?CidrRule {
    const slash = std.mem.indexOfScalar(u8, text, '/') orelse return null;
    const net = parseIpv4(text[0..slash]) orelse return null;
    const prefix = std.fmt.parseUnsigned(u32, trimList(text[slash + 1 ..]), 10) catch return null;
    if (prefix > 32) return null;
    return .{ .network = net, .prefix = prefix };
}

fn wildcardMatch(ip: []const u8, pattern: []const u8) bool {
    var ip_it = std.mem.splitScalar(u8, ip, '.');
    var pat_it = std.mem.splitScalar(u8, pattern, '.');
    var n: usize = 0;
    while (true) {
        const a = ip_it.next();
        const b = pat_it.next();
        if (a == null and b == null) return n == 4;
        if (a == null or b == null) return false;
        n += 1;
        if (std.mem.eql(u8, b.?, "*")) continue;
        if (!std.mem.eql(u8, a.?, b.?)) return false;
    }
}

/// 判断 IP 是否在 `net/mask` 子网内（`net` 为 IPv4 字面量，`mask` 为前缀位数文本）。
///
/// 规则引擎的 `InSubnet` 操作符把网段拆成「net + mask 两个输入」，这里直接吃这两段，
/// 避免为了拼 `net/mask` 字符串付一次分配。
pub fn ipInSubnet(ip: []const u8, net: []const u8, mask_text: []const u8) bool {
    const prefix = std.fmt.parseUnsigned(u32, trimList(mask_text), 10) catch
        return eqIgnoreCase(trimList(ip), trimList(net));
    if (prefix > 32) return false;
    const ipv4 = parseIpv4(ip) orelse return eqIgnoreCase(trimList(ip), trimList(net));
    const netv4 = parseIpv4(net) orelse return false;
    const mask: u32 = if (prefix == 0) 0 else ~@as(u32, 0) << @intCast(32 - prefix);
    return (ipv4 & mask) == (netv4 & mask);
}

/// 判断 IP 是否命中列表（分隔符：`,` `;` 空白与换行均可混合）。
pub fn ipInList(ip: []const u8, list: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, list, ";, \t\r\n");
    while (it.next()) |rule| {
        if (ipMatch(ip, rule)) return true;
    }
    return false;
}

/// 从黑/白名单文件加载（逐行；忽略空行与 `#` 注释）。
///
/// 返回的所有切片都分配自 `allocator`（通常为 Waf 的 arena），调用方无需逐个释放。
pub fn loadIpFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ![][]const u8 {
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(4 * 1024 * 1024)) catch return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        const t = trimList(line);
        if (t.len == 0 or t[0] == '#') continue;
        try out.append(allocator, t);
    }
    return out.toOwnedSlice(allocator);
}

/// 请求体是否「文本类」内容（可安全按 UTF-8 扫描）。
pub fn isTextContentType(content_type: []const u8) bool {
    return std.mem.startsWith(u8, content_type, "text/") or
        containsIgnoreCase(content_type, "json") or
        containsIgnoreCase(content_type, "x-www-form-urlencoded") or
        containsIgnoreCase(content_type, "xml");
}

/// 静态资源扩展名（CC 限速不计数、攻击扫描只查路径）。
pub const static_exts = [_][]const u8{
    "js",   "css",   "png", "jpg", "jpeg", "gif", "svg", "ico",  "webp", "avif", "bmp",
    "woff", "woff2", "ttf", "otf", "eot",  "map", "mp4", "webm", "mp3",  "ogg",
};

/// 是否静态资源（看路径最后一段的扩展名）。
pub fn isStaticAsset(path: []const u8) bool {
    const p = if (std.mem.indexOfAny(u8, path, "?#")) |i| path[0..i] else path;
    const last = if (std.mem.lastIndexOfScalar(u8, p, '/')) |i| p[i + 1 ..] else p;
    const dot = std.mem.lastIndexOfScalar(u8, last, '.') orelse return false;
    const ext = last[dot + 1 ..];
    for (static_exts) |e| {
        if (eqIgnoreCase(ext, e)) return true;
    }
    return false;
}

test "stripPort 口径" {
    const t = std.testing;
    try t.expectEqualStrings("192.168.1.5", stripPort("192.168.1.5:51234"));
    try t.expectEqualStrings("127.0.0.1", stripPort("127.0.0.1"));
    try t.expectEqualStrings("::1", stripPort("[::1]:8080"));
    try t.expectEqualStrings("::1", stripPort("::1"));
    try t.expectEqualStrings("", stripPort(""));
    try t.expectEqualStrings("host:abc", stripPort("host:abc"));
}

test "IP 匹配" {
    const t = std.testing;
    try t.expect(ipMatch("192.168.1.100", "192.168.1.100"));
    try t.expect(!ipMatch("192.168.1.101", "192.168.1.100"));
    try t.expect(ipMatch("10.1.2.3", "10.0.0.0/8"));
    try t.expect(!ipMatch("11.1.2.3", "10.0.0.0/8"));
    try t.expect(ipMatch("192.168.1.5", "192.168.*.*"));
    try t.expect(!ipMatch("192.169.1.5", "192.168.*.*"));
    try t.expect(ipMatch("192.168.1.5", "0.0.0.0/0"));
    try t.expect(ipMatch("::1", "::1"));
    try t.expect(ipMatch("1.2.3.4", "*"));
}

test "IP 列表混合分隔符" {
    const list = "192.168.1.100, 10.0.0.0/8; 172.16.*.*\n203.0.113.9";
    try std.testing.expect(ipInList("10.5.5.5", list));
    try std.testing.expect(ipInList("172.16.9.9", list));
    try std.testing.expect(ipInList("203.0.113.9", list));
    try std.testing.expect(!ipInList("8.8.8.8", list));
}

test "回环判定" {
    try std.testing.expect(isLoopback("127.0.0.1"));
    try std.testing.expect(isLoopback("127.5.6.7"));
    try std.testing.expect(isLoopback("::1"));
    try std.testing.expect(isLoopback("::ffff:127.0.0.1"));
    try std.testing.expect(!isLoopback("10.0.0.1"));
}

test "静态资源与文本类型" {
    try std.testing.expect(isStaticAsset("/assets/app.js"));
    try std.testing.expect(isStaticAsset("/img/logo.PNG?v=2"));
    try std.testing.expect(!isStaticAsset("/api/cards"));
    try std.testing.expect(isTextContentType("application/json; charset=utf-8"));
    try std.testing.expect(isTextContentType("application/x-www-form-urlencoded"));
    try std.testing.expect(!isTextContentType("image/png"));
}

test "规则成员取值" {
    const req = WafRequest{
        .path = "/api/test",
        .method = "GET",
        .remote_ip = "1.2.3.4",
        .user_agent = "curl/8.0",
        .headers = &.{.{ .name = "Host", .value = "example.com" }},
    };
    try std.testing.expectEqualStrings("/api/test", req.member("Path"));
    try std.testing.expectEqualStrings("1.2.3.4", req.member("RemoteIp"));
    try std.testing.expectEqualStrings("1.2.3.4", req.member("IpAddress"));
    try std.testing.expectEqualStrings("", req.member("IpCountry"));
    try std.testing.expectEqualStrings("example.com", req.header("host").?);
}
