//! 爬虫分级管理：放行正常搜索引擎与 GEO-AI 抓取，拦截恶意爬虫/扫描器。
//!
//! 移植自 Rust `Pek.RWaf::bots`（名单与判定顺序逐项对齐）：
//! - `search_engine`：主流搜索引擎蜘蛛；
//! - `ai_crawler`：正常 GEO 抓取（GPTBot/ClaudeBot/PerplexityBot…）；
//! - `social_preview`：社交平台链接预览；
//! - `monitor`：灰色（记录+限速，默认不拦）；
//! - `malicious`：恶意爬虫 / 扫描器（默认拦截）；
//! - `unknown`：疑似机器人（UA 含 bot/spider/crawl 等词但不在名单）。

const std = @import("std");

/// 爬虫分类。
pub const BotKind = enum {
    search_engine,
    ai_crawler,
    social_preview,
    monitor,
    malicious,
    unknown,

    /// 是否属于默认放行的正常抓取器（搜索引擎 / AI-GEO / 社交预览）。
    pub fn isFriendly(self: BotKind) bool {
        return switch (self) {
            .search_engine, .ai_crawler, .social_preview => true,
            else => false,
        };
    }

    /// 中文类别名（日志用）。
    pub fn nameCn(self: BotKind) []const u8 {
        return switch (self) {
            .search_engine => "搜索引擎",
            .ai_crawler => "AI/GEO 抓取",
            .social_preview => "社交预览",
            .monitor => "灰色爬虫",
            .malicious => "恶意爬虫/扫描器",
            .unknown => "疑似机器人",
        };
    }

    /// 规则引擎 `IsBotKind` 的目标值（大小写不敏感）。
    pub fn nameEn(self: BotKind) []const u8 {
        return switch (self) {
            .search_engine => "SearchEngine",
            .ai_crawler => "AiCrawler",
            .social_preview => "SocialPreview",
            .monitor => "Monitor",
            .malicious => "Malicious",
            .unknown => "Unknown",
        };
    }
};

/// 搜索引擎蜘蛛（官方 UA 子串，表内已小写）。
pub const search_engines = [_][]const u8{
    "googlebot",
    "google-inspectiontool",
    "storebot-google",
    "googleother",
    "bingbot",
    "bingpreview",
    "adidxbot",
    "msnbot",
    "baiduspider",
    "yandex",
    "duckduckbot",
    "duckduckgo-favicons-bot",
    "sogou",
    "360spider",
    "haosouspider",
    "applebot",
    "petalbot",
    "yisouspider",
    "shenmaspider",
    "slurp",
    "exabot",
    "qwantify",
    "seznam",
    "mojeek",
    "ia_archiver",
    "archive.org_bot",
    "tineye",
};

/// 正常 GEO / AI 抓取器。
pub const ai_crawlers = [_][]const u8{
    "gptbot",
    "chatgpt-user",
    "oai-searchbot",
    "claudebot",
    "claude-web",
    "claude-user",
    "anthropic-ai",
    "perplexitybot",
    "perplexity-user",
    "google-extended",
    "applebot-extended",
    "ccbot",
    "commoncrawl",
    "meta-externalagent",
    "facebookbot",
    "amazonbot",
    "cohere-ai",
    "youbot",
};

/// 社交平台链接预览。
pub const social_previews = [_][]const u8{
    "facebookexternalhit",
    "twitterbot",
    "linkedinbot",
    "slackbot",
    "telegrambot",
    "discordbot",
    "skypeuripreview",
    "whatsapp",
    "pinterestbot",
    "redditbot",
    "embedly",
    "quora link preview",
    "outbrain",
};

/// 灰色爬虫（记录 + 限速；默认不拦）。
pub const monitor_bots = [_][]const u8{
    "bytespider",
    "scrapy",
    "nutch",
    "axios/",
    "node-fetch",
    "okhttp",
    "java/",
    "php/",
    "gigabot",
    "diffbot",
    "dataprovider",
    "seekport",
};

/// 恶意爬虫 / 扫描器（默认拦截）。
pub const malicious_bots = [_][]const u8{
    // 商业 SEO/采集爬虫（不等 robots，普遍滥用）
    "mj12bot",
    "dotbot",
    "semrushbot",
    "ahrefsbot",
    "megaindex",
    "blexbot",
    "dataforseo",
    "serpstat",
    "zoominfobot",
    "maui bot",
    "turnitinbot",
    "majestic",
    "rogerbot",
    "screaming frog",
    // 脚本/库默认 UA（自家工具请走 IP 白名单或回环）
    "python-requests",
    "python-urllib",
    "aiohttp",
    "curl/",
    "wget/",
    "go-http-client",
    "libwww-perl",
    "lwp::simple",
    "pycurl",
    "winhttp",
    "guzzle",
    "restsharp",
    "apachebench",
    "ab/",
    // 漏洞扫描器 / 安全探测
    "sqlmap",
    "nikto",
    "nmap",
    "zgrab",
    "masscan",
    "dirbuster",
    "gobuster",
    "wfuzz",
    "hydra",
    "nessus",
    "acunetix",
    "nuclei",
    "whatweb",
    "wpscan",
    "httrack",
    "w3af",
    "xray",
    "goby",
    "netsparker",
    // 网络空间测绘（持续扫描全网）
    "censys",
    "shodan",
    "internet-measurement",
    "leakix",
    "binaryedge",
    "netsystemsresearch",
    "expanse",
    "palo alto networks",
    "driftnet",
};

/// 疑似机器人关键词（UA 含其一且不在任何名单 → `.unknown`）。
pub const bot_keywords = [_][]const u8{
    "bot",
    "spider",
    "crawl",
    "slurp",
    "scan",
    "fetcher",
    "harvest",
    "headless",
    "phantom",
    "selenium",
    "puppeteer",
    "playwright",
    "lighthouse",
};

fn hitAny(lower: []const u8, list: []const []const u8) bool {
    for (list) |k| {
        if (std.mem.indexOf(u8, lower, k) != null) return true;
    }
    return false;
}

/// 不区分大小写的子串查找（超长 UA 兜底路径用，避免为分类整体分配）。
fn indexOfIgnoreCase(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0) return 0;
    if (needle.len > haystack.len) return null;
    var i: usize = 0;
    const last = haystack.len - needle.len;
    while (i <= last) : (i += 1) {
        var j: usize = 0;
        while (j < needle.len) : (j += 1) {
            if (std.ascii.toLower(haystack[i + j]) != needle[j]) break;
        }
        if (j == needle.len) return i;
    }
    return null;
}

fn hitAnyIgnoreCase(text: []const u8, list: []const []const u8) bool {
    for (list) |k| {
        if (indexOfIgnoreCase(text, k) != null) return true;
    }
    return false;
}

fn classifyLower(lower: []const u8) ?BotKind {
    if (hitAny(lower, malicious_bots[0..])) return .malicious;
    if (hitAny(lower, search_engines[0..])) return .search_engine;
    if (hitAny(lower, ai_crawlers[0..])) return .ai_crawler;
    if (hitAny(lower, social_previews[0..])) return .social_preview;
    if (hitAny(lower, monitor_bots[0..])) return .monitor;
    if (hitAny(lower, bot_keywords[0..])) return .unknown;
    return null;
}

fn classifyIgnoreCase(text: []const u8) ?BotKind {
    if (hitAnyIgnoreCase(text, malicious_bots[0..])) return .malicious;
    if (hitAnyIgnoreCase(text, search_engines[0..])) return .search_engine;
    if (hitAnyIgnoreCase(text, ai_crawlers[0..])) return .ai_crawler;
    if (hitAnyIgnoreCase(text, social_previews[0..])) return .social_preview;
    if (hitAnyIgnoreCase(text, monitor_bots[0..])) return .monitor;
    if (hitAnyIgnoreCase(text, bot_keywords[0..])) return .unknown;
    return null;
}

/// 分类 UA（空 UA 返回 `null`——由门面按 `blockEmptyUa` 策略处理）。
///
/// 实现口径与 Rust 版一致：**整体小写一次**再逐名单 `contains`。
/// 栈上 512 字节覆盖几乎所有真实 UA；更长的 UA（极罕见）退回不区分大小写的逐名单匹配，
/// 因此本函数**不需要分配器**。
pub fn classify(ua: []const u8) ?BotKind {
    const t = std.mem.trim(u8, ua, " \t\r\n");
    if (t.len == 0) return null;
    var buf: [512]u8 = undefined;
    if (t.len <= buf.len) {
        for (t, 0..) |c, i| buf[i] = std.ascii.toLower(c);
        return classifyLower(buf[0..t.len]);
    }
    return classifyIgnoreCase(t);
}

/// 每线程「UA → 分类」小缓存（固定 8 槽，按 64 位哈希 + 长度比对，**不持有 UA 切片**）。
///
/// 为什么要：`classify` 要在 130+ 个关键词上逐个 `contains`，UA 不命中任何名单是最坏情况
/// （每次都全表扫完）。真实流量 UA 高度重复，缓存后重复 UA 只剩一次哈希。
/// 名单是编译期常量，不存在「配置变了缓存不失效」。
const MemoSlot = struct {
    hash: u64 = 0,
    len: usize = 0,
    value: ?BotKind = null,
    used: bool = false,
};

threadlocal var ua_memo: [8]MemoSlot = @splat(.{});

/// 带缓存的 [`classify`]：热路径用这个。
pub fn classifyCached(ua: []const u8) ?BotKind {
    const t = std.mem.trim(u8, ua, " \t\r\n");
    if (t.len == 0) return null;
    const h = std.hash.Wyhash.hash(0x9e37_79b9_7f4a_7c15, t);
    const idx: usize = @intCast(h % ua_memo.len);
    const slot = &ua_memo[idx];
    if (slot.used and slot.hash == h and slot.len == t.len) return slot.value;
    const v = classify(t);
    slot.* = .{ .hash = h, .len = t.len, .value = v, .used = true };
    return v;
}

test "classify 主要类别" {
    const t = std.testing;
    try t.expectEqual(BotKind.search_engine, classify("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)").?);
    try t.expectEqual(BotKind.search_engine, classify("Mozilla/5.0 (compatible; Baiduspider/2.0)").?);
    try t.expectEqual(BotKind.search_engine, classify("bingbot/2.0").?);
    try t.expectEqual(BotKind.ai_crawler, classify("ClaudeBot/1.0").?);
    try t.expectEqual(BotKind.ai_crawler, classify("PerplexityBot/1.0").?);
    try t.expectEqual(BotKind.social_preview, classify("facebookexternalhit/1.1").?);
    try t.expectEqual(BotKind.malicious, classify("Mozilla/5.0 (compatible; MJ12bot/v1.4.8)").?);
    try t.expectEqual(BotKind.malicious, classify("python-requests/2.31.0").?);
    try t.expectEqual(BotKind.malicious, classify("curl/8.4.0").?);
    try t.expectEqual(BotKind.malicious, classify("sqlmap/1.7").?);
    try t.expectEqual(BotKind.monitor, classify("Mozilla/5.0 (compatible; Bytespider)").?);
    try t.expectEqual(BotKind.unknown, classify("SomeRandomBot/0.1").?);
    // 普通浏览器 / 移动端 / Dart（App）→ 非 bot
    try t.expectEqual(@as(?BotKind, null), classify("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0"));
    try t.expectEqual(@as(?BotKind, null), classify("Dart/3.11 (dart:io)"));
    try t.expectEqual(@as(?BotKind, null), classify(""));
    try t.expectEqual(@as(?BotKind, null), classify("   "));
}

test "friendly 标记" {
    const t = std.testing;
    try t.expect(BotKind.search_engine.isFriendly());
    try t.expect(BotKind.ai_crawler.isFriendly());
    try t.expect(BotKind.social_preview.isFriendly());
    try t.expect(!BotKind.malicious.isFriendly());
    try t.expect(!BotKind.monitor.isFriendly());
}

test "超长 UA 走不区分大小写兜底" {
    // Zig 0.17 起 `**` 不再是字符串重复运算符，用缓冲拼一个 >512 字节的 UA
    var buf: [720]u8 = undefined;
    @memset(buf[0..600], 'x');
    const tail = " SQLMap/1.7";
    @memcpy(buf[600 .. 600 + tail.len], tail);
    const ua = buf[0 .. 600 + tail.len];
    try std.testing.expectEqual(BotKind.malicious, classify(ua).?);
}

test "缓存分类与普通分类一致" {
    const cases = [_][]const u8{
        "",
        "   ",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "sqlmap/1.7",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0",
    };
    for (cases) |c| {
        try std.testing.expectEqual(classify(c), classifyCached(c));
        // 再查一次（命中缓存路径）
        try std.testing.expectEqual(classify(c), classifyCached(c));
    }
}
