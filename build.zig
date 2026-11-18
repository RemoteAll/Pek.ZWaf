const std = @import("std");

/// Pek.ZWaf —— Zig 版 Web 应用防火墙（对齐 Rust `Pek.RWaf` 与 C# `Pek.WAF`）。
///
/// 构建口径与 zzig 各消费方一致：库只暴露模块 `pek_zwaf`，测试用 `zig build test`。
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zzig_dep = b.dependency("zzig", .{
        .target = target,
        .optimize = optimize,
    });

    const mod = b.addModule("pek_zwaf", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zzig", .module = zzig_dep.module("zzig") },
        },
    });

    const lib_tests = b.addTest(.{ .root_module = mod });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const test_step = b.step("test", "运行单元测试");
    test_step.dependOn(&run_lib_tests.step);

    // 端到端演示服务（`zig build demo` 启动后可用 curl 验证拦截效果）
    const demo_mod = b.createModule(.{
        .root_source_file = b.path("examples/waf_demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    demo_mod.addImport("zzig", zzig_dep.module("zzig"));
    demo_mod.addImport("pek_zwaf", mod);

    const demo = b.addExecutable(.{ .name = "zwaf-demo", .root_module = demo_mod });
    const run_demo = b.addRunArtifact(demo);

    const demo_step = b.step("demo", "启动 WAF 演示服务（127.0.0.1:18080）");
    demo_step.dependOn(&run_demo.step);

    // 性能基准（100 万次判定 / 100 万条名单）：`zig build bench -Doptimize=ReleaseFast`
    const bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/waf_bench.zig"),
        .target = target,
        .optimize = optimize,
    });
    bench_mod.addImport("zzig", zzig_dep.module("zzig"));
    bench_mod.addImport("pek_zwaf", mod);

    const bench_exe = b.addExecutable(.{ .name = "zwaf-bench", .root_module = bench_mod });
    const run_bench = b.addRunArtifact(bench_exe);

    const bench_step = b.step("bench", "运行性能基准（建议 -Doptimize=ReleaseFast）");
    bench_step.dependOn(&run_bench.step);
}
