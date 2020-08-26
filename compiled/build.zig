const std = @import("std");
const Builder = std.build.Builder;
const packages = @import("zig-cache/packages.zig").list;
const builtin = @import("builtin");

pub fn build(b: *Builder) void {
    const bpf = comptime blk: {
        for (packages) |pkg| {
            if (std.mem.eql(u8, pkg.name, "bpf")) {
                break :blk pkg;
            }
        } else return @compileError("no bpf package");
    };

    const obj = b.addObject("probe", "src/probe.zig");
    obj.setTarget(std.zig.CrossTarget{
        .cpu_arch = if (builtin.endian == .Big) .bpef else .bpfel,
        .os_tag = .freestanding,
    });
    obj.setBuildMode(.ReleaseFast);
    obj.setOutputDir("src");
    obj.addPackage(bpf);
    obj.addIncludeDir("/usr/include");

    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();
    const exe = b.addExecutable("zig-sock_example", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.addPackage(bpf);
    exe.linkLibC();
    exe.install();
    exe.step.dependOn(&obj.step);

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const probe_step = b.step("probe", "Build the probe");
    probe_step.dependOn(&obj.step);
}
