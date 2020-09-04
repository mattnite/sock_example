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
    const compiled = b.addExecutable("compiled", "src/compiled-main.zig");
    compiled.setTarget(target);
    compiled.setBuildMode(mode);
    compiled.addPackage(bpf);
    compiled.linkLibC();
    compiled.install();
    compiled.step.dependOn(&obj.step);

    const assembly = b.addExecutable("asm", "src/asm-main.zig");
    assembly.setTarget(target);
    assembly.setBuildMode(mode);
    assembly.linkLibC();
    assembly.install();

    const run_compiled = compiled.run();
    run_compiled.step.dependOn(b.getInstallStep());

    const run_assembly = assembly.run();
    run_assembly.step.dependOn(b.getInstallStep());

    const compiled_step = b.step("run-compiled", "Run the app");
    compiled_step.dependOn(&run_compiled.step);

    const asm_step = b.step("run-asm", "Run the app");
    asm_step.dependOn(&run_assembly.step);

    const probe_step = b.step("probe", "Build the probe");
    probe_step.dependOn(&obj.step);
}
