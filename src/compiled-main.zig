const std = @import("std");
const bpf = @import("bpf");
const BPF = std.os.linux.BPF;
const os = std.os;
const assert = std.debug.assert;

usingnamespace std.os;
usingnamespace @import("common.zig");

const c = @cImport({
    @cInclude("stdio.h");
    @cInclude("net/if.h");
});

const probe = @embedFile("probe.o");

comptime {
    @setEvalBranchQuota(2000);
    assert(bpf.elf.has_section(probe, "socket1"));
}

pub fn main() anyerror!void {
    const stdout = std.io.getStdOut().outStream();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    var obj = try bpf.Object.init(&gpa.allocator, probe);
    defer obj.deinit();

    try obj.load();
    defer obj.unload();

    const sock_fd = try create_raw_socket("lo");
    defer os.close(sock_fd);

    const prog = obj.find_prog("socket1") orelse unreachable;
    try os.setsockopt(sock_fd, c.SOL_SOCKET, c.SO_ATTACH_BPF, std.mem.asBytes(&prog));

    const map = obj.find_map("counters") orelse unreachable;
    const f = c.popen("ping -4 -c5 localhost", "r");
    while (true) {
        var key: i32 = std.c.IPPROTO_TCP;
        var cnt: usize = undefined;

        try BPF.map_lookup_elem(map, std.mem.asBytes(&key), std.mem.asBytes(&cnt));
        try stdout.print("TCP {} ", .{cnt});

        key = std.c.IPPROTO_UDP;
        try BPF.map_lookup_elem(map, std.mem.asBytes(&key), std.mem.asBytes(&cnt));
        try stdout.print("UDP {} ", .{cnt});

        key = std.c.IPPROTO_ICMP;
        try BPF.map_lookup_elem(map, std.mem.asBytes(&key), std.mem.asBytes(&cnt));
        try stdout.print("ICMP {} packets\n", .{cnt});

        os.nanosleep(1, 0);
    }
}
