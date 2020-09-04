const std = @import("std");
const BPF = std.os.linux.BPF;
const os = std.os;

usingnamespace BPF.Insn;
usingnamespace @import("common.zig");

const c = @cImport({
    @cInclude("stdio.h");
    @cInclude("linux/if_ether.h");
    @cInclude("net/if.h");
});

pub fn main() anyerror!void {
    const stdout = std.io.getStdOut().outStream();

    const map = try BPF.map_create(.array, @sizeOf(i32), @sizeOf(usize), 256);
    defer os.close(map);

    const insns = [_]BPF.Insn{
        mov(.r6, .r1),
        ld_abs(.byte, c.ETH_HLEN + @byteOffsetOf(iphdr, "protocol")),
        stx_mem(.word, .r10, .r0, -4),
        mov(.r2, .r10),
        add(.r2, -4),
        ld_map_fd1(.r1, map),
        ld_map_fd2(map),
        call(.map_lookup_elem),
        jeq(.r0, 0, 2),
        mov(.r1, 1),
        xadd(.r0, .r1),
        mov(.r0, 0),
        exit(),
    };

    const prog = try BPF.prog_load(.socket_filter, &insns, null, "GPL", 0);
    defer os.close(prog);

    const sock_fd = try create_raw_socket("lo");
    defer os.close(sock_fd);

    try os.setsockopt(sock_fd, c.SOL_SOCKET, c.SO_ATTACH_BPF, std.mem.asBytes(&prog));
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
