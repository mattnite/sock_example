usingnamespace BPF.Insn;
const std = @import("std");
const BPF = std.os.linux.BPF;
const os = std.os;

const c = @cImport({
    @cInclude("stdio.h");
    @cInclude("linux/if_ether.h");
    @cInclude("net/if.h");
    @cInclude("linux/if_packet.h");
    @cInclude("linux/ip.h");
    @cInclude("arpa/inet.h");
    @cInclude("linux/version.h");
});

const stderr = std.io.getStdErr().outStream();
const stdout = std.io.getStdOut().outStream();

const iphdr = extern struct {
    i_dont_care: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
};

pub fn main() anyerror!void {
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

    const sock_fd = try os.socket(
        c.PF_PACKET,
        c.SOCK_RAW | c.SOCK_NONBLOCK | c.SOCK_CLOEXEC,
        c.htons(c.ETH_P_ALL),
    );
    defer os.close(sock_fd);

    var sll = std.mem.zeroes(c.sockaddr_ll);
    sll.sll_family = c.AF_PACKET;
    //sll.sll_ifindex = @intCast(c_int, c.if_nametoindex("lo"));
    sll.sll_ifindex = @intCast(c_int, c.if_nametoindex("enp39s0"));
    sll.sll_protocol = c.htons(c.ETH_P_ALL);

    try os.bind(sock_fd, @ptrCast(*std.c.sockaddr, &sll), @sizeOf(c.sockaddr_ll));
    try os.setsockopt(sock_fd, c.SOL_SOCKET, c.SO_ATTACH_BPF, std.mem.asBytes(&prog));

    //const f = c.popen("ping -4 -c5 localhost", "r");

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
