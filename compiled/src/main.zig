const std = @import("std");
const bpf = @import("bpf");
const BPF = std.os.linux.BPF;
const os = std.os;
const assert = std.debug.assert;

usingnamespace std.os;
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

const probe = @embedFile("probe.o");

comptime {
    //    assert(bpf.elf.has_map(probe, "counts"));
    //   assert(bpf.elf.has_section(probe, "socket1"));
}

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = &std.heap.loggingAllocator(&gpa.allocator, stderr).allocator;
    var obj = try bpf.Object.init(allocator, probe);
    defer obj.deinit();

    try obj.load();
    defer obj.unload();

    const sock_fd = try os.socket(
        c.PF_PACKET,
        c.SOCK_RAW | c.SOCK_NONBLOCK | c.SOCK_CLOEXEC,
        c.htons(c.ETH_P_ALL),
    );
    defer os.close(sock_fd);

    var sll = std.mem.zeroes(c.sockaddr_ll);
    sll.sll_family = c.AF_PACKET;
    sll.sll_ifindex = @intCast(c_int, c.if_nametoindex("lo"));
    sll.sll_protocol = c.htons(c.ETH_P_ALL);

    const prog = obj.find_prog("socket1") orelse unreachable;
    try os.bind(sock_fd, @ptrCast(*std.c.sockaddr, &sll), @sizeOf(c.sockaddr_ll));
    try os.setsockopt(sock_fd, c.SOL_SOCKET, c.SO_ATTACH_BPF, std.mem.asBytes(&prog));

    const f = c.popen("ping -4 -c5 localhost", "r");
    const map = obj.find_map("counters") orelse unreachable;
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
        try stdout.print("ICMP {} bytes\n", .{cnt});

        os.nanosleep(1, 0);
    }
}
