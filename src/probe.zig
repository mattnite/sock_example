const std = @import("std");
usingnamespace std.os.linux.BPF.kern;
usingnamespace @import("common.zig");

const c = @cImport({
    @cInclude("linux/if_packet.h");
    @cInclude("linux/if_ether.h");
});

export const counters linksection("maps") = Map(u32, usize, .array, 256).init();

extern fn @"llvm.bpf.load.byte"(skb: ?*c_void, off: c_ulonglong) c_ulonglong;

export fn bpf_prog1(skb: *__sk_buff) linksection("socket1") c_int {
    const index = @intCast(u32, @"llvm.bpf.load.byte"(skb, c.ETH_HLEN + @byteOffsetOf(iphdr, "protocol")));
    if (skb.pkt_type == c.PACKET_OUTGOING) {
        return 0;
    }

    if (counters.lookup(&index)) |value| {
        _ = @atomicRmw(usize, value, .Add, 1, .SeqCst);
    }

    return 0;
}

export const _license linksection("license") = "GPL".*;
