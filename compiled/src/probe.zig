const std = @import("std");
usingnamespace std.os.linux.BPF.kern;

const c = @cImport({
    @cInclude("linux/if_packet.h");
    @cInclude("linux/if_ether.h");
});

export const counters linksection("maps") = Map(u32, std.atomic.Int(usize), .array, 256).init();

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

extern fn @"llvm.bpf.load.byte"(skb: ?*c_void, off: c_ulonglong) c_ulonglong;

export fn bpf_prog1(skb: *__sk_buff) linksection("socket1") c_int {
    const index = @intCast(u32, @"llvm.bpf.load.byte"(skb, c.ETH_HLEN + @byteOffsetOf(iphdr, "protocol")));
    if (skb.pkt_type == c.PACKET_OUTGOING) {
        return 0;
    }

    if (counters.lookup(&index)) |value| {
        _ = value.fetchAdd(skb.len);
    }

    return 0;
}

export const _license linksection("license") = "GPL".*;
