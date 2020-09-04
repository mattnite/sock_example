const zkg = @import("zkg");

pub const bpf = zkg.import.git(
    "https://github.com/mattnite/bpf.git",
    "master",
    null,
);
