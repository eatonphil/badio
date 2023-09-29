const std = @import("std");
const c = @cImport({
    @cInclude("sys/ptrace.h");
    @cInclude("sys/types.h");
    @cInclude("sys/user.h");
    @cInclude("sys/wait.h");
    @cInclude("unistd.h");
});

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var args = try std.process.argsAlloc(arena.allocator());
    std.debug.assert(args.len >= 2);

    const pid = try std.os.fork();

    if (pid < 0) {
        std.debug.print("Fork failed!\n", .{});
        return;
    } else if (pid == 0) {
        return execChild(&arena, args, pid);
    } else {
        try interceptChildSyscalls(&arena, pid);
    }
}

const cNullPtr: ?*anyopaque = null;

fn execChild(
    arena: *std.heap.ArenaAllocator,
    args: []const []const u8,
    childPid: std.os.pid_t,
) std.process.ExecvError {
    _ = c.ptrace(c.PTRACE_TRACEME, childPid, cNullPtr, cNullPtr);
    return std.process.execv(
        arena.allocator(),
        args[1..],
    );
}

fn interceptChildSyscalls(
    arena: *std.heap.ArenaAllocator,
    pid: std.os.pid_t,
) !void {
    var status: i32 = 0;

    while (true) {
        // Handle syscall entrance
        _ = c.ptrace(c.PTRACE_SYSCALL, pid, cNullPtr, cNullPtr);
        _ = c.waitpid(pid, &status, 0);
        if (status == 0) {
            break;
        }

        var regs: c.user_regs_struct = undefined;
        _ = c.ptrace(c.PTRACE_GETREGS, pid, cNullPtr, &regs);

        const syscall: std.os.linux.syscalls.X64 = @enumFromInt(regs.orig_rax);
        switch (syscall) {
            .write => {
                const fd = regs.rdi;
                const dataAddress = regs.rsi;
                const dataLength = regs.rdx;

                var data = std.ArrayList(u8).init(arena.allocator());
                while (data.items.len < dataLength) {
                    var word = c.ptrace(
                        c.PTRACE_PEEKDATA,
                        pid,
                        dataAddress + data.items.len,
                        cNullPtr,
                    );

                    for (std.mem.asBytes(&word)) |byte| {
                        try data.append(byte);
                    }
                }

                std.debug.print("Got a write to {}: {s}\n", .{ fd, data.items });
                if (dataLength > 2) {
                    regs.rdi = fd;
                    regs.rsi = dataAddress;
                    regs.rdx = dataLength - 2;
                    _ = c.ptrace(c.PTRACE_SETREGS, pid, cNullPtr, &regs);
                }
            },
            .close => {
                std.debug.print("Got a close\n", .{});
            },
            .fsync => {
                std.debug.print("Got an fsync\n", .{});
            },
            else => {},
        }

        // Handle syscall exit
        _ = c.ptrace(c.PTRACE_SYSCALL, pid, cNullPtr, cNullPtr);
        _ = c.waitpid(pid, &status, 0);
        if (status == 0) {
            break;
        }
    }
}
