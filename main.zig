const std = @import("std");
const c = @cImport({
    @cInclude("sys/ptrace.h");
    @cInclude("sys/user.h");
    @cInclude("sys/wait.h");
    @cInclude("errno.h");
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

        var syscall = std.os.linux.syscalls.X64.futex_waitv;
        if (regs.orig_rax < @intFromEnum(std.os.linux.syscalls.X64.futex_waitv)) {
            syscall = @enumFromInt(regs.orig_rax);
        }
        const fd = regs.rdi;
        var waitForExit = true;
        switch (syscall) {
            .write => {
                const dataAddress = regs.rsi;
                var dataLength = regs.rdx;

                // Truncate some bytes
                if (dataLength > 2) {
                    regs.rdx -= 2;
                    dataLength -= 2;
                    _ = c.ptrace(c.PTRACE_SETREGS, pid, cNullPtr, &regs);
                }

                var data = std.ArrayList(u8).init(arena.allocator());
                while (data.items.len < dataLength) {
                    var word = c.ptrace(
                        c.PTRACE_PEEKDATA,
                        pid,
                        dataAddress + data.items.len,
                        cNullPtr,
                    );

                    for (std.mem.asBytes(&word)) |byte| {
                        if (data.items.len == dataLength) {
                            break;
                        }
                        try data.append(byte);
                    }
                }

                std.debug.print("Got a write on {}: {s}\n", .{ fd, data.items });
            },
            .close => {
                std.debug.print("Got a close on {}\n", .{fd});
            },
            .fsync => {
                std.debug.print("Got an fsync on {}\n", .{fd});
            },
            else => {
                waitForExit = false;
            },
        }

        if (waitForExit) {
            // Handle syscall exit
            _ = c.ptrace(c.PTRACE_SYSCALL, pid, cNullPtr, cNullPtr);
            _ = c.waitpid(pid, &status, 0);
            if (status == 0) {
                break;
            }

            var regs2: c.user_regs_struct = undefined;
            _ = c.ptrace(c.PTRACE_GETREGS, pid, cNullPtr, &regs2);

            var syscall2 = std.os.linux.syscalls.X64.futex_waitv;
            if (regs2.orig_rax < @intFromEnum(std.os.linux.syscalls.X64.futex_waitv)) {
                syscall2 = @enumFromInt(regs2.orig_rax);
            }
            std.debug.assert(syscall == syscall2);
            switch (syscall2) {
                .write => {
                    std.debug.assert(regs.rsi == regs2.rsi);
                    std.debug.assert(regs.rdx == regs2.rdx);

                    var dataLength = regs.rdx;
                    if (dataLength > 2) {
                        // Force the writes to stop after the first one.
                        // -EPERM == maxValue(c_ulonglong)
                        // -EIO   == maxValue(c_ulonglong)  -4
                        regs2.rax = std.math.maxInt(c_ulonglong) - 4;
                        _ = c.ptrace(c.PTRACE_SETREGS, pid, cNullPtr, &regs2);
                    }
                },
                else => {},
            }
        }
    }
}
