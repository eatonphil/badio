const std = @import("std");
const c = @cImport({
    @cInclude("sys/ptrace.h");
    @cInclude("sys/user.h");
    @cInclude("sys/wait.h");
    @cInclude("errno.h");
});

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

const ABIArguments = struct {
    regs: c.user_regs_struct,

    fn nth(aa: ABIArguments, i: u8) c_ulonglong {
        std.debug.assert(i < 4);

        return switch (i) {
            0 => aa.regs.rdi,
            1 => aa.regs.rsi,
            2 => aa.regs.rdx,
            else => unreachable,
        };
    }

    fn setNth(aa: *ABIArguments, i: u8, value: c_ulonglong) void {
        std.debug.assert(i < 4);

        switch (i) {
            0 => {
                aa.regs.rdi = value;
            },
            1 => {
                aa.regs.rsi = value;
            },
            2 => {
                aa.regs.rdx = value;
            },
            else => unreachable,
        }
    }

    fn result(aa: ABIArguments) c_ulonglong {
        return aa.regs.rax;
    }

    fn setResult(aa: *ABIArguments, value: c_ulonglong) void {
        aa.regs.rax = value;
    }

    fn function(aa: ABIArguments) c_ulonglong {
        return aa.regs.orig_rax;
    }
};

const ChildManager = struct {
    arena: *std.heap.ArenaAllocator,
    childPid: std.os.pid_t,

    fn getABIArguments(cm: ChildManager) ABIArguments {
        var args = ABIArguments{ .regs = undefined };
        _ = c.ptrace(c.PTRACE_GETREGS, cm.childPid, cNullPtr, &args.regs);
        return args;
    }

    fn setABIArguments(cm: ChildManager, args: *ABIArguments) void {
        _ = c.ptrace(c.PTRACE_SETREGS, cm.childPid, cNullPtr, &args.regs);
    }

    fn childReadData(
        cm: ChildManager,
        address: c_ulonglong,
        length: c_ulonglong,
    ) !std.ArrayList(u8) {
        var data = std.ArrayList(u8).init(cm.arena.allocator());
        while (data.items.len < length) {
            var word = c.ptrace(
                c.PTRACE_PEEKDATA,
                cm.childPid,
                address + data.items.len,
                cNullPtr,
            );

            for (std.mem.asBytes(&word)) |byte| {
                if (data.items.len == length) {
                    break;
                }
                try data.append(byte);
            }
        }
        return data;
    }

    fn childWaitForSyscall(cm: ChildManager) i32 {
        var status: i32 = 0;
        _ = c.ptrace(c.PTRACE_SYSCALL, cm.childPid, cNullPtr, cNullPtr);
        _ = c.waitpid(cm.childPid, &status, 0);
        return status;
    }

    const hooks = &[_]struct {
        syscall: c_ulonglong,
        hook: *const fn (ChildManager, *ABIArguments) anyerror!void,
    }{.{
        .syscall = @intFromEnum(std.os.linux.syscalls.X64.write),
        .hook = writeHandler,
    }};

    fn childInterceptSyscalls(
        cm: *ChildManager,
    ) !void {
        while (true) {
            // Handle syscall entrance
            const status = cm.childWaitForSyscall();
            if (status == 0) {
                break;
            }

            var args: ABIArguments = cm.getABIArguments();
            const address = args.function();

            for (hooks) |hook| {
                if (address == hook.syscall) {
                    try hook.hook(cm.*, &args);
                }
            }
        }
    }

    fn writeHandler(cm: ChildManager, entryArgs: *ABIArguments) anyerror!void {
        const fd = entryArgs.nth(0);
        const dataAddress = entryArgs.nth(1);
        var dataLength = entryArgs.nth(2);

        // Truncate some bytes
        if (dataLength > 2) {
            dataLength -= 2;
            entryArgs.setNth(2, dataLength);
            cm.setABIArguments(entryArgs);
        }

        const data = try cm.childReadData(dataAddress, dataLength);
        defer data.deinit();
        std.debug.print("Got a write on {}: {s}\n", .{ fd, data.items });

        // Handle syscall exit
        _ = cm.childWaitForSyscall();

        var exitArgs = cm.getABIArguments();
        dataLength = exitArgs.nth(2);
        if (dataLength > 2) {
            // Force the writes to stop after the first one by returning EIO.
            var result: c_ulonglong = 0;
            result = result -% c.EIO;
            exitArgs.setResult(result);
            cm.setABIArguments(&exitArgs);
        }
    }
};

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
        var cm = ChildManager{ .arena = &arena, .childPid = pid };
        try cm.childInterceptSyscalls();
    }
}
