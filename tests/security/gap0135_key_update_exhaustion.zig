const std = @import("std");
const tls13 = @import("tls13");
const tls13_full = @import("tls13_full");

test "GAP-0135: KeyUpdate CPU exhaustion budget" {
    const alloc = std.testing.allocator;

    // Set up a context with a tight budget
    const budget: u32 = 3;
    const config = tls13.Config{
        .allocator = alloc,
        .role = .Client,
        .max_peer_key_updates = budget,
    };

    const callbacks = tls13.Callbacks{};
    var ctx = try tls13.Context.init(config, callbacks);
    defer ctx.deinit();

    // Fast-forward phase to application ready so it accepts KeyUpdate
    ctx.phase = .application_ready;

    // We need to set a recv_slot application secret to avoid UnexpectedMessage
    const dummy_secret = tls13.Secret{ .len = 32, .bytes = [_]u8{0} ** 48 };
    ctx.secrets.slot(.Application, .recv).store(.Application, .sha256, dummy_secret);

    // Build a KeyUpdate message
    const key_update_msg = try tls13.buildKeyUpdate(alloc, false);
    defer alloc.free(key_update_msg);

    // Inject 'budget' number of KeyUpdates
    for (0..budget) |_| {
        try ctx.processCrypto(.Application, key_update_msg);
    }

    // Inject the budget+1th update
    const err = ctx.processCrypto(.Application, key_update_msg);
    try std.testing.expectError(error.TooManyKeyUpdates, err);
}
