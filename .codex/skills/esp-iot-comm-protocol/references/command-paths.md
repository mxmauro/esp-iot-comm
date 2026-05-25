# Command Paths

## Core Files

- `include/iot_comm/iot_comm.h`: public command IDs, packet layout comments, session/event API.
- `src/iot_comm.cpp`: implementation for HTTP/WebSocket setup, session creation, packet decode, built-in command dispatch, UDP server task, and cleanup.

## Main Runtime Flow

1. HTTP init/auth/bootstrap establishes session state.
2. WebSocket packets are received, decrypted, and validated against `nextRxCounter`.
3. `dispatchCommand()` serializes work with `dispatchMtx`.
4. Built-in commands are handled in `src/iot_comm.cpp`; custom commands go through the app callback.
5. Replies are encrypted and sent synchronously.

## UDP Notes

- UDP enablement is per session through `CMD_UDP_OPEN`.
- UDP packet acceptance depends on session-visible state such as connection ID, remote address, counters, and derived key/IV material.
- If UDP-visible state is replaced, update it under `serverCtx->sessions.mtx` so lookup and snapshot logic see a coherent state.
- In-flight UDP packets may continue with the snapshot they already captured unless the task explicitly requires cancellation.

## Review Checklist

- Did packet layout comments stay in sync with implementation?
- Did counters remain monotonic and transport-specific?
- Did error paths wipe or reset sensitive state correctly?
- Did the edit accidentally turn a synchronous callback contract into an async one?
- Does a behavior change need a new or updated Unity test?
