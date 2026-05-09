# IoT Communication Server

This is the core of the library. It exposes the authenticated HTTP/WebSocket server declared in `include/iot_comm/iot_comm.h`, and in most
integrations it is the part that owns the application-facing protocol.

If you are integrating `esp-iot-comm` for the first time, start here. The Wi-Fi and captive portal modules mainly exist to get the device
online and initialized. Once that is done, `iot_comm` is the piece that receives commands, manages users and sessions, and drives the
secure channel.

## Responsibilities

* Accepts incoming HTTP/WebSocket connections.
* Authenticates users and tracks session state.
* Dispatches built-in commands and application-defined commands.
* Applies request throttling and challenge tracking.
* Uses application callbacks to load and save the user database.

## Main Flow

The usual setup looks like this:

1. Start from `iotCommDefaultConfig()`.
2. Fill in the storage callbacks used to load and save users.
3. Provide a root key source for the first-boot path.
4. Register an `IotCommEventHandler_t`.
5. Call `iotCommInit()`.
6. Start the listener with `iotCommStartServer()`.

In practice, your event handler is where the application protocol lives. The library takes care of authentication and parsing; your code
decides what a custom command means and how to answer it.

## Main APIs

| API                              | Purpose                                                |
|----------------------------------|--------------------------------------------------------|
| `iotCommInit()`                  | Initializes global communication state.                |
| `iotCommStartServer()`           | Starts accepting HTTP/WebSocket connections.           |
| `iotCommStopServer()`            | Stops the listener and active server work.             |
| `iotCommSetSessionUserData()`    | Attaches application-owned state to a session.         |
| `iotCommEventReply()`            | Sends a successful response from the current callback. |
| `iotCommEventReplyWithError()`   | Sends an application error from the callback.          |
| `iotCommSessionClose()`          | Rejects or closes a client session.                    |
| `iotCommInitRootUserPublicKey()` | Stores the initial root key after onboarding.          |

## Event Handling

* `IotCommEventTypeSessionStart`: a client session is being established.
* `IotCommEventTypeSessionEnd`: a session has ended.
* `IotCommEventTypeCustomCommand`: an authenticated custom command was received.

The important rule here is that replies are synchronous to the event callback. If you receive a custom command, answer it inside that
callback with `iotCommEventReply()`, `iotCommEventReplyWithError()`, or `iotCommSessionClose()`. Do not keep the command pointer around or
defer the reply to another task after the callback has returned.

## Storage Expectations

* The user database is application-owned. The library calls your `storage.load` and `storage.save` callbacks to read and write the
  serialized state.
* The first root key can be injected through the default-root-key callback or stored explicitly later with `iotCommInitRootUserPublicKey()`.
* If user storage fails with a hard error, initialization should be treated as failed rather than partially usable.

## See Also

* [Wi-Fi provisioning](WIFI_PROVISIONING.md)
* [OTA update flow](OTA.md)
