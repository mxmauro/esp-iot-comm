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
* Uses application callbacks to load and save the user database and device identity.

## Main Flow

The usual setup looks like this:

1. Start from `iotCommDefaultConfig()`.
2. Fill in the typed storage callbacks used to load and save library-managed state.
3. Provide a root key source for the first-boot path.
4. Register an `IotCommEventHandler_t`.
5. Call `iotCommInit()`.
6. Start the listener with `iotCommStartServer()`.

In practice, your event handler is where the application protocol lives. The library takes care of authentication and parsing; your code
decides what a custom command means and how to answer it.

## Main APIs

| API                                   | Purpose                                                |
|---------------------------------------|--------------------------------------------------------|
| `iotCommInit()`                       | Initializes global communication state.                |
| `iotCommStartServer()`                | Starts accepting HTTP/WebSocket connections.           |
| `iotCommStopServer()`                 | Stops the listener and active server work.             |
| `iotCommGetDeviceIdentityPublicKey()` | Returns the persisted device identity public key.      |
| `iotCommSetSessionUserData()`         | Attaches application-owned state to a session.         |
| `iotCommEventReply()`                 | Sends a successful response from the current callback. |
| `iotCommEventReplyWithError()`        | Sends an application error from the callback.          |
| `iotCommSessionClose()`               | Rejects or closes a client session.                    |
| `iotCommInitRootUserPublicKey()`      | Stores the initial root key after onboarding.          |

## WebSocket Authentication Flow

The authenticated WebSocket path is a three-step flow:

1. `POST /ws/init`
2. `POST /ws/auth`
3. `GET /ws` upgrade

`/ws/init` accepts only `clientNonce` and `clientPublicKey`. Its response returns:

* `token`
* `serverNonce`
* `serverPublicKey`
* `devicePublicKey`
* `deviceSignature`
* `maxPacketSize`

`maxPacketSize` is the effective maximum encrypted packet size accepted by the server. It applies to complete WebSocket messages and UDP
datagrams; application payloads must leave room for the protocol header and authentication tag.

The device identity is the server identity for this handshake. Clients that pin or verify the device should verify `deviceSignature`
against `devicePublicKey` over:

* `SHA256("ws-login-v1/server-auth" || clientPublicKey || serverPublicKey || clientNonce || serverNonce || token)`

If an application wants a displayable fingerprint, compute `SHA-256(devicePublicKey)` locally. The fingerprint is not sent by the server.

`/ws/auth` accepts plaintext JSON with:

* `token`
* `authIv`
* `encryptedAuth`

The `encryptedAuth` payload decrypts to JSON with:

* `userName`
* `authNonce`
* `signature`

The auth-envelope AES key is derived from the ECDH shared secret using the dedicated HKDF info label `mx-iot-auth-v1`.

The user signature inside the decrypted payload must verify:

* `SHA256("ws-login-v1/user-auth" || clientPublicKey || serverPublicKey || clientNonce || serverNonce || token || authNonce || userName)`

The `/ws/auth` response returns:

* `mustChangeCredentials`
* `isAdmin`
* `wsNonce`
* `wsTicket`

`isAdmin` is `true` when the authenticated user is the root administrator.

`wsNonce` is still required after authentication because transport-key derivation is unchanged.

The `/ws` upgrade accepts only the opaque `wsTicket`. The server checks ticket carriers in this order:

1. `wsTicket` query parameter
2. `Authorization: Bearer <wsTicket>`
3. cookie set by `/ws/auth`

If a higher-priority carrier is present but malformed, the server rejects the request instead of falling back to a lower-priority carrier.

Node-style clients should usually send `Authorization: Bearer <wsTicket>` on the upgrade request. Browser clients can rely on the short-lived
ticket cookie when `/ws/auth` is performed with credentials enabled.

## Built-In User Management Commands

The component reserves command IDs in the `0x7F00-0x7FFF` range for built-in behavior.

`CMD_CREATE_USER` (`0x7FF1`) expects:

* `flags`: bitmask byte. Bit `0` forces the new user to change credentials on the next login.
* `name`: NUL-terminated string
* `public key`: raw 65-byte uncompressed P-256 public key

`CMD_DELETE_USER` (`0x7FF2`) expects:

* `name`: NUL-terminated string

`CMD_RESET_USER_CREDENTIALS` (`0x7FF3`) expects:

* `name`: NUL-terminated string
* `new public key`: raw 65-byte uncompressed P-256 public key

`CMD_CHANGE_USER_CREDENTIALS` (`0x7FF4`) expects:

* `new public key`: raw 65-byte uncompressed P-256 public key

## Event Handling

* `IotCommEventTypeSessionStart`: a client session is being established.
* `IotCommEventTypeSessionEnd`: a session has ended.
* `IotCommEventTypeCustomCommand`: an authenticated custom command was received.

The important rule here is that replies are synchronous to the event callback. If you receive a custom command, answer it inside that
callback with `iotCommEventReply()`, `iotCommEventReplyWithError()`, or `iotCommSessionClose()`. Do not keep the command pointer around or
defer the reply to another task after the callback has returned.

## Storage Expectations

* `storage.load` and `storage.save` are typed callbacks. The library passes `IotCommStorageItemTypeUsers` for the serialized user database
  and `IotCommStorageItemTypeDeviceIdentityKeyPair` for the persisted device identity.
* The device identity key pair is library-managed and is generated automatically on first boot when storage returns `ESP_ERR_NOT_FOUND`.
* The first root key can be injected through the default-root-key callback or stored explicitly later with `iotCommInitRootUserPublicKey()`.
* If storage fails with a hard error for either item, initialization should be treated as failed rather than partially usable.

## See Also

* [Wi-Fi provisioning](WIFI_PROVISIONING.md)
* [OTA update flow](OTA.md)
