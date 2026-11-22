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
6. After a network interface is connected and a root user is configured, start the listener with `iotCommStartServer()`.

After successful initialization, repeated `iotCommInit()` calls return `ESP_OK` and retain the original configuration.

## Application HTTP Handlers

Set `IotCommServerConfig_t::extraUriHandlers` and `extraUriHandlersCount` to register application-specific HTTP handlers after
IoT-Comm's built-in handlers. IoT-Comm reserves space for every supplied handler before starting, and stops the server if any handler
cannot be registered.

```cpp
IotCommHttpEndpoint_t extraHandlers[1] = {};

extraHandlers[0].uri = "/status";
extraHandlers[0].method = HTTP_GET;
extraHandlers[0].handler = serveStatus;
extraHandlers[0].ctx = &appState;
extraHandlers[0].rateLimit = false;

serverConfig.extraUriHandlers = extraHandlers;
serverConfig.extraUriHandlersCount = 1;
```

IoT-Comm retains the handler, context, and rate-limit setting, but the application owns the URI strings and contexts. Keep those valid
until `iotCommStopServer()` or a failed `iotCommStartServer()` call returns. Extra endpoints are ordinary HTTP handlers; WebSocket
endpoints are not supported. Set `rateLimit` to `true` to apply IoT-Comm's configured per-client request limit before the application
handler runs. Rate-limited endpoints share that limit with IoT-Comm's built-in authentication routes. Each protected request consumes
one slot in the shared budget; a complete login consumes three slots for `/ws/init`, `/ws/auth`, and the `/ws` upgrade.

## CORS

Set `IotCommServerConfig_t::cors` to enable CORS for the authenticated server. A null pointer is the default and sends no CORS headers.
Start from `iotCommDefaultCORSConfig()` and customize the methods and request headers accepted by browser preflights. Null or empty
method and header strings use the defaults.

```cpp
IotCommCORSConfig_t cors = iotCommDefaultCORSConfig();

cors.allowedMethods = "GET,POST,OPTIONS";
cors.allowedHeaders = "Content-Type, Authorization";
cors.useWildcardOrigin = false;
serverConfig.cors = &cors;
```

With `useWildcardOrigin == false`, IoT-Comm reflects a supplied `Origin`, sends `Vary: Origin`, and enables credentials for browser
cookie support. Requests without an `Origin` header use `Access-Control-Allow-Origin: *`. With `useWildcardOrigin == true`, responses
always use `*` and do not enable credentials.

IoT-Comm applies the configured CORS headers to its built-in HTTP responses, extra endpoint responses before calling the application
handler, and ESP-IDF-generated error responses. Extra endpoints also receive automatic `OPTIONS` preflight responses with status 204;
they do not invoke the application handler or consume rate-limit slots. When CORS is enabled, applications must not register an extra
`HTTP_OPTIONS` endpoint because `iotCommStartServer()` rejects that configuration. Application handlers that add CORS headers after
IoT-Comm has done so can produce duplicate HTTP headers and are responsible for their own response policy.

Include `iot_comm/http/helpers.h` in an application handler to reuse the request-body, query-parameter, CORS, and standard error-response
helpers. `httpGetClientIpFromRequest(req, &address)` resolves the client address using the trusted-proxy configuration supplied to
`iotCommInit()`; application handlers do not pass or retain that configuration themselves. It returns `false` when called without an
initialized IoT-Comm runtime or when the peer address cannot be determined.

## Reverse Proxies

By default, client identity, challenge binding, and rate limiting use the direct TCP peer address. The component considers
`X-Forwarded-For` only when that peer matches a CIDR entry in `config.proxy.trustedProxies`. Configure this only for reverse proxies under
your control; the component copies the entries during `iotCommInit()`.

```cpp
IotCommTrustedProxy_t proxies[1] = {};

parseIP(&proxies[0].network, "192.0.2.0");
proxies[0].prefixLength = 24;
config.proxy.trustedProxies = proxies;
config.proxy.trustedProxiesCount = 1;
```

Each entry must use its canonical network address (host bits clear). Invalid entries make `iotCommInit()` fail.

When the peer is trusted, the component reads `X-Forwarded-For` from right to left, skips listed proxy addresses, and uses the first
remaining address as the client. Configure proxies to append or overwrite this header. A missing, malformed, or all-proxy header falls
back to the direct peer address.

In practice, your event handler is where the application protocol lives. The library takes care of authentication and parsing; your code
decides what a custom command means and how to answer it.

## Main APIs

| API                                   | Purpose                                                |
|---------------------------------------|--------------------------------------------------------|
| `iotCommInit()`                       | Initializes global communication state.                |
| `iotCommGetReadiness()`               | Reports initialization and root-user readiness.        |
| `iotCommStartServer()`                | Starts accepting HTTP/WebSocket connections.           |
| `iotCommStopServer()`                 | Stops the listener and active server work.             |
| `iotCommGetDeviceIdentityPublicKey()` | Returns the persisted device identity public key.      |
| `iotCommSignDeviceIdentityHash()`      | Signs a SHA-256 digest with the device identity key.   |
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

UDP is a one-way transport for custom commands only. It accepts custom command IDs outside the reserved range. A reserved built-in command
ID is rejected and invalidates the current UDP negotiation; issue `CMD_UDP_OPEN` again over WebSocket before sending more UDP commands.
For UDP custom-command events, `iotCommEventReply()` and `iotCommEventReplyWithError()` return `ESP_ERR_NOT_ALLOWED`.

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

The important rule here is that WebSocket replies are synchronous to the event callback. If you receive a WebSocket custom command, answer
it inside that callback with `iotCommEventReply()`, `iotCommEventReplyWithError()`, or `iotCommSessionClose()`. Do not keep the command
pointer around or defer the reply to another task after the callback has returned. UDP custom commands are one-way; both reply APIs return
`ESP_ERR_NOT_ALLOWED`.

Do not call `iotCommStopServer()` or `iotCommDeinit()` synchronously from an IoT-Comm event callback. Both APIs wait for the callback's
rundown reference to finish, so doing so would deadlock. Call them after the callback has returned.

## Storage Expectations

* `storage.load` and `storage.save` are typed callbacks. The library passes `IotCommStorageItemTypeUsers` for the serialized user database
  and `IotCommStorageItemTypeDeviceIdentityKeyPair` for the persisted device identity.
* The device identity key pair is library-managed and is generated automatically on first boot when storage returns `ESP_ERR_NOT_FOUND`.
* The first root key can be injected through the default-root-key callback or stored explicitly later with `iotCommInitRootUserPublicKey()`.
* If storage fails with a hard error for either item, initialization should be treated as failed rather than partially usable.

## See Also

* [Wi-Fi provisioning](WIFI_PROVISIONING.md)
* [OTA update flow](OTA.md)
