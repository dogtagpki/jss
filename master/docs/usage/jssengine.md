# `JSSEngine` - Documentation

## About `JSSEngine`

`JSSEngine` is JSS's implementation of the [`SSLEngine`][javax.ssl-engine]
contract for non-blocking TLS. Unlike the `SunJSSE` provider's `SSLEngine`
(when using the `SunPKCS11-NSS` provider for primitives), this is built
directly on NSS's high-level SSL module. This is better for FIPS compliance
and HSM support (as keys never leave the NSS cryptographic module) and also
means that we don't need to reimplement the underlying state machine. This
approach is consistent with our [JSS `SSLSocket`][jss.ssl-socket].


## Using `JSSEngine`

There are two ways to use the `JSSEngine`: via the JCA Provider interface,
or constructing a `JSSEngine` instance directly. The former method is
preferred out of the two.

Please refer to the [`JSSEngine` test cases][jss.jssengine.tests] or to
the [Oracle `SSLEngine` demo][oracle.sslengine.demo] for information on
using it. Usually a `SSLEngine` instance is asked by an external API
(e.g., Tomcat) or used inside a `SSLSocket` implementation, such as the
`SSLSocket` implementation provided by `Mozilla-JSS`'s SSLContext`.


### Via the JSSProvider

This is the preferred way of using the `JSSEngine`. To construct a new
[`SSLEngine`][javax.ssl-engine] instance, first get `Mozilla-JSS`'s
[`SSLContext`][javax.ssl-context]:

```java
// First get the necessary KeyManagers and TrustManagers. Note that
// selecting KeyManagers and TrustManagers is discussed more below.
KeyManagerFactory kmf = KeyManagerFactory.getInstance("NssX509", "Mozilla-JSS");
KeyManager[] kms = kmf.getKeyManagers();

TrustManagerFactory tmf = TrustManagerFactory.getInstance("NssX509", "Mozilla-JSS");
TrustManager[] tms = tmf.getTrustManagers();

// Then, initialize the SSLContext with the above information. Note that
// we don't utilize the SecureRandom parameter, as NSS internally handles
// generating random numbers for us.
SSLContext ctx = SSLContext.getInstance("TLS", "Mozilla-JSS");
ctx.init(kms, tms, null);

// If we don't have any peer host/port information, use this form:
SSLEngine engine = ctx.createSSLEngine();

// Otherwise, use this form:
SSLEngine engine = ctx.createSSLEngine(peerHost, peerPort);
```

The [`SSLContext`][javax.ssl-context] also provides methods helpful for
configuring the [`SSLEngine`][javax.ssl-engine]. These are
`SSLContext.getDefaultSSLParameters()` and
`SSLContext.getSupportedSSLParameters()`. These provide the default parameters
used by the SSLEngine and all supported SSLParameters, respectively.

For more information about configuring the `JSSEngine`, see the section below.

Note that the `Mozilla-JSS` provider's `SSLContext` instance also provides
methods for creating `SSLSocket` factories which conform to the same
`javax.net.ssl` interfaces. These sockets utilize the `JSSEngine` internally
and expose many of the same configuration methods under the `JSSSocket` class
namespace. The results of these factories can be directly cast to `JSSSocket`
or `JSSServerSocket` as appropriate.


### Direct Utilization

This is the less preferred way of using the `JSSEngine`. This requires
understanding the class layout of `JSSEngine`. See the section below for more
information.

First, get an instance of `JSSEngine`:

```java
/* If no session resumption hints are provided: */
// JSSEngine engine = new JSSEngine<$Impl>();

/* If we already know the peer's host and port: */
// String peerHost;
// int peerPort;
// JSSEngine engine = new JSSEngine<$Impl>(peerHost, peerPort);

/* Or laastly, if we know the peer's host and port, and want to set
 * a certificate and key to use for our side of the connection: */
// X509Certificate localCert;
// PrivateKey localKey;
JSSEngine engine = new JSSEngine<$Impl>(peerHost, peerPort, localCert, localKey);
```

Replace `JSSEngine<$Impl>` with one of the implementing classes below.

Then, continue with configuring the `JSSEngine` below.


### Configuring the `JSSEngine`

Configuring the `JSSEngine` is a multi-step process. Below are common
configuration options grouped into categories.

#### Choosing Handshake Side

Configuring which side of the handshake this `JSSEngine` will use occurs via
a call to `setUseClientMode(boolean mode)`. When `mode` is `true`, this engine
will handshake as if it was the client. Otherwise, this engine will handshake
as a server. Note that calling `setUseClientMode(...)` after the handshake has
started (either via calling `beginHandshake(...)`, `wrap(...)`, or
`unwrap(...)`) isn't supported.

Checking the current mode can be done via `getUseClientMode(...)`.

#### Choosing Key Material

Key material can be chosen in several ways. In every scenario, a JSSKeyManager
instance needs to be passed to the JSSEngine:

```java
// JSSEngine inst;
inst.setKeyManager(new JSSKeyManager());
```

For direct selection of key from an existing instance, call `setKeyMaterials`:

```java
// JSSEngine inst;
inst.setKeyMaterials(myPK11Cert, myPK11PrivKey);
```

Note that these must be instances of [`PK11Cert`][jss.pk11-cert] and
[`PK11PrivKey`][jss.pk11-privkey] respectively. These can be obtained from
the [`CryptoManager`][jss.cryptomanager] and casting `X509Certificate` to
`PK11Cert` and `PrivateKey` to `PK11PrivKey`.

For selection of a key via an alias in the certificate database, call
`setCertFromAlias`:

```java
// JSSEngine inst;
inst.setCertFromAlias("server-cert-alias");
```

Lastly, key material could've been provided when the `JSSEngine` was
constructed; see the section on direct utilization above.

Note that SNI support isn't yet added so the key selection must occur prior
to the initial handshake.

#### Choosing TLS protocol version

There are two ways to choose TLS protocol version. The first is via the Java
Provider interface, selecting the TLS version directly. The `Mozilla-JSS`
provider understands the following aliases:

 - `SSL` and `TLS`, enabling any allowed SSL and TLS protocol version,
 - `TLSv1.1` to enable only TLS version 1.1 by default,
 - `TLSv1.2` to enable only TLS version 1.2 by default, and
 - `TLSv1.3` to enable only TLS version 1.3 by default.

Alternatively, the standard `SSLEngine` configuration method of passing
a list of protocols to `setEnabledProtocols` is also allowed. Note that this
will override any value passed via the Provider interface. Additionally, due
to restrictions in NSS, a contiguous range of protocols will be enabled. For
example, the following call:

```java
// SSLEngine inst;
inst.setEnabledProtocols(new String[] { "TLSv1.1", "TLSv1.3" });
```

will enable TLSv1.1, TLSv1.2, and TLSv1.3.

Alternative methods are available that take JSS standard `SSLVersion` and
`SSLVersionRange` values as parameters; see the `JSSEngine` javadoc for
more information.

#### Choosing Cipher Suite

Configuring cipher suites is performed using the standard `SSLEngine`
configuration method of passing a list of cipher suites to
`setEnabledCipherSuites`. We filter the list of passed cipher suites to
only those allowed by local policy. For example:

```java
// SSLEngine inst;
inst.setEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256" });
```

will enable only a single TLSv1.3 cipher suite.

Alternative methods are available that take JSS standard `SSLCipher`
values as parameters; see the `JSSEngine` javadoc for more information.

#### Using `JSSParameters`

`JSSParameters` largely aligns with `SSLParameters` except that it allows
two important introductions:

 1. Selection of key material, like above. See the javadocs on `JSSParameters`
    for more information.
 2. Setting the peer's hostname, for use with validation of certificates. This
    allows us to tie into NSS's hostname verification directly, instead of
    responding after the fact by closing the connection.

Generally, using `SSLParameters` should be sufficient for most applications.
Two exceptions are when we wish to explicitly select key material (e.g., from
a certificate nickname) or when using NSS for SSL hostname validation.

#### Session Control

The `JSSEngine` lacks many of the session control functions other `SSLEngine`
implementations might have. In particular, we:

 - Always enable session resumption; this cannot be disabled.
 - Allow forced expiration of a session as long as the `SSLEngine`'s
   connection isn't yet closed.
 - Report accurate creation/expiration/last accessed times.

However, other features of sessions (such as configuring location and size of
the session cache) aren't yet configurable.


## Design of the `JSSEngine`

### Class Structuring

The below is a digram showing the structure of `JSSEngine` classes:

                           -----------
                          | JSSEngine |-------------------------
                           -----------                          \
                            /       \                            \
     ------------------------       ------------------------     ------
    | JSSEngineReferenceImpl |     | JSSEngineOptimizedImpl |   | .... |
     ------------------------       ------------------------     ------

`JSSEngine` is an abstract class extending [`SSLEngine`][javax.ssl-engine].
This class implements some of the boilerplate required for implementing a
`SSLEngine`, including handling cipher and protocol version configuration.
Individual implementations implement `wrap`, `unwrap`, and whatever specifics
are necessary to initialize and release the SSL-backed `PRFileDesc`.

We expect two primary implementations:

 - `JSSEngineReferenceImpl`, a reference implementation with more logging
   and debugging statements. This also includes port-based debugging, so
   situations where a `SSLEngine` isn't writing to the network can still
   be tracked and analyzed in Wireshark. Each call to `wrap` or `unwrap`
   makes several JNI calls, incurring lots of overhead.
 - `JSSEngineOptimizedImpl`, an optimized, production-ready implementation.
   This one is harder to debug due to fewer logging statements, but does
   improve performance significantly with fewer JNI calls.


### Non-Blocking IO

In order to implement `wrap` and `unwrap` on the SSLEngine, we use NSPR
sockets configured in non-blocking mode. Data is held in buffers rather
than being written to the network; in this way, data is passed from a
`unwrap` call to `NSPR` so that `NSS` can decrypt the wire data, with
the result being returned from `unwrap`.

This is implemented as follows:

NSPR introduces a platform-independent abstraction over C's file descriptors
(usually an `int`) in the form of the `PRFileDesc` structure. This is
layer-able, allowing us to write our own and then have it be accepted by
NSS's SSL `PRFileDesc` implementation as the underlying transport.

Our `PRFileDesc` is called `BufferPRFD` and lives next to the `JSSEngine`
implementation in `org/mozilla/jss/ssl/javax`. Each `BufferPRFD` is backed
by two `j_buffer` instances (located adjacent). A `j_buffer` is a circular
ring buffer optimized to allow efficient access to the underlying data. One
`j_buffer` is dedicated to the read end of this `BufferPRFD` (the data that
is returned when `recv(...)` is called); the other is dedicated to the write
end of this `BufferPRFD` (the data that is waiting to get sent on the wire).
Note that the `j_buffer` instances exist independently from the `BufferPRFD`:
the `JSSEngine` itself creates the `j_buffer`s and hands them to the
`BufferPRFD` to use, because it too needs to be able to read from them.

This forms the following data path once the initial handshake is complete:

     -------------
    | Application |
     -------------
         |  ^
    app  |  | wire  SSLEngine.wrap(data, result)
    data |  | data
         V  |
      -----------  jb_read(write, result) ----------
     | JSSEngine | <-------------------- | j_buffer |
      -----------                         ----------
          |                                   ^
          | PR.Write(ssl_fd, data)            | jb_write(write, enc_data)
          v                                   |
        -----                            -----------
       | NSS | -----------------------> | PRFileDesc|
        -----                            -----------
             PR.Write(buffer_fd, enc_data)


The application creates application data it wants to send to its peer. It
invokes `SSLEngine.wrap(data, result)`, where `data` is the application data
and `result` is an empty buffer large enough to store the resulting wire data.
The `JSSEngine` passes this data (via a call to `PR.Write`) to NSS along the
SSL `PRFileDesc` (`ssl_fd`) associated with this `JSSEngine`. NSS encrypts
this data and writes it to the underlying `BufferPRFD`. If the `BufferPRFD`
has sufficient space in its write `j_buffer`, it can accept all the data.
This occurs in the `PR.Write` call on the `BufferPRFD`. At this point, the
call stack returns to `JSSEngine.wrap(...)`. When it sees that there is data
in the underlying write `j_buffer`, `JSSEngine` reads from the write
`j_buffer`, thereby freeing space in it for the next PR.Write(...) invocation,
and adds this to the application's `result` (wire data) buffer.

A similar process (with the bottom loop reversed) occurs for the application
decrypting data from its peer. In this case, encrypted wire data is written
to the read `j_buffer`, a call to `jb_read(read)` from `PR.Read(buffer_fd)`
occurs inside NSS when a call to `PR.Read(ssl_fd)` is made from the SSLEngine.
The unencrypted result is then passed to the caller of
`SSLEngine.unwrap(...)`.


### Handshaking

The data flow described above in the section on Non-Blocking IO applies to
the initial TLS Handshake as well, except there's no initial application data
and the `JSSEngine` doesn't call `PR.Write(...)`. [TLSv1.2][rfc.tls-1.2] and
[TLSv1.3][rfc.tls-1.3] both have state machines at the core of their handshake
mechanism. However, NSS doesn't expose the current state of the handshake or
whether or not we can continue without any additional information from the
remote peer.

When a `JSSEngine` is initialized, the first thing it expects to do is begin
a handshake with a peer. The TLS handshake begins with the client sending a
Client Hello message to the server. When the SSLEngine is initialized as a
client, it sets the handshake state to `NEED_WRAP` (so we can send the
outbound Client Hello); when initialized as a server, it gets set to
`NEED_UNWRAP` so we can receive the inbound Client Hello from the peer.

When `SSL.ForceHandshake` is called, NSS steps the internal state machine.
This results in a call to `PR.Read(...)` to read any inbound data, and if
this client needs to write a message, a call to `PR.Write(...)`. In this way,
all inbound data on the wire is consumed, and if a message needs to be
transmitted, we can check the amount of data in the write `j_buffer`. This
gives us the following heuristic for handshaking:

 1. Get the Security Status prior to handshaking via `SSL.SecurityStatus(...)`
 2. Perform `SSL.ForceHandshake(...)`
 3. Get the Security Status again
 4. Determine our next step:
    - If we need to send data to the client (and this wasn't a `wrap` call),
      change status to `NEED_WRAP`
    - If the handshake status reports security is on (and there is no more
      data to send in a `wrap` call!), we've just finished handshaking and
      have sent the last commit message, so change status to `FINISHED`.
    - If we have no more data to read from the client (and no outbound data
      either), we assume we need more data from the client so we change the
      status to `NEED_UNWRAP`.
    - Otherwise, we keep the status the same. We increment a unknown state
      counter -- this flips the value from its previous value to the opposite
      of what it was (e.g., `NEED_WRAP` to `NEED_UNWRAP`). This helps to
      ensure we don't ever get stuck.

This heuristic is wrapped in `updateHandshakeState`, which is called from
`wrap`, `unwrap`, and `getHandshakeStatus`; the unknown state counter gets
incremented in all three places.


### Post-Handshake Auth (PHA) and Re-Handshaking

Prior to TLS 1.3, clients and servers could initiate another handshake,
allowing clients the chance to specify authentication that wasn't provided at
the initial handshake. This also allowed the client and server to negotiate a
new key. Because this poses a [security risk][rfc.tls-renegotiation], a TLS
extension modifies the behavior to improve security. However, this behavior
was removed in TLS 1.3 and replaced with two separate steps: one mechanism
to provide authentication post-handshake and another to rekey the handshake.

By default, renegotiation and PHA support are both enabled for a `JSSEngine`.
In order to issue such a renegotiation, change the status of client
authentication after the initial handshake:

```java
// SSLEngine inst;
inst.setNeedClientAuth(true);
```

Then call `beginHandshake()` in order to re-handshake:

```java
inst.beginHandshake();
```

Complete a handshake as usual. Note that this will detect if TLS 1.3 or a
previous version was negotiated and choose between a rehandshaking and
PHA as appropriate for the selected TLS version.


#### Disabling Post-Handshake Auth (PHA)

In order to disable PHA support, cast `SSLEngine` to a `JSSEngine` instance
prior to the initial handshake and remove the PHA configuration option,
`SSL.ENABLE_POST_HANDSHAKE_AUTH` or set it to `0` to disable it:

```java
import org.mozilla.jss.ssl.javax.JSSEngine;
import org.mozilla.jss.nss.SSL;

// JSSEngine inst;
inst.addConfiguration(SSL.ENABLE_POST_HANDSHAKE_AUTH, 0);
```

Note that this must be done before `beginHandshake()`, `wrap()`, or `unwrap()`
is called.


#### Disabling Re-Handshaking

In order to disable or configure secure renegotiation, the following
configuration options can be modified:

 - `SSL.ENABLE_RENEGOTATION` - set to `SSL.RENEGOTIATE_NEVER` to disable all
   attempts at renegotation; set to `SSL.RENEGOTIATE_UNRESTRICTED` to always
   renegotiation even in unsafe scenarios; set to
   `SSL.RENEGOTIATE_REQUIRES_XTN` to only allow secure renegotiation; set to
   `SSL.RENEGOTIATE_TRANSITIONAL` to require the renegotiation extension
   when this is a server connection, but allowing clients to handshake with
   vulnerable servers.
 - `SSL.REQUIRE_SAFE_NEGOTIATION` - set to `1` by default, can be set to `0`
   to enable unsafe renegotiation.
 - `SSL.ENABLE_FALLBACK_SCSV` - set to `1` by default to send the fallback
   `SCSV` pseudo-ciphersuite; can be set to `0` to disable sending the
   option.

For example, to disable renegotiation completely:

```java
import org.mozilla.jss.ssl.javax.JSSEngine;
import org.mozilla.jss.nss.SSL;

// JSSEngine inst;
inst.addConfiguration(SSL.ENABLE_RENEGOTATION, SSL.RENEGOTIATE_NEVER);
```

Note that this must be done before `beginHandshake()`, `wrap()`, or `unwrap()`
or called.


### SSL Alert Handling

NSS exposes access to protocol-level alerts via the two callback functions,
`SSL_AlertReceivedCallback` (for when an alert was received from the remote
peer) and `SSL_AlertSentCallback` (for when NSS sends an alert to the
remote peer).  When attempting non-blocking IO, there's a weird quirk about
how these callbacks function: the only execute when a NSPR `PR_Read(...)` or
`PR_Write(...)` call executes on the SSL `PRFileDesc`. In particular, it
isn't sufficient to simply call `SSL_ForceHandshake(...)`! The callbacks
strictly occur when the alerts are on the wire, and don't execute for future
alerts we're expecting to send. This convolutes our exception handling
slightly.

JSS takes the following approach to handling SSL Alerts and exposing them to
callers via exceptions:

 1. `SSLFDProxy` contains separate queues of inbound and outbound `SSLAlert`s.
 2. `checkSSLAlert` verifies whether or not a fatal alert was received and/or
    sent.
 3. The first such fatal alert that was received or sent is converted into an
    `SSLException` instance; this is saved to the `JSSEngine`'s state and
    returned.
 4. `updateHandshakeState()` checks to see if a SSL alert occurred prior to
    calling SSL_ForceHandshake(...)` -- if so, it does no work.
 5. `wrap` and `unwrap` also check SSL alerts after all work is done. This
    ensures we always trigger a call into NSPR's `PR_Write(...)` or
    `PR_Read(...)`.
 6. When an alert occurs in `unwrap` (especially during a handshake), we
    make sure to set the state to `wrap` so our response (either the alert
    itself or our confirmation of it) is recorded.
 7. Lastly, we make sure to throw an exception only once and not multiple
    times.

### `wrap`/`unwrap` with large Buffers

While `SSLSession` indiciates the size of its internal buffers (via
`SSLSession.getApplicationBufferSize()`), we might get `src` and `dst`
buffers large enough to overflow our internal buffer multiple times. While
we could indicate this via returning a short read (`bytesConsumed()` or
`bytesProduced()` on `SSLEngineResult` from a `wrap` or `unwrap`
respectively), this could make the application allocate multiple buffers or
invoke `wrap()`/`unwrap()` multiple times. This overhead isn't necessary, as
we can detect this ourselves within `JSSEngine`.

For a `wrap()` call, there's two places data could be produced: in
`updateHandshakeState()` when we're handshaing or in `writeData()`. There's
only one place wire data is placed: `write_buf`. Because `write_buf` is
limited to `BUFFER_SIZE` bytes, we could produce bytes (up to the capacity
of `write_buf`), write them to `dst`, and then be able to produce more bytes.
We stop when we are no longer producing or consuming any bytes. This leaves
us with one extra invocation of `updateHandshakeState()`, `writeData()`, and
reading from `write_buf`, but this is necessary to flush the internal NSS
buffer.

A similar description applies to `unwrap`. To accomplish handling large
buffers, we simply wrap the core body of `wrap()` and `unwrap()` in a loop,
stopping when no more data is being produced and consumed. This will stop
because: the input and output buffers we're given are bounded in size and
if an exception occurs, after writting the appropriate alert to the wire,
NSS will quit reading/writing data. This means these loops are bound to
terminate eventually.

### Future Improvements

Currently we've only implemented the `JSSEngineReferenceImpl`; the optimized
implementation still needs to be written. In particular, the performance of
multiple JNI calls per step (`wrap` or `unwrap`) needs to be evaluated. We
could replace this with a copy of the contents of the underlying ByteBuffer,
perform a PR_Read or PR_Write operation, and then (in the event of a write),
copy the modified data back. This would give us better performance for large
buffers.

We only have a single `JSSKeyManager` that doesn't understand SNI; we should
make sure we support SNI from a client and server perspective.

We need to make sure we can interact with external (non-JSS)
[`X509TrustManager`s](javax.x09trustmanager) and use them to validate the
peer's certificates.

[javax.ssl-context]: https://docs.oracle.com/javase/8/docs/api/javax/net/ssl/SSLContext.html "javax.net.ssl.SSLContext"
[javax.ssl-engine]: https://docs.oracle.com/javase/8/docs/api/javax/net/ssl/SSLEngine.html "javax.net.ssl.SSLEngine"
[javax.x509trustmanager]: https://docs.oracle.com/javase/8/docs/api/javax/net/ssl/X509TrustManager.html "javax.net.ssl.X509TrustManager"
[jss.jssengine-tests]: https://github.com/dogtagpki/jss/blob/master/org/mozilla/jss/tests/TestSSLEngine.java "JSS SSLEngine tests"
[jss.pk11-cert]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/pkcs11/PK11Cert.html "org.mozilla.jss.pkcs11.PK11Cert"
[jss.pk11-privkey]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/pkcs11/PK11PrivKey.html "org.mozilla.jss.pkcs11.PK11PrivKey"
[jss.ssl-socket]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/ssl/SSLSocket.html "org.mozilla.jss.ssl.SSLSocket"
[oracle.sslengine.demo]: https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/samples/sslengine/SSLEngineSimpleDemo.java "Oracle SSLEngineSimpleDemo"
[rfc.tls-1.2]: https://tools.ietf.org/html/rfc5246 "TLSv1.2 RFC 5246"
[rfc.tls-renegotiation]: https://tools.ietf.org/html/rfc5746#section-5
[rfc.tls-1.3]: https://tools.ietf.org/html/rfc8446 "TLSv1.3 RFC 8446"
