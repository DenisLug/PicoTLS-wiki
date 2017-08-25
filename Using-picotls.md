Picotls implements the [TLS 1.3 protocol](https://tlswg.github.io/tls13-spec/).

The library relies on either of the two backends for cryptographic operations.
The [OpenSSL](https://www.openssl.org) backend uses libcrypto (the crypto library part of OpenSSL) for the operations.
The minicrypto backend uses [micro-ecc](https://github.com/kmackay/micro-ecc) and [cifra](https://github.com/ctz/cifra).

## Table of Contents

* [The Output Buffer](#the-output-buffer)
  * [Packetization and Zero-copy](#packetization-and-zero-copy)
* [Initializing the Context](#initializing-the-context)
  * [Initializing a Client Context](#initializing-a-client-context)
  * [Initializing a Server Context](#initializing-a-server-context)
* [Creating / Destroying a Connection Object](#creating--destroying-a-connection-object)
* [Performing a Handshake](#performing-a-handshake)
  * [Server Name Indication](#server-name-indication)
  * [Handshake Properties](#handshake-properties)
   * [Sending / Receiving Arbitrary Extensions](#sending--receiving-arbitrary-extensions)
* [Sending Data](#sending-data)
* [Receiving Data](#receiving-data)
* [Sending an Alert](#sending-an-alert)
* Resumption
* Using Early Data
* Error Codes

## The Output Buffer

Picotls uses a structured output buffer called `ptls_buffer_t` throughout the API that it provides.

By using `ptls_buffer_t`, applications can rely on picotls to allocate space for buffers, or can supply a buffer to avoid extra copying of data as well the cost of memory allocation.

`ptls_buffer_init` is the function that initializes the buffer object. When calling the function, the application optionally supplies a buffer owned by the application.
Picotls will at first try to fill into the buffer supplied by the application.
If the size of the buffer supplied by the application turns out to be too small, picotls will try to dynamically allocate a chunk of memory and set the `is_allocated` flag of the object to 1.
If the flag is set to a non-zero value, applications must call `ptls_buffer_dispose` to release the memory after handling the data stored in the buffer.
Applications can also call `ptls_buffer_dispose` for a buffer that does not have the flag set, however it should be noted that the memory block that the buffer points to will be zero-cleared by calling the function.

The following example illustrates the easiest way of using `ptls_buffer_t`.

```c
ptls_buffer_t sendbuf;

// supply a zero-sized application buffer (i.e. request use of dynamically allocated buffer)
ptls_buffer_init(&sendbuf, "", 0);
// encrypt application data
ret = ptls_send(tls, &sendbuf, "hello world", 11);
// send encrypted data
write(fd, sendbuf.base, sendbuf.off);
// dispose memory associated to the buffer
ptls_buffer_dispose(&sendbuf);
```

### Packetization and Zero-copy

It is possible to obtain the per record overhead imposed by TLS framing and AEAD by calling `ptls_get_record_overhead`.
The following example uses the function to obtain the exact size of payload that fits in a single packet, then uses a stack-based memory block for encrypting and sending the data.

```c
int send_encrypted_packet(int fd, ptls_t *tls, size_t mtu, struct iovec_t *data)
{
    size_t payload_size = min(data->len, mtu - ptls_get_record_overhead(tls));
    ptls_buffer_t sendbuf;
    uint8_t rawbuf[mtu];

    // encrypt payload_size bytes
    ptls_buffer_init(&sendbuf, rawbuf, mtu);
    if ((ret = ptls_send(tls, &sendbuf, data->base, payload_size) != 0)
        return ret;
    assert(!sendbuf.is_allocated);
    assert(sendbuf.base == rawbuf);

    // adjust the data range
    data->base += payload_size;
    data->len -= payload_size;

    // actually send the data
    return send_fully(fd, rawbuf, sendbuf.off);
}
```

## Initializing the Context

`ptls_context_t` is an object that stores the context of how a TLS connection should be created and used. The context object is shared among multiple TLS connections.

At the bare minimum, you need to initialize the following three members: `random_bytes`, `key_exchanges`, `cipher_suites`.
`random_bytes` is a callback for generating random bytes.
`key_exchanges` is a list of key exchange methods to be supported.
`cipher_suites` is a list of cipher-suites.

If you are using OpenSSL as the backend crypto library, you can assign `ptls_openssl_random_bytes`, `ptls_openssl_key_exchanges`, `ptls_openssl_cipher_suites`. The latter two include all the methods supported by the backend.
If you are using the minicrypto backend, instead use `ptls_minicrypto_random_bytes`, `ptls_minicrypto_key_exchanges`, `ptls_minicrypto_cipher_suites`.

The example below illustrates how you setup the three members.

```c
ptls_context_t ctx;
memset(&ctx, 0, sizeof(ctx));
ctx.random_bytes = ptls_openssl_random_bytes;
ctx.key_exchanges = ptls_openssl_key_exchanges;
ctx.cipher_suites = ptls_openssl_cipher_suites;
```

### Initializing a Client Context

If you are implementing a client, you should also setup the `verify_certificate` property.
For OpenSSL backend, you can do it by calling `ptls_openssl_init_verify_certificate` and then setting the pointer to the initialized object as a member of the context.
The second argument of the function is a pointer to a X509 store that contains the trusted CAs. If the supplied value is NULL, the default store will be used.

```c
ptls_openssl_verify_certificate_t verifier;
ptls_openssl_init_verify_certificate(&verifier, NULL);
ctx.verify_certificate = &verifier.super;
```

### Initializing a Server Context

If you are implementing a server, you need to setup the `certificates` property (which is a list of binary octets repesenting each piece of certificate) and a `sign_certificate` callback.

The example below shows how you can use OpenSSL to load a chain of PEM-encoded certificates.
 
```c
static ptls_iovec_t certs[16];
size_t count = 0;
FILE *fp = fopen("cert-chain.pem", "rb");
assert(fp != NULL);
X509 *cert;
while ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
    ptls_iovec_t *dst = certs + count++;
    dst->len = i2d_X509(cert, &dst->base);
}
fclose(fp);
ctx.certificates.list = certs;
ctx.certificates.count = count;
```

The code below shows how you can setup a `sign_certificate` object using OpenSSL.

```c
static ptls_openssl_sign_certificate_t signer;
FILE *fp = fopen(optarg, "rb");
assert(fp != NULL);
EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
assert(pkey != NULL);
ptls_openssl_init_sign_certificate(&signer, pkey);
EVP_PKEY_free(pkey);
ctx.sign_certificate = &signer.super;
fclose(fp);
```

## Creating / Destroying a Connection Object

The `ptls_new` function creates an object for handling a TLS connection.
The first argument is the pointer to the context.
The second argument is a boolean indicating the side of the connection (0: client, 1 : server).

```c
ptls_t *tls = ptls_new(&ctx, is_server);
```

`ptls_free` should be called to release the resources allocated for the connection.
Note that you need to call `ptls_send_alert` to send a closure alert before closing the underlying connection and freeing the resources.

## Performing a Handshake

`ptls_handshake` function performs the handshake. It consumes _some_ of the supplied input, and optionally pushes some response to the send buffer which is also supplied as an argument to the function.

The input must be zero-sized for the first call to the handshake function on the client-side, since it is the responsibility of the client to start the handshake.

The following code snippet starts a TLS handshake on the client side (i.e. sends ClientHello).

```c
ptls_buffer_t sendbuf;
// initialize sendbuf to use dynamically allocated buffer (by supplying a zero-
// sized buffer)
ptls_buffer_init(&sendbuf, "", 0);
// start the handshake
int ret = ptls_handshake(tls, &sendbuf, NULL, NULL, NULL);
assert(ret == PTLS_ERROR_IN_PROGRESS);
// send data in send buffer
if (!send_fully(fd, sendbuf.base, sendbuf.off)) {
    ptls_buffer_dispose(&sendbuf);
    goto Closed;
}
// dispose the buffer
ptls_buffer_dispose(&sendbuf);
```

The code below proceeds the handshake until it completes (either on the server-side or on the client-side).

```c
uint8_t recvbuf[8192];
ssize_t roff, rret;
ptls_buffer_t sendbuf;
int ret;

do {
    // read data from socket
    while ((rret = read(fd, recvbuf, sizeof(recvbuf)) == -1 && errno == EINTR)
        ;
    if (rret == 0)
        goto Closed;
    // repeatedly call ptls_handshake (and send the output) until handshake
    // completes or when the function consumes all input
    roff = 0;
    do {
        ptls_buffer_init(&sendbuf, "", 0);
        size_t consumed = rret - roff;
        ret = ptls_handshake(tls, &sendbuf, recvbuf + roff, &consumed, NULL);
        roff += consumed;
        if ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS) && sendbuf.off != 0) {
            if (!send_fully(fd, sendbuf.base, sendbuf.off)) {
                ptls_buffer_dispose(&sendbuf);
                goto Closed;
            }
        }
        ptls_buffer_dispose(&sendbuf);
    } while (ret == PTLS_ERROR_IN_PROGRESS && rret != roff);
} while (ret == PTLS_ERROR_IN_PROGRESS);

if (ret == 0) {
    // handshake succeeded (we might have some application data after
    // recvbuf + roff)
} else {
    // handshake failed
}
```

### Server Name Indication

If the client intends to send a Server Name Indication extension, it should call `ptls_set_server_name` prior to initiating a TLS handshake.

A server can obtain the value of the extension provided by the client by calling `ptls_get_server_name`. The function will return `NULL` in case the client did not use the extension.

### Handshake Properties

The last argument of `ptls_handshake` is an optional pointer to `ptls_handshake_properties_t`, which is used for setting and / or obtaining additional information related to the handshake.

It can be used to set or obtain the following properties, as well as for sending / receiving arbitrary extensions.

* client-only
  * ALPN offerings to be sent (`client.negotiated_protocols`)
  * session ticket to be sent (`client.session_ticket`)
  * amount of early data that can be sent (`client.max_early_data_size`)
  * whether if early data has been accepted by peer (`client.early_data_accepted_by_peer`)
* server-only
  * PSK binder being selected

#### Sending / Receiving Arbitrary Extensions

An endpoint can specify arbitrary extensions that should be sent to the peer, by setting an array of `ptls_raw_extensions_t` to the `additional_extensions` field of `ptls_handshake_properties_t`.
The array is terminated with an extension type of `UINT16_MAX`.
If the endpoint is the client, the extensions are sent as part of ClientHello.
If the endpoint is the server, the extensions are sent as part of EncryptedExtensions.

To receive such extensions, an endpoint should set two callbacks `collect_extension`, `collected_extensions`.
The `collect_extension` callback accepts an extension type that has been sent by the peer as an argument, and should return a boolean value indicating if the extension should be recorded.
After receiving all extensions (and recording the extensions that were deemed necessary by the `collect_extension` callback), picotls calls the `collected_extensions` callback, supplying the list of extensions that have been recorded as the argument (the list is terminated with a type of `UINT16_MAX`).
The TLS handshake will continue if the `collected_extensions` callback return zero; otherwise the handshake is aborted using the value returned by the callback as the error code that is being sent to the peer as an TLS Alert.

## Sending Data

`ptls_send` accepts a input block and appends encrypted output to the send buffer (as more than one TLS record).

```c
uint8_t *input = ...;
size_t input_size = ...;

int ret = ptls_send(tls, &sendbuf, input, input_size);
assert(ret == 0);
send_fully(fd, sendbuf.base, sendbuf.off);
ptls_buffer_dispose(&sendbuf);
```

## Receiving Data

`ptls_receive` consumes _some_ of the input and decrypts _at most one_ TLS record.

`handle_input` function in the following example consumes all input and processes the decrypted data.

```c
int handle_input(ptls_t *tls, const uint8_t *input, size_t input_size)
{
    size_t input_off = 0;
    ptls_buffer_t plaintextbuf;
    int ret;

    if (input_size == 0)
        return 0;

    ptls_buffer_init(&plaintextbuf, "", 0);

    do {
        size_t consumed = input_size - input_off;
        ret = ptls_receive(tls, &plaintextbuf, input + input_off, &consumed);
        input_off += consumed;
    } while (ret == 0 && input_off < input_size);

    if (ret == 0)
        ret = handle_decrypted_data(plaintextbuf.base, plaintextbuf.off);

    ptls_buffer_dispose(&plaintextbuf);

    return ret;
}
```

## Sending an Alert

`ptls_send_alert` function can be used for sending an alert.

If something goes wrong during handshake, `ptls_handshake` will implicitly call the function to notify the peer of the error that has occurred.
The application is responsible for calling the function for sending an alert in case of other occasions (including graceful shutdown of a TLS connection).