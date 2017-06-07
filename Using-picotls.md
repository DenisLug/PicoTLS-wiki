## Table of Contents

* [Background Information](#background-information)
* [Initializing the Context](#initializing-the-context)
  * [Initializing a Client Context](#initializing-a-client-context)
  * [Initializing a Server Context](#initializing-a-server-context)
* [Creating / Destroying a Connection Object](#creating--destroying-a-connection-object)
* [Performing a Handshake](#performing-a-handshake)
* [Sending Data](#sending-data)
* Receiving Data
* Sending an Alert
* Resumption
* Using Early Data

## Background Information

Picotls implements the [TLS 1.3 protocol](https://tlswg.github.io/tls13-spec/).

The library relies on either of the two backends for the cryptographic operations.
The OpenSSL backend uses libcrypto (the crypto library part of OpenSSL) for the operations.
The minicrypto backend uses [micro-ecc](https://github.com/kmackay/micro-ecc) and [cifra](https://github.com/ctz/cifra).

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

The output buffer is supplied as a pointer to `ptls_buffer_t`.
`ptls_buffer_init` is the function that initializes the buffer object.
The object either contains a buffer that is supplied from the application (by passing a non-zero sized buffer as an argument to `ptls_buffer_init`), or a dynamically allocated buffer managed by itself. In case of the latter, the `is_allocated` flag of the object is set to a non-zero value, and the application is responsible for calling `ptls_buffer_dispose` so that the allocated chunk of memory can be freed.

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

The last argument of `ptls_handshake` can be used to set and / or obtain additional information related to the handshake (e.g. use of session ticket, handle TLS extensions).

## Sending Data

`pls_send` accepts a input block and appends encrypted output to the send buffer (as more than one TLS record).

```c
uint8_t *input = ...;
size_t input_len = ...;

int ret = ptls_send(tls, &sendbuf, input, input_size);
assert(ret == 0);
send_fully(fd, sendbuf.base, sendbuf.off);
ptls_buffer_dispose(&sendbuf);
```
