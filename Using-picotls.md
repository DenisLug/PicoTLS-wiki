## Table of Contents

* Initializing the Context
 * Initializing a Client Context
 * Initializing a Server Context
* Creating / Destroying a Connection Object
* Performing a Handshake
* Send / Receive
* Sending an Alert
* Resumption
* Using Early Data

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