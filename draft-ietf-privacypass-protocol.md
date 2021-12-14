---
title: "Privacy Pass Issuance Protocol"
abbrev: PP integration
docname: draft-ietf-privacypass-protocol-latest
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: A. Davidson
    name: Alex Davidson
    org: Brave Software
    city: Lisbon
    country: Portugal
    email: alex.davidson92@gmail.com
 -
    ins: S. Valdez
    name: Steven Valdez
    org: Google LLC
    email: svaldez@chromium.org
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: caw@heapingbits.net

normative:
  RFC2119:
  RFC8446:
  I-D.irtf-cfrg-voprf:
  I-D.ietf-privacypass-architecture:
  I-D.ietf-privacypass-http-api:
informative:
  RFC7049:
  RFC7159:

--- abstract

This document specifies two variants of the the two-message issuance protocol
for Privacy Pass tokens: one that produces tokens that are privately
verifiable, and another that produces tokens that are publicly verifiable.
The privately verifiable issuance protocol optionally supports public
metadata during the issuance flow.

--- middle

# Introduction

The Privacy Pass protocol provides a privacy-preserving authorization
mechanism. In essence, the protocol allows clients to provide
cryptographic tokens that prove nothing other than that they have been
created by a given server in the past {{I-D.ietf-privacypass-architecture}}.

This document describes the issuance protocol for Privacy Pass. It specifies
two variants: one that is privately verifiable based on the oblivious
pseudorandom function from {{!OPRF=I-D.irtf-cfrg-voprf}}, and one that is
publicly verifiable based on the blind RSA signature scheme
{{!BLINDRSA=I-D.irtf-cfrg-blind-signatures}}.

This document DOES NOT cover the architectural framework required for
running and maintaining the Privacy Pass protocol in the Internet
setting. In addition, it DOES NOT cover the choices that are necessary
for ensuring that client privacy leaks do not occur. Both of these
considerations are covered in {{I-D.ietf-privacypass-architecture}}.

# Terminology

{::boilerplate bcp14}

The following terms are used throughout this document.

- Client: An entity that provides authorization tokens to services
  across the Internet, in return for authorization.
- Issuer: A service produces Privacy Pass tokens to clients.
- Private Key: The secret key used by the Issuer for issuing tokens.
- Public Key: The public key used by the Issuer for issuing and verifying
  tokens.

We assume that all protocol messages are encoded into raw byte format
before being sent across the wire.

# Issuance Protocol for Privately Verifiable Tokens with Public Metadata {#private-flow}

The Privacy Pass issuance protocol is a two message protocol that takes
as input a challenge from the redemption protocol and produces a token,
as shown in the figure below.

~~~
   Origin          Client                   Issuer
                (pkI, info)            (skI, pkI, info)
                  +------------------------------------\
  Challenge   ----> TokenRequest ------------->        |
                  |                       (evaluate)   |
    Token    <----+     <--------------- TokenResponse |
                  \------------------------------------/
~~~

Issuers provide a Private and Public Key, denoted skI and pkI, respectively,
used to produce tokens as input to the protocol. See {{issuer-configuration}}
for how this key pair is generated.

Clients provide the following as input to the issuance protocol:

- Issuer name, identifying the Issuer. This is typically a host name that
  can be used to construct HTTP requests to the Issuer.
- Issuer Public Key pkI, with a key identifier `key_id` computed as
  described in {{issuer-configuration}}.
- Challenge value `challenge`, an opaque byte string provided by the
  corresponding redemption protocol [http-auth-doc].

Both Client and Issuer also share a common public string called `info`.

Given this configuration and these inputs, the two messages exchanged in
this protocol are described below.

## Client-to-Issuer Request {#client-to-issuer}

The Client first creates a verifiable context as follows:

~~~
client_context = SetupVerifiableClient(0x0004, pkI)
~~~

Here, 0x0004 is the two-octet identifier corresponding to
the OPRF(P-384, SHA-384) ciphersuite in {{OPRF}}.

The Client then creates an issuance request message for a random value `nonce`
using the input challenge and Issuer key identifier as follows:

~~~
nonce = random(32)
context = SHA256(challenge)
token_input = concat(0x0001, nonce, context, key_id)
blind, blinded_message = client_context.Blind(nonce)
~~~

The Client then creates a TokenRequest structured as follows:

~~~
struct {
   uint8_t token_type;
   uint8_t token_key_id;
   uint8_t blinded_msg[Nk];
} TokenRequest;
~~~

The structure fields are defined as follows:

- "version" is a 1-octet integer, which matches the version in the challenge.
This document defines version 1.

- "token_key_id" is the least significant byte of the `key_id`.

- "blinded_msg" is the Nk-octet request defined above.

The Client then generates an HTTP POST request to send to the Issuer,
with the TokenRequest as the body. The media type for this request
is "message/token-request". An example request is shown below, where
Nk = 48.

~~~
:method = POST
:scheme = https
:authority = issuer.net
:path = /token-request
accept = message/token-response
cache-control = no-cache, no-store
content-type = message/token-request
content-length = 50

<Bytes containing the TokenRequest>
~~~

Upon receipt of the request, the Issuer validates the following conditions:

- The TokenRequest contains a supported version
- For version 1, the TokenRequest.token_key_id corresponds to a key ID
  of a Public Key owned by the issuer.
- For version 1, the TokenRequest.blinded_msg is of the correct size

If any of these conditions is not met, the Issuer MUST return an HTTP 400 error
to the Client, which will forward the error to the client.

## Issuer-to-Client Response {#issuer-to-client}

If the Issuer is willing to produce a token token to the Client, the Issuer
completes the issuance flow by computing a blinded response as follows:

~~~
server_context = SetupVerifiableServer(0x0004, skI, pkI)
evaluated_msg, proof = server_context.Evaluate(skI,
    TokenRequest.blinded_message, info)
~~~

The Issuer then creates a TokenResponse structured as follows:

~~~
struct {
   uint8_t evaluated_msg[Nk];
   uint8_t proof[Ns+Ns];
} TokenResponse;
~~~

The structure fields "evaluated_msg" and "proof" are as computed above,
where Ns is as defined in {{OPRF, Section 4}}.

The Issuer generates an HTTP response with status code 200 whose body consists
of TokenResponse, with the content type set as "message/token-response".

~~~
:status = 200
content-type = message/token-response
content-length = 144

<Bytes containing the TokenResponse>
~~~

## Finalization

Upon receipt, the Client handles the response and, if successful, processes the
body as follows:

~~~
authenticator = client_context.Finalize(context, blind, pkI,
  evaluated_msg, blinded_msg, info)
~~~

If this succeeds, the Client then constructs a Token as described in
[http-auth-doc] as follows:

~~~
struct {
    uint16_t token_type = 0x0001
    uint8_t nonce[32];
    uint8_t context[32];
    uint8_t key_id[32];
    uint8_t authenticator[Nk];
} Token;
~~~

Otherwise, the Client aborts the protocol.

## Issuer Configuration

Issuers are configured with Private and Public Key pairs, each denoted skI and
pkI, respectively, used to produce tokens. Each key pair MUST be generated as
follows:

~~~
(skI, pkI) = GenerateKeyPair()
~~~

The key identifier for this specific key pair, denoted `key_id`, is computed
as follows:

~~~
key_id = SHA256(0x0004 || SerializeElement(pkI))
~~~

# Issuance Protocol for Publicly Verifiable Tokens {#public-flow}

This section describes a variant of the issuance protocol in {{private-flow}}
for producing publicly verifiable tokens. It differs from the previous variant
in two important ways:

1. The output tokens are publicly verifiable by anyone with the Issuer public
   key; and
1. The issuance protocol does not admit public or private metadata to bind
   additional context to tokens.

Otherwise, this variant is nearly identical. In particular, Issuers provide a
Private and Public Key, denoted skI and pkI, respectively, used to produce tokens
as input to the protocol. See {{public-issuer-configuration}} for how this key
pair is generated.

Clients provide the following as input to the issuance protocol:

- Issuer name, identifying the Issuer. This is typically a host name that
  can be used to construct HTTP requests to the Issuer.
- Issuer Public Key pkI, with a key identifier `key_id` computed as
  described in {{issuer-configuration}}.
- Challenge value `challenge`, an opaque byte string provided by the
  corresponding redemption protocol [http-auth-doc].

Given this configuration and these inputs, the two messages exchanged in
this protocol are described below.

## Client-to-Issuer Request {#public-request}

The Client first creates an issuance request message for a random value
`nonce` using the input challenge and Issuer key identifier as follows:

~~~
nonce = random(32)
context = SHA256(challenge)
token_input = concat(0x0002, nonce, context, key_id)
blinded_msg, blind_inv = rsabssa_blind(ORIGIN_TOKEN_KEY, message)
~~~

The Client then creates a TokenRequest structured as follows:

~~~
struct {
   uint8_t token_type;
   uint8_t token_key_id;
   uint8_t blinded_msg[Nk];
} TokenRequest;
~~~

The structure fields are defined as follows:

- "version" is a 1-octet integer, which matches the version in the challenge.
This document defines version 1.

- "token_key_id" is the least significant byte of the `key_id`.

- "blinded_msg" is the Nk-octet request defined above.

The Client then generates an HTTP POST request to send to the Issuer,
with the TokenRequest as the body. The media type for this request
is "message/token-request". An example request is shown below, where
Nk = 512.

~~~
:method = POST
:scheme = https
:authority = issuer.net
:path = /token-request
accept = message/token-response
cache-control = no-cache, no-store
content-type = message/token-request
content-length = 514

<Bytes containing the TokenRequest>
~~~

Upon receipt of the request, the Issuer validates the following conditions:

- The TokenRequest contains a supported version.
- For version 1, the TokenRequest.token_key_id corresponds to a key ID
  of a Public Key owned by the issuer.
- For version 1, the TokenRequest.blinded_msg is of the correct size.

If any of these conditions is not met, the Issuer MUST return an HTTP 400 error
to the Client, which will forward the error to the client.

## Issuer-to-Client Response {#public-response}

If the Issuer is willing to produce a token token to the Client, the Issuer
completes the issuance flow by computing a blinded response as follows:

~~~
blind_sig = rsabssa_blind_sign(skI, TokenRequest.blinded_rmsg)
~~~

The Issuer generates an HTTP response with status code 200 whose body consists
of `blind_sig`, with the content type set as "message/token-response".

~~~
:status = 200
content-type = message/token-response
content-length = 512

<Bytes containing the TokenResponse>
~~~

## Finalization

Upon receipt, the Client handles the response and, if successful, processes the
body as follows:

~~~
authenticator = rsabssa_finalize(pkI, nonce, blind_sig, blind_inv)
~~~

If this succeeds, the Client then constructs a Token as described in
[http-auth-doc] as follows:

~~~
struct {
    uint16_t token_type = 0x0002
    uint8_t nonce[32];
    uint8_t context[32];
    uint8_t key_id[32];
    uint8_t authenticator[Nk];
} Token;
~~~

Otherwise, the Client aborts the protocol.

## Issuer Configuration {#public-issuer-configuration}

Issuers are configured with Private and Public Key pairs, each denoted skI and
pkI, respectively, used to produce tokens. Each key pair MUST be generated as
as a valid 4096-bit RSA private key according to [TODO]. The key identifier
for a keypair (skI, pkI), denoted `key_id`, is computed as SHA256(encoded_key),
where encoded_key is a DER-encoded SubjectPublicKeyInfo object carrying pkI.

--- back

# Security considerations

This document outlines how to instantiate the Privacy Pass protocol
based on the VOPRF defined in {{I-D.irtf-cfrg-voprf}}. All security
considerations described in the VOPRF document also apply in the Privacy
Pass use-case. Considerations related to broader privacy and security
concerns in a multi-client and multi-server setting are deferred to the
Architecture document {{I-D.ietf-privacypass-architecture}}.

# IANA considerations

This document updates the "Token Type" Registry with the following values.

| Value  | Name                   | Public | Nk  | Reference        |
|:-------|:-----------------------|:-------|:----|:-----------------|
| 0x0000 | (reserved)             | N/A    | N/A | N/A              |
| 0x0001 | OPRF(P-384, SHA-384)   | N      | 48  | {{private-flow}} |
| 0x0002 | Blind RSA, 4096        | Y      | 512 | {{public-flow}} |
{: #aeadid-values title="Token Types"}

# Acknowledgements

The authors of this document would like to acknowledge the helpful
feedback and discussions from Benjamin Schwartz, Joseph Salowey, Sofía
Celi, and Tara Whalen.

