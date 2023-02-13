---
title: "Privacy Pass Issuance Protocol"
abbrev: Privacy Pass Issuance
docname: draft-ietf-privacypass-protocol-latest
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: S. Celi
    name: Sofía Celi
    org: Brave Software
    city: Lisbon
    country: Portugal
    email: cherenkov@riseup.net
 -
    ins: A. Davidson
    name: Alex Davidson
    org: Brave Software
    city: Lisbon
    country: Portugal
    email: alex.davidson92@gmail.com
 -
    ins: A. Faz-Hernandez
    name: Armando Faz-Hernandez
    org: Cloudflare
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: armfazh@cloudflare.com
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
  WellKnownURIs:
    title: Well-Known URIs
    target: https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml

--- abstract

This document specifies two variants of the two-message issuance protocol
for Privacy Pass tokens: one that produces tokens that are privately
verifiable using the issuance private key, and another that produces tokens
that are publicly verifiable using the issuance public key.

--- middle

# Introduction

The Privacy Pass protocol provides a privacy-preserving authorization
mechanism. In essence, the protocol allows clients to provide cryptographic
tokens that prove nothing other than that they have been created by a given
server in the past {{?ARCHITECTURE=I-D.ietf-privacypass-architecture}}.

This document describes the issuance protocol for Privacy Pass built on
{{?HTTP=RFC9110}}. It specifies two variants: one that is privately verifiable
using the issuance private key based on the oblivious pseudorandom function from
{{!OPRF=I-D.irtf-cfrg-voprf}}, and one that is publicly verifiable using the
issuance public key based on the blind RSA signature scheme
{{!BLINDRSA=I-D.irtf-cfrg-rsa-blind-signatures}}.

This document does not cover the Privacy Pass architecture, including
choices that are necessary for deployment and application specific choices
for protecting client privacy. This information is covered in {{ARCHITECTURE}}.

# Terminology

{::boilerplate bcp14}

The following terms are used throughout this document.

- Client: An entity that runs the Issuance protocol with an Issuer to produce
  Tokens that can be later used for redemption (see
  {{Section 2.2 of !AUTHSCHEME=I-D.ietf-privacypass-auth-scheme}}).
- Issuer: A service that provides Tokens to Clients.
- Issuer Public Key: The public key (from a private-public key pair) used by
  the Issuer for issuing and verifying Tokens.
- Issuer Private Key: The private key (from a private-public key pair) used by
  the Issuer for issuing and verifying Tokens.

This document additionally uses the terms "Origin" and "Token" as defined in
{{ARCHITECTURE}}.

Unless otherwise specified, this document encodes protocol messages in TLS
notation from {{Section 3 of !TLS13=RFC8446}}. Moreover, all constants are in
network byte order.

# Protocol Overview

The issuance protocols defined in this document embody the core of Privacy Pass.
Clients receive TokenChallenge inputs from the redemption protocol
({{AUTHSCHEME, Section 2.1}}) and use the issuance protocols to produce
corresponding Token values ({{AUTHSCHEME, Section 2.2}}). The issuance protocol
describes how Clients and Issuers interact to compute a token using a one-round
protocol consisting of a TokenRequest from the Client and TokenResponse from
the Issuer. This interaction is shown below.

~~~ aasvg
  Origin             Client        Attester          Issuer

                    +-------------------------------------.
  TokenChallenge ---> Attest ------->                      |
                    | TokenRequest ------------------>     |
                    |                            (evaluate)|
      Token  <------+  <-------------------  TokenResponse |
                     `------------------------------------'
~~~
{: #fig-issuance title="Issuance Overview"}

The TokenChallenge inputs to the issuance protocols described in this
document can be interactive or non-interactive, and per-origin or cross-origin.

The issuance protocols defined in this document are compatible with any
deployment model defined in {{Section 4 of ARCHITECTURE}}. The details of
attestation are outside the scope of the issuance protocol; see
{{Section 4 of ARCHITECTURE}} for information about how attestation can
be implemented in each of the relevant deployment models.

This document describes two variants of the issuance protocol: one that is
privately verifiable ({{private-flow}}) using the issuance private key based on
the oblivious pseudorandom function from {{!OPRF=I-D.irtf-cfrg-voprf}}, and one
that is publicly verifiable ({{public-flow}}) using the issuance public key
based on the blind RSA signature scheme
{{!BLINDRSA=I-D.irtf-cfrg-rsa-blind-signatures}}.

# Configuration {#setup}

Issuers MUST provide two parameters for configuration:

1. Issuer Request URL: A token request URL for generating access tokens.
   For example, an Issuer URL might be
   https://issuer.example.net/request.
2. Issuer Public Key values: A list of Issuer Public Keys for the issuance
   protocol.

The Issuer parameters can be obtained from an Issuer via a directory object,
which is a JSON object ({{!RFC8259, Section 4}}) whose values are other JSON
values ({{RFC8259, Section 3}}) for the parameters. The contents of this JSON
object are defined in {{directory-values}}.

| Field Name           | Value                                                  |
|:---------------------|:-------------------------------------------------------|
| issuer-request-uri   | Issuer Request URL value (as an absolute or relative URL) as a percent-encoded URL string, represented as a JSON string ({{RFC8259, Section 7}}) |
| token-keys           | List of Issuer Public Key values, each represented as JSON objects ({{RFC8259, Section 4}}) |
{: #directory-values title="Issuer directory object description"}

Each "token-keys" JSON object contains the fields and corresponding raw values
defined in {{tokenkeys-values}}.

| Field Name   | Value                                                  |
|:-------------|:-------------------------------------------------------|
| token-type   | Integer value of the Token Type, as defined in {{token-type}}, represented as a JSON number ({{RFC8259, Section 6}}) |
| token-key    | The base64url encoding of the Public Key for use with the issuance protocol, including padding, represented as a JSON string ({{RFC8259, Section 7}}) |
{: #tokenkeys-values title="Issuer 'token-keys' object description'"}

Issuers MAY advertise multiple token-keys for the same token-type to
support key rotation. In this case, Issuers indicate preference for which
token key to use based on the order of keys in the list, with preference
given to keys earlier in the list.

Altogether, the Issuer's directory could look like:

~~~
 {
    "issuer-request-uri": "https://issuer.example.net/request",
    "token-keys": [
      {
        "token-type": 2,
        "token-key": "MI...AB",
      },
      {
        "token-type": 2,
        "token-key": "MI...AQ",
      }
    ]
 }
~~~

Issuer directory resources have the media type
"application/token-issuer-directory" and are located at the well-known location
/.well-known/token-issuer-directory; see {{wkuri-reg}} for the registration
information for this well-known URI.

Issuers SHOULD use HTTP caching to permit caching of this resource
{{!RFC5861}}. The cache lifetime depends on the Issuer's key rotation schedule.
Regular rotation of token keys is recommended to minimize the risk of key
compromise.

Issuers can control cache lifetime with the Cache-Control header, as follows:

~~~
  Cache-Control: max-age=86400
~~~

Consumers of the Issuer directory resource SHOULD follow the usual HTTP caching
{{!RFC9111}} semantics when processing this resource. Long cache lifetimes may
result in use of stale Issuer configuration information, whereas short
lifetimes may result in decreased performance. When use of an Issuer
configuration results in token issuance failures, e.g., because the
configuration information is too stale, the directory SHOULD be fetched and
revalidated.

# Issuance Protocol for Privately Verifiable Tokens {#private-flow}

The privately verifiable issuance protocol allows Clients to produce Token
values that verify using the Issuer Private Key. This protocol is based
on the oblivious pseudorandom function from {{!OPRF=I-D.irtf-cfrg-voprf}}.

Issuers provide a Private and Public Key, denoted `skI` and `pkI` respectively,
used to produce tokens as input to the protocol. See {{issuer-configuration}}
for how this key pair is generated.

Clients provide the following as input to the issuance protocol:

- Issuer Request URI: A URI to which token request messages are sent. This can
  be a URL derived from the "issuer-request-uri" value in the Issuer's
  directory resource, or it can be another Client-configured URL. The value
  of this parameter depends on the Client configuration and deployment model.
  For example, in the 'Joint Origin and Issuer' deployment model, the Issuer
  Request URI might be correspond to the Client's configured Attester, and the
  Attester is configured to relay requests to the Issuer.
- Issuer name: An identifier for the Issuer. This is typically a host name that
  can be used to construct HTTP requests to the Issuer.
- Issuer Public Key: `pkI`, with a key identifier `token_key_id` computed as
  described in {{issuer-configuration}}.
- Challenge value: `challenge`, an opaque byte string. For example, this might
  be provided by the redemption protocol in {{AUTHSCHEME}}.

Given this configuration and these inputs, the two messages exchanged in
this protocol are described below. This section uses notation described in
{{OPRF, Section 4}}, including SerializeElement and DeserializeElement,
SerializeScalar and DeserializeScalar, and DeriveKeyPair.

The constants `Ne` and `Ns` are as defined in {{OPRF, Section 4}} for
OPRF(P-384, SHA-384). The constant `Nk` is defined by {{private-token-type}}.

## Client-to-Issuer Request {#private-request}

The Client first creates a context as follows:

~~~
client_context = SetupVOPRFClient(0x0004, pkI)
~~~

Here, 0x0004 is the two-octet identifier corresponding to the
OPRF(P-384, SHA-384) ciphersuite in {{OPRF}}. SetupVOPRFClient
is defined in {{OPRF, Section 3.2}}.

The Client then creates an issuance request message for a random value `nonce`
with the input challenge and Issuer key identifier as described below:

~~~
nonce = random(32)
challenge_digest = SHA256(challenge)
token_input = concat(0x0001, // Token type field is 2 bytes long
                     nonce,
                     challenge_digest,
                     token_key_id)
blind, blinded_element = client_context.Blind(token_input)
~~~

The Blind function is defined in {{OPRF, Section 3.3.2}}.
If the Blind function fails, the Client aborts the protocol.
The Client stores the `nonce` and `challenge_digest` values locally
for use when finalizing the issuance protocol to produce a token
(as described in {{private-finalize}}).

The Client then creates a TokenRequest structured as follows:

~~~
struct {
  uint16_t token_type = 0x0001; /* Type VOPRF(P-384, SHA-384) */
  uint8_t truncated_token_key_id;
  uint8_t blinded_msg[Ne];
} TokenRequest;
~~~

The structure fields are defined as follows:

- "token_type" is a 2-octet integer, which matches the type in the challenge.

- "truncated_token_key_id" is the least significant byte of the `token_key_id`
  ({{issuer-configuration}}) in network byte order (in other words, the last 8
  bits of `token_key_id`).

- "blinded_msg" is the Ne-octet blinded message defined above, computed as
  `SerializeElement(blinded_element)`.

The values `token_input` and `blinded_element` are stored locally and used
later as described in {{private-finalize}}. The Client then generates an HTTP
POST request to send to the Issuer Request URI, with the TokenRequest as the
content. The media type for this request is
"application/private-token-request". An example request is shown below.

~~~
:method = POST
:scheme = https
:authority = issuer.example.net
:path = /request
accept = application/private-token-response
cache-control = no-cache, no-store
content-type = application/private-token-request
content-length = <Length of TokenRequest>

<Bytes containing the TokenRequest>
~~~

## Issuer-to-Client Response {#private-response}

Upon receipt of the request, the Issuer validates the following conditions:

- The TokenRequest contains a supported token_type.
- The TokenRequest.truncated_token_key_id corresponds to the truncated key ID
  of a Public Key owned by the issuer.
- The TokenRequest.blinded_msg is of the correct size.

If any of these conditions is not met, the Issuer MUST return an HTTP 400 error
to the client. The Issuer then tries to deseralize
TokenRequest.blinded_msg using DeserializeElement from {{Section 2.1 of OPRF}},
yielding `blinded_element`. If this fails, the Issuer MUST return an HTTP 400
error to the client. Otherwise, if the Issuer is willing to produce a token to
the Client, the Issuer completes the issuance flow by computing a blinded
response as follows:

~~~
server_context = SetupVOPRFServer(0x0004, skI, pkI)
evaluate_element, proof =
  server_context.Evaluate(skI, blinded_element)
~~~

SetupVOPRFServer is in {{OPRF, Section 3.2}} and Evaluate is defined in
{{OPRF, Section 3.3.2}}. The Issuer then creates a TokenResponse structured
as follows:

~~~
struct {
   uint8_t evaluate_msg[Ne];
   uint8_t evaluate_proof[Ns+Ns];
} TokenResponse;
~~~

The structure fields are defined as follows:

- "evaluate_msg" is the Ne-octet evaluated message, computed as
  `SerializeElement(evaluate_element)`.

- "evaluate_proof" is the (Ns+Ns)-octet serialized proof, which is a pair of
  Scalar values, computed as
  `concat(SerializeScalar(proof[0]), SerializeScalar(proof[1]))`.

The Issuer generates an HTTP response with status code 200 whose content
consists of TokenResponse, with the content type set as
"application/private-token-response".

~~~
:status = 200
content-type = application/private-token-response
content-length = <Length of TokenResponse>

<Bytes containing the TokenResponse>
~~~

## Finalization {#private-finalize}

Upon receipt, the Client handles the response and, if successful, deserializes
the content values TokenResponse.evaluate_msg and TokenResponse.evaluate_proof,
yielding `evaluated_element` and `proof`. If deserialization of either value
fails, the Client aborts the protocol. Otherwise, the Client processes the
response as follows:

~~~
authenticator = client_context.Finalize(token_input, blind,
                                        evaluated_element,
                                        blinded_element,
                                        proof)
~~~

The Finalize function is defined in {{OPRF, Section 3.3.2}}. If this
succeeds, the Client then constructs a Token as follows:

~~~
struct {
  uint16_t token_type = 0x0001; /* Type VOPRF(P-384, SHA-384) */
  uint8_t nonce[32];
  uint8_t challenge_digest[32];
  uint8_t token_key_id[32];
  uint8_t authenticator[Nk];
} Token;
~~~

The Token.nonce value is that which was sampled in {{private-request}}.
If the Finalize function fails, the Client aborts the protocol.

## Token Verification

Verifying a Token requires creating a VOPRF context using the Issuer Private
Key and Public Key, evaluating the token contents, and comparing the result
against the token authenticator value:

~~~
server_context = SetupVOPRFServer(0x0004, skI, pkI)
token_authenticator_input =
  concat(Token.token_type,
         Token.nonce,
         Token.challenge_digest,
         Token.token_key_id)
token_authenticator =
  server_context.Evaluate(token_authenticator_input)
valid = (token_authenticator == Token.authenticator)
~~~

## Issuer Configuration

Issuers are configured with Private and Public Key pairs, each denoted `skI`
and `pkI`, respectively, used to produce tokens. These keys MUST NOT be reused
in other protocols. A RECOMMENDED method for generating key pairs is as
follows:

~~~
seed = random(Ns)
(skI, pkI) = DeriveKeyPair(seed, "PrivacyPass")
~~~

The key identifier for a public key `pkI`, denoted `token_key_id`, is computed
as follows:

~~~
token_key_id = SHA256(SerializeElement(pkI))
~~~

Since Clients truncate `token_key_id` in each `TokenRequest`, Issuers should
ensure that the truncated form of new key IDs do not collide with other
truncated key IDs in rotation.

# Issuance Protocol for Publicly Verifiable Tokens {#public-flow}

This section describes a variant of the issuance protocol in {{private-flow}}
for producing publicly verifiable tokens using the protocol in {{BLINDRSA}}.
In particular, this variant of the issuance protocol works for the
RSABSSA-SHA384-PSS-Deterministic and RSABSSA-SHA384-PSSZERO-Deterministic
blind RSA protocol variants described in {{Section 5 of BLINDRSA}}.

The publicly verifiable issuance protocol differs from the protocol in
{{private-flow}} in that the output tokens are publicly verifiable by anyone
with the Issuer Public Key. This means any Origin can select a given Issuer to
produce tokens, as long as the Origin has the Issuer public key, without
explicit coordination or permission from the Issuer. This is because the Issuer
does not learn the Origin that requested the token during the issuance protocol.

Beyond this difference, the publicly verifiable issuance protocol variant is
nearly identical to the privately verifiable issuance protocol variant. In
particular, Issuers provide a Private and Public Key, denoted skI and pkI,
respectively, used to produce tokens as input to the protocol. See
{{public-issuer-configuration}} for how this key pair is generated.

Clients provide the following as input to the issuance protocol:

- Issuer Request URI: A URI to which token request messages are sent. This can
  be a URL derived from the "issuer-request-uri" value in the Issuer's
  directory resource, or it can be another Client-configured URL. The value
  of this parameter depends on the Client configuration and deployment model.
  For example, in the 'Split Origin, Attester, Issuer' deployment model, the
  Issuer Request URI might be correspond to the Client's configured Attester,
  and the Attester is configured to relay requests to the Issuer.
- Issuer name: An identifier for the Issuer. This is typically a host name that
  can be used to construct HTTP requests to the Issuer.
- Issuer Public Key: `pkI`, with a key identifier `token_key_id` computed as
  described in {{public-issuer-configuration}}.
- Challenge value: `challenge`, an opaque byte string. For example, this might
  be provided by the redemption protocol in {{AUTHSCHEME}}.

Given this configuration and these inputs, the two messages exchanged in
this protocol are described below. The constant `Nk` is defined by
{{public-token-type}}.

## Client-to-Issuer Request {#public-request}

The Client first creates an issuance request message for a random value
`nonce` using the input challenge and Issuer key identifier as follows:

~~~
nonce = random(32)
challenge_digest = SHA256(challenge)
token_input = concat(0x0002, // Token type field is 2 bytes long
                     nonce,
                     challenge_digest,
                     token_key_id)
blinded_msg, blind_inv =
  Blind(pkI, PrepareIdentity(token_input))
~~~

The PrepareIdentity and Blind functions are defined in
{{Section 4.1 of BLINDRSA}} and {{Section 4.2 of BLINDRSA}}, respectively.
The Client stores the nonce and challenge_digest values locally for use
when finalizing the issuance protocol to produce a token (as described
in {{public-finalize}}).

The Client then creates a TokenRequest structured as follows:

~~~
struct {
  uint16_t token_type = 0x0002; /* Type Blind RSA (2048-bit) */
  uint8_t truncated_token_key_id;
  uint8_t blinded_msg[Nk];
} TokenRequest;
~~~

The structure fields are defined as follows:

- "token_type" is a 2-octet integer, which matches the type in the challenge.

- "truncated_token_key_id" is the least significant byte of the `token_key_id`
  ({{public-issuer-configuration}}) in network byte order (in other words, the
  last 8 bits of `token_key_id`).

- "blinded_msg" is the Nk-octet request defined above.

The Client then generates an HTTP POST request to send to the Issuer Request
URI, with the TokenRequest as the content. The media type for this request
is "application/private-token-request". An example request is shown below:

~~~
:method = POST
:scheme = https
:authority = issuer.example.net
:path = /request
accept = application/private-token-response
cache-control = no-cache, no-store
content-type = application/private-token-request
content-length = <Length of TokenRequest>

<Bytes containing the TokenRequest>
~~~

## Issuer-to-Client Response {#public-response}

Upon receipt of the request, the Issuer validates the following conditions:

- The TokenRequest contains a supported token_type.
- The TokenRequest.truncated_token_key_id corresponds to the truncated key
  ID of an Issuer Public Key.
- The TokenRequest.blinded_msg is of the correct size.

If any of these conditions is not met, the Issuer MUST return an HTTP 400 error
to the Client, which will forward the error to the client. Otherwise, if the
Issuer is willing to produce a token token to the Client, the Issuer
completes the issuance flow by computing a blinded response as follows:

~~~
blind_sig = BlindSign(skI, TokenRequest.blinded_msg)
~~~

The BlindSign function is defined in {{Section 4.3 of BLINDRSA}}.
The result is encoded and transmitted to the client in the following
TokenResponse structure:

~~~
struct {
  uint8_t blind_sig[Nk];
} TokenResponse;
~~~

The Issuer generates an HTTP response with status code 200 whose content
consists of TokenResponse, with the content type set as
"application/private-token-response".

~~~
:status = 200
content-type = application/private-token-response
content-length = <Length of TokenResponse>

<Bytes containing the TokenResponse>
~~~

## Finalization {#public-finalize}

Upon receipt, the Client handles the response and, if successful, processes the
content as follows:

~~~
authenticator =
  Finalize(pkI, nonce, blind_sig, blind_inv)
~~~

The Finalize function is defined in {{Section 4.4 of BLINDRSA}}. If this
succeeds, the Client then constructs a Token as described in {{AUTHSCHEME}} as
follows:

~~~
struct {
  uint16_t token_type = 0x0002; /* Type Blind RSA (2048-bit) */
  uint8_t nonce[32];
  uint8_t challenge_digest[32];
  uint8_t token_key_id[32];
  uint8_t authenticator[Nk];
} Token;
~~~

The Token.nonce value is that which was sampled in {{private-request}}.
If the Finalize function fails, the Client aborts the protocol.

## Token Verification

Verifying a Token requires checking that Token.authenticator is a valid
signature over the remainder of the token input using the Issuer Public Key.
The function `RSASSA-PSS-VERIFY` is defined in {{Section 8.1.2 of !RFC8017}},
using SHA-384 as the Hash function, MGF1 with SHA-384 as the PSS mask
generation function (MGF), and a 48-byte salt length (sLen).

~~~
token_authenticator_input =
  concat(Token.token_type,
         Token.nonce,
         Token.challenge_digest,
         Token.token_key_id)
valid = RSASSA-PSS-VERIFY(pkI,
                          token_authenticator_input,
                          Token.authenticator)
~~~

## Issuer Configuration {#public-issuer-configuration}

Issuers are configured with Private and Public Key pairs, each denoted skI and
pkI, respectively, used to produce tokens. Each key pair SHALL be generated as
as specified in FIPS 186-4 {{?DSS=DOI.10.6028/NIST.FIPS.186-4}}. These key
pairs MUST NOT be reused in other protocols.

The key identifier for a keypair (skI, pkI), denoted `token_key_id`, is
computed as SHA256(encoded_key), where encoded_key is a DER-encoded
SubjectPublicKeyInfo (SPKI) object carrying pkI. The SPKI object MUST use the
RSASSA-PSS OID {{!RFC5756}}, which specifies the hash algorithm and salt size.
The salt size MUST match the output size of the hash function associated with
the public key and token type.

Since Clients truncate `token_key_id` in each `TokenRequest`, Issuers should
ensure that the truncated form of new key IDs do not collide with other
truncated key IDs in rotation.

# Security considerations

This document outlines how to instantiate the Issuance protocol
based on the VOPRF defined in {{OPRF}} and blind RSA protocol defined in
{{BLINDRSA}}. All security considerations described in the VOPRF and blind RSA
documents also apply in the Privacy Pass use-case. Considerations related to
broader privacy and security concerns in a multi-Client and multi-Issuer
setting are deferred to the Architecture document {{ARCHITECTURE}}. In
particular, the privacy considerations in
{{Section 4 and Section 5 of ARCHITECTURE}}, particularly those pertaining to
Issuer Public Key rotation and consistency (where consistency is as described
in {{?CONSISTENCY=I-D.privacypass-key-consistency}}) and Issuer selection, are
relevant for implementations of the protocols in this document.

# IANA considerations

This section contains considerations for IANA.

## Well-Known 'token-issuer-directory' URI {#wkuri-reg}

This document updates the "Well-Known URIs" Registry {{WellKnownURIs}} with the
following values.

| URI Suffix  | Change Controller  | Reference | Status | Related information |
|:------------|:-------------------|:----------|:-------|:--------------------|
| token-issuer-directory | IETF | [this document] | permanent | None |
{: #wellknownuri-values title="'token-issuer-directory' Well-Known URI"}

## Token Type Registry Updates {#token-type}

This document updates the "Token Type" Registry from
{{AUTHSCHEME, Section 5.2}} with the following entries.

### Token Type VOPRF (P-384, SHA-384) {#private-token-type}

* Value: 0x0001
* Name: VOPRF (P-384, SHA-384)
* Token Structure: As defined in {{Section 2.2 of AUTHSCHEME}}
* TokenChallenge Structure: As defined in {{Section 2.1 of AUTHSCHEME}}
* Publicly Verifiable: N
* Public Metadata: N
* Private Metadata: N
* Nk: 48
* Nid: 32
* Reference: {{private-flow}}
* Notes: None

### Token Type Blind RSA (2048-bit) {#public-token-type}

* Value: 0x0002
* Name: Blind RSA (2048-bit)
* Token Structure: As defined in {{Section 2.2 of AUTHSCHEME}}
* TokenChallenge Structure: As defined in {{Section 2.1 of AUTHSCHEME}}
* Publicly Verifiable: Y
* Public Metadata: N
* Private Metadata: N
* Nk: 256
* Nid: 32
* Reference: {{public-flow}}
* Notes: The RSABSSA-SHA384-PSS-Deterministic and
  RSABSSA-SHA384-PSSZERO-Deterministic variants are supported

## Media Types

This specification defines the following protocol messages, along with their
corresponding media types:

- Token issuer directory: "application/token-issuer-directory"
- TokenRequest: "application/private-token-request"
- TokenResponse: "application/private-token-response"

The definition for each media type is in the following subsections.

### "application/token-issuer-directory" media type

Type name:

: application

Subtype name:

: token-issuer-directory

Required parameters:

: N/A

Optional parameters:

: None

Encoding considerations:

: "binary"

Security considerations:

: see {{setup}}

Interoperability considerations:

: N/A

Published specification:

: this specification

Applications that use this media type:

: N/A

Fragment identifier considerations:

: N/A

Additional information:

: <dl spacing="compact">
  <dt>Magic number(s):</dt><dd>N/A</dd>
  <dt>Deprecated alias names for this type:</dt><dd>N/A</dd>
  <dt>File extension(s):</dt><dd>N/A</dd>
  <dt>Macintosh file type code(s):</dt><dd>N/A</dd>
  </dl>

Person and email address to contact for further information:

: see Authors' Addresses section

Intended usage:

: COMMON

Restrictions on usage:

: N/A

Author:

: see Authors' Addresses section

Change controller:

: IESG
{: spacing="compact"}

### "application/private-token-request" media type

Type name:

: application

Subtype name:

: private-token-request

Required parameters:

: N/A

Optional parameters:

: None

Encoding considerations:

: "binary"

Security considerations:

: see {{security-considerations}}

Interoperability considerations:

: N/A

Published specification:

: this specification

Applications that use this media type:

: N/A

Fragment identifier considerations:

: N/A

Additional information:

: <dl spacing="compact">
  <dt>Magic number(s):</dt><dd>N/A</dd>
  <dt>Deprecated alias names for this type:</dt><dd>N/A</dd>
  <dt>File extension(s):</dt><dd>N/A</dd>
  <dt>Macintosh file type code(s):</dt><dd>N/A</dd>
  </dl>

Person and email address to contact for further information:

: see Authors' Addresses section

Intended usage:

: COMMON

Restrictions on usage:

: N/A

Author:

: see Authors' Addresses section

Change controller:

: IESG
{: spacing="compact"}

### "application/private-token-response" media type

Type name:

: application

Subtype name:

: private-token-response

Required parameters:

: N/A

Optional parameters:

: None

Encoding considerations:

: "binary"

Security considerations:

: see {{security-considerations}}

Interoperability considerations:

: N/A

Published specification:

: this specification

Applications that use this media type:

: N/A

Fragment identifier considerations:

: N/A

Additional information:

: <dl spacing="compact">
  <dt>Magic number(s):</dt><dd>N/A</dd>
  <dt>Deprecated alias names for this type:</dt><dd>N/A</dd>
  <dt>File extension(s):</dt><dd>N/A</dd>
  <dt>Macintosh file type code(s):</dt><dd>N/A</dd>
  </dl>

Person and email address to contact for further information:

: see Authors' Addresses section

Intended usage:

: COMMON

Restrictions on usage:

: N/A

Author:

: see Authors' Addresses section

Change controller:

: IESG
{: spacing="compact"}

--- back

# Acknowledgements

The authors of this document would like to acknowledge the helpful
feedback and discussions from Benjamin Schwartz, Joseph Salowey, Sofía
Celi, and Tara Whalen.

# Test Vectors

This section includes test vectors for the two basic issuance protocols
specified in this document. {{test-vectors-poprf}} contains test vectors
for token issuance protocol 1 (0x0001), and {{test-vectors-rsa}} contains
test vectors for token issuance protocol 2 (0x0002).

## Issuance Protocol 1 - VOPRF(P-384, SHA-384) {#test-vectors-poprf}

The test vector below lists the following values:

- skS: The Issuer private Key, serialized using SerializeScalar from
  {{Section 2.1 of OPRF}} and represented as a hexadecimal string.
- pkS: The Issuer Public Key, serialized using SerializeElement from
  {{Section 2.1 of OPRF}} and represented as a hexadecimal string.
- token_challenge: A randomly generated TokenChallenge structure, represented
  as a hexadecimal string.
- nonce: The 32-byte client nonce generated according to {{private-request}},
  represented as a hexadecimal string.
- blind: The blind used when computing the OPRF blinded message, serialized
  using SerializeScalar from {{Section 2.1 of OPRF}} and represented as a
  hexadecimal string.
- token_request: The TokenRequest message constructed according to
  {{private-request}}, represented as a hexadecimal string.
- token_response: The TokenResponse message constructed according to
  {{private-response}}, represented as a hexadecimal string.
- token: The output Token from the protocol, represented as a hexadecimal
  string.

~~~
skS: 08f572b675c83bf83c8037e503816119409a21d26e097414678eb44c625f
cddd9b2e4eb16dbccc975c5ae745ffa3f4fa
pkS: 0371b63695ddf79655f770ced74c17938d60c9cb9d8b9537614072b001ff
c6085e80f310cdb4475487736f0f9d1406c7c9
token_challenge: 0001000e6973737565722e6578616d706c6500000e6f7269
67696e2e6578616d706c65
nonce:
1a177bae66ea3341c367c160c635aa52daef9f105bb1240d06a063ae12e9798a
blind: 1e46366a7b619aea7d7e24d2b853f5ddc64524eb5a78f4e3af108f0291
9827cbdea2f8d753869ab9229aeb7fe9988763
token_request: 00017f023d788d4089a5f76f908ce26d18bb3b8ee826223b8a
1df70a052e092aaf235c44c6f1e57f81d17d31632d090d260dc531
token_response: 03c1854b0cb631ceff11079299fdc5c8d9f94c6d7d6dbc862
b259916a4dba69e39ac38817fafaa6e48842c610d41bf0bb6fa3ae6e3025acf22
38c0ef02e0b628437944cdbd0207c86bd9c3025fcacbd0e520576c7ad9bb9cc18
46687168e7c5226bdfd0c89be908d5d90eb60e5533045358e3063b6d3a24cc2f5
5891cded1a7642ef945bcec888e92e15d5ecdb431fdc6d
token: 00011a177bae66ea3341c367c160c635aa52daef9f105bb1240d06a063
ae12e9798ac994f7d5cdc2fb970b13d4e8eb6e6d8f9dcdaa65851fb091025dfe1
34bd5a62a7f13956db7526669425e8eb1128273c17972b5f16a9bc835a9c9f357
72a2add9f5e1bb3ab71770ada81faf1af0fbdfa476fc92a3ff25fac14639b7fe3
4365118ae2ff55a2399e1580bec9aa759659317
~~~

## Issuance Protocol 2 - Blind RSA, 2048 {#test-vectors-rsa}

The test vector below lists the following values:

- skS: The PEM-encoded PKCS#8 RSA Issuer Private Key used for signing tokens,
  represented as a hexadecimal string.
- pkS: The DER-encoded SubjectPublicKeyInfo object carrying the Issuer Public
  Key, as described in {{public-issuer-configuration}}, represented as a
  hexadecimal string.
- token_challenge: A randomly generated TokenChallenge structure, represented
  as a hexadecimal string.
- nonce: The 32-byte client nonce generated according to {{public-request}},
  represented as a hexadecimal string.
- blind: The blind used when computing the blind RSA blinded message,
  represented as a hexadecimal string.
- salt: The randomly generated 48-byte salt used when encoding the blinded
  token request message, represented as a hexadecimal string.
- token_request: The TokenRequest message constructed according to
  {{public-request}}, represented as a hexadecimal string.
- token_request: The TokenResponse message constructed according to
  {{public-response}}, represented as a hexadecimal string.
- token: The output Token from the protocol, represented as a hexadecimal
  string.

~~~
skS: 2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a4d49
4945765149424144414e42676b71686b6947397730424151454641415343424b6
3776767536a41674541416f49424151444c4775317261705831736334420a4f6b
7a38717957355379356b6f6a41303543554b66717444774e38366a424b5a4f764
57245526b49314c527876734d6453327961326333616b4745714c756b440a556a
35743561496b3172417643655844644e44503442325055707851436e6969396e6
b492b6d67725769744444494871386139793137586e6c5079596f784f530a646f
6558563835464f314a752b62397336356d586d34516a755139455961497138337
1724450567a50335758712b524e4d636379323269686763624c766d42390a6a41
355334475666325a6c74785954736f4c364872377a58696a4e394637486271656
76f753967654b524d584645352f2b4a3956595a634a734a624c756570480a544f
72535a4d4948502b5358514d4166414f454a4547426d6d4430683566672f43473
475676a79486e4e51383733414e4b6a55716d3676574574413872514c620a4530
742b496c706641674d4241414543676745414c7a4362647a69316a506435384d6
b562b434c6679665351322b7266486e7266724665502f566344787275690a3270
316153584a596962653645532b4d622f4d4655646c485067414c7731785134576
57266366336444373686c6c784c57535638477342737663386f364750320a6359
366f777042447763626168474b556b5030456b62395330584c4a5763475347356
1556e484a585237696e7834635a6c666f4c6e7245516536685578734d710a6230
644878644844424d644766565777674b6f6a4f6a70532f39386d4555793756422
f3661326c7265676c766a632f326e4b434b7459373744376454716c47460a787a
414261577538364d435a342f5131334c762b426566627174493973715a5a776a7
264556851483856437872793251564d515751696e57684174364d7154340a5342
5354726f6c5a7a7772716a65384d504a393175614e4d6458474c63484c4932367
3587a76374b53514b42675144766377735055557641395a325a583958350a6d49
784d54424e6445467a56625550754b4b413179576e31554d444e63556a71682b7
a652f376b337946786b68305146333162713630654c393047495369414f0a354b
4f574d39454b6f2b7841513262614b314d664f5931472b386a7a4258557042733
9346b353353383879586d4b366e796467763730424a385a6835666b55710a5732
306f5362686b686a5264537a48326b52476972672b5553774b426751445a4a4d6
e7279324578612f3345713750626f737841504d69596e6b354a415053470a7932
7a305a375455622b7548514f2f2b78504d376e433075794c494d44396c61544d4
8776e3673372f4c62476f455031575267706f59482f4231346b2f526e360a6675
77524e3632496f397463392b41434c745542377674476179332b6752775974534
33262356564386c4969656774546b6561306830754453527841745673330a6e35
6b796132513976514b4267464a75467a4f5a742b7467596e576e5155456757385
0304f494a45484d45345554644f637743784b7248527239334a6a7546320a4533
77644b6f546969375072774f59496f614a5468706a50634a62626462664b792b6
e735170315947763977644a724d6156774a6376497077563676315570660a5674
4c61646d316c6b6c7670717336474e4d386a6e4d30587833616a6d6d6e6665573
9794758453570684d727a4c4a6c394630396349324c416f4742414e58760a7567
5658727032627354316f6b6436755361427367704a6a5065774e526433635a4b3
97a306153503144544131504e6b7065517748672f2b36665361564f487a0a7941
7844733968355272627852614e6673542b7241554837783153594456565159564
d68555262546f5a6536472f6a716e544333664e6648563178745a666f740a306c
6f4d4867776570362b53494d436f6565325a6374755a5633326c6349616639726
2484f633764416f47416551386b3853494c4e4736444f413331544535500a6d30
31414a49597737416c5233756f2f524e61432b78596450553354736b75414c787
86944522f57734c455142436a6b46576d6d4a41576e51554474626e594e0a5363
77523847324a36466e72454374627479733733574156476f6f465a6e636d504c5
0386c784c79626c534244454c79615a762f624173506c4d4f39624435630a4a2b
4e534261612b6f694c6c31776d4361354d43666c633d0a2d2d2d2d2d454e44205
0524956415445204b45592d2d2d2d2d0a
pkS: 30820156304106092a864886f70d01010a3034a00f300d06096086480165
030402020500a11c301a06092a864886f70d010108300d0609608648016503040
2020500a2030201300382010f003082010a0282010100cb1aed6b6a95f5b1ce01
3a4cfcab25b94b2e64a23034e4250a7eab43c0df3a8c12993af12b111908d4b47
1bec31d4b6c9ad9cdda90612a2ee903523e6de5a224d6b02f09e5c374d0cfe01d
8f529c500a78a2f67908fa682b5a2b430c81eaf1af72d7b5e794fc98a31392768
79757ce453b526ef9bf6ceb99979b8423b90f4461a22af37aab0cf5733f7597ab
e44d31c732db68a181c6cbbe607d8c0e52e0655fd9996dc584eca0be87afbcd78
a337d17b1dba9e828bbd81e291317144e7ff89f55619709b096cbb9ea474cead2
64c2073fe49740c01f00e109106066983d21e5f83f086e2e823c879cd43cef700
d2a352a9babd612d03cad02db134b7e225a5f0203010001
token_challenge:
d0bea78c3b452a4ccd4484e4c6f1e73d3c494be58a5a81c7c97f12fe5f9bb03c
nonce:
23b29061bc9d3cf3637e067c47abe5122d355e9d681a3fc249fd4d4dd4ae7d61
blind: 1206c0f56241aac4716329f2eb1423dea369eaf05ce759c3ca6426c415
b44f90d4466ba4f57993b0ed753a156aa067a04d5eb9cd27ab930fdedf46a3c5f
d46fed554849fd03df605602b33ed5e70d6266a74dd067563cab0d0f5fae416df
b862b32a1254d60c5add16bbc6382273c75599f50abbe1b0ae9e63a1384a50738
5e492de216fdb9477ab0a4a6843d8068fd533b3014ca2aa127045bc99bb40311c
ed536f28896bcd222b9bc1ba10ade0fa6b1e355af27f00bb189d37142c2976ebb
9c52da0372c3c1b75d030ab736a2889372e55dcd5970fce79cdddd10abf37dd60
ad2e1168081aab519041346cef7b4f4a8052d1c67cf83cf36d7bfac2111a3e00
salt: 0660138f93e216110f176800079b11f2da8ef31ab539ecee16a6c012085
79a61f043c7c8253f830ad38b06b8aa4314aa
token_request: 0002f84040a643a8297d0c6f77c51fe71ab33ba77d1113345f
12d1c6224376b0ae8f332e8df4557c06f9c014ed859dbe5f87cd7811cbf3de6fa
9c680447b28d30cd379776c86dc16d7bfe96336321374d15cd728321fcfd939ea
ef01ebcfe52a72ec0131fcecd447818339a6acde3e3d9034d50e2d88c2360a506
df1fb33f95d9bb84d5af1870f00576c9b47cf949f1f5bd57b7b334fefa3cf301a
52e08c449d198ec8e391b39de3d4d6a121b5288a4ec90df722b43cb13c50d58ce
52d78916ac4bb4d3597c7c816edd2997383fb59b0e565c36b9c19b63deea7538a
c9e5d60e3e28b03b651edb6b3e0c647b327b153f61176ee6d2e1f3708ba946ecd
447610b2c8347
token_response: 67393299cc66da3b450f1c73836a918e543392ce11ccca9a8
a26eb2d9b8aa3f31825d7b89e7f0dd07bdc2770a39d1d0cda6bf597e4585468d4
bc608268b7786cb86be017913d284be7d040069c667dbb2ce49fe87b5e936e5b6
8f66f34d7828f281ea2a5a913cdf97b4b5e60153f9f2fcfebe4099c3bbc2f9d0c
bd63197bf30a451c93f7677665c46112a2296b5e359589cb66c13d2bb6a49b985
89bb3580225bad2014fc433c1801328c1f064fee894cb037613dccc33af197d71
119b572f9fc32dcd614de2008ebfaafad393ff4f95b9d91662ae4a7952f13e958
7aa87810f586b03a14b096ea949da8d4e1d56de7a31a5bd93e921f3652a4d63ab
d70f2d6d
token: 000223b29061bc9d3cf3637e067c47abe5122d355e9d681a3fc249fd4d
4dd4ae7d61a982f3054cb8cd7dd827eb06f6c7bbd05b1f65a8e6e2968895c0ed1
642be52faf861220ad4241ee0e33eb4a486a32f05af05ee33fcfdd1104c665eb8
27c2062154c68677136693e8301583932d67445e8d073eb2dc2593583b0111e36
92129fa6bfa50f556d284e885ea8113a4500619d1559a00739774c4bb9b32adb5
43ee67a0db240ae44e6e84a5bedbe44d3db69b4859e6a36c5a51fa7da5deb13fe
38b3a04335c7e3b4ca495692d4efdec8272f9a718c4dd86a661161b9f26729fe4
87b35d2ccb0729adcfaec1393c64186002641177853e3af7f64f2384c81f3765c
d572d618771a2b845647b4a4a167d51df8b49abe412310a6f1cdcdaea1efe6deb
97ca9cba9b5d90798b2399effeae0ff66a6a67b2f69961b4b34db5f5c79d5e48c
67ace06ba2836197fdb98bb6d276d1df03a006f9f8b06e09c7db7f473fb4736cc
~~~
