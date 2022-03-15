---
title: The Privacy Pass HTTP Authentication Scheme
abbrev: Privacy Pass Authentication
docname: draft-ietf-privacypass-auth-scheme-latest
category: std

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: T. Pauly
    name: Tommy Pauly
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: tpauly@apple.com
 -
    ins: S. Valdez
    name: Steven Valdez
    org: Google LLC
    email: svaldez@chromium.org
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare
    email: caw@heapingbits.net

--- abstract

This document defines an HTTP authentication scheme that can be used by clients
to redeem Privacy Pass tokens with an origin. It can also be used by origins to
challenge clients to present an acceptable Privacy Pass token.

--- middle

# Introduction {#introduction}

Privacy Pass tokens are unlinkable authenticators that can be used to
anonymously authorize a client (see {{?I-D.ietf-privacypass-architecture}}). A
client possessing such a token is able to prove that it was able to get a token
issued by a token issuer -- based on some check from a token issuer, such as
authentication or solving a CAPTCHA -- without allowing the relying party
redeeming the client's token (the origin) to link it with issuance flow.

Different types of authenticators, using different token issuance protocols, can
be used as Privacy Pass tokens.

This document defines a common HTTP authentication scheme ({{!RFC7235}}),
PrivateToken, that allows clients to redeem various kinds of Privacy Pass
tokens.

Clients and relying parties interact using this scheme to perform the token challenge
and token redemption flow. Clients use a token issuance protocol to actually fetch
tokens to redeem.

~~~
 Client                             Relying Party (Origin)

    <------------------------------ Challenge \
                                              |
+----------------------------------\          |
|                                  |          |
|  Issuance Protocol               |          |
|                                  |          |
+----------------------------------/          |
                                              |
     Redemption -------------------------- >  /
~~~
{: #fig-overview title="Token Architectural Components"}

In addition to working with different token issuance protocols, this scheme
supports optionally associating tokens with origin-chosen contexts and
specific origin names. Relying parties that request and redeem tokens can choose
a specific kind of token, as appropriate for its use case. These options allow
for different deployment models to prevent double-spending, and allow for both
interactive (online challenges) and non-interactive (pre-fetched) tokens.

## Terminology

{::boilerplate bcp14}

<!-- TODO: Remove duplicates that occur in Architecture doc -->

Unless otherwise specified, this document encodes protocol messages in TLS
notation from {{!TLS13=RFC8446}}, Section 3.

This document uses the terms "Client", "Origin", "Issuer", "Issuance Protocol",
and "Token" as defined in {{?I-D.ietf-privacypass-architecture}}. It additionally
uses the following terms in more specific ways:

- Issuer key: Keying material that can be used with an issuance protocol
to create a signed token.

- Token challenge: A requirement for tokens sent from an origin to a client, using
the "WWW-Authenticate" HTTP header. This challenge is bound to a specific token
issuer and issuance protocol, and may be additionally bound to a specific context or origin name.

- Token redemption: An action by which a client presents a token to an origin,
using the "Authorization" HTTP header.

# HTTP Authentication Scheme {#challenge-redemption}

Token redemption is performed using HTTP Authentication ({{!RFC7235}}), with
the scheme "PrivateToken". Origins challenge clients to present a token
from a specific issuer ({{challenge}}). Once a client has received a token
from that issuer, or already has a valid token available, it presents the
token to the origin ({{redemption}}).

## Token Challenge {#challenge}

Origins send a token challenge to Clients in an "WWW-Authenticate" header with
the "PrivateToken" scheme. This challenge includes a TokenChallenge message,
along with information about what keys to use when requesting a token from
the issuer.

The TokenChallenge message has the following structure:

~~~
struct {
    uint16_t token_type;
    opaque issuer_name<1..2^16-1>;
    opaque redemption_context<0..32>;
    opaque origin_name<0..2^16-1>;
} TokenChallenge;
~~~

The structure fields are defined as follows:

- "token_type" is a 2-octet integer, in network byte order. This type indicates
the issuance protocol used to generate the token. Values are registered
in an IANA registry, {{token-types}}. Challenges with unsupported token_type
values MUST be ignored.

- "issuer_name" is a string containing the name of the issuer. This is a
hostname that is used to identify the issuer that is allowed to issue
tokens that can be redeemed by this origin. The string is prefixed with a
2-octet integer indicating the length, in network byte order.

- "redemption_context" is an optional field. If present, it allows the origin
to require that clients fetch tokens bound to a specific context, as opposed
to reusing tokens that were fetched for other contexts. When present, this value
is a 32-byte context generated by the origin. This value can be a unique
per-request nonce, or represent some state such as properties of the client
session or current time window. Valid lengths for this field are either 0 or
32 bytes. The field is prefixed with a single octet indicating the length.
Challenges with redemption_context values of invalid lengths MUST be ignored.

- "origin_name" is an optional string containing the name of the origin, which
allows a token to be scoped to a specific origin. The string is prefixed with a
2-octet integer indicating the length, in network byte order. If empty, any
non-origin-specific token can be redeemed. 

When used in an authentication challenge, the "PrivateToken" scheme uses the
following attributes:

- "challenge", which contains a base64url-encoded {{!RFC4648}} TokenChallenge
value. Since the length of the challenge is not fixed, the base64url data MUST
include padding. This MUST be unique for every 401 HTTP response to prevent
replay attacks. This attribute is required for all challenges.

- "token-key", which contains a base64url encoding of the public key for
use with the issuance protocol indicated by the challenge. Since the length of
the key is not fixed, the base64url data MUST include padding. This attribute MAY
be omitted in deployments where clients are able to retrieve the issuer key using
an out-of-band mechanism.

- "max-age", an optional attribute that consists of the number of seconds for which
the challenge will be accepted by the Origin.

Clients can ignore the challenge if the token-key is invalid or otherwise untrusted.

Origins MAY also include the standard "realm" attribute, if desired. Issuance protocols
MAY require other attributes.

As an example, the WWW-Authenticate header could look like this:

~~~
WWW-Authenticate: PrivateToken challenge=abc..., token-key=123...
~~~

Upon receipt of this challenge, a client uses the message and keys in the
issuance protocol indicated by the token_type. If the TokenChallenge has a
token_type the client does not recognize or support, it MUST NOT parse or
respond to the challenge.

Note that it is possible for the WWW-Authenticate header to include multiple
challenges, in order to allow the Client to fetch a batch of multiple tokens
for future use.

For example, the WWW-Authenticate header could look like this:

~~~
WWW-Authenticate: PrivateToken challenge=abc..., token-key=123...,
PrivateToken challenge=def..., token-key=234...
~~~

## Token Redemption {#redemption}

The output of the issuance protocol is a token that corresponds to the origin's
challenge (see {{challenge}}). A token is a structure that begins with a two-octet
field that indicates a token type, which MUST match the token_type in the TokenChallenge
structure.

~~~
struct {
    uint16_t token_type;
    uint8_t nonce[32];
    uint8_t challenge_digest[32];
    uint8_t token_key_id[Nid];
    uint8_t authenticator[Nk];
} Token;
~~~

The structure fields are defined as follows:

- "token_type" is a 2-octet integer, in network byte order. This value must
match the value in the challenge ({{challenge}}).

- "nonce" is a 32-octet message containing a client-generated random
nonce.

- "challenge_digest" is a 32-octet message containing the hash of the
original TokenChallenge, SHA256(TokenChallenge).

- "token_key_id" is an Nid-octet identifier for the the token authentication
key. The value of this field is defined by the token_type and corresponding
issuance protocol.

- "authenticator" is a Nk-octet authenticator that covers the preceding fields in
the token. The value of this field is defined by the token_type and corresponding
issuance protocol.

The authenticator value in the Token structure is computed over the token_type,
nonce, context, and token_key_id fields.

When used for client authorization, the "PrivateToken" authentication
scheme defines one parameter, "token", which contains the base64url-encoded
Token struct. Since the length of the Token struct is not fixed, the base64url
data MUST include padding. All unknown or unsupported parameters to "PrivateToken"
authentication credentials MUST be ignored.

Clients present this Token structure to Origins in a new HTTP request using
the Authorization header as follows:

~~~
Authorization: PrivateToken token=abc...
~~~

For token types that support public verifiability, origins verify the token
authenticator using the public key of the issuer, and validate that the signed
message matches the concatenation of the client nonce and the hash of a
valid TokenChallenge. For context-bound tokens, origins store or reconstruct the
contexts of previous TokenChallenge structures in order to validate the token.
A TokenChallenge MAY be bound to a specific HTTP session with client, but
origins can also accept tokens for valid challenges in new sessions.
Origins SHOULD implement some form of double-spend prevention that prevents
a token with the same nonce from being redeemed twice. This prevents clients
from "replaying" tokens for previous challenges. For context-bound tokens,
this double-spend prevention can require no state or minimal state, since
the context can be used to verify token uniqueness.

If a client is unable to fetch a token, it MUST react to the challenge as
if it could not produce a valid Authorization response.

# Issuance Protocol Requirements

Clients initiate the issuance protocol using a challenge, a randomly
generated nonce, and a public key for the issuer. The issuance protocol
itself can be any interactive protocol between client, issuer, or other
parties that produces a valid authenticator over the client's input, subject
to the following security requirements.

1. Unconditional input secrecy. The issuance protocol MUST NOT reveal anything
about the client's private input, including the challenge and nonce. The issuance
protocol can reveal the issuer public key for the purposes of determining which
private key to use in producing the issuance protocol. A result of this property
is that the redemption flow is unlinkable from the issuance flow.
1. One-more forgery security. The issuance protocol MUST NOT allow malicious
clients to forge tokens without interacting with the issuer directly.
1. Concurrent security. The issuance protocol MUST be safe to run concurrently
with arbitrarily many clients.

# User Interaction

When used in contexts like websites, origins that challenge clients for
tokens need to consider how to optimize their interaction model to ensure a
good user experience.

Tokens challenges can be performed without explicit user involvement, depending
on the issuance protocol. If tokens are scoped to a specific origin,
there is no need for per-challenge user interaction. Note that the issuance
protocol may separately involve user interaction if the client needs to be newly
validated.

If a client cannot use cached tokens to respond to a challenge (either because
it has run out of cached tokens or the associated context is unique), the token
issuance process can add user-perceivable latency. Origins need not block useful
work on token authentication. Instead, token authentication can be used in similar
ways to CAPTCHA validation today, but without the need for user interaction. If issuance
is taking a long time, a website could show an indicator that it is waiting,
or fall back to another method of user validation.

An origin MUST NOT use more than one redemption context value for a given token type
and issuer per client request. If an origin issues a large number of challenges with
unique contexts, such as more than once for each request, this can indicate that the
origin is either not functioning correctly or is trying to attack or overload the client
or issuance server. In such cases, a client MUST ignore redundant token challenges for
the same request and SHOULD alert the user if possible.

Origins MAY include multiple challenges, where each challenge refers to a different issuer
or a different token type, to allow clients to choose a preferred issuer or type.

# Security Considerations {#sec-considerations}

The security properties of token challenges vary depending on whether the challenge
contains a redemption context or not, as well as whether the challenge is per-origin
or not. For example, cross-origin tokens with empty contexts can be replayed from one
party by another, as shown below.

~~~
 Client          Attacker                  Origin

                       <----------- Challenge \
                                              |
   <--------- Challenge                       |
                                              |
   Redemption ---->                           |
                                              |
                       Redemption ----------> /
~~~
{: #fig-replay title="Token Architectural Components"}

Context-bound token challenges require clients to obtain matching tokens when challenged,
rather than presenting a token that was obtained in the past. This can make it more likely
that issuance and redemption events will occur at approximately the same time. For example, if
a client is challenged for a token with a unique context at time T1 and then subsequently obtains
a token at time T2, a colluding issuer and origin can link this to the same client if
T2 is unique to the client. This linkability is less feasible as the number of issuance
events at time T2 increases. Depending on the "max-age" token challenge attribute,
clients MAY try to augment the time between getting challenged then redeeming a token
so as to make this sort of linkability more difficult. For more discussion on correlation risks between
token issuance and redemption, see {{?I-D.ietf-privacypass-architecture}}.

Applications SHOULD constrain tokens to a single origin unless the use case can
accommodate such replay attacks.

All random values in the challenge and token MUST be generated using a cryptographically
secure source of randomness.

# IANA Considerations {#iana}

## Authentication Scheme

This document registers the "PrivateToken" authentication scheme in the "Hypertext
Transfer Protocol (HTTP) Authentication Scheme Registry" established by {{!RFC7235}}.

Authentication Scheme Name: PrivateToken

Pointer to specification text: {{challenge-redemption}} of this document

## Token Type Registry {#token-types}

The "Token Type" registry lists identifiers for issuance protocols defined for use
with the Privacy Pass token authentication scheme. These identifiers are two-byte values,
so the maximum possible value is 0xFFFF = 65535.

Template:

* Value: The two-byte identifier for the algorithm
* Name: Name of the issuance protocol
* Publicly Verifiable: A Y/N value indicating if the output tokens are publicly verifiable
* Public Metadata: A Y/N value indicating if the output tokens can contain public metadata.
* Private Metadata: A Y/N value indicating if the output tokens can contain private metadata.
* Nk: The length in bytes of an output authenticator
* Nid: The length of the token key identifier
* Reference: Where this algorithm is defined

The initial contents for this registry are defined in the table below.

| Value  | Name                   | Publicly Verifiable | Public Metadata | Private Metadata | Nk  | Nid | Reference    |
|:-------|:-----------------------|:--------------------|:----------------|:-----------------|:----|:----|:-------------|
| 0x0000 | (reserved)             | N/A                 | N/A             | N/A              | N/A | N/A | N/A          |
{: #aeadid-values title="Token Types"}
