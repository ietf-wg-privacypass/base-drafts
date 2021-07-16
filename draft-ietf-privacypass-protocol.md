---
title: "Privacy Pass Protocol Specification"
abbrev: PP protocol
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
    org: Cloudflare
    city: Lisbon
    country: Portugal
    email: sceli@cloudflare.com
 -
    ins: A. Davidson
    name: Alex Davidson
    org: LIP
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

normative:
  RFC2119:
  RFC8446:
  I-D.irtf-cfrg-voprf:
informative:
  RFC7049:
  RFC7159:
  KLOR20:
    title: Anonymous Tokens with Private Metadata Bit
    target: https://eprint.iacr.org/2020/072
    authors:
      -
        ins: B. Kreuter
        org: Google
      -
        ins: T. Lepoint
        org: Google
      -
        ins: M. Orrú
        org: ENS/INRIA, Paris, France; Recurse Center, NYC, USA
      -
        ins: M. Raykova
        org: Google
  DGSTV18:
    title: Privacy Pass, Bypassing Internet Challenges Anonymously
    target: https://petsymposium.org/2018/files/papers/issue3/popets-2018-0026.pdf
    authors:
      -
        ins: A. Davidson
        org: RHUL, UK
      -
        ins: I. Goldberg
        org: University of Waterloo, Canada
      -
        ins: N. Sullivan
        org: Cloudflare
      -
        ins: G. Tankersley
        org: Independent
      -
        ins: F. Valsorda
        org: Independent
  TrustTokenAPI:
    title: Trust Token API
    target: https://github.com/WICG/trust-token-api
    author:
      name: WICG
  PrivateStorage:
    title: The Path from S4 to PrivateStorage
    target: https://medium.com/least-authority/the-path-from-s4-to-privatestorage-ae9d4a10b2ae
    author:
      name: Liz Steininger
      ins: L. Steininger
      org: Least Authority
  OpenPrivacy:
    title: Token Based Services - Differences from PrivacyPass
    target: https://openprivacy.ca/assets/towards-anonymous-prepaid-services.pdf
    authors:
      -
        ins: E. Atwater
        org: OpenPrivacy, Canada
      -
        ins: S. J. Lewis
        org: OpenPrivacy, Canada
  Brave:
    title: Brave Rewards
    target: https://brave.com/brave-rewards/

--- abstract

This document specifies the Privacy Pass protocol. This protocol
provides anonymity-preserving authorization of clients to servers. In
particular, client re-authorization events cannot be linked to any
previous initial authorization. Privacy Pass is intended to be used as a
performant protocol in the application-layer.

--- middle

# Introduction

A common problem on the Internet is providing an effective mechanism for
servers to derive trust from clients that they interact with. Typically,
this can be done by providing some sort of authorization challenge to
the client. But this also negatively impacts the experience of clients
that regularly have to solve such challenges.

To mitigate accessibility issues, a client that correctly solves the
challenge can be provided with a cookie. This cookie can be presented
the next time the client interacts with the server, instead of
performing the challenge. However, this does not solve the problem of
reauthorization of clients across multiple domains. Using current tools,
providing some multi-domain authorization token would allow linking
client browsing patterns across those domains, and severely reduces
their online privacy.

The Privacy Pass protocol provides a set of cross-domain authorization
tokens that protect the client's anonymity in message exchanges with a
server. This allows clients to communicate an attestation of a
previously authenticated server action, without having to reauthenticate
manually. The tokens retain anonymity in the sense that the act of
revealing them cannot be linked back to the session where they were
initially issued.

This document lays out the generic description of the protocol, along
with the data and message formats. We detail an implementation of the
protocol functionality based on the description of a verifiable
oblivious pseudorandom function {{I-D.irtf-cfrg-voprf}}.

This document does not cover the architectural framework required for
running and maintaining the Privacy Pass protocol in the Internet
setting. In addition, it DOES NOT cover the choices that are necessary
for ensuring that client privacy leaks do not occur. Both of these
considerations are covered in a separate document
{{!I-D.ietf-privacypass-architecture}}. In addition,
{{!I-D.ietf-privacypass-http-api}} provides an instantiation of this protocol
intended for the HTTP setting.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}.

The following terms are used throughout this document.

- Server: A service that provides the server-side functionality required
  by the protocol. May be referred to as the issuer.
- Client: An entity that seeks authorization from a server that supports
  interactions in the Privacy Pass protocol.
- Key: The secret key used by the server for authorizing client data.

We assume that all protocol messages are encoded into raw byte format
before being sent. We use the TLS presentation language {{RFC8446}} to
describe the structure of protocol data types and messages.

# Background

We discuss the core motivation behind the protocol along with the
guarantees and assumptions that we make in this document.

## Motivating use-cases

The Privacy Pass protocol was originally developed to provide anonymous
authorization of Tor users. In particular, the protocol allows clients
to reveal authorization tokens that they have been issued without
linking the authorization to the actual issuance event. This means that
the tokens cannot be used to link the browsing patterns of clients that
reveal tokens.

Beyond these uses-cases, the Privacy Pass protocol is used in a number
of practical applications. See {{DGSTV18}}, {{TrustTokenAPI}},
{{PrivateStorage}}, {{OpenPrivacy}}, and {{Brave}} for examples.

## Anonymity and security guarantees

Privacy Pass provides anonymity-preserving authorization tokens for
clients. Throughout this document, we use the terms "anonymous",
"anonymous-preserving" and "anonymity" to refer to the core security
guarantee of the protocol. Informally, this guarantee means that any
token issued by a server key and subsequently redeemed is
indistinguishable from any other token issued under the same key.

Privacy Pass also prohibits clients from forging tokens, as otherwise
the protocol would have little value as an authorization protocol.
Informally, this means any client that is issued `N` tokens under a
given server key cannot redeem more than `N` valid tokens.

{{sec-reqs}} elaborates on these protocol anonymity and security
requirements.

## Basic assumptions

We make only a few minimal assumptions about the environment of the
clients and servers supporting the Privacy Pass protocol.

- At any one time, we assume that the server uses only one configuration
  containing their ciphersuite choice along with their secret key data.
  This ensures that all clients are issued tokens under the single key
  associated with any given epoch.
- We assume that the client has access to a global directory of the
  current public parts of the configurations used the server.

The wider ecosystem that this protocol is employed in is described in
{{I-D.ietf-privacypass-architecture}}.

# Notation

The following terms are used throughout this document to describe the
protocol operations in this document:

- I2OSP and OS2IP: Convert a byte string to and from a non-negative integer as
  described in {{!RFC8017}}. Note that these functions operate on byte strings
  in big-endian byte order.
- random_bytes(L): Generate a random, uniformly distributed byte string of
  length L.
- len(s): The length of a byte string, in octets.

# Protocol description {#pp-protocol}

The Privacy Pass protocol is split into the two following sub-protocols:

1. Issuance: this protocol provides the client with unlinkable tokens
that can be used to initiate re-authorization with the server in the
future.
2. Redemption: this protocol allows the client to redeem a given
re-authorization token with the server that it interacted with during
the Issuance protocol. The protocol must satisfy two cryptographic
security requirements known as "unlinkability" and "unforgeability".
These requirements are covered in {{sec-reqs}}.

The data structures and protocol messages used throughout the remainder
of this document are written in the TLS presentation language {{RFC8446, Section 3}}.

## Variants {#variants}

This document specifies a single Privacy Pass variant, defined by the
following enumeration:

~~~
enum {
  VOPRF_decaf448_shake256 = 0x0001,
} ProtocolSuite;
~~~

## Setup {#setup}

Before the protocol takes place, the server chooses a ciphersuite and
generates a keypair by running `(pkS, skS) = KeyGen()`. This
configuration must be available to all clients that interact with the
server (for the purpose of engaging in a Privacy Pass exchange). We
assume that the server has a public (and unique) identity that the
client uses to retrieve this configuration.

The client initialises itself with the server public key `pkS` and its
corresponding configuration. Mechanisms to ensure that this key and
configuration are consistent, i.e., not unique to the client, are out
of scope for this protocol.

## Issuance {#issuance-phase}

Issuance is a two-round protocol that allows the client to request and
receive `m` anonymous authorization tokens from the server. The first
round sees the server generate a commitment. The second round sees the
server issue a token to the client.

~~~
  Client(pkS, m, info)                        Server(skS, pkS)
  ------------------------------------------------------------

  commit_req = Prepare(m, info)

                           commit_req
                      ------------------->

                    commit_resp = Commit(skS, pkS, commit_req)

                          commit_resp
                      <-------------------

  issue_req, state = Generate(m, commit_resp)

                          issue_req
                      ------------------->

                        issue_resp = Issue(pkS, skS, issue_req)

                          issue_resp
                      <-------------------

  tokens = Process(pkS, state, issue_resp)
  Output tokens
~~~

Note that the first round of the protocol is only necessitated for
certain ciphersuites that require client and servers commit to some
value. When such commitment `commit_resp` is generated and sent to the
client, the client returns `commit_resp` with the `IssuanceRequest`
message. The server MUST check that the commitment corresponds to
`commit_resp` that was previously committed. This requires the
commitment to either be a reference to some commitment on the server, or
the commitment be an encrypted (and authenticated) blob that the server
can use to recover commitment. The mechanism by which servers handle
this commitment is implementation specific, and similar to how TLS
session resumption state is managed; see {{RFC8446}} for details. In
addition, the `Commit` function is implementation-specific and MUST be
defined by the underlying ciphersuite.

<!-- TODO(caw): include errors here -->

When the server does not need to generate this commitment, the client
runs the server issuance flow with an empty ("") `CommitResponse`:

~~~
issue_req, state = Generate(m, "")
~~~

A server that is expecting some non-empty `commit_resp` to be passed
MUST abort the protocol on receiving a request containing an empty
`commit_resp` value.

Note: currently, no ciphersuites are supported that support working with
empty commitment messages.

### Issuance messages

This section describes the Issuance protocol messages exchanged during
the protocol. The variants described in this document do not require a
prior commit exchange, so the `CommitRequest` and `CommitResponse` messages
are omitted.

~~~
struct {
  ProtocolSuite proto;
	uint16 length;
	select (proto) {
		case VOPRF:
			VOPRFIssuanceRequest;
	}
} IssuanceRequest;
~~~

proto
: Protocol variant.

length
: Length of the remainder of the IssuanceRequest.

Details of the VOPRFIssuanceRequest are in {{voprf-protocol}}.

~~~
struct {
	Protocol proto;
	uint16 length;
	select (proto) {
		case VOPRF:
			VOPRFIssuanceResponse
	}
} IssuanceResponse;
~~~

proto
: Protocol variant.

length
: Length of the remainder of the IssuanceResponse.

Details of the VOPRFIssuanceResponse are in {{voprf-protocol}}.

### Client info {#client-info}

The client input `info` is arbitrary byte data that is used for linking
the redemption request to the specific session. We RECOMMEND that `info`
is constructed as the following concatenated byte-encoded data:

~~~
len(aux) || aux || len(server.id) || server.id || current_time()
~~~

where `len(x)` is the length of `x` in bytes, and `aux` is arbitrary
auxiliary data chosen by the client. The usage of `current_time()`
allows the server to check that the redemption request has happened in
an appropriate time window.

## Redemption {#redemption-phase}

Redemption is a one round protocol that allows the client to present,
or spend, tokens received during Issuance. The client learns a single
output -- whether or not the token is valid -- and the server learns
the private input the client used during the Issuance protocol.

~~~
  Client(token, info)                          Server(skS, pkS)
  ------------------------------------------------------------
  redeem_req = Redeem(token, info)

                            redeem_req
                        ------------------>

                            redeem_resp = Verify(pkS, skS, req)

                            redeem_resp
                        <------------------
  Output redeem_resp
~~~

<!-- TODO(caw): include errors here -->
<!-- TODO(caw): include how server must handle the request -->

### Redemption messages

This section describes the Redemption protocol messages exchanged during
the protocol.

~~~
struct {
  ProtocolSuite proto;
	uint16 length;
	select (proto) {
		case VOPRF:
			VOPRFRedemptionRequest;
	}
} RedeemRequest;
~~~

proto
: Protocol variant.

length
: Length of the remainder of the RedeemRequest.

Details of the VOPRFRedemptionRequest are in {{voprf-protocol}}.

~~~
struct {
	Protocol proto;
	uint16 length;
	uint8 valid;
} RedeemResponse;
~~~

proto
: Protocol variant.

length
: Length of the remainder of the RedeemResponse.

valid
: Single byte indicating if the redemption request was valid (0x01) or
  not (0x00).

### Double-spend protection

Depending on how servers use tokens, it may be necessary for servers to
implement some form of double spend mitigation that prevents clients from
spending tokens more than once. In general, clients are disincentivized
from spending a token more than once as it can increase the amount of
information linked to a single client. However, in cases where tokens
admit useful features, such as in the original Privacy Pass protocol,
malicious clients may compromise this privacy limitation for a better
user experience, or to abuse the server. See {{sec-reqs}} for more details.

## Handling errors

It is possible for the API functions from {{pp-protocol}} to return one
of the errors indicated in {{issuance-phase}} and {{redemption-phase}}
rather than their expected value. In these cases, we assume that the entire
protocol aborts.

# VOPRF instantiation {#voprf-protocol}

In this section, we instantiate the Privacy Pass Issuance and Redemption
protocols using the VOPRF protocol described in {{I-D.irtf-cfrg-voprf}}.
This instantiation makes use of the following types and parameters
defined in {{I-D.irtf-cfrg-voprf, Section 2.1}}, each of which are fully
defined by the corresponding VOPRF ciphersuite `suite`:

- SerializedElement: A serialized VOPRF element of size `Ne`.
- SerializedScalar: A serialized VOPRF scalar of size `Ns`.
- Scalar: A VOPRF scalar element.
- Hash: A cryptographic hash function of output length `Nh`.

## Issuance

This section describes the client and server behavior for Issuance. Given the
VOPRF ciphersuite `suite` and server public key `pkS`, clients begin Issuance
by creating a VOPRF context as follows:

```
context = SetupVerifiableClient(suite, pkS)
```

Likewise, a server with key pair `(skS, pkS)` begins Issuance by creating a VOPRF
context as follows:

```
context = SetupVerifiableServer(suite, skS, pkS)
```

Given this context, the client then samples `m` random nonces, denoted `nonce_i` for i = 1 to m,
each of of size 32 bytes:

```
nonce_i = random_bytes(32)
```

Hre, `random_bytes`

Each of these random nonces is then used to produce a single token request as follows:

```
blind_i, blinded_element_i = context.VerifiableBlind(nonce_i)
```

Let `nonce_list`, `blind_list`, and `blinded_element_list` denote the concatenation of
all `m` `nonce`, `blind`, and `blinded_element` values. The client then constructs
the `IssuanceRequest` by concatenating each blindedElement output as follows:

~~~
struct {
  opaque blinded_elements[Ne * m];
} VOPRFIssuanceRequest;
~~~

Upon receipt of a VOPRFIssuanceRequest denoted `issuance_req`, the server evaluates it
to produce a response as follows:

```
evaluated_elements, proof =
  context.Evaluate(skS, pkS, issuance_req.blinded_elements)
```

It then returns these to the client in a VOPRFIssuanceResponse `issuance_resp`, constructed
as follows:

~~~
struct {
  opaque evaluated_elements[Ne * m];
  opaque proof[2 * Ns];
} VOPRFIssuanceResponse;
~~~

Upon receipt of an `VOPRFIssuanceResponse` denoted `issuance_resp`, the client then
finalizes the result to produce a single output as follows:

```
output =
  context.Finalize(nonce_list, blind_list, issuance_resp.evaluated_elements, pkS, issuance_resp.proof)
```

If Finalize succeeds, then output is parsed as `m` values of length `Nh` each, denoted
`output_i`. The client then constructs and outputs `m` individual token structures, each
constructed as follows:

~~~
struct {
  opaque nonce[32];
  opaque output[Nh];
} Token;
~~~

If Finalize fails, the client aborts and outputs an error.

## Redemption

This section describes the client and server behavior for Redemption.
In Redemption, clients input a single `Token` denoted `token` for redemption.
The client first proceeds by sending token to the server in the corresponding
`RedeemRequest`. Upon receipt of this message, the server computes the following:

```
valid = context.VerifyFinalize(skS, token.nonce, token.output)
```

The server then returns `valid` to the client in a RedeemResponse, denoted `redeem_resp`.

Upon receipt, the client outputs `redeem_resp.valid`.

# Extensibility {#extensions}

Privacy Pass is extensible via the `Protocol` enumeration. New variants
need only specify a new enumeration and the corresponding Issuance
and Redemption protocol message formats. Note that new variants may
introduce new application API parameters, e.g., public metadata exchanged
and bound to tokens during Issuance, that is not present in the VOPRF
variant described in this document.

Each new extension that modifies the internals of the protocol MUST
justify that the extended protocol still satisfies the security requirements
in {{sec-reqs}}. Protocol extensions MAY put forward new security guarantees
where applicable.

The extensions MUST also conform with the extension framework policy as
set out in {{I-D.ietf-privacypass-architecture}}. For example, this may
concern any potential impact on client anonymity that the extension may
introduce.

# Security Considerations {#sec-reqs}

We discuss the security requirements that are necessary to uphold when
instantiating the Privacy Pass protocol. In particular, we focus on the
security requirements of "unlinkability", and "unforgeability".
Informally, the notion of unlinkability is required to preserve the
anonymity of the client in the redemption phase of the protocol. The
notion of unforgeability is to protect against an adversarial client
that may look to subvert the security of the protocol.

Both requirements are modelled as typical cryptographic security games,
following the formats laid out in {{DGSTV18}} and {{KLOR20}}.

Note that the privacy requirements of the protocol are covered in the
architectural framework document {{I-D.ietf-privacypass-architecture}}.

## Unlinkability {#unlinkability}

Formally speaking the security model is the following:

- The adversary runs the server setup and generates a keypair `(pkS,
  skS)`.
- The adversary specifies a number `Q` of issuance phases to initiate,
  where each phase `i in range(Q)` consists of `m_i` Issue evaluations.
- The adversary runs `Issue` using the keypair that it generated on each
  of the client messages in the issuance phase.
- When the adversary wants, it stops the issuance phase, and a random
  number `l` is picked from `range(Q)`.
- A redemption phase is initiated with a single token with index `i`
  randomly sampled from `range(m_l)`.
- The adversary guesses an index `l_guess` corresponding to the index of
  the issuance phase that it believes the redemption token was received
  in.
- The adversary succeeds if `l == l_guess`.

The security requirement is that the adversary has only a negligible
probability of success greater than `1/Q`.

## One-more unforgeability {#unforgeability}

The one-more unforgeability requirement states that it is hard for any
adversarial client that has received `m` valid tokens from the issuance
phase to redeem `m+1` of them. In essence, this requirement prevents a
malicious client from being able to forge valid tokens based on the
Issue responses that it sees.

The security model roughly takes the following form:

- The adversary specifies a number `Q` of issuance phases to initiate
  with the server, where each phase `i in range(Q)` consists of `m_i`
  server evaluation. Let `m = sum(m_i)` where `i in range(Q)`.
- The adversary receives `Q` responses, where the response with index
  `i` contains `m_i` individual tokens.
- The adversary initiates `m_adv` redemption sessions with the server
  and the server verifies that the sessions are successful (return
  true), and that each request includes a unique token. The adversary
  succeeds in `m_succ =< m_adv` redemption sessions.
- The adversary succeeds if `m_succ > m`.

The security requirement is that the adversarial client has only a
negligible probability of succeeding.

Note that {{KLOR20}} strengthens the capabilities of the adversary, in
comparison to the original work of {{DGSTV18}}. In {{KLOR20}}, the
adversary is provided with oracle access that allows it to verify that
the server responses in the issuance phase are valid.

## Double-spend protection

All issuing servers should implement a robust, global storage-query
mechanism for checking that tokens sent by clients have not been spent
before. Such tokens only need to be checked for each server
individually. This prevents clients from "replaying" previous requests,
and is necessary for achieving the unforgeability requirement.

## Additional token metadata

Some use-cases of the Privacy Pass protocol benefit from associating a
limited amount of metadata with tokens that can be read by the server
when a token is redeemed. Adding metadata to tokens can be used as a
vector to segment the anonymity of the client in the protocol.
Therefore, it is important that any metadata that is added is heavily
limited.

Any additional metadata that can be added to redemption tokens should be
described in the specific protocol instantiation. Note that any
additional metadata will have to be justified in light of the privacy
concerns raised above. For more details on the impacts associated with
segmenting user privacy, see {{I-D.ietf-privacypass-architecture}}.

Any metadata added to tokens will be considered either "public" or
"private". Public metadata corresponds to unmodifiable bits that a
client can read. Private metadata corresponds to unmodifiable private
bits that should be obscured to the client.

Note that the instantiation in {{voprf-protocol}} provides randomized
redemption tokens with no additional metadata for an server with a
single key.

## Maximum number of tokens issued {#max-tokens}

Servers SHOULD impose a hard ceiling on the number of tokens that can be
issued in a single issuance phase to a client. If there is no limit,
malicious clients could abuse this and cause excessive computation,
leading to a Denial-of-Service attack.

## VOPRF variant security

The protocol devised in {{pp-protocol}}, coupled with the instantiation
in {{voprf-protocol}}, are equivalent to the protocol description in
{{DGSTV18}} and {{KLOR20}} from a security perspective. In {{DGSTV18}},
it is proven that this protocol satisfies the security requirements of
unlinkability ({{unlinkability}}) and unforgeability
({{unforgeability}}).

The unlinkability property follows unconditionally as the view of the
adversary in the redemption phase is distributed independently of the
issuance phase. The unforgeability property follows from the one-more
decryption security of the ElGamal cryptosystem {{DGSTV18}}. In
{{KLOR20}} it is also proven that this protocol satisfies the stronger
notion of unforgeability, where the adversary is granted a verification
oracle, under the chosen-target Diffie-Hellman assumption.

Note that the existing security proofs do not leverage the VOPRF
primitive as a black-box in the security reductions. Instead, it relies
on the underlying operations in a non-black-box manner. Hence, an
explicit reduction from the generic VOPRF primitive to the Privacy Pass
protocol would strengthen these security guarantees.

--- back

# Document contributors

- Alex Davidson (alex.davidson92@gmail.com)
- Sofía Celi (cherenkov@riseup.net)
- Christopher Wood (caw@heapingbits.net)
