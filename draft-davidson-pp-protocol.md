---
title: "Privacy Pass: The Protocol"
abbrev: PP protocol
docname: draft-davidson-pp-protocol-latest
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
    org: Cloudflare
    city: Lisbon
    country: Portugal
    email: alex.davidson92@gmail.com

normative:
  RFC2119:
  RFC8446:
  I-D.irtf-cfrg-voprf:
  draft-davidson-pp-architecture:
    title: "Privacy Pass: Architectural Framework"
    target: https://github.com/alxdavids/privacy-pass-ietf/tree/master/drafts/draft-davidson-pp-architecture
    author:
      ins: A. Davidson
      org: Cloudflare
  draft-svaldez-pp-http-api:
    title: "Privacy Pass: HTTP API"
    target: https://github.com/alxdavids/privacy-pass-ietf/tree/master/drafts/draft-davidson-pp-architecture
    author:
      ins: A. Davidson
      org: Cloudflare
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

--- abstract

This document specifies the Privacy Pass protocol. This protocol
provides privacy-preserving authorization of clients to servers. In
particular, client re-authorization events cannot be linked to any
previous initial authorization. Privacy Pass is intended to be used as a
performant protocol in the application-layer.

--- middle

# Introduction

A common problem on the Internet is providing an effective mechanism for
servers to derive trust from clients they interact with. Typically, this
can be done by providing some sort of authorization challenge to the
client. But this also negatively impacts the experience of clients that
regularly have to solve such challenges.

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
server. This allows clients to communicate to a server an attestation of
a previously authenticated action, without having to reauthenticate
manually. The tokens are retain anonymity in the sense that the act of
revealing them cannot be linked back to the session where they were
initially issued.

This document lays out the generic description of the protocol, along
with the data and message formats. We detail an implementation of the
protocol functionality based on the description of a verifiable
oblivious pseudorandom function {{I-D.irtf-cfrg-voprf}}.

This document DOES NOT cover the architectural framework required for
running and maintaining the Privacy Pass protocol in the Internet
setting. In addition, it DOES NOT cover the choices that are necessary
for ensuring that client privacy leaks do not occur. Both of these
considerations are covered in a separate document
{{draft-davidson-pp-architecture}}. A separate document
{{draft-svaldez-pp-http-api}} provides an instantiation of this protocol
intended for the HTTP setting.

## Layout

- {{prelim}}: Describes the terminology and assumptions adopted
  throughout this document.
- {{pp-api}}: Describes the internal functions and data structures that
  are used by the Privacy Pass protocol.
- {{overview}}: Describes the generic protocol structure, based on the
  API provided in {{pp-api}}.
- {{sec-reqs}}: Describes the security requirements of the
  generic protocol description.
- {{voprf-protocol}}: Describes an instantiation of the API in
  {{pp-api}} based on the VOPRF protocol described in
  {{I-D.irtf-cfrg-voprf}}.
- {{pp-ciphersuites}}: Describes ciphersuites for use with the Privacy
  Pass protocol based on the instantiation in {{voprf-protocol}}.
- {{extensions}}: Describes the policy for implementing extensions to
  the Privacy Pass protocol.

# Preliminaries {#prelim}

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}.

The following terms are used throughout this document.

- Issuer: A service that provides the server-side functionality required
  by the protocol documented here. May also be known as the Server.
- Client: An entity that seeks authorization from a server that supports
  interactions in the Privacy Pass protocol.
- Key: The secret key used by the Server for authorizing client data
  (typically denoted key).

We assume that all protocol messages are encoded into raw byte format
before being sent. We use the TLS presentation language {{RFC8446}} to
describe the structure of protocol data types and messages.

## Basic assumptions

We make only a few minimal assumptions about the environment of the
clients and servers supporting the Privacy Pass protocol.

- At any one time, we assume that the Issuer uses only one configuration
  containing their ciphersuite choice along with their secret key data.
- We assume that the client has access to a global directory of the
  current public parts of the configurations used the Issuer.

The wider ecosystem that this protocol is employed in is described in
{{draft-davidson-pp-architecture}}.

# Protocol description {#overview}

The Privacy Pass protocol is split into two phases that are built upon
the functionality described in {{pp-api}} later.

The first phase, "issuance", provides the client with unlinkable tokens
that can be used to initiate re-authorization with the server in the
future. The second phase, "redemption", allows the client to redeem a
given re-authorization token with the server that it interacted with
during the issuance phase. The protocol must satisfy two cryptographic
security requirements known as "unlinkability" and "unforgeability".
These requirements are covered in {{sec-reqs}}.

## Issuer setup {#issuer-setup}

Before the protocol takes place, the Issuer chooses a ciphersuite and
generates a keypair by running `(pkI, skI) = KeyGen()`. This
configuration must be available to all Clients that interact with the
Issuer (for the purpose of engaging in a Privacy Pass exchange). We
assume that the Issuer has a unique identifier `id` that is known to the
client.

## Client setup {#client-setup}

The client initialises a global storage system `store` that allows it
store the tokens that are received during issuance. The storage system
is a map of Issuer identifiers (`Issuer.id`) to arrays of stored tokens.
We assume that the client knows the Issuer public key `pkI` ahead of time.

## Issuance phase {#issuance-phase}

The issuance phase allows the Client to receive anonymous authorization
tokens from the Issuer.

~~~
  Client(pkI, m)                              Issuer(skI, pkI)
  ------------------------------------------------------------
  cInput = Generate(m)
  msg = cInput.msg

                              msg
                      ------------------->

                             issuerResp = Issue(skI, pkI, msg)

                           issueResp
                      <-------------------

  tokens = Process(pkI, cInput, issueResp)
  store[Issuer.id].push(tokens)
~~~

## Redemption phase {#redemption-phase}

The redemption phase allows the client to anonymously reauthenticate to
the server, using data that it has received from a previous issuance
phase.

~~~
  Client(info)                                   Issuer(skI)
  ------------------------------------------------------------
  token = store[Issue.id].pop()
  msg = Redeem(token, info)

                               msg
                        ------------------>

                               if (dsIdx.includes(msg.data)) {
                                 raise ERR_DOUBLE_SPEND
                               }
                               resp = Verify(skI, msg)
                               if (resp.success) {
                                 dsIdx.push(msg.data)
                               }

                                resp
                        <------------------
  Output resp
~~~

### Client info {#client-info}

The client input `info` is arbitrary byte data that is used for linking
the redemption request to the specific session. We RECOMMEND that `info`
is constructed as the following concatenated byte-encoded data:

~~~
len(aux) || aux || len(Issuer.id) || Issuer.id || current_time()
~~~

where `aux` is arbitrary auxiliary data chosen by the client. The usage
of `current_time()` allows the server to check that the redemption
request has happened in an appropriate time window.

### Double-spend protection

To protect against clients that attempt to spend a value `msg.data` more
than once, the server uses an index, `dsIdx`, to collect valid inputs
and then check against it in future sessions. Since this store needs to
only be optimized for storage and querying, a structure such as a Bloom
filter suffices. The storage should be parameterized to live as long as
the Issuer keypair that is in use. See {{sec-reqs} for more details.

## Handling errors

It is possible for the API functions from {{pp-functions}} to return one
of the errors indicated in {{errors}} rather than their expected value.
In these cases, we assume that the entire protocol aborts. If this
occurs during the server's operations for one of the documented errors,
then the server returns an error response indicating the error type that
occurred.

# Functionality {#pp-api}

This section details the data types and API functions that are used to
construct the protocol in {{overview}}.

We provide an explicit instantiation of the Privacy Pass API, based on
the public API provided in {{I-D.irtf-cfrg-voprf}}.

## Data structures {#pp-structs}

The following data structures are used throughout the Privacy Pass
protocol and are written in the TLS presentation language {{RFC8446}}.
It is intended that any of these data structures can be written into
widely-adopted encoding schemes such as those detailed in TLS
{{RFC8446}}, CBOR {{RFC7049}}, and JSON {{RFC7159}}.

### Ciphersuite {#pp-ciphersuite-struct}

The `Ciphersuite` enum provides identifiers for each of the supported
ciphersuites of the protocol. Some initial values that are supported by
the core protocol are described in {{pp-ciphersuites}}. Note that the
list of supported ciphersuites may be expanded by extensions to core
protocol description.

### Keys {#pp-issuer-keys}

We use the following types to describe the public and private keys used
by the Issuer.

~~~
opaque PublicKey<1..2^16-1>
opaque PrivateKey<1..2^16-1>
~~~

### IssuanceInput {#pp-cli-issue-input}

The `IssuanceInput` struct describes the data that is initially
generated by the client during the issuance phase.

Firstly, we define sequences of bytes that partition the client input.

~~~
opaque Internal<1..2^16-1>
opaque IssuanceMessage<1..2^16-1>
~~~

These data types represent members of the wider `IssuanceInput` data
type.

~~~
struct {
  Internal data[m]
  IssuanceMessage msg[m]
} IssuanceInput;
~~~

Note that a `IssuanceInput` contains equal-length arrays of `Internal`
and `IssuanceMessage` types corresponding to the number of tokens that
should be issued.

### IssuanceResponse {#pp-srv-issue-response}

Firstly, the `IssuedToken` type corresponds to a single sequence of
bytes that represents a single issued token received from the Issuer.

~~~
opaque IssuedToken<1..2^16-1>
~~~

Then an `IssuanceResponse` corresponds to a collection of `IssuedTokens`
as well as a sequence of bytes `proof`.

~~~
struct {
  IssuedToken tokens[m]
  opaque proof<1..2^16-1>
}
~~~

The value of `m` is equal to the length of the `IssuanceMessage` vector
sent by the Client.

### RedemptionToken {#pp-redemption-token}

The `RedemptionToken` struct contains the data required to generate the
client message in the redemption phase of the Privacy Pass protocol.

~~~
struct {
  opaque data<1..2^16-1>;
  opaque issued<1..2^16-1>;
} RedemptionToken;
~~~

### RedemptionMessage {#pp-redemption-message}

The `RedemptionMessage` struct consists of the data that is sent by the
client during the redemption phase of the protocol.

~~~
struct {
  opaque data<1..2^16-1>;
  opaque tag<1..2^16-1>;
  opaque info<1..2^16-1>;
} RedemptionMessage;
~~~

### RedemptionResponse {#pp-redemption-response}

The `RedemptionResponse` struct corresponds to a boolean value that
indicates whether the `RedemptionMessage` sent by the client is
valid. It can also contain any associated data.

~~~
struct {
  boolean success;
  opaque ad<1..2^16-1>;
} RedemptionResponse;
~~~

## API functions {#pp-functions}

The following functions wrap the core of the functionality required in
the Privacy Pass protocol. For each of the descriptions, we essentially
provide the function signature, leaving the actual contents to be
defined by specific instantiations or extensions of the protocol.

### Generate

A function run by the client to generate the initial data that is used
as its input in the Privacy Pass protocol.

Inputs:

- `m`:       A `uint8` value corresponding to the number of Privacy
             Pass tokens to generate.

Outputs:

- `input`: An `IssuanceInput` struct.

### Issue

A function run by the server to issue valid redemption tokens to the
client.

Inputs:

- `pkI`: An Issuer `PublicKey`.
- `skI`: An Issuer `PrivateKey`.
- `msg`:  An `IssuanceMessage` struct.

Outputs:

- `resp`: An `IssuanceResponse` struct.

### Process

Run by the client when processing the server response in the issuance
phase of the protocol.

Inputs:

- `pkI`: An Issuer `PublicKey`.
- `resp`: An `IssuanceResponse` struct.
- `input`: An `IssuanceInput` struct.

Outputs:

- `tokens`: A vector of `RedemptionToken` structs, whose length is
  equal to length of the internal `ServerEvaluation` vector in the
  `IssuanceResponse` struct.

Throws:

- `ERR_PROOF_VALIDATION` ({{errors}})

### Redeem

Run by the client in the redemption phase of the protocol to generate
the client's message.

Inputs:

- `token`: A `RedemptionToken` struct.
- `info`: An `opaque<1..2^16-1>` type corresponding to data that is
  linked to the redemption. See {{client-info}} for advice on how to
  construct this.

Outputs:

- `msg`: A `RedemptionMessage` struct.

### Verify

Run by the server in the redemption phase of the protocol. Determines
whether the data sent by the client is valid.

Inputs:

- `pkI`: An Issuer `PublicKey`.
- `skI`: An Issuer `PrivateKey`.
- `msg`: A `RedemptionMessage` struct.

Outputs:

- `resp`: A `RedemptionResponse` struct.

## Error types {#errors}

- `ERR_PROOF_VALIDATION`: Error occurred when a client attempted to
  verify the proof that is part of the server's response.
- `ERR_DOUBLE_SPEND`: Error occurred when a client has attempted to
  redeem a token that has already been used for authorization.

# Security considerations {#sec-reqs}

We discuss the security requirements that are necessary to uphold when
instantiating the Privacy Pass protocol. In particular, we focus on the
security requirements of "unlinkability", and "unforgeability".
Informally, the notion of unlinkability is required to preserve the
privacy of the client in the redemption phase of the protocol. The
notion of unforgeability is to protect against adversarial clients that
look to subvert the security of the protocol.

Since these are cryptographic security requirements we discuss them with
respect to a polynomial-time algorithm known as the adversary that is
looking to subvert the security guarantee. More details on both security
requirements can be found in {{DGSTV18}} and {{KLOR20}}.

Note that the privacy requirements of the protocol are covered in the
architectural framework document {{draft-davidson-pp-architecture}}.

## Unlinkability {#unlinkability}

Informally, the "unlinkability" requirement states that it is impossible
for an adversarial Issuer to link the Client's message in a redemption
session, to any previous issuance session that it has encountered.

Formally speaking the security model is the following:

- The adversary runs the Issuer setup and generates a Issue keypair
  `(pkI, skI)`.
- The adversary specifies a number `Q` of issuance phases to initiate,
  where each phase `i in range(Q)` consists of `m_i` Issue evaluations.
- The adversary runs `Issue` using the keypair that it generated on
  each of the Client messages in the issuance phase.
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
adversarial Client that has received `m` valid tokens from a Issue to
redeem `m+1` of them. In essence, this requirement prevents a malicious
Client from being able to forge valid tokens based on the Issue
responses that it sees.

The security model roughly takes the following form:

- The adversary specifies a number `Q` of issuance phases to initiate
  with the Issuer, where each phase `i in range(Q)` consists of `m_i`
  Issuer evaluation. Let `m = sum(m_i)` where `i in range(Q)`.
- The adversary receives `Q` responses, where the response with index
  `i` contains `m_i` individual tokens.
- The adversary initiates `m_adv` redemption sessions with the Issuer
  and the Issuer verifies that the sessions are successful (return
  true), and that each request includes a unique token. The adversary
  succeeds in `m_succ =< m_adv` redemption sessions.
- The adversary succeeds if `m_succ > m`.

The security requirement is that the adversarial Client has only a
negligible probability of succeeding.

Note that {{KLOR20}} strengthens the capabilities of the adversary, in
comparison to the original work of {{DGSTV18}}. In {{KLOR20}}, the
adversary is provided with oracle access that allows it to verify that
the server responses in the issuance phase are valid.

## Double-spend protection

All issuing servers should implement a robust, global storage-query
mechanism for checking that tokens sent by clients have not been spent
before. Such tokens only need to be checked for each issuer
individually. This prevents clients from "replaying" previous requests,
and is necessary for achieving the unforgeability requirement.

# VOPRF instantiation {#voprf-protocol}

In this section, we show how to instantiate the functional API in
{{pp-api}} with the VOPRF protocol described in {{I-D.irtf-cfrg-voprf}}.
Moreover, we show that this protocol satisfies the security requirements
laid out in {{sec-reqs}}, based on the security proofs provided
in {{DGSTV18}} and {{KLOR20}}.

## Recommended ciphersuites {#voprf-ciph-recs}

The RECOMMENDED Issuer ciphersuites are as follows:
detailed in {{I-D.irtf-cfrg-voprf}}:

- OPRF(curve448, SHA-512) (ID = 0x0002);
- OPRF(P-384, SHA-512) (ID = 0x0004);
- OPRF(P-521, SHA-512) (ID = 0x0005).

We deliberately avoid the usage of smaller ciphersuites (associated with
P-256 and curve25519) due to the potential to reduce security via
static Diffie Hellman attacks. See {{I-D.irtf-cfrg-voprf}} for more details.

## Protocol contexts

Note that we must run the verifiable version of the protocol in
{{I-D.irtf-cfrg-voprf}}. Therefore the `Issuer` takes the role of the
`Server` running in `modeVerifiable`. In other words, the `Issuer` runs
`(ctxtI, pkI) = SetupVerifiableServer(suite)`; where `suite` is one of
the ciphersuites in {{voprf-ciph-recs}}, `ctxt` contains the internal
VOPRF Server functionality and secret key `skI`, and `pkI` is the Issuer
public key. Likewise, run `ctxtC = SetupVerifiableClient(suite)` to
generate the Client context.

## Functionality {#voprf-api}

For the explicit signatures of each of the functions, refer to
{{pp-api}}.

### Generate

~~~
def Generate(m):
  inputs = []
  for i in range(m):
    inputs[i] = random_bytes()
  (tokens, blindedTokens) = Blind(inputs)
  return IssuanceInput {
           internal: tokens,
           msg: blindedTokens,
         }
~~~

### Issue

~~~
def Issue(pkI, skI, msg):
  Ev = Evaluate(skI, pkI, msg)
  return IssuanceResponse {
           tokens: Ev.elements,
           proof: Ev.proof,
         }
~~~

### Process

~~~
Process(pkI, input, resp):
  unblindedTokens = Unblind(pkI, input.data, input.msg, resp)
  redemptionTokens = []
  for bt in unblindedTokens:
    rt = RedemptionToken { data: input.data, issued: bt }
    redemptionTokens[i] = rt
  return redemptionTokens
~~~

### Redeem

~~~
def Redeem(token, info):
  tag = Finalize(token.data, token.issued, info)
  return RedemptionMessage {
           data: data,
           tag: tag,
           info: info,
         }
~~~

### Verify

~~~
def Verify(pkI, skI, msg):
  resp = VerifyFinalize(skI, pkI, msg.data, msg.info, msg.tag)
  Output RedemptionResponse {
           success: resp
         }
~~~

## Security justification

The protocol devised in {{overview}}, coupled with the API instantiation
in {{voprf-api}}, are equivalent to the protocol description in
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

# Protocol ciphersuites {#pp-ciphersuites}

The ciphersuites that we describe for the Privacy Pass protocol are
derived from the core instantiations of the protocol (such as in
{{voprf-protocol}}).

In each of the ciphersuites below, the maximum security provided
corresponds to the maximum difficulty of computing a discrete logarithm
in the group. Note that the actual security level MAY be lower, see the
security considerations in {{I-D.irtf-cfrg-voprf}} for examples.

## PP(OPRF2)

- OPRF2 = OPRF(curve448, SHA-512)
- ID = 0x0001
- Maximum security provided: 224 bits

## PP(OPRF4)

- OPRF4 = OPRF(P-384, SHA-512)
- ID = 0x0002
- Maximum security provided: 192 bits

## PP(OPRF5)

- OPRF5 = OPRF(P-521, SHA-512)
- ID = 0x0003
- Maximum security provided: 256 bits

# Extensions framework policy {#extensions}

The intention with providing the Privacy Pass API in {{pp-api}} is to
allow new instantiations of the Privacy Pass protocol. These
instantiations may provide either modified VOPRF constructions, or
simply implement the API in a completely different way.

Extensions to this initial draft SHOULD be specified as separate
documents taking one of two possible routes:

- Produce new VOPRF-like primitives that use the same public API
  provided in {{I-D.irtf-cfrg-voprf}} to implement the Privacy Pass API,
  but with different internal operations.
- Implement the Privacy Pass API in a different way to the proposed
  implementation in {{voprf-protocol}}.

If an extension requires changing the generic protocol description as
described in {{overview}}, then the change may have to result in changes
to the draft specification here also.

Each new extension that modifies the internals of the protocol in either
of the two ways MUST re-justify that the extended protocol
still satisfies the security requirements in {{sec-reqs}}.
Protocol extensions MAY put forward new security guarantees if they
are applicable.

The extensions MUST also conform with the extension framework policy as
set out in the architectural framework document. For example, this may
concern any potential impact on client privacy that the extension may
introduce.

--- back

# Document contributors

- Alex Davidson (alex.davidson92@gmail.com)
- Sofía Celi    (cherenkov@riseup.net)
- Chris Wood    (caw@heapingbits.net)
