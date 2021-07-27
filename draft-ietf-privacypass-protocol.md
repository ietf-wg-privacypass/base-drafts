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
      ins: S. Valdez
      org: Google
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

This document DOES NOT cover the architectural framework required for
running and maintaining the Privacy Pass protocol in the Internet
setting. In addition, it DOES NOT cover the choices that are necessary
for ensuring that client privacy leaks do not occur. Both of these
considerations are covered in a separate document
{{draft-davidson-pp-architecture}}. In addition,
{{draft-svaldez-pp-http-api}} provides an instantiation of this protocol
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

## Server setup {#server-setup}

Before the protocol takes place, the server chooses a ciphersuite and
generates a keypair by running `(pkS, skS) = KeyGen()`. The client and
server also agree on public metadata values used during the protocol.
See {{client-setup}} for more information about this metadata. This
configuration must be available to all clients that interact with
the server (for the purpose of engaging in a Privacy Pass exchange). We
assume that the server has a public (and unique) identity that the client
uses to retrieve this configuration.

## Client setup {#client-setup}

The client initialises a global storage system `store` that allows it
store the tokens that are received during issuance. The storage system
is a map of server identifiers (`server.id`) to arrays of stored tokens.
We assume that the client knows the server public key `pkS` ahead of
time. As above, the client and server also agree on public metadata values
used during the protocol. Each metadata value is an arbitrary-length byte
string. The client picks a value `m` of tokens to receive during the
issuance phase. In {{draft-davidson-pp-architecture}} we discuss mechanisms
that the client can use to ensure that this public key is consistent across
the entire ecosystem.

## Issuance phase {#issuance-phase}

The issuance phase is a two-round protocol that allows the client to
receive `m` anonymous authorization tokens from the server. The first
round sees the server generate a commitment. The second round sees the
server issue a token to the client.

~~~
  Client(pkS, m, info, clientMetadata, serverMetadata)                        Server(skS, pkS, clientMetadata, serverMetadata)
  -----------------------------------------------------------------------------------------------------------------------------

  commit_req = Prepare(info)

                                         commit_req
                                                        ------------------->

                                                                              commit_resp = Commit(skS, pkS, commit_req)

                                                              commit_resp
                                                        <-------------------

  cInput = Generate(m, commit_resp)
  req = cInput.req

                                                                req
                                                        ------------------->

                                                                         issueResp = Issue(pkS, skS, req, serverMetadata, clientMetadata)

                                                             serverResp
                                                        <-------------------

  tokens = Process(pkS, cInput, serverResp, serverMetadata, clientMetadata)
  store[server.id].push(tokens)
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

When the server does not need to generate this commitment, the client
instead DOES NOT send the `CommitRequest` message, and runs:

~~~
cInput = Generate(m, "")
~~~

A server that is expecting some non-empty `commit_resp` to be passed
must abort the protocol on receiving a request containing an empty
`commit_resp` value.

Note: currently, no ciphersuites are supported that support working with
empty commitment messages.

## Redemption phase {#redemption-phase}

The redemption phase allows the client to anonymously reauthenticate to
the server, using data that it has received from a previous issuance
phase.

~~~
  Client(info, clientMetadata, serverMetadata)                                Server(skS, pkS, serverMetadata)
  ---------------------------------------------------------------------------------------------------------------
  token = store[server.id].pop()
  req = Redeem(token, info, serverMetadata, clientMetadata)

                                                             req
                                                             ------------------>

                                                                    if (dsIdx.includes(req.data)) {
                                                                      raise ERR_DOUBLE_SPEND
                                                                    }
                                                                    resp = Verify(pkS, skS, req, serverMetadata, clientMetadata)
                                                                    if (resp.success) {
                                                                      dsIdx.push(req.data)
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
len(aux) || aux || len(server.id) || server.id || current_time()
~~~

where `len(x)` is the length of `x` in bytes, and `aux` is arbitrary
auxiliary data chosen by the client. The usage of `current_time()`
allows the server to check that the redemption request has happened in
an appropriate time window.

### Double-spend protection

To protect against clients that attempt to spend a value `req.data` more
than once, the server uses an index, `dsIdx`, to collect valid inputs it
witnesses. Since this store needs to only be optimized for storage and
querying, a structure such as a Bloom filter suffices. The storage
should be parameterized to live as long as the server keypair that is in
use. See {{sec-reqs}} for more details.

## Handling errors

It is possible for the API functions from {{pp-functions}} to return one
of the errors indicated in {{errors}} rather than their expected value.
In these cases, we assume that the entire protocol aborts.

# Functionality {#pp-api}

This section details the data types and API functions that are used to
construct the protocol in {{overview}}.

We provide an explicit instantiation of the Privacy Pass API in
{{voprf-api}}, based on the public API provided in
{{I-D.irtf-cfrg-voprf}}.

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
list of supported ciphersuites may be expanded by extensions to the core
protocol description in separate documents.

### Keys {#pp-server-keys}

We use the following types to describe the public and private keys used
by the server.

~~~
opaque PublicKey<1..2^16-1>
opaque PrivateKey<1..2^16-1>
~~~

### CommitRequest {#pp-cli-commit-request}

The `CommitRequest` struct is simply a fixed message allowing opaque
metadata.

~~~
struct {
  opaque info<1..2^16-1>
} CommitRequest;
~~~

### CommitResponse {#pp-cli-commit-response}

The `CommitResponse` struct is contains an opaque set of bytes that
correspond to some commitment that the server has generated. The
structure and format of this value is implementation specific depending
on whether the server is stateful.

~~~
struct {
  opaque commitment<1..2^16-1>
} CommitResponse;
~~~

### IssuanceInput {#pp-cli-issue-input}

The `IssuanceInput` struct describes the data that is initially
generated by the client during the issuance phase.

Firstly, we define sequences of bytes that partition the client input.

~~~
opaque Internal<1..2^16-1>
opaque IssuanceRequest<1..2^16-1>
~~~

These data types represent members of the wider `IssuanceInput` data
type.

~~~
struct {
  Internal data[m]
  IssuanceRequest req[m]
} IssuanceInput;
~~~

Note that a `IssuanceInput` contains equal-length arrays of `Internal`
and `IssuanceRequest` types corresponding to the number of tokens that
should be issued.

### IssuanceResponse {#pp-srv-issue-response}

Firstly, the `IssuedToken` type corresponds to a single sequence of
bytes that represents a single issued token received from the server.

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

The value of `m` is equal to the length of the `IssuanceRequest` vector
sent by the client.

### RedemptionToken {#pp-redemption-token}

The `RedemptionToken` struct contains the data required to generate the
client message in the redemption phase of the Privacy Pass protocol.

~~~
struct {
  opaque data<1..2^16-1>;
  opaque issued<1..2^16-1>;
} RedemptionToken;
~~~

### RedemptionRequest {#pp-redemption-message}

The `RedemptionRequest` struct consists of the data that is sent by the
client during the redemption phase of the protocol.

~~~
struct {
  opaque data<1..2^16-1>;
  opaque tag<1..2^16-1>;
  opaque info<1..2^16-1>;
} RedemptionRequest;
~~~

### RedemptionResponse {#pp-redemption-response}

The `RedemptionResponse` struct corresponds to a boolean value that
indicates whether the `RedemptionRequest` sent by the client is valid.
It can also contain any associated data.

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

### Prepare

A function run by the client to prepare for a commitment will used
during the issuance flow of the Privacy Pass protocol.

Inputs:

`info`: An opaque byte application-specific byte string.

Outputs:

`commit_req`: A `CommitRequest` struct.

This function should be implemented by any ciphersuites that require a
two-phase issuance protocol (`COMMIT=true`).

### Commit

A function run by the server that generates a commitment in the first
phase of the issuance protocol.

Inputs:

- `skS`: A server `PrivateKey`.
- `pkS`: A server `PublicKey`.
- `commit_req`: A `CommitRequest` struct

Outputs:

- `commit_resp`: A `CommitResponse` struct.

This function should be implemented by any ciphersuites that require a
two-phase issuance protocol (`COMMIT=true`).

### Generate

A function run by the client to generate the initial data that is used
as its input in the Privacy Pass protocol.

Inputs:

- `m`:       A `uint8` value corresponding to the number of Privacy Pass
             tokens to generate.

Outputs:

- `input`: An `IssuanceInput` struct.

### Issue

A function run by the server to issue valid redemption tokens to the
client.

Inputs:

- `pkS`: A server `PublicKey`.
- `skS`: A server `PrivateKey`.
- `req`: An `IssuanceRequest` struct.
- `serverMetadata`: A optional server metadata, an arbitrary-length byte string.
- `clientMetadata`: A optional client metadata, an arbitrary-length byte string.

Outputs:

- `resp`: An `IssuanceResponse` struct.

Throws:

- `ERR_FAILED_COMMITMENT` ({{errors}})

### Process

Run by the client when processing the server response in the issuance
phase of the protocol.

Inputs:

- `pkS`: An server `PublicKey`.
- `input`: An `IssuanceInput` struct.
- `resp`: An `IssuanceResponse` struct.
- `serverMetadata`: A optional server metadata, an arbitrary-length byte string.
- `clientMetadata`: A optional client metadata, an arbitrary-length byte string.

Outputs:

- `tokens`: A vector of `RedemptionToken` structs, whose length is equal
  to length of the internal `ServerEvaluation` vector in the
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
- `serverMetadata`: A optional server metadata, an arbitrary-length byte string.
- `clientMetadata`: A optional client metadata, an arbitrary-length byte string.

Outputs:

- `req`: A `RedemptionRequest` struct.

### Verify

Run by the server in the redemption phase of the protocol. Determines
whether the data sent by the client is valid.

Inputs:

- `pkS`: An server `PublicKey`.
- `skS`: An server `PrivateKey`.
- `req`: A `RedemptionRequest` struct.
- `serverMetadata`: A optional server metadata, an arbitrary-length byte string.
- `clientMetadata`: A optional client metadata, an arbitrary-length byte string.

Outputs:

- `resp`: A `RedemptionResponse` struct.

## Error types {#errors}

- `ERR_PROOF_VALIDATION`: Error occurred when a client attempted to
  verify the proof that is part of the server's response.
- `ERR_DOUBLE_SPEND`: Error occurred when a client has attempted to
  redeem a token that has already been used for authorization.
- `ERR_FAILED_COMMITMENT`: Error occurs during issuance phase if
  non-empty commitment does not match the commitment generated in the
  first round.

# Security considerations {#sec-reqs}

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
architectural framework document {{draft-davidson-pp-architecture}}.

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

Note that any additional metadata will have to be justified in light of
the privacy concerns raised above. For more details on the impacts
associated with segmenting user privacy, see {{draft-davidson-pp-architecture}}.

Any metadata added to tokens will be considered either "public" or
"private". This document adds a mechanism to add this public metadata.
Public metadata corresponds to unmodifiable bits that a
client can read. Private metadata corresponds to unmodifiable private
bits that should be obscured to the client.

Note that the instantiation in {{voprf-protocol}} provides randomized
redemption tokens with additional metadata for an server with a
single key.

## Maximum number of tokens issued {#max-tokens}

Servers SHOULD impose a hard ceiling on the number of tokens that can be
issued in a single issuance phase to a client. If there is no limit,
malicious clients could abuse this and cause excessive computation,
leading to a Denial-of-Service attack.

# VOPRF instantiation {#voprf-protocol}

In this section, we show how to instantiate the functional API in
{{pp-api}} with the VOPRF protocol described in {{I-D.irtf-cfrg-voprf}}.
Moreover, we show that this protocol satisfies the security requirements
laid out in {{sec-reqs}}, based on the security proofs provided in
{{DGSTV18}} and {{KLOR20}}.

## Recommended ciphersuites {#voprf-ciph-recs}

The RECOMMENDED server ciphersuites are as follows: detailed in
{{I-D.irtf-cfrg-voprf}}:

- OPRF(decaf448, SHA-512) (ID = 0x0002);
- OPRF(P-384, SHA-512) (ID = 0x0004);
- OPRF(P-521, SHA-512) (ID = 0x0005).

We deliberately avoid the usage of smaller ciphersuites (associated with
P-256 and ristretto255) due to the potential to reduce security to
unfavourable levels via static Diffie Hellman attacks. See
{{I-D.irtf-cfrg-voprf}} for more details.

## Protocol contexts

Note that we must run the verifiable version of the protocol in
{{I-D.irtf-cfrg-voprf}}. Therefore the `server` takes the role of the
`Server` running in `modeVerifiable`. In other words, the `server` runs
`ctxtS = SetupVerifiableServer(suite, skS, pkS)`; where `suite` is one
of the ciphersuites in {{voprf-ciph-recs}}, `skS` and `pkS` is the
server's secret and public key respectively (generated by calling
`KeyGen`). It returns `ctxtS`, which is the Server context. Likewise,
run `ctxtC = SetupVerifiableClient(suite, pkS)` to generate the Client
context.

## Functionality {#voprf-api}

We instantiate each functions using the API functions in
{{I-D.irtf-cfrg-voprf}}. Note that we use the framework mentioned in the
document to allow for batching multiple tokens into a single VOPRF
evaluation. For the explicit signatures of each of the functions, refer
to {{pp-api}}.

### Generate

The generate functionality generates an initial set of tokens and
blinded representation on the client-side. The function also takes an
optional (possibly empty) value for a commitment `com` committed to by
the server.

~~~
def Generate(m, com):
  tokens = []
  blindedTokens = []
  for i in range(m):
    x = random_bytes()
    (token, blindedToken) = Blind(x, com)
    tokens[i] = token
    blindedTokens[i] = blindedToken
  return IssuanceInput {
           data: tokens,
           req: blindedTokens,
         }
~~~

### Issue

For this functionality, note that we supply multiple tokens in `req` to
`Evaluate`. This allows batching a single proof object for multiple
evaluations. While the construction in {{I-D.irtf-cfrg-voprf}} only
permits a single input, we follow the advice for providing vectors of
inputs.

~~~
def Issue(pkS, skS, req, serverMetadata, clientMetadata):
  elements, proof = Evaluate(skS, pkS, req, serverMetadata, clientMetadata)
  return IssuanceResponse {
           tokens: elements,
           proof: proof,
         }
~~~

### Process

Similarly to `Issue`, we follow the advice for providing vectors of
inputs to the `Unblind` function for verifying the batched proof object.

~~~
Process(pkS, input, resp, serverMetadata, clientMetadata):
  unblindedTokens = VerifiableUnblind(input.data, resp.elements,
                                      input.req, pkS, resp.proof,
                                      serverMetadata, clientMetadata)
  redemptionTokens = []
  for bt in unblindedTokens:
    rt = RedemptionToken { data: input.data, issued: bt }
    redemptionTokens[i] = rt
  return redemptionTokens
~~~

### Redeem

~~~
def Redeem(token, info):
  tag = VerifiableFinalize(token.data, token.issued, info, serverMetadata,
                           clientMetadata)
  return RedemptionRequest {
           data: data,
           tag: tag,
           info: info,
         }
~~~

### Verify

~~~
def Verify(pkS, skS, req):
  resp = VerifyFinalize(skS, req.data, req.info, req.tag, serverMetadata,
                        clientMetadata)
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
in the group. Note that the actual security level MAY be lower. See the
security considerations in {{I-D.irtf-cfrg-voprf}} for examples.

The COMMIT parameter refers to whether the first round of the issuance
phase of the protocol is necessary. When this is false, the client
ignores the first message and uses an empty value for the commitment
parameter to `Generate`.

## PP(OPRF2)

- OPRF2 = OPRF(decaf448, SHA-512)
- ID = 0x0001
- COMMIT = false
- Maximum security provided: 224 bits

## PP(OPRF4)

- OPRF4 = OPRF(P-384, SHA-512)
- ID = 0x0002
- COMMIT = false
- Maximum security provided: 192 bits

## PP(OPRF5)

- OPRF5 = OPRF(P-521, SHA-512)
- ID = 0x0003
- COMMIT = false
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
of the two ways MUST re-justify that the extended protocol still
satisfies the security requirements in {{sec-reqs}}. Protocol extensions
MAY put forward new security guarantees if they are applicable.

The extensions MUST also conform with the extension framework policy as
set out in the architectural framework document. For example, this may
concern any potential impact on client anonymity that the extension may
introduce.

--- back

# Document contributors

- Alex Davidson (alex.davidson92@gmail.com)
- Sofía Celi (cherenkov@riseup.net)
- Christopher Wood (caw@heapingbits.net)
