---
title: "Privacy Pass: the protocol"
abbrev: PP protocol
docname: draft-pp-protocol-00
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
    org: Cloudflare Portugal
    street: Largo Rafael Bordalo Pinheiro 29
    city: Lisbon
    country: Portugal
    email: alex.davidson92@gmail.com

normative:
  RFC2119:
  I-D.irtf-cfrg-voprf:
  I-D.irtf-cfrg-hash-to-curve:
  TRUST:
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
  PPEXT:
    title: Privacy Pass Browser Extension
    target: https://github.com/privacypass/challenge-bypass-extension
  PPSRV:
    title: Cloudflare Supports Privacy Pass
    target: https://blog.cloudflare.com/cloudflare-supports-privacy-pass/
    author:
      ins: N. Sullivan
      org: Cloudflare

--- abstract

This document specifies the Privacy Pass protocol for providing
client-authorization without providing the ability to link client
interactions together.

--- middle

# Introduction

A common problem on the internet is providing an effective mechanism for
servers to derive trust from the clients that it interacts with, without
hampering the accessibility of honest clients. Typically, this can be
done by providing some sort of authorization challenge to the client. A
client providing a correct solution can be provided with a cookie that
it can present the next time it interacts with the server. Resurfacing
the cookie allows the server to see that the client passed the
authorization check in the past. This allows the server to authorize the
client again immediately.

In scenarios where clients need to identify themselves, the
authorization challenge usually takes the form of some sort of login
procedure. In other scenarios, the server may just want to verify that
the client demonstrates some particular facet of behavior (such as being
human). Such cases may only require a lightweight form of challenge
(such as completing a CAPTCHA). Moreover, providing a re-authentication
token like a cookie provides the server with the ability to link all of
the client's browsing sessions that it witnesses. In these situations,
the client's online privacy is dramatically reduced.

The Privacy Pass protocol was initially introduced as a mechanism for
authorizing clients that had already been authorized in the past,
without compromizing their privacy {{DGSTV18}}. The protocol works by
providing client's with privacy-preserving re-authentication tokens for
a particular server. The tokens are "privacy-preserving" in the sense
that they cannot be linked back to the previous session where they were
issued.

The Internet performance company Cloudflare has already implemented
server-side support for an initial version of the Privacy Pass protocol
{{PPSRV}}, and client-side implementations also exist {{PPEXT}}. More
recently, a number of applications have been built upon the protocol, or
slight variants of it, see: {{TRUST}}, {{OpenPrivacy}},
{{PrivateStorage}}.

The protocol uses a cryptographic primitive known as a verifiable
oblivious pseudorandom function (VOPRF) for implementing the
authorization mechanism. The VOPRF is implemented using elliptic curves
and is currently in a separate standardization process
{{I-D.irtf-cfrg-voprf}}. The protocol is split into three stages. The
first two stages, initialisation and evaluation, are essentially
equivalent to the VOPRF setup and evaluation phases from
{{I-D.irtf-cfrg-voprf}}. The final stage, redemption, essentially
amounts to revealing the client's secret inputs in the VOPRF protocol.
The security (pseudorandomness) of the VOPRF protocol means that the
client retains their privacy even after revealing this data.

This document will lay out the generic description of the protocol based
on the VOPRF primitive. It will provide a number of parametrizations of
the security parameters associated with the protocol for establishing a
secure VOPRF instantiation, along with ciphersuites that match these
instantiations. It will also describe the structure of protocol
messages, and the framework for characterizing possible extensions to
the protocol description.

This document DOES NOT cover the architectural framework required for
running and maintaining the Privacy Pass protocol. In addition, it DOES
NOT cover the choices that are necessary for ensuring that client
privacy leaks do not occur.

## Preliminaries

### Terminology

The following terms are used throughout this document.

- Server: A service that provides access to a certain resource
  (typically denoted S)
- Client: An entity that seeks authorization from a server (typically
  denoted C)
- Key: Server VOPRF key
- Commitment: Alternative name for Server's public key.

### Protocol messages

We assume that all protocol messages in raw byte format before being
sent. The actual format of the messages before encoding will be
determined by context (e.g. as a JSON structure, or as a single elliptic
curve point).

## Layout

TODO: layout

## Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}.

# Privacy Pass functional API {#pp-api}

Before describing the protocol itself in {{overview}}, we describe the
underlying functions that are used in substantiating the protocol
itself. Instantiating this set of functions, along with meeting the
security requirements highlighted in {{sec-requirements}}, provides an
instantiation of the wider protocol.

## Data structures {#pp-structs}

### ServerConfig {#pp-srv-cfg-struct}

The `ServerConfig` struct describes and maintains the underlying
functionality that is used by the server for instantiating the Privacy
Pass functional API ({{pp-functions}}).

Fields:

- ciphersuite: Internal ciphersuite that is used for instantiating the
               Privacy Pass functionality.
- key:         The private key used by the server (in byte format).
- pub_key:     The public key used by the server (in byte format).
- max_evals:   An integer value corresponding to the the maximum number
               of valid redemption tokens that the server will sanction
               in any given issuance session.

### ClientConfig {#pp-cli-cfg-struct}

The `ClientConfig` struct describes and maintains the underlying
functionality that is used by the client for instantiating the Privacy
Pass functional API ({{pp-functions}}).

Fields:

- ciphersuite: Internal ciphersuite that is used for instantiating the
               Privacy Pass functionality.
- pub_key:     The public key used by the server (in byte format).

### RedemptionToken {#pp-storage-struct}

The `RedemptionToken` struct contains the data associated required to
generate the client message in the redemption phase of the Privacy Pass
protocol. This data is generated in the issuance phase of the protocol.

Fields:

- data:   A byte array corresponding to the initial client input in
  PP_Generate.
- issued: A byte array corresponding to the server response after
          running PP_Issue.

## API functions {#pp-functions}

The following functions wrap the core of the functionality required in
the Privacy Pass protocol. For each of the descriptions, we essentially
provide the function signature, leaving the actual contents to be
provided by specific instantiations or extensions.

### PP_Server_Setup

Run by the Privacy Pass server to generate its configuration for use in
the Privacy Pass protocol. Th key-pair used in the server configuration
are generated fresh on each invocation.

Inputs:

- id:  A string identifier corresponding to a valid Privacy Pass server
       configuration.

Outputs:

- cfg: A `ServerConfig` struct ({{pp-srv-cfg-struct}}).

Possible errors:

- ERR_UNSUPPORTED_CONFIG ({{errors}})

### PP_Client_Setup

Run by the Privacy Pass client to generate its configuration for use in
the Privacy Pass protocol. The public key in the client configuration is
set to be the server public key that is used as an input.

Inputs:

- id:      A string identifier corresponding to a valid Privacy Pass
           server configuration.
- pub_key: A byte array corresponding to the public key of a Privacy
           Pass server.

Outputs:

- cfg:     A `ClientConfig` struct ({{pp-cli-cfg-struct}}).

Possible errors:

- ERR_UNSUPPORTED_CONFIG ({{errors}})

### PP_Generate

A function run by the client to generate the initial data that is used
as its input in the Privacy Pass protocol.

Inputs:

- cli_cfg:     A `ClientConfig` struct.
- m:           An integer value corresponding to the number of Privacy
               Pass tokens to generate.

Outputs:

- client_data: An array of byte arrays. This data is kept private until
               the redemption phase of the protocol.
- issue_data:  An array of byte arrays, sent in the client's message
               during the issuance phase.
- gen_data:    An byte array of arbitrary length that corresponds to
               private data stored by the client, following on from the
               generation process.

### PP_Issue

Inputs:

- srv_cfg:      A `ServerConfig` struct.
- client_data:  An array of byte arrays.

Outputs:

- evals: An array of byte arrays.
- proof: A byte array.

Possible errors:

- ERR_MAX_EVALS ({{errors}})

### PP_Process

Run by the client when processing the server response in the issuance
phase of the protocol.

Inputs:

- cli_cfg:  A `ClientConfig` struct.
- evals:    An array of byte arrays, received from the server.
- proof:    A byte array, also received from the server.
- gen_data: A byte array of arbitrary length, corresponding to the
            client's secret data output by PP_Generate.

Outputs:

- tokens:   An array of byte-encoded `RedemptionToken` structs.

Possible errors:

- ERR_PROOF_VALIDATION ({{errors}})

### PP_Redeem

Run by the client in the redemption phase of the protocol to generate
the client's message.

Inputs:

- cli_cfg: A `ClientConfig` struct.
- token:   A byte-encoded `RedemptionToken` struct.
- aux:     A byte array corresponding to arbitrary auxiliary data.

Outputs:

- tag:     A byte array that is used as part of the client's message in
           the redemption phase of the protocol.

### PP_Verify

Run by the server in the redemption phase of the protocol. Determines
whether the data sent by the client is valid.

Inputs:

- srv_cfg:     A `ServerConfig` struct.
- client_data: A byte array corresponding to the client-generated input
               data output by PP_Issue.
- tag:         A byte array corresponding to the client-generated tag
               from the output of PP_Redeem.

Outputs:

- b:           A boolean value corresponding to whether the data
               verifies correctly, or not.

## Error types {#errors}

- ERR_UNSUPPORTED_CONFIG: Error occurred when trying to recover
  configuration with unknown identifier
- ERR_MAX_EVALS: Client attempted to invoke server issuance with number
  of inputs that is larger than server-specified max_evals value.
- ERR_PROOF_VALIDATION: Client unable to verify proof that is part of
  the server response.
- ERR_DOUBLE_SPEND: Indicates that a client has attempted to redeem a
  token that has already been used for authorization.

# Generalized protocol overview {#overview}

In this document, we will be assuming that a client (C) is attempting to
authenticate itself in a lightweight manner to a server (S). The
authorization mechanism should not reveal to the server anything about
the client; in addition, the client should not be able to forge valid
credentials in situations where it does not possess any.

In this section, we will give a broad overview of how the Privacy Pass
protocol functions in achieving these goals. The generic protocol can be
split into three phases: initialisation, issuance and redemption. To
construct these protocol phases, we develop a new API that is tied to
the Privacy Pass functionality. We show later ({{voprf-protocol}}) that
this API can be facilitated using an underlying VOPRF protocol. We
provide this extra layer of abstraction to allow building extensions
into the Privacy Pass protocol that go beyond what is specified in
{{I-D.irtf-cfrg-voprf}}.

## Key initialisation phase

In the initialisation phase, the server generates the configuration that
it will use for future instantiations of the protocol. It MUST also use
this phase to broadcast the configuration that it uses, along with the
public key that it generates.

In situations where the number of clients are small, it could do this by
sending the data to the client directly. But in situations where there
is a large number of clients, the best way of doing is likely to be via
posting this information to a public bulletin board.

We give a diagrammatic representation of the initialisation phase below.

~~~
  C(cfgs)                                                   S(cfg_id)
  -------------------------------------------------------------------
                                      s_cfg = PP_Server_Setup(cfg_id)
                                      pk = s_cfg.pub_key

                          (cfg_id,pk)
                      <-------------------

  c_cfg = PP_Client_Setup(cfg_id,pk)
  cfgs.set(S.id,c_cfg)
~~~

In the following (and as above), we will assume that the server `S` is
uniquely identifiable by an internal attribute `id`. We assume the same
internal attribute exists for the public key `s_cfg.pub_key`. This can
be obtained, for example, by hashing the contents of the object --
either the name or underlying contained bytes -- using a
collision-resistant hash function that SHA256.

Note that the client stores their own configuration in the map `cfgs`
for future Privacy Pass interactions with `S`.

## Issuance phase

The issuance phase allows the client to construct `RedemptionToken`
resulting from an interaction with a server `S` that it has previously
interacted with. We give a diagrammatic overview of the protocol below.

~~~
  C(cfgs,store,m)                                            S(s_cfg)
  -------------------------------------------------------------------
                             S.id
                      <------------------

  c_cfg = cfgs.get(S.id)
  (c_dat,i_dat,g_dat) = PP_Generate(c_cfg,m)

                              i_dat
                      ------------------->

                                  (evs,proof) = PP_Issue(s_cfg,c_dat)

                           (evs,proof)
                      <-------------------

  tokens = PP_Process(c_cfg,evs,proof,g_dat)
  store[S.id].push(tokens)
~~~

In the diagram above, the client knows the VOPRF group configuration
supported by the server when it retrieves in the first step. It uses
this information to correctly perform group operations before sending
the first message.

## Redemption phase

The redemption phase allows the client to reauthenticate to the server,
using data that it has received from a previous issuance phase. We lay
out the security requirements in {{sec-requirements}} that establish
that the client redemption data is not linkable to any given issuance
session.

~~~
  C(cfgs,store,aux)                                   S(s_cfg,ds_idx)
  -------------------------------------------------------------------
                               S.id
                        <------------------

  c_cfg = cfgs.get(S.id)
  token = store[S.id].pop()
  tag = PP_Redeem(c_cfg,token,aux)
  data = token.data

                             (data,tag)
                        ------------------>

                                      if (ds_idx.includes(data)) {
                                        panic(ERR_DOUBLE_SPEND)
                                      }
                                      b = PP_Verify(srv_cfg,data,tag)
                                      if (b) {
                                        ds_idx.push(data)
                                      }
                                 b
                        <------------------
  Output b
~~~

### Double-spend protection

To protect against clients that attempt to spend a value x more than
once, the server uses an index, `ds_idx`, to collect valid inputs and
then check against in future protocols. Since this store needs to only
be optimized for storage and querying, a structure such as a Bloom
filter suffices. Importantly, the server MUST only eject this storage
after a key rotation occurs since all previous client data will be
rendered obsolete after such an event.

## Handling errors

It is possible for the API functions from {{pp-functions}} to return one
of the errors indicated in {{errors}} rather than their expected value.
In these cases, we assume that the protocol execution panics with the
value of the error.

If the panic occurs during the server's operations, then the server
returns an error response indicating the error that occurred.

# Security considerations {#security}

We discuss the security requirements that are necessary to uphold when
instantiating the Privacy Pass protocol.

## Requirements {#sec-requirements}

We first discuss the security requirements of `unlinkability`, and
`unforgeability`. Since these are cryptographic security requirements we
discuss them with respect to a polynomial-time algorithm known as the
adversary that is looking to subvert the security guarantee. More
details on both security requirements can be found in {{DGSTV18}} and
{{KLOR20}}.

### Unlinkability {#unlinkability}

Informally, the `unlinkability` requirement states that it is impossible
for an adversarial server to link the client's message in a redemption
session, to any previous issuance session that it has encountered.

Formally speaking the security model is the following:

- The adversary runs PP_Server_Setup and generates a key-pair `(k, pk)`.
- The adversary specifies a number `Q` of issuance phases to initiate,
  where each phase `i in 1..Q` consists of `m_i` server evaluations.
- The adversary runs PP_Eval using the key-pair that it generated on
  each of the client messages in the issuance phase.
- When the adversary wants it stops the issuance phase, and a random
  number `l` is picked from `1..Q`.
- A redemption phase is initiated with a single token with index `i`
  randomly sampled from `1..m_i`.
- The adversary guesses an index `l_guess` corresponding to the index of
  the issuance phase that it believes the redemption token was received
  in.
- The adversary succeeds if `l == l_guess`.

The security requirement is that the adversary has only a negligible
probability of success greater than `1/Q`.

### One-more unforgeability {#unforgeability}

The one-more unforgeability requirement states that it is hard for any
adversarial client that has received `m` valid tokens from a server to
redeem `m+1` of them. In essence, this requirement prevents a malicious
client from being able to forge valid tokens based on the server
responses that it sees.

The security model takes the following form:

- A server is created that runs PP_Server_Setup and broadcasts `pk`.
- The adversary runs PP_Client_Setup on the server public key `pk`.
- The adversary specifies a number `Q` of issuance phases to initiate
  with the server, where each phase `i in 1..Q` consists of `m_i` server
  evaluations. Let `m = sum(m_i)` where `i in 1..Q`.
- The client receives Q responses, where the ith response contains `m_i`
  individual tokens.
- The adversary initiates `m_adv` redemption sessions with the server
  and the server verifies that the sessions are successful (return
  true). The adversary succeeds in `m_succ =< m_adv` redemption
  sessions.
- The adversary succeeds if `m_succ > m`.

The security requirement is that the adversarial client has only a
negligible probability of succeeding.

Note that {{KLOR20}} strengthens the capabilities of the adversary, in
comparison to the original work of {{DGSTV18}}. In {{KLOR20}}, the
adversary is provided with oracle access that allows it to verify that
the server responses in the issuance phase are valid.

### Double-spend protection

All issuing server should implement a robust storage-query mechanism for
checking that tokens sent by clients have not been spent before. Such
tokens only need to be checked for each issuer individually. But all
issuers must perform global double-spend checks to avoid clients from
exploiting the possibility of spending tokens more than once against
distributed token checking systems. For the same reason, the global data
storage must have quick update times. While an update is occurring it
may be possible for a malicious client to spend a token more than once.

# VOPRF instantiation {#voprf-protocol}

In this section, we show how to instantiate the functional API in
{{pp-api}} with the VOPRF protocol described in {{I-D.irtf-cfrg-voprf}}.
Moreover, we show that this protocol satisfies the security requirements
laid out in {{sec-requirements}}, based on the security proofs provided
in {{DGSTV18}}.

## VOPRF conventions

The VOPRF ciphersuite ({{I-D.irtf-cfrg-voprf}}; section TODO) that is
used determines the member functions and prime-order group used by the
protocol. We detail a number of specific conventions here that we use
for interacting with the specific ciphersuite.

### Ciphersuites

Let VOPRF_* denote a generic VOPRF API function as detailed in
{{I-D.irtf-cfrg-voprf}} (Section TODO), and let `ciph` denote the
ciphersuite that is used for instantiating the VOPRF. In this
document, we explicitly write `ciph.VOPRF_*` to show that VOPRF_* is
explicitly evaluated with respect to `ciph`.

In addition, we define the following member functions associated with
the ciphersuite.

- `recover_ciphersuite_from_id(id)`: Takes a string identifier `id` as
  input, and outputs a VOPRF ciphersuite.
- `group()`: Returns the prime-order group associated with the
  ciphersuite.
- `H1()`: The function `H1()` defined in {{I-D.irtf-cfrg-voprf}}
  (Section TODO). This function allows deterministically mapping
  arbitrary bytes to a random element of the group. In the elliptic
  curve setting, this is achieved using the functions defined in
  {{I-D.irtf-cfrg-hash-to-curve}}.

### Prime-order group conventions

We detail a few functions that are required of the prime-order group
`GG` used by the VOPRF in {{I-D.irtf-cfrg-voprf}}.

Let `p` be the order of the Galois field `GF(p)` associated with the
group `GG`. We expose the following functions associated with `GG`.

- `GG.generator()`: Returns the fixed generator associated with the
  group `GG`.
- `GG.scalar_field()`: Provides access to the field `GF(p)`.
- `GG.scalar_field().random()`: Samples a scalar uniformly at random
  from GF(p). This can be done by sampling a random sequence of bytes
  that produce a scalar `r`, where `r < p` is satisfied (via
  rejection-sampling).

We also use the following functions for transitioning between different
data types.

- `as_bytes()`: For a scalar element of `GG.scalar_field()`, or an
  element of `GG`; the `as_bytes()` functions serializes the element
  into bytes and returns this array as output.
- `as_scalar()`: Interprets a sequence of bytes as a scalar value in
  `GG.scalar_field()`. For an array of byte arrays, we define the
  function `as_scalars()` to individually deserialize each of the
  individual byte arrays into a scalar and output a new array containing
  each scalar value.
- `as_element()`: Interprets a sequence of bytes as a group element in
  `GG`. For an array of byte arrays, we define the function
  `as_elements()` to individually deserialize each of the individual
  byte arrays into a group element and output a new array containing
  each scalar value.

## API instantiation {#voprf-api}

For the explicit signatures of each of the functions, refer to
{{pp-functions}}.

### PP_Server_Setup

~~~
1. ciph = recover_ciphersuite_from_id(id)
2. if ciph == null: panic(ERR_UNSUPPORTED_CONFIG)
3. (k,Y,GG) = ciph.VOPRF_Setup()
4. key = k.as_bytes()
5. pub_key = Y.as_bytes()
6. cfg = ServerConfig {
            ciphersuite: ciph,
            key: key,
            pub_key: pub_key,
            max_evals: max_evals
        }
7. Output cfg
~~~

### PP_Client_Setup

~~~
1. ciph = recover_ciphersuite_from_id(id)
2. if ciph == null: panic(ERR_UNSUPPORTED_CONFIG)
3. cfg = ClientConfig { ciphersuite: ciph, pub_key: pub_key }
4. Output cfg
~~~

### PP_Generate

~~~
1. ciph = cli_cfg.ciphersuite
2. GG = ciph.group()
3. c_data = []
4. i_data = []
5. g_data = []
6. for i in 0..m:
       1. c_data[i] = GG.scalar_field().random().as_bytes()
7. (blinds,groupElems) = ciph.VOPRF_Blind(i_data)
8. for i in 0..m:
       1. i_data[i] = groupElems[i].as_bytes()
       2. g_data[i] = blinds[i].as_bytes()
9. Output (c_data,i_data,g_data)
~~~

### PP_Issue

~~~
1. ciph = srv_cfg.ciphersuite
2. GG = ciph.group()
3. m = i_data.length
4. if m > max_evals: panic(ERR_MAX_EVALS)
5. G = GG.generator()
6. elts = i_data.as_elements();
7. Z,D = ciph.VOPRF_Eval(key.as_scalar(),G,pub_key.as_element(),elts)
8. evals = []
9. for i in 0..m: evals[i] = Z[i].as_bytes();
10. proof = D.as_bytes()
11. Output (evals, proof)
~~~

### PP_Process

~~~
1. ciph = cli_cfg.ciphersuite
2. GG = ciph.group()
3. G = GG.generator()
4. pk = cli_cfg.pub_key.as_element()
5. M = i_data.as_elements()
6. Z = evals.as_elements()
7. r = g_data.as_scalars()
8. N = ciph.VOPRF_Unblind(G, pk, M, Z, r, proof)
9. if N == "error": panic(ERR_PROOF_VALIDATION)
10. tokens = []
11. for i in 0..m:
        1. issued = N[i].as_bytes()
        2. rt = RedemptionToken { data: c_data[i], issued: issued }
        3. tokens[i] = rt
12. Output tokens
~~~

### PP_Redeem

~~~
1. ciph = cli_cfg.ciphersuite
2. GG = ciph.group()
3. t = ciph.VOPRF_Finalize(token.data,token.issued.as_element(),aux)
4. Output t
~~~

### PP_Verify

~~~
1. ciph = cli_cfg.ciphersuite
2. GG = ciph.group()
3. key = srv_cfg.key
4. T = ciph.H1(x)
5. N' = GG.OPRF_Eval(key, T)
6. tag' = GG.OPRF_Finalize(x,N',aux)
7. Output (tag == tag')
~~~

Note: we use the OPRF_* API functions rather than VOPRF_*, as we do not
need to recompute the data that is used for producing verifiable outputs
at this stage.

## Security justification

The protocol that we devise in {{overview}}, coupled with the API
instantiation in {{voprf-api}}, are equivalent to the protocol
description in {{DGSTV18}}. In {{DGSTV18}}, it is proven that this
protocol satisfies the security requirements of unlinkability
({{unlinkability}}) and unforgeability ({{unforgeability}}).

The unlinkability property follows unconditionally as the view of the
adversary in the redemption phase is distributed independently of the
issuance phase. The unforgeability property follows from the one-more
decryption security of the ElGamal cryptosystem {{DGSTV18}}. In
{{KLOR20}} it is also proven that this protocol satisfies the stronger
notion of unforgeability, where the adversary is granted a verification
oracle, under the chosen-target Diffie-Hellman assumption.

Note that the existing security proofs do not leverage the VOPRF
primitive as a black-box in the security reductions, instead relying on
the underlying operations in a non-black-box manner. Hence, an explicit
reduction from the generic VOPRF primitive to the Privacy Pass protocol
would strengthen these security guarantees.

# Ciphersuites & security settings {#pp-ciphersuites}

We provide a summary of the parameters that we use in the Privacy Pass
protocol. These parameters are informed by both privacy and security
considerations that are highlighted in {{security}}, respectively. These
parameters are intended as a single reference point for implementers
when implementing the protocol for ensuring cryptographic security.

| parameter | value |
|---|---|
| Minimum security parameter | 196 bits |
