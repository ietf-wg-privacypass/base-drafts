---
title: "Privacy Pass: the protocol"
abbrev: PP protocol
docname: draft-pp-protocol-latest
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
  DGSTV18:
    title: Privacy Pass, Bypassing Internet Challenges Anonymously
    target: https://www.degruyter.com/view/j/popets.2018.2018.issue-3/popets-2018-0026/popets-2018-0026.xml
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
  I-D.irtf-cfrg-voprf:
  PPEXT:
    title: Privacy Pass Browser Extension
    target: https://github.com/privacypass/challenge-bypass-extension
  PPSRV:
    title: Cloudflare Supports Privacy Pass
    target: https://blog.cloudflare.com/cloudflare-supports-privacy-pass/
    author:
      ins: N. Sullivan
      org: Cloudflare
  DSS:
    title: "FIPS PUB 186-4: Digital Signature Standard (DSS)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    author:
      -
        ins: Federal Information Processing Standards Publication
  keytrans:
    title: "Security Through Transparency"
    target: https://security.googleblog.com/2017/01/security-through-transparency.html
    authors:
      -
        ins: R. Hurst
        org: Google
      -
        ins: G. Belvin
        org: Google

--- abstract

This document specifies the Privacy Pass protocol for providing
client-authorization without providing the ability to link client interactions
together.

--- middle

# Introduction

A common problem on the internet is providing an effective mechanism for servers
to derive trust from the clients that it interacts with, without hampering the
accessibility of honest clients. Typically, this can be done by providing some
sort of authorization challenge to the client. A client providing a correct
solution can be provided with a cookie that it can present the next time it
interacts with the server. Resurfacing the cookie allows the server to see that
the client passed the authorization check in the past. This allows the server to
authorize the client again immediately.

In scenarios where clients need to identify themselves, the authorization
challenge usually takes the form of some sort of login procedure. In other
scenarios, the server may just want to verify that the client demonstrates some
particular facet of behavior (such as being human). Such cases may only require
a lightweight form of challenge (such as completing a CAPTCHA). Moreover,
providing a re-authentication token like a cookie provides the server with the
ability to link all of the client's browsing sessions that it witnesses. In
these situations, the client's online privacy is dramatically reduced.

The Privacy Pass protocol was initially introduced as a mechanism for
authorizing clients that had already been authorized in the past, without
compromizing their privacy {{DGSTV18}}. The protocol works by providing client's
with privacy-preserving re-authentication tokens for a particular server. The
tokens are "privacy-preserving" in the sense that they cannot be linked back to
the previous session where they were issued.

The Internet performance company Cloudflare has already implemented server-side
support for an initial version of the Privacy Pass protocol {{PPSRV}}, and
client-side implementations also exist {{PPEXT}}. More recently, a number of
applications have been built upon the protocol, or slight variants of it, see:
{{TRUST}}, {{OpenPrivacy}}, {{PrivateStorage}}.

The protocol uses a cryptographic primitive known as a verifiable oblivious
pseudorandom function (VOPRF) for implementing the authorization mechanism. The
VOPRF is implemented using elliptic curves and is currently in a separate
standardization process {{I-D.irtf-cfrg-voprf}}. The protocol is split into
three stages. The first two stages, initialisation and evaluation, are
essentially equivalent to the VOPRF setup and evaluation phases from
{{I-D.irtf-cfrg-voprf}}. The final stage, redemption, essentially amounts to
revealing the client's secret inputs in the VOPRF protocol. The security
(pseudorandomness) of the VOPRF protocol means that the client retains their
privacy even after revealing this data.

This document will lay out the generic description of the protocol based on the
VOPRF primitive. It will provide a number of parametrizations of the security
parameters associated with the protocol for establishing a secure VOPRF
instantiation, along with ciphersuites that match these instantiations. It will
also describe the structure of protocol messages, and the framework for
characterizing possible extensions to the protocol description.

## Preliminaries

### Terminology

The following terms are used throughout this document.

- Server: A service that provides access to a certain resource (typically
  denoted S)
- Client: An entity that seeks authorization from a server (typically denoted C)
- Key: Server VOPRF key
- Commitment: Alternative name for Server's public key.

### Protocol messages

We assume that all protocol messages in raw byte format before being sent. The
actual format of the messages before encoding will be determined by context
(e.g. as a JSON structure, or as a single elliptic curve point).

## Layout

TODO: layout

## Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in {{RFC2119}}.

# Privacy Pass functional API {#pp-api}

Before describing the protocol itself in {{overview}}, we describe the
underlying functions that are used in substantiating the protocol itself.
Instantiating this set of functions, along with meeting the security
requirements highlighted in {{requirements}}, provides an instantiation of the
wider protocol.

## Data structures {#pp-structs}

### ServerConfig {#pp-srv-cfg-struct}

The `ServerConfig` struct describes and maintains the underlying functionality
that is used by the server for instantiating the Privacy Pass functional API
({{pp-functions}}).

Fields:

- name:        String identifier for the config that is in use.
- ciphersuite: Internal ciphersuite that is used for instantiating the Privacy
               Pass functionality.
- key:         The private key used by the server (in byte format).
- pub_key:     The public key used by the server (in byte format).
- max_evals:   An integer value corresponding to the the maximum number of valid
               redemption tokens that the server will sanction in any given
               issuance session.

### ClientConfig {#pp-cli-cfg-struct}

The `ClientConfig` struct describes and maintains the underlying functionality
that is used by the client for instantiating the Privacy Pass functional API
({{pp-functions}}).

Fields:

- name:        String identifier for the config that is in use.
- ciphersuite: Internal ciphersuite that is used for instantiating the Privacy
               Pass functionality.
- pub_key:     The public key used by the server (in byte format).

### RedemptionToken {#pp-storage-struct}

The `RedemptionToken` struct contains the data associated required to generate
the client message in the redemption phase of the Privacy Pass protocol. This
data is generated in the issuance phase of the protocol.

Fields:

- data:   A byte array corresponding to the initial client input in PP_Generate.
- issued: A byte array corresponding to the server response after running
          PP_Issue.

## Functions {#pp-functions}

The following functions wrap the core of the functionality required in the
Privacy Pass protocol. For each of the descriptions, we essentially provide the
function signature, leaving the actual contents to be provided by specific
instantiations or extensions.

### PP_Server_Setup

Run by the Privacy Pass server to generate its configuration for use in the
Privacy Pass protocol. Th key-pair used in the server configuration are
generated fresh on each invocation.

Inputs:

- id:  A string identifier corresponding to a valid Privacy Pass server
       configuration.

Outputs:

- cfg: A `ServerConfig` struct ({{pp-srv-cfg-struct}}).

Possible errors:

- ERR_UNSUPPORTED_CONFIG ({{errors}})

### PP_Client_Setup

Run by the Privacy Pass client to generate its configuration for use in the
Privacy Pass protocol. The public key in the client configuration is set to be
the server public key that is used as an input.

Inputs:

- id:      A string identifier corresponding to a valid Privacy Pass server
           configuration.
- pub_key: A byte array corresponding to the public key of a Privacy Pass
           server.

Outputs:

- cfg:     A `ClientConfig` struct ({{pp-cli-cfg-struct}}).

Possible errors:

- ERR_UNSUPPORTED_CONFIG ({{errors}})

### PP_Generate

A function run by the client to generate the initial data that is used as its
input in the Privacy Pass protocol.

Inputs:

- cli_cfg:     A `ClientConfig` struct.
- m:           An integer value corresponding to the number of Privacy Pass tokens to
               generate.

Outputs:

- client_data: An array of byte arrays. This data is kept private until the
               redemption phase of the protocol.
- issue_data:  An array of byte arrays, sent in the client's message during the
               issuance phase.
- gen_data:    An byte array of arbitrary length that corresponds to private data
               stored by the client, following on from the generation process.

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

Run by the client when processing the server response in the issuance phase of
the protocol.

Inputs:

- cli_cfg:  A `ClientConfig` struct.
- evals:    An array of byte arrays, received from the server.
- proof:    A byte array, also received from the server.
- gen_data: A byte array of arbitrary length, corresponding to the client's
            secret data output by PP_Generate.

Outputs:

- tokens:   An array of byte-encoded `RedemptionToken` structs.

Possible errors:

- ERR_PROOF_VALIDATION ({{errors}})

### PP_Redeem

Run by the client in the redemption phase of the protocol to generate the
client's message.

Inputs:

- cli_cfg: A `ClientConfig` struct.
- token:   A byte-encoded `RedemptionToken` struct.
- aux:     A byte array corresponding to arbitrary auxiliary data.

Outputs:

- tag:     A byte array that is used as part of the client's message in the
           redemption phase of the protocol.

### PP_Verify

Run by the server in the redemption phase of the protocol. Determines whether
the data sent by the client is valid.

Inputs:

- srv_cfg:     A `ServerConfig` struct.
- client_data: A byte array corresponding to the client-generated input data
               output by PP_Issue.
- tag:         A byte array corresponding to the client-generated tag from the output
               of PP_Redeem.

Outputs:

- b:           A boolean value corresponding to whether the data verifies correctly, or
               not.

## Error types {#errors}

- ERR_UNSUPPORTED_CONFIG: Error occurred when trying to recover configuration
  with unknown identifier
- ERR_MAX_EVALS: Client attempted to invoke server issuance with number of
  inputs that is larger than server-specified max_evals value.
- ERR_PROOF_VALIDATION: Client unable to verify proof that is part of the server
  response.
- ERR_DOUBLE_SPEND: Indicates that a client has attempted to redeem a token
  that has already been used for authorization.

# Generalized protocol overview {#overview}

In this document, we will be assuming that a client (C) is attempting to
authenticate itself in a lightweight manner to a server (S). The authorization
mechanism should not reveal to the server anything about the client; in
addition, the client should not be able to forge valid credentials in situations
where it does not possess any.

In this section, we will give a broad overview of how the Privacy Pass protocol
functions in achieving these goals. The generic protocol can be split into three
phases: initialisation, issuance and redemption. To construct these protocol
phases, we develop a new API that is tied to the Privacy Pass functionality. We
show later ({{voprf-protocol}}) that this API can be facilitated using an
underlying VOPRF protocol. We provide this extra layer of abstraction to allow
building extensions into the Privacy Pass protocol that go beyond what is
specified in {{OPRF}}.

## Key initialisation phase

In the initialisation phase, the server generates the configuration that it will
use for future instantiations of the protocol. It MUST also use this phase to
broadcast the configuration that it uses, along with the public key that it
generates.

In situations where the number of clients are small, it could do this by sending
the data to the client directly. But in situations where there is a large number
of clients, the best way of doing is likely to be via posting this information
to a public bulletin board.

We give a diagrammatic representation of the initialisation phase below.

~~~
    C(cfgs)                                                      S(cfg_id)
    ----------------------------------------------------------------------
                                            s_cfg = PP_Server_Setup(cfg_id)
                                            pk = s_cfg.pub_key

                            (cfg_id,pk)
                       <-------------------

    c_cfg = PP_Client_Setup(cfg_id,pk)
    cfgs.set(S.id,c_cfg)
~~~

In the following (and as above), we will assume that the server `S` is uniquely
identifiable by an internal attribute `id`. We assume the same internal
attribute exists for the public key `s_cfg.pub_key`. This can be obtained, for
example, by hashing the contents of the object -- either the name or underlying
contained bytes -- using a collision-resistant hash function that SHA256.

Note that the client stores their own configuration in the map `cfgs` for future
Privacy Pass interactions with `S`.

## Issuance phase

The issuance phase allows the client to construct `RedemptionToken` resulting
from an interaction with a server `S` that it has previously interacted with. We
give a diagrammatic overview of the protocol below.

~~~
    C(cfgs,store,m)                                             S(s_cfg)
    ----------------------------------------------------------------------
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

In the diagram above, the client knows the VOPRF group configuration supported
by the server when it retrieves in the first step. It uses this information to
correctly perform group operations before sending the first message.

## Redemption phase

The redemption phase allows the client to reauthenticate to the server, using
data that it has received from a previous issuance phase. We lay out the
security requirements in {{requirements}} that establish that the client
redemption data is not linkable to any given issuance session.

~~~
    C(cfgs,store,aux)                                         S(s_cfg,ds_idx)
    ----------------------------------------------------------------------
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

To protect against clients that attempt to spend a value x more than once, the
server uses an index, `ds_idx`, to collect valid inputs and then check against
in future protocols. Since this store needs to only be optimized for storage and
querying, a structure such as a Bloom filter suffices. Importantly, the server
MUST only eject this storage after a key rotation occurs since all previous
client data will be rendered obsolete after such an event.

## Handling errors

It is possible for the API functions from {{pp-functions}} ever return one of
the errors indicated in {{errors}} rather than their expected value. In these
cases, we assume that the protocol execution panics with the value of the error.

If the panic occurs during the server's operations, then the server returns an
error response indicating the error that occurred.

# Security considerations {#security}

We present a number of security considerations that prevent a malicious actors
from abusing the protocol.

## Requirements {#requirements}

TODO: write security requirements for protocol in {{overview}}.

## Double-spend protection

All issuing server should implement a robust storage-query mechanism for
checking that tokens sent by clients have not been spent before. Such tokens
only need to be checked for each issuer individually. But all issuers must
perform global double-spend checks to avoid clients from exploiting the
possibility of spending tokens more than once against distributed token checking
systems. For the same reason, the global data storage must have quick update
times. While an update is occurring it may be possible for a malicious client to
spend a token more than once.

## Key rotation

We highlighted previously that short key-cycles can be used to reduce client
privacy. However, regular key rotations are still recommended to maintain good
server key hygiene. The key material that we consider to be important are:

- the VOPRF key;
- the signing key used to sign commitment information;
- the signing key used to sign SRRs in the SIAV configuration.

In summary, our recommendations are that VOPRF keys are rotated from anywhere
between a month and a single year. With an active user-base, a month gives a
fairly large window for clients to participate in the Privacy Pass protocol and
thus enjoy the privacy guarantees of being part of a larger group. The low
ceiling of a year prevents a key compromise from being too destructive. If a
server realizes that a key compromise has occurred then the server should revoke
the previous key in the trusted registry and specify a new key to be used.

For the two signing keys, these should both be well-known keys associated with
the issuer (TODO: where should they be stored?). Issuers may choose to use the
same key for both signing purposes. The rotation schedules for these keys can be
much longer, if necessary.

## Token exhaustion

When a client holds tokens for an issuer, it is possible for any verifier to
invoke that client to redeem tokens for that issuer. This can lead to an attack
where a malicious verifier can force a client to spend all of their tokens for a
given issuer. To prevent this from happening, methods should be put into place
to prevent many tokens from being redeemed at once.

For example, it may be possible to cache a redemption for the entity that is
invoking a token redemption. In SISV/SIFV, if the verifier requests more tokens
then the client simply returns the cached token that it returned previously.
This could also be handled by simply not redeeming any tokens for the entity if
a redemption had already occurred in a given time window.

In SIAV, the client instead caches the SRR that it received in the asynchronous
redemption exchange with the issuer. If the same verifier attempts another trust
attestation request, then the client simply returns the cached SRR. The SRRs can
be revoked by the issuer, if need be, by providing an expiry date or by
signaling that records from a particular window need to be refreshed.

# VOPRF instantiation {#voprf-protocol}

TODO: write VOPRF instantiation of API in {{pp-api}}.

# Ciphersuites & security settings {#ciphersuites}

We provide a summary of the parameters that we use in the Privacy Pass protocol.
These parameters are informed by both privacy and security considerations that
are highlighted in {{privacy}} and {{security}}, respectively. These parameters
are intended as a single reference point for implementers when implementing the
protocol.

Firstly, let U be the total number of users, I be the total number of issuers.
Assuming that each user accept tokens from a uniform sampling of all the
possible issuers, as a worst-case analysis, this segregates users into a total
of 2^I buckets. As such, we see an exponential reduction in the size of the
anonymity set for any given user. This allows us to specify the privacy
constraints of the protocol below, relative to the setting of A.

| parameter | value |
|---|---|
| Minimum anonymity set size (A) | 5000 |
| Recommended key lifetime (L) | 1 - 6 months |
| Recommended key rotation frequency (F) | L/2 |
| Maximum allowed issuers (I) | log_2(U/A)-1 |
| Maximum active issuance keys | 1 |
| Maximum active redemption keys | 2 |
| Minimum security parameter | 196 bits |

## Justification

We make the following assumptions in these parameter choices.

- Inferring the identity of a user in a 5000-strong anonymity set is difficult
- After 2 weeks, all clients in a system will have rotated to the new key

The maximum choice of I is based on the equation 1/2 * U/2^I = A. This is
because I issuers lead to 2^I segregations of the total user-base U. By reducing
I we limit the possibility of performing the attacks mentioned in
{{segregation}}.

We must also account for each user holding issued data for more then one
possible active keys. While this may also be a vector for monitoring the access
patterns of clients, it is likely to unavoidable that clients hold valid
issuance data for the previous key epoch. This also means that the server can
continue to verify redemption data for a previously used key. This makes the
rotation period much smoother for clients.

For privacy reasons, it is recommended that key epochs are chosen that limit
clients to holding issuance data for a maximum of two keys. By choosing F = L/2
then the minimum value of F is 1/2 a month, since the minimum recommended value
of L is 1 month. Therefore, by the initial assumption, then all users should
only have access to only two keys at any given time. This reduces the anonymity
set by another half at most.

Finally, the minimum security parameter size is related to the cryptographic
security offered by the group instantiation that is chosen. For example, if we
use an elliptic curve over a 256-bit prime field, then the actual group
instantiation offers 128 bits of security (or a security parameter of size 128
bits). However, as noted in {{OPRF}}, OPRF protocols reduce the effective
security of the group by log_2(M) where M is the number of queries. As such, we
choose the minimum size of the security parameter to be 196 bits, so that it is
difficult for a malicious client to exploit this.

## Example parameterization

Using the specification above, we can give some example parameterizations. For
example, the current Privacy Pass browser extension {{PPEXT}} has over 150,000
active users (from Chrome and Firefox). Then log_2(U/A) is approximately 5 and
so the maximum value of I should be 4.

If the value of U is much bigger (e.g. 5 million) then this would permit I =
log_2(5000000/5000)-1 = 8 issuers.