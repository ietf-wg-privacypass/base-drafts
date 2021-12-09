---
title: "Privacy Pass Protocol Specification"
abbrev: PP integration
docname: draft-ietf-privacypass-integration-latest
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

This document specifies the necessary integration for building the
Privacy Pass protocol, supporting symmetric verification and public
metadata, on top of an existing oblivious pseudorandom function
protocol.

--- middle

# Introduction

The Privacy Pass protocol provides a privacy-preserving authorization
mechanism. In essence, the protocol allows clients to provide
cryptographic tokens that prove nothing other than that they have been
created by a given server in the past
{{I-D.ietf-privacypass-architecture}}.

This document provides the necessary integration for building the
authorization framework, based on existing constructions of oblivious
pseudorandom function protocols {{I-D.irtf-cfrg-voprf}}. Moreover, we
show how this integration allows public metadata to be introduced to the
protocol, that is agreed by both clients and servers.

This document DOES NOT cover the architectural framework required for
running and maintaining the Privacy Pass protocol in the Internet
setting. In addition, it DOES NOT cover the choices that are necessary
for ensuring that client privacy leaks do not occur. Both of these
considerations are covered in {{I-D.ietf-privacypass-architecture}}. In
addition, considerations of how to embed the protocol interactions in
the HTTP setting are considered in {{I-D.ietf-privacypass-http-api}}.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}.

The following terms are used throughout this document.

- Client: An entity that provides authorization tokens to services
  across the Internet, in return for authorization.
- Server: A service (also known as an Issuer) that issues Privacy Pass
  tokens to clients.
- Key: The secret key used by the server for authorizing client data.

We assume that all protocol messages are encoded into raw byte format
before being sent across the wire.

# Privacy Pass flow {#protocol-flow}

There are three phases in the protocol: the initialization phase, the
issuance phase, and the redemption phase. We construct each phase based
on the POPRF protocol construction detailed in {{I-D.irtf-cfrg-voprf}},
and all algorithms and data types are inherited as such. All
implementations MUST use the `OPRF(P-384, SHA-384)` ciphersuite.

## Initialization phase

The server samples a keypair and publishes a key configuration in a way
that clients can retrieve it. This configuration consists of the
server's public key and configuration information for the underlying
POPRF.

~~~
struct {
   uint16 suite;
   uint8 public_key[Ne];
} KeyConfig;
~~~

KeyConfig.suite corresponds to a POPRF ciphersuite from
{{I-D.irtf-cfrg-voprf, Section 4}}, and KeyConfig.public_key corresponds
to a serialized public key of length `Ne` bytes (denoted as a
`SerializedElement` in {{I-D.irtf-cfrg-voprf, Section 2}}). In

In order for higher-level applications to indicate which key
configuration is being used, a common identifier, such as
`id=SHA256(KeyConfig)`, should be used. Note that the ciphersuite that
is used is determined entirely by the choice of `suite` in the server
key configuration.

## Issuance phase

Let `info` be the agreed upon metadata between client and server, and
let `config` be the server's chosen key configuration.

First, a client configures its verifiable context using `config`:

~~~
client_context = SetupVerifiableClient(
                  config.suite, config.public_key
                 )
~~~

Likewise, the server creates its own context using `config` and the
corresponding private key `key`:

~~~
server_context = SetupVerifiableServer(
                  config.suite, key, config.public_key
                 )
~~~

The client then creates an issuance request for a random value `nonce`
as follows:

~~~
nonce = random(32)
blind, blindedElement = client_context.Blind(nonce)
~~~

The client then sends `blindedElement` to the server. The server, upon
receipt, evaluates the request:

~~~
evaluatedElement, proof = server_context.Evaluate(
                           key, config.public_key,
                           blindedElement, info
                          )
~~~

The server sends both `evaluatedElement` and `proof` to the client.
These are concatenated together. As the length of both is fixed, there
is no ambiguity in parsing the result.

The client then completes issuance as follows:

~~~
output = client_context.Finalize(
          nonce, blind, evaluatedElement, info
         )
~~~

This procedure may fail with an error (`VerifyError` or
`DeserializeError`), in which case the issuance is said to have failed.
The output of the issuance protocol is the concatenation of `nonce` and
`output`, denoted as `token`:

~~~
struct {
   uint8 nonce[32];
   uint8 output[Nh];
} Token;
~~~

where `Nh` is as defined in {{I-D.irtf-cfrg-voprf}}.

## Redemption phase

The client sends the `Token` to the server to verify locally. In
particular, the server verifies the `Token` as follows:

~~~
valid = server_context.VerifyFinalize(
         key, token.nonce, token.output, info
        )
~~~

Redemption is considered successful if `valid` is true.

--- back

# Security considerations

This document outlines how to instantiate the Privacy Pass protocol
based on the VOPRF defined in {{I-D.irtf-cfrg-voprf}}. All security
considerations described in the VOPRF document also apply in the Privacy
Pass use-case. Considerations related to broader privacy and security
concerns in a multi-client and multi-server setting are deferred to the
Architecture document {{I-D.ietf-privacypass-architecture}}.

# IANA considerations

Currently there are no IANA considerations associated with this
document.

# Acknowledgements

The authors of this document would like to acknowledge the helpful
feedback and discussions from Benjamin Schwartz, Joseph Salowey, Sofía
Celi, and Tara Whalen.

