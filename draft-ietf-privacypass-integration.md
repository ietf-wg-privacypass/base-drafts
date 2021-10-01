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
authorized by a given server in the past
{{I-D.ietf-privacypass-architecture}}.

This document provides the necessary integration for building the
authorization framework, based on existing constructions of oblivious
pseudorandom function protocols {{I-D.irtf-cfrg-voprf}}. Moreover, we
show how this integration allows public metadata to be introduced to
the protocol, that is agreed by both clients and servers.

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
issuance phase, and the redemption phase.

In the initialization phase, the server samples a keypair and publishes
a key configuration in a way that clients can retrieve it. This configuration consists
of the server's public key and configuration information for the underlying POPRF.

~~~
struct {
   uint8 version;
   uint16 suite;
   uint8 public_key[Ne];
} KeyConfig;
~~~

KeyConfig.suite corresponds to a POPRF ciphersuite from {{I-D.irtf-cfrg-voprf, Section 4}},
and KeyConfig.public_key corresponds to a serialized public key of length `Ne` bytes 
(denoted as a `SerializedElement` in {{I-D.irtf-cfrg-voprf, Section 2}}).

In the issuance phase:

- The client and server optionally agree on some public ``metadata``.
- The client retrieves an servers public key, and generates some initial
  ``token`` data. The client cryptographically ``blinds`` this data, and
  sends it to the server.
- The server ``signs`` the blinded token data (including optional), and
  produces a proof that it used the committed keypair, and sends the
  signature and proof back to the client.
- The client ``verifies`` the proof, ``unblinds`` the signature, and
  stores an authenticated triple of the token, optional metadata, and
  unblinded signature.

In the redemption phase:

- The client retrieves an authenticated token, optional metadata and
  signature triple, and sends it to the server.
- The server ``validates`` that the pair is authenticated correctly and
  authorizes the client.

# Partially Oblivious Pseudorandom Function Protocol

We can instantiate the protocol flow in {{protocol-flow}} using the
partially oblivious pseudorandom function (POPRF) protocol in
{{I-D.irtf-cfrg-voprf}}. In summary, the issuance phase corresponds to
receiving a pseudorandom function evaluation on the blinded data (with
optional metadata). The redemption phase corresponds to revealing
`finalized` data back to the original issuing server.

Note that this instantiation only provides a symmetric verification
mechanism, since the verification of redemptions can only be performed
by the server possessing the secret issuing key. In
{{I-D.ietf-privacypass-architecture}}, we provide alternative frameworks
for allowing asynchronous and delegated verification of tokens.

## Security guarantees

The privacy of clients is determined by the unlinkability of client
requests during the POPRF protocol. Moreover, the one-more-forgery
security of the POPRF prevents clients from forging valid tokens for a
given server. See {{I-D.irtf-cfrg-voprf}} for more details.

## Metadata

The POPRF protocol provides mechanisms for embedding public metadata
into the function evaluations. Such metadata should be agreed apriori by
clients and servers, and is regarded as being public to entities that
are not even included in the explicit issuance and redemption exchanges.

# Protocol ciphersuites {#ciphersuites}

Ciphersuite negotiation is only relevant in terms of negotiating the
appropriate ciphersuites for the underlying POPRF protocol.

--- back

