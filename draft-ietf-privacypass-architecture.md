---
title: "The Privacy Pass Architecture"
abbrev: Privacy Pass Architecture
docname: draft-ietf-privacypass-architecture-latest
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
    org: LIP
    city: Lisbon
    country: Portugal
    email: alex.davidson92@gmail.com
 -
    ins: J. Iyengar
    name: Jana Iyengar
    org: Fastly
    email: jri@fastly.com
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: caw@heapingbits.net

normative:

informative:
  PrivacyPassExtension:
    title: Privacy Pass Browser Extension
    target: https://github.com/privacypass/challenge-bypass-extension
  PrivacyPassCloudflare:
    title: Cloudflare Supports Privacy Pass
    target: https://blog.cloudflare.com/cloudflare-supports-privacy-pass/
    author:
      ins: N. Sullivan
      org: Cloudflare
  DMS2004:
    title: "Tor: The Second-Generation Onion Router"
    date: 2004-08
    target: "https://svn.torproject.org/svn/projects/design-paper/tor-design.html"
    author:
      - ins: R. Dingledine
      - ins: N. Mathewson
      - ins: P. Syverson
  HIJK21:
    title: "PrivateStats: De-Identified Authenticated Logging at Scale"
    target: https://research.fb.com/privatestats
    date: Jan 2021
    author:
      -
        ins: S. Huang
      -
        ins: S. Iyengar
      -
        ins: S. Jeyaraman
      -
        ins: S. Kushwah
      -
        ins: C. K. Lee
      -
        ins: Z. Luo
      -
        ins: P. Mohassel
      -
        ins: A. Raghunathan
      -
        ins: S. Shaikh
      -
        ins: Y. C. Sung
      -
        ins: A. Zhang

--- abstract

This document specifies the Privacy Pass architecture and requirements for
its constituent protocols used for constructing privacy-preserving
authentication mechanisms. It provides recommendations on how the architecture
should be deployed to ensure the privacy of clients and the security of all
participating entities.

--- middle

# Introduction

Privacy Pass is an architecture for authorization based on privacy-preserving
authentication mechanisms. Typical approaches for authorizing clients,
such as through the use of long-term cookies, are not privacy-friendly
since they allow servers to track clients across sessions and interactions.
Privacy Pass takes a different approach: instead of presenting linkable
state-carrying information to servers, e.g., a cookie indicating whether
or not the client is an authorized user or has completed some prior
challenge, clients present unlinkable proofs that attest to this information.
These proofs, or tokens, are private in the sense that a given token cannot
be linked to the protocol interaction where that token was initially issued.

At a high level, the Privacy Pass architecture consists of two protocols:
redemption and issuance. The redemption protocol, described in
{{?AUTHSCHEME=I-D.ietf-privacypass-auth-scheme}}, runs between Clients and
Origins (servers). It allows Origins to challenge Clients to present tokens
for authorization. Depending on the type of token, e.g., whether or not it
can be cached, the Client either presents a previously obtained token or
invokes an issuance protocol, such as
{{?ISSUANCE=I-D.ietf-privacypass-protocol}}, to acquire a token to present as
authorization.

This document describes requirements for both redemption and issuance
protocols and how they interact. It also provides recommendations on how
the architecture should be deployed to ensure the privacy of clients and
the security of all participating entities.

# Terminology

{::boilerplate bcp14}

The following terms are used throughout this document:

Client:
: An entity that seeks authorization to an Origin.

Origin:
: An entity that redeems tokens presented by Clients.

Issuer:
: An entity that issues tokens to Clients for properties
  attested to by the Attester.

Attester:
: An entity that attests to properties of Client for the
  purposes of token issuance.

# Architecture

The Privacy Pass architecture consists of four logical entities --
Client, Origin, Issuer, and Attester -- that work in concert
for token redemption and issuance. This section describes the purpose
of token the redemption and issuance protocols and the requirements
on the relevant participants.

The typical interaction flow for Privacy Pass uses the following steps:

1. A Client interacts with an Origin by sending an HTTP request.
The Origin sends an HTTP response that contains a token challenge
that indicates a specific Issuer to use.
Note that the request might be made as part of accessing a
resource normally, or with the specific intent of triggering a token
challenge.

2. If the Client already has a token available that satisfies the token
challenge, e.g., because the Client has a cache of previously issued tokens,
it can skip to [step 6](#step-redemption){: format="none"} and redeem its
token. Otherwise, it invokes the issuance
protocol to request a token from the designated Issuer.

3. The first step in the issuance protocol is attestation. Specifically, the
Attester performs attestation checks on the Client. These checks
could be proof of solving a CAPTCHA, device trust, hardware attestation,
etc (see {{attester}}).

4. If attestation succeeds, the client creates a Token Request to send
to the designated Issuer (generally via the Attester). The Attester and Issuer
might be functions on the same server, depending on the deployment model
(see {{deployment}}). Depending on the details of Attestation, the Client can
send the Token Request to the Attester alongside any attestation information.
If attestation fails, the Client receives an error and issuance aborts without
a token.

5. The Issuer generates a Token Response based on the Token Request, which
is returned to the Client (generally via the Attester). Upon receiving the
Token Response, the Client computes a token from the token challenge and Token
Response. This token can be validated by anyone with the per-Issuer key, but
cannot be linked to the content of the Token Request or Token Response.

6. If the Client has a token, it includes it in a subsequent HTTP
request to the Origin, as authorization. This token is sent only once.
The Origin validates that the token was generated by the expected Issuer
and has not already been redeemed for the corresponding token challenge.
If the Client does not have a token, perhaps because issuance failed, the
client does not reply to the Origin's challenge with a new request.
{: anchor="step-redemption"}

~~~ aasvg
+--------+            +--------+         +----------+ +--------+
| Origin |            | Client |         | Attester | | Issuer |
+---+----+            +---+----+         +----+-----+ +---+----+
    |                     |                   |           |
    |<----- Request ------+                   |           |
    +-- TokenChallenge -->|                   |           |
    |                     |<== Attestation ==>|           |
    |                     |                   |           |
    |                     +--------- TokenRequest ------->|
    |                     |<-------- TokenResponse -------+
    |<-- Request+Token ---+                   |           |
    |                     |                   |           |
~~~
{: #fig-overview title="Privacy pass redemption and issuance protocol interaction"}

The end-to-end flow for Privacy Pass involves three different types of
contexts:

Redemption context:
: The interactions and set of information shared
between the Client and Origin. This context includes all information
associated with redemption, such as the timestamp of the event, Client
visible information (including the IP address), and the Origin name.

Issuance context:
: The interactions and set of information shared
between the Client, Attester, and Issuer. This context includes all
information associated with issuance, such as the timestamp of the event,
any Client visible information (including the IP address), and the
Origin name (if revealed during issuance).

Attestation context:
: The interactions and set of information shared between
the Client and Attester only, for the purposes of attesting the vailidity of
the Client. This context includes all information associated with attestation,
such as the timestamp of the event and any Client visibile information,
including information needed for the attestation procedure to complete.

The privacy goals of Privacy Pass are oriented around unlinkability based on
these contexts. In particular, Privacy Pass aims to achieve three different
types of unlinkability:

1. Origin-Client unlinkability. This means that given two redemption contexts,
the Origin cannot determine if both redemption contexts correspond to the same
Client or two different Clients. Informally, this means that a Client in a
redemption context is indistinguishable from any other Client that might use
the same redemption context. The set of Clients that share the same redemption
context is referred to as a redemption anonymity set.
2. Issuer-Client unlinkability. This is similar to Origin-Client unlinkability
in that a Client in an issuance context is indistinguishable from any other
Client that might use the same issuance context. The set of Clients that share
the same redemption context is referred to as a redemption anonymity set.
3. Attester-Origin unlinkability. This is similar to Origin-Client and
Issuer-Client unlinkability. It means that given two attestation contexts,
the Attester cannot determine if both contexts correspond to the same Origin
or two different Origins. The set of Clients that share the same attestation
context is referred to as an anonymity set.

By ensuring that different contexts cannot be linked in this way, only the
Client is able to correlate information that might be used to identify them with
activity on the Origin.  The Attester, Issuer, and Origin only receive the
information necessary to perform their respective functions.

The manner in which Origin-Client, Issuer-Client, and Attester-Origin
unlinkability are achieved depends on the deployment model, type of
attestation, and issuance protocol details. For example, as discussed in
{{deployment}}, failure to use a privacy-enhancing proxy system such as Tor
{{DMS2004}} when interacting with Attesters, Issuers, or Origins allows
the set of possible Clients to be partitioned by the Client's IP address, and
can therefore lead to unlinkability violations. Similarly, malicious Origins
may attempt to link two redemption contexts together by using Client-specific
Issuer public keys. See {{deployment}} and {{privacy}} for more information.

The remainder of this section describes the functional properties and security
requirements of the redemption and issuance protocols in more detail.

## Redemption Protocol

The Privacy Pass redemption protocol, described in
{{?AUTHSCHEME=I-D.ietf-privacypass-auth-scheme}}, is an authorization protocol
wherein Clients present tokens to Origins for authorization. Normally,
redemption follows a challenge-response flow, wherein the Origin challenges
Clients for a token with a TokenChallenge ({{AUTHSCHEME, Section 2.1}}) and,
if possible, Clients present a valid Token ({{AUTHSCHEME, Section 2.2}})
in response. This interaction is shown below.

~~~ aasvg
     Origin               Client
                   +------------------.
TokenChallenge --->|                   |
                   | Issuance protocol |
     Token    <----+                   |
                    `-----------------'
~~~
{: #fig-redemption title="Challenge-response redemption protocol interaction"}

Alternatively, when configured to do so, Clients may opportunistically present
Token values to Origins without a corresponding TokenChallenge.

The structure and semantics of the TokenChallenge and Token messages depend
on the issuance protocol and token type being used; see {{AUTHSCHEME}} for
more information.

The challenge provides the client with the information necessary to obtain
tokens that the server might subsequently accept in the redemption context.
There are a number of ways in which the token may vary based on this challenge,
including:

- Issuance protocol. The challenge identifies the type of issuance protocol
  required for producing the token. Different issuance protocols have different
  security properties, e.g., some issuance protocols may produce tokens that
  are publicly verifiable, whereas others may not have this property.
- Issuer identity. Token challenges identify which Issuers are trusted for a
  given issuance protocol. Each Issuer, in turn, determines which Attesters it
  is willing to accept in the issuance protocol. This means that if an Origin
  origin.example accepts tokens issued by Issuer issuer.example, and that
  Issuer in turn accepts different types of attestation from more than one
  trusted Attester, then a Client may use either of these trusted Attesters
  to issue and redeem tokens for origin.example. However, origin.example
  neither explicitly specifies nor learns the Attesters or their attestation
  formats used for token issuance.
- Redemption context. Challenges can be bound to a given redemption context,
  which influences a client's ability to pre-fetch and cache tokens. For
  example, an empty redemption context always allows tokens to be issued and
  redeemed non-interactively, whereas a fresh and random redemption context
  means that the redeemed token must be issued only after the client receives
  the challenge. See Section 2.1.1 of {{AUTHSCHEME}} for more details.
- Per-Origin or cross-Origin. Challenges can be constrained to the Origin for
  which the challenge originated (referred to as per-Origin tokens), or
  can be used across multiple Origins (referred to as cross-Origin tokens).
  The set of Origins for which a cross-Origin token is applicable is referred
  to as the cross-Origin set.

Origins that admit cross-Origin tokens bear some risk of allowing tokens
issued for one Origin to be spent in an interaction with another Origin.
In particular, depending on the use case, Origins may need to maintain
state to track redeemed tokens. For example, Origins that accept cross-Origin
tokens across shared redemption contexts SHOULD track which tokens have been
redeemed already in those redemption contexts, since these tokens can
be issued and then spent multiple times in response to any such challenge.
See Section 2.1.1 of {{AUTHSCHEME}} for discussion.

## Issuance Protocol

The Privacy Pass issuance protocol, described in {{ISSUANCE}}, is a two-message
protocol that takes as input a TokenChallenge from the redemption protocol
({{AUTHSCHEME, Section 2.1}}) and produces a Token
({{AUTHSCHEME, Section 2.2}}), as shown in the figure below.

~~~ aasvg
   Origin              Client      Attester     Issuer
                   +-----------------------------------.
TokenChallenge --->| <--(Attestation)-->                |
                   | TokenRequest ---------------->     |
     Token    <----+     <--------------- TokenResponse |
                    `----------------------------------'
~~~
{: #fig-issuance title="Issuance protocol interaction"}

The structure and semantics of the TokenRequest and TokenResponse messages
depend on the issuance protocol and token type being used; see {{ISSUANCE}}
for more information.

Clients interact with the Attester and Issuer to produce a token in response to
a challenge. The context in which an Attester vouches for a Client during
issuance is referred to as the attestation context. This context includes all
information associated with the issuance event, such as the timestamp of the
event and Client visible information, including the IP address or other
information specific to the type of attestation done.

Each issuance protocol may be different, e.g., in the number and types of
participants, underlying cryptographic constructions used when issuing tokens,
and even privacy properties.

Clients initiate the issuance protocol using the token challenge, a randomly
generated nonce, and public key for the Issuer, all of which are the Client's
private input to the protocol and ultimately bound to an output Token;
see {{Section 2.2 of AUTHSCHEME}} for details. Future specifications
may change or extend the Client's input to the issuance protocol to produce
Tokens with a different structure.

The issuance protocol itself can be any interactive protocol between Client,
Issuer, or other parties that produces a valid token bound to the Client's
private input, subject to the following security requirements.

1. Unconditional input secrecy. The issuance protocol MUST NOT reveal anything
about the Client's private input, including the challenge and nonce, to the
Attester or Issuer, regardless of the hardness assumptions of the underlying
cryptographic protocol(s). The issuance protocol can reveal the Issuer public
key for the purposes of determining which private key to use in producing the
token. This property is sometimes also referred to as blindness.
1. One-more forgery security. The issuance protocol MUST NOT allow malicious
Clients or Attesters (acting as Clients) to forge tokens offline or otherwise
without interacting with the Issuer directly.
1. Concurrent security. The issuance protocol MUST be safe to run concurrently
with arbitrarily many Clients, Attesters and Issuers.

See {{extensions}} for requirements on new issuance protocol variants and
related extensions.

In the sections below, we describe the Attester and Issuer roles in more
detail.

### Attester Role {#attester}

Attestation is an important part of the issuance protocol. In Privacy Pass,
attestation is the process by which an Attester bears witness to, confirms,
or authenticates a Client so as to verify a property about the Client that
is required for Issuance. Clients explicitly trust Attesters to perform
attestation correctly and in a way that does not violate their privacy.

{{?RFC9334}} describes an architecture for attestation procedures. Using
that architecture as a conceptual basis, Clients are RATS attesters that
produce attestation evidence, and Attesters are RATS verifiers that
appraise the validity of attestation evidence.

The type of attestation procedure is a deployment-specific option and outside
the scope of the issuance protocol. Example attestation procedures are below.

- Solving a CAPTCHA. Clients that solve CAPTCHA challenges can be attested to
  have this capability for the purpose of being ruled out as a bot or otherwise
  automated Client.
- Presenting evidence of Client device validity. Some Clients run on trusted
  hardware that are capable of producing device-level attestation evidence.
- Proving properties about Client state. Clients can be associated with state
  and the Attester can verify this state. Examples of state include the
  Client's geographic region and whether the Client has a valid
  application-layer account.

Attesters may support different types of attestation procedures. A type of
attestation procedure is also referred as an attestation format.

In general, each attestation format has different security properties. For
example, attesting to having a valid account is different from attesting to
running on trusted hardware. In general, minimizing the set of attestation
formats helps minimize the amount of information leaked through a token.

Each attestation format also has an impact on the overall system privacy.
Requiring a conjunction of attestation types could decrease the overall
anonymity set size. For example, the number of Clients that have solved a
CAPTCHA in the past day, that have a valid account, and that are running on a
trusted device is less than the number of Clients that have solved a CAPTCHA in
the past day. Attesters SHOULD not admit attestation types that result in small
anonymity sets.

The trustworthiness of Attesters depends on their ability to correctly and
reliably perform attestation during the issuance protocol. Indeed, Issuers
trust Attesters to correctly and reliably perform attestation. However, certain
types of attestation can vary in value over time, e.g., if the attestation
process is compromised or maliciously automated. These are considered
exceptional events and require configuration changes to address the underlying
cause. For example, if attestation is compromised because of a zero-day exploit
on compliant devices, then the corresponding attestation format should be
untrusted until the exploit is patched. Addressing changes in attestation
quality is therefore a deployment-specific task. In Split Attester and Issuer
deployments (see {{deploy-split}}), Issuers can choose to remove compromised
Attesters from their trusted set until the compromise is patched.

### Issuer Role

In Privacy Pass, the Issuer is responsible for completing the issuance protocol
for Clients that complete attestation through a trusted Attester. As described
in {{attester}}, Issuers explicitly trust Attesters to correctly and reliably
perform attestation. Origins explicitly trust Issuers to only issue tokens
from trusted Attesters. Clients do not explicitly trust Issuers.

Depending on the deployment model case, issuance may require some form of
Client anonymization service, similar to an IP-hiding proxy, so that Issuers
cannot learn information about Clients. This can be provided by an explicit
participant in the issuance protocol, or it can be provided via external means,
such as through the use of an IP-hiding proxy service like Tor.
In general, Clients SHOULD minimize or remove identifying
information where possible when invoking the issuance protocol.

Issuers are uniquely identifiable by all Clients with a consistent
identifier. In a web context, this identifier might be the Issuer host name.
Issuers maintain one or more configurations, including issuance key pairs, for
use in the issuance protocol. Issuers can rotate these configurations as needed
to mitigate risk of compromise; see {{rotation-and-consistency}} for more
considerations around configuration rotation. The Issuer public key for each
active configuraton is made available to Origins and Clients for use in the
issuance and redemption protocols.

### Issuance Metadata {#metadata}

Certain instantiations of the issuance protocol may permit public or private
metadata to be cryptographically bound to a token. As an example, one
trivial way to include public metadata is to assign a unique Issuer
public key for each value of metadata, such that N keys yields log2(N)
bits of metadata. Metadata may be public or private.

Public metadata is that which clients can observe as part of the token
issuance flow. Public metadata can either be transparent or opaque. For
example, transparent public metadata is a value that the client either
generates itself, or the Issuer provides during the issuance flow and
the client can check for correctness. Opaque public metadata is metadata
the client can see but cannot check for correctness. As an example, the
opaque public metadata might be a "fraud detection signal", computed on
behalf of the Issuer, during token issuance. In normal circumstances,
Clients cannot determine if this value is correct or otherwise a tracking
vector.

Private metadata is that which Clients cannot observe as part of the token
issuance flow. Such instantiations can be built on the Private Metadata Bit
construction from Kreuter et al. {{?KLOR20=DOI.10.1007/978-3-030-56784-2_11}}
or the attribute-based VOPRF from Huang et al. {{HIJK21}}.

Metadata can be arbitrarily long or bounded in length. The amount of permitted
metadata may be determined by application or by the underlying cryptographic
protocol. The total amount of metadata bits included in a token is the sum of
public and private metadata bits. Every bit of metadata can be used to
partition the Client issuance or redemption anonymity sets; see
{{metadata-privacy}} for more information.

### Issuance Protocol Extensibility {#extensions}

The Privacy Pass architecture and ecosystem are both intended to be receptive
to extensions that expand the current set of functionalities through new
issuance protocols. Each issuance protocol MUST include a detailed analysis
of the privacy impacts of the extension, why these impacts are justified,
and guidelines on how to deploy the protocol to minimize any privacy impacts.
Any extension to the Privacy Pass protocol MUST adhere to the guidelines
specified in {{issuer-role}} for managing Issuer public key data.

# Deployment Considerations {#deployment}

The Origin, Attester, and Issuer portrayed in {{fig-overview}} can be
instantiated and deployed in a number of ways. The deployment model directly
influences the manner in which attestation, issuance, and redemption contexts
are separated to achieve Origin-Client, Issuer-Client, and Attester-Origin
unlinkability.

This section covers some expected deployment models and their corresponding
security and privacy considerations. Each deployment model is described in
terms of the trust relationships and communication patterns between Client,
Attester, Issuer, and Origin.

The discussion below assumes non-collusion between entities that have access to
the attestation, issuance, and redemption contexts, as collusion between such
entities would enable linking of these contexts and may lead to unlinkability
violations. Generally, this means that entities operated by separate parties do
not collude. Mechanisms for enforcing non-collusion are out of scope for this
architecture.

## Shared Origin, Attester, Issuer {#deploy-shared}

In this model, the Origin, Attester, and Issuer are all operated by the same
entity, as shown in the figure below.

~~~ aasvg
                   +-----------------------------------------.
      Client       |  Attester         Issuer         Origin  |
        |          |                                          |
        |          |       TokenChallenge                     |
        <----------------------------------------------+      |
        |          | Attest                                   |
        +----------------->                                   |
        |          |     TokenRequest                         |
        +-------------------------------->                    |
        |          |     TokenResponse                        |
        <--------------------------------+                    |
        |          |           Token                          |
        +---------------------------------------------->      |
                    `----------------------------------------'
~~~
{: #fig-deploy-shared title="Shared Deployment Model"}

This model represents the initial deployment of Privacy Pass, as described in
{{PrivacyPassCloudflare}}. In this model, the Attester, Issuer, and Origin
share the attestation, issuance, and redemption contexts. As a result,
attestation mechanisms that can uniquely identify a Client, e.g., requiring
that Clients authenticate with some type of application-layer account, are
not appropriate, as they could lead to unlinkability violations.

Origin-Client, Issuer-Client, and Attester-Origin unlinkability requires that
issuance and redemption events be separated over time, such as through the use
of tokens with an empty redemption context, or be separated over space, such
as through the use of an anonymizing proxy when connecting to the Origin.

## Joint Attester and Issuer {#deploy-joint-issuer}

In this model, the Attester and Issuer are operated by the same entity
that is separate from the Origin. The Origin trusts the joint Attester
and Issuer to perform attestation and issue Tokens. Clients interact
with the joint Attester and Issuer for attestation and issuance. This
arrangement is shown in the figure below.

~~~ aasvg
                                                   +----------.
      Client                                       |   Origin  |
        |                 TokenChallenge           |           |
        <-----------------------------------------------+      |
        |                                          |           |
        |          +--------------------------.    |           |
        |          |  Attester         Issuer  |   |           |
        |          |                           |   |           |
        |          | Attest                    |   |           |
        +----------------->                    |   |           |
        |          |     TokenRequest          |   |           |
        +-------------------------------->     |   |           |
        |          |     TokenResponse         |   |           |
        <--------------------------------+     |   |           |
        |           `-------------------------'    |           |
        |                                          |           |
        |                     Token                |           |
        +----------------------------------------------->      |
                                                   |           |
                                                    `---------'
~~~
{: #fig-deploy-joint-issuer title="Joint Attester and Issuer Deployment Model"}

This model is useful if an Origin wants to offload attestation and issuance to
a trusted entity. In this model, the Attester and Issuer share an attestation
and issuance context for the Client, which is separate from the Origin's
redemption context.

For certain types of issuance protocols, this model achieves
Origin-Client, Issuer-Client, and Attester-Origin
unlinkability. However, issuance protocols that require the Issuer to
learn information about the Origin, such as that which is described in
{{?RATE-LIMITED=I-D.privacypass-rate-limit-tokens}}, are not appropriate since
they could lead to Attester-Origin unlinkability violations through the Origin
name.

## Joint Origin and Issuer {#deploy-joint-origin}

In this model, the Origin and Issuer are operated by the same entity, separate
from the Attester, as shown in the figure below. The Issuer accepts token
requests that come from trusted Attesters. Since the Attester and Issuer are
separate entities, the Attester must authenticate itself to the Issuer. In
settings where the Attester is a Client-trusted service, one way Attesters
can authenticate to Issuers is via mutually-authenticated TLS. However,
alernative authentication mechanisms are possible. This arrangement is shown
below.

~~~ aasvg
                                    +-------------------------.
      Client                        |   Issuer         Origin  |
        |         TokenChallenge    |                          |
        <-----------------------------------------------+      |
        |                           |                          |
        |          +----------.     |                          |
        |          |  Attester |    |                          |
        |          |           |    |                          |
        |          | Attest    |    |                          |
        +----------------->    |    |                          |
        |          |           |    |                          |
        |          |     TokenRequest                          |
        +-------------------------------->                     |
        |          |           |    |                          |
        |          |     TokenResponse                         |
        <--------------------------------+                     |
        |          |           |    |                          |
        |           `---------'     |                          |
        |                           |                          |
        |              Token        |                          |
        +----------------------------------------------->      |
                                     `------------------------'
~~~
{: #fig-deploy-joint-origin title="Joint Origin and Issuer Deployment Model"}

This model is useful for Origins that require Client-identifying attestation,
e.g., through the use of application-layer account information, but do not
otherwise want to learn information about individual Clients beyond what is
observed during the token redemption, such as Client IP addresses.

In this model, attestation contexts are separate from issuer and redemption
contexts. As a result, any type of attestation is suitable in this model.
Moreover, any type of token challenge is suitable assuming there is more than
one Origin involved, since no single party will have access to the identifying
Client information and unique Origin information. If there is only a single
Origin, then per-Origin tokens are not appropriate in this model, since the
Attester can learn the redemption context. However, the Attester does not
learn whether a token is per-Origin or cross-Origin.

## Split Origin, Attester, Issuer {#deploy-split}

In this model, the Origin, Attester, and Issuer are all operated by different
entities, as shown in the figure below. As with the joint Origin and Issuer
model, the Issuer accepts token requests that come from trusted Attesters, and
the details of that trust establishment depend on the issuance protocol and
relationship between Attester and Issuer.

~~~ aasvg
                                                   +----------.
      Client                                       |   Origin  |
        |                 TokenChallenge           |           |
        <-----------------------------------------------+      |
        |                                          |           |
        |          +----------.                    |           |
        |          |  Attester |                   |           |
        |          |           |                   |           |
        |          | Attest    |    +---------.    |           |
        +----------------->    |    |  Issuer  |   |           |
        |          |           |    |          |   |           |
        |          |     TokenRequest          |   |           |
        +-------------------------------->     |   |           |
        |          |           |    |          |   |           |
        |          |     TokenResponse         |   |           |
        <--------------------------------+     |   |           |
        |          |           |    |          |   |           |
        |           `---------'      `--------'    |           |
        |                                          |           |
        |                     Token                |           |
        +----------------------------------------------->      |
                                                   |           |
                                                    `---------'
~~~
{: #fig-deploy-split title="Split Deployment Model"}

This is the most general deployment model, and is necessary for some
types of issuance protocols where the Attester plays a role in token
issuance; see {{RATE-LIMITED}} for one such type of issuance protocol.
In this model, the Attester, Issuer, and Origin have a separate view
of the Client: the Attester sees potentially sensitive Client identifying
information, such as account identifiers or IP addresses, the Issuer
sees only the information necessary for issuance, and the Origin sees
token challenges, corresponding tokens, and Client source information,
such as their IP address. As a result, attestation, issuance, and redemption
contexts are separate, and therefore any type of token challenge is suitable in
this model as long as there is more than a single Origin. As in the
Joint Origin and Issuer model in {{deploy-joint-origin}}, if there is
only a single Origin, then per-Origin tokens are not appropriate.

# Centralization Considerations

A consequence of limiting the number of participants (Attesters or Issuers) in
Privacy Pass deployments for meaningful privacy is that it forces concentrated
centralization amongst those participants.
{{?CENTRALIZATION=I-D.nottingham-avoiding-internet-centralization}} discusses
several ways in which this might be mitigated. For example, a multi-stakeholder
governance model could be established to determine what candidate participants
are fit to operate as participants in a Privacy Pass deployment. This is
precisely the system used to control the Web's trust model.

Alternatively, Privacy Pass deployments might mitigate this problem through
implementation. For example, rather than centralize the role of attestation
in one or few entities, attestation could be a distributed function performed
by a quorum of many parties, provided that neither Issuers nor Origins learn
which Attester implementations were chosen. As a result, Clients could have
more opportunities to switch between attestation participants.

# Privacy Considerations {#privacy}

The previous section discusses the impact of deployment details on
Origin-Client, Issuer-Client, and Attester-Origin unlinkability.
The value these properties affords to end users depends on
the size of anonymity sets in which Clients or Origins are
unlinkable. For example, consider two different deployments, one wherein
there exists a redemption anonymity set of size two and another
wherein there redemption anonymity set of size 2<sup>32</sup>. Although
Origin-Client unlinkabiity guarantees that the Origin cannot link any two
requests to the same Client based on these contexts, respectively, the
probability of determining the "true" Client is higher the smaller these
sets become.

In practice, there are a number of ways in which the size of anonymity sets
may be reduced or partitioned, though they all center around the concept of
consistency. In particular, by definition, all Clients in an anonymity set
share a consistent view of information needed to run the issuance and
redemption protocols. An example type of information needed to run these
protocols is the Issuer public key. When two Clients have inconsistent
information, these Clients effectively have different redemption contexts and
therefore belong in different anonymity sets.

The following sections discuss issues that can influence anonymity set size.
For each issue, we discuss mitigations or safeguards to protect against the
underlying problem.

## Partitioning by Issuance Metadata {#metadata-privacy}

Any metadata bits of information can be used to further segment the size
of the Client's anonymity set. Any Issuer that wanted to track a single
Client could add a single metadata bit to Client tokens. For the tracked
Client it would set the bit to `1`, and `0` otherwise. Adding additional
bits provides an exponential increase in tracking granularity similarly to
introducing more Issuers (though with more potential targeting).

For this reason, the amount of metadata used by an Issuer in creating
redemption tokens must be taken into account -- together with the bits
of information that Issuers may learn about Clients otherwise. Since this
metadata may be useful for practical deployments of Privacy Pass, Issuers
must balance this against the reduction in Client privacy.

In general, limiting the amount of metadata permitted helps limit the extent
to which metadata can uniquely identify individual Clients. Clients SHOULD
bound the number of possible metadata values in practice. Most token types do
not admit any metadata, so this bound is implicitly enforced. Moreover,
Privacy Pass deployments SHOULD NOT use metadata unless its value has been
assessed and weighed against the corresponding reduction in Client privacy.

## Partitioning by Issuance Consistency {#rotation-and-consistency}

Anonymity sets can be partitioned by information used for the issuance
protocol, including: metadata, Issuer configuration (keys), and Issuer
selection.

Any issuance metadata bits of information can be used to partition the Client
anonymity set. For example, any Issuer that wanted to track a single Client
could add a single metadata bit to Client tokens. For the tracked Client it
would set the bit to `1`, and `0` otherwise. Adding additional bits provides an
exponential increase in tracking granularity similarly to introducing more
Issuers (though with more potential targeting).

The number of active Issuer configurations also contributes to anonymity set
partitioning. In particular, when an Issuer updates their configuration and
the corresponding key pair, any Client that invokes the issuance protocol with
this configuration becomes be part of a set of Clients which also ran the
issuance protocol using the same configuration. Issuer configuration updates,
e.g., due to key rotation, are an important part of hedging against long-term
private key compromise. In general, key rotations represent a trade-off between
Client privacy and Issuer security. Therefore, it is important that key
rotations occur on a regular cycle to reduce the harm of an Issuer key
compromise.

Lastly, if Clients are willing to issue and redeem tokens from a large number
of Issuers for a specific Origin, and that Origin accepts tokens from all
Issuers, segregation can occur. In particular, if a Client obtains tokens from
many Issuers and an Origin later challenges that Client for a token from each
Issuer, the Origin can learn information about the Client. Each per-Issuer
token that a Client holds essentially corresponds to a bit of information about
the Client that Origin learns. Therefore, there is an exponential loss in
privacy relative to the number of Issuers.

The fundamental problem here is that the number of possible issuance
configurations, including the keys in use and the Issuer identities themselves,
can partition the Client anonymity set. To mitigate this problem, Clients
SHOULD bound the number of active issuance configurations per Origin as well as
across Origins. Moreover, Clients SHOULD employ some form of consistency
mechanism to ensure that they receive the same configuration information and
are not being actively partitioned into smaller anonymity sets. See
{{?CONSISTENCY=I-D.ietf-privacypass-key-consistency}} for possible consistency
mechanisms. Depending on the deployment, the Attester might assist the Client
in applying these consistency checks across clients. Failure to apply a
consistency check can allow Client-specific keys to violate Origin-Client
unlinkability.

## Partitioning by Side-Channels

Side-channel attacks, such as those based on timing correlation, could be
used to reduce anonymity set size. In particular,
for interactive tokens that are bound to a Client-specific redemption
context, the anonymity set of Clients during the issuance protocol consists
of those Clients that started issuance between the time of the Origin's
challenge and the corresponding token redemption. Depending on the number
of Clients using a particular Issuer during that time window, the set can
be small. Appliations should take such side channels into consideration before
choosing a particular deployment model and type of token challenge and
redemption context.

# Security Considerations {#security}

This document describes security and privacy requirements for the Privacy Pass
redemption and issuance protocols. It also describes deployment models and
privacy considerations for using Privacy Pass within those models. Ensuring
Client privacy -- separation of attestation and redemption contexts -- requires
active work on behalf of the Client, especially in the presence of malicious
Issuers and Origins. Implementing mitigations discused in {{deployment}}
and {{privacy}} is therefore necessary to ensure that Privacy Pass offers
meaningful privacy improvements to end-users.

--- back

# Acknowledgements

The authors would like to thank Eric Kinnear, Scott Hendrickson, Tommy Pauly,
Christopher Patton, Benjamin Schwartz, Martin Thomson, Steven Valdez and other
contributors of the Privacy Pass Working Group for many helpful contributions
to this document.
