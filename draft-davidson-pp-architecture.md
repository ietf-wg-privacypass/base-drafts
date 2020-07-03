---
title: "Privacy Pass: Architectural Framework"
abbrev: PP architecture
docname: draft-davidson-pp-architecture-latest
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
  RFC8446:
  draft-davidson-pp-protocol:
    title: "Privacy Pass: The Protocol"
    target: https://tools.ietf.org/html/draft-davidson-pp-protocol-00
    author:
      ins: A. Davidson
      org: Cloudflare Portugal
  draft-svaldez-pp-http-api:
    title: "Privacy Pass: HTTP API"
    target: https://github.com/alxdavids/privacy-pass-ietf/tree/master/drafts/draft-svaldez-pp-http-api
    author:
      ins: S. Valdez
      org: Google LLC
  X9.62:
    title: "Public Key Cryptography for the Financial Services Industry: The Elliptic Curve Digital Signature Algorithm (ECDSA)"
    author:
      name: American National Standards Institute
    seriesinfo: ANSI X9.62-2005
    date: November 2005
informative:
  I-D.irtf-cfrg-voprf:
  keytrans:
    title: "Security Through Transparency"
    target: https://security.googleblog.com/2017/01/security-through-transparency.html
    authors:
      -
        ins: Ryan Hurst
        org: Google
      -
        ins: Gary Belvin
        org: Google
  TrustTokenAPI:
    title: Getting started with Trust Tokens
    target: https://web.dev/trust-tokens/
    author:
      name: Google
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

This document specifies the architectural framework for constructing
secure and privacy-preserving instantiations of the Privacy Pass
protocol (as described in {{draft-davidson-pp-protocol}}). The framework
refers to the entire ecosystem of Privacy Pass clients and servers. This
document makes recommendations on how this ecosystem should be
constructed to ensure the privacy of clients and the security of all
participating entities.

--- middle

# Introduction

The Privacy Pass protocol provides a privacy-preserving mechanism for
authorization of clients with servers. The protocol is detailed in
{{draft-davidson-pp-protocol}} and is intended for use in
performance-critical settings, such as while browsing the Internet.

The way that the ecosystem around the protocol is set up can have
significant impacts on the stated privacy and security guarantees of the
protocol. For instance, the number of servers issuing Privacy Pass
tokens, along with the number of registered clients, determines the
privacy budget available to each individual client. This can be further
influenced by other factors, such as: the key rotation policy used by
each server; and, the number of supported ciphersuites. There are also
client-behavior patterns that can reduce the effective security of the
server.

In this document, we will provide a structural framework for building
the ecosystem around the Privacy Pass protocol. Firstly, it will
identify a number of common interfaces for integrating the Privacy Pass
protocol and the API detailed in {{draft-davidson-pp-protocol}}. The API
in the protocol document represents a basic one-on-one exchange between
a client and a server. The interfaces that we describe in this document
reproduce this API into the setting where clients and servers are part
of a wider ecosystem.

On top of this, the document also includes policies for the following
considerations:

- How server configurations and key material should be stored and
  rotated in an open and transparent manner.
- Compatible server issuance and redemption running modes and associated
  expectations.
- A concrete assessment and parametrization of the privacy budget
  associated with different settings of the above policies.
- Recommendations for identifying malicious server behavior.
- Assessment of client incentives for eschewing privacy features.
- The incorporation of potential extensions into the wider ecosystem.

Finally, we will discuss existing applications that make use of the
Privacy Pass protocol, and highlight how these may fit with the proposed
framework.

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}.

The following terms are used throughout this document.

- Server: A service that provides access to a certain resource
  (typically denoted S)
- Client: An entity that seeks authorization from a server (typically
  denoted C)
- Key: Server's secret key
- Config: The server configuration associated with the key material and
  ciphersuite choices that it makes.

We assume that all protocol messages are encoded into raw byte format
before being sent. We use the TLS presentation language {{RFC8446}} to
describe the structure of the data that is communicated and stored.

## Layout

- {{ecosystem}}: Describes the basic assumptions that we make in this
  document on the shape and topology of the Privacy Pass ecosystem: the
  environment in which Privacy Pass supporting clients and servers
  interact with each other.
- {{integration}}: Describes the policy and framework for building
  interoperable client and server implementations. Also provides the
  necessary foundations for interacting with the global configuration
  registry.
- {{key-mgmt}}: Describes the structure of server key configurations and
  how this configuration is retrieved and updated.
- {{running-modes}}: Describes the different running modes that are
  currently expected from Privacy Pass servers.
- {{privacy}}: An analysis of the characteristics of the Privacy Pass
  architecture that have an impact on the privacy of clients
  participating in the ecosystem.
- {{security}}: An analysis of the security characteristics of the
  protocol when viewed as a part of the wider architecture of the
  protocol ecosystem. Includes discussions of the cases for both servers
  and clients.
- {{parametrization}}: Provides an example parametrization of the
  privacy and security parameters that are associated with the protocol,
  based on the previous discussions.
- {{recs-srvr}}: Recommendations for identifying and highlighting
  potential malicious behavior by a server.
- {{extensions}}: Describes the policy for writing extensions to the
  Privacy Pass protocol, and how they may be incorporated into the wider
  architecture.
- {{applications}}: A non-exhaustive list of the applications that make
  use of the Privacy Pass protocol, or some variant of it.

# Architectural ecosystem assumptions {#ecosystem}

The Privacy Pass ecosystem refers to the global framework in which
multiple instances of the Privacy Pass protocol operate. This refers to
all servers that support the protocol, or any extension of it, along
with all of the clients that may interact with these servers. Moreover,
there is a singular public entity known as the 'global configuration
registry'. This registry presents the public information related to all
supported server key material. This is required to enable the client to
process issuance responses from each of the available servers.

The ecosystem itself, and the way it is constructed, is critical for
evaluating the privacy of each individual client. We assume that a
client's privacy refers to fraction of users that it represents in the
anonymity set that it belongs to. We discuss this more in {{privacy}}.

## Servers {#ecosystem-servers}

Servers in the Privacy Pass ecosystem are entities whose primary
function is to undertake the role of the `Server` in
{{draft-davidson-pp-protocol}}. To facilitate this, the server must hold
the following data at any given time:

- a valid server configuration (`ServerConfig`) as specified in
  {{draft-davidson-pp-protocol}};
- a long-term signing key pair for a signature scheme `sig_alg`;
- storage of Privacy Pass tokens that have been previously redeemed with
  the server.

The server must be available at a specified address (uniquely identified
by `server_id`) that accepts communications from Privacy Pass clients
{{ecosystem-clients}} on the interfaces defined in
{{server-interfaces}}. When the server wants to update its
configuration, it communicates with the global configuration registry
{{ecosystem-config}}.

### Long-term signing

The long-term signing key pair `(k_sign, k_vrfy)` is used to sign
configuration data that is sent to the global configuration registry.
The server must prove to the global key configuration registry the
veracity of the long-term key-pair that it uses. This key pair is
attached to the configuration that it maintains. We assume the following
functional API:

- `sig = sig_alg.sign(k_sign, data)`: produces a signature `sig` using
  the signing key, `k_sign`, over the bytes of `data`.
- `b = sig_alg.verify(k_vrfy, data, sig)`: produces a boolean result `b`
  indicating that `sig` is a valid signature over `data` using the
  signing key `k_sign`.

As per usual, we assume that any signature produced by the `.sign`
function produces a result of `true` when verifying using `.verify`.
Likewise, the scheme should also satisfy the well-known security
property of existential unforgeability. Valid instantiations include DSA
(and ECDSA) {{X9.62}}.

## Clients {#ecosystem-clients}

Clients in the Privacy Pass ecosystem are entities whose primary
function is to undertake the role of the `Client` in
{{draft-davidson-pp-protocol}}. The clients are assumed to only store
data related to the tokens that it has been issued by the server. This
storage is used for constructing redemption requests, see the
`CLIENT_REDEEM` interface ({{interface-cli-redeem}}) for more details.

The clients must also have access to the global config store
{{ecosystem-config}}. This is so that the client can retrieve data
related to the configuration of the server that it is communicating
with.

Each client must be addressed by a unique identifier, given by
`client_id`.

## Global configuration store {#ecosystem-config}

The global configuration store controls all the configuration data that
is used by the servers that are part of the Privacy Pass ecosystem. This
data is required to allow clients to verify server issuance responses.
The server configuration data corresponds to all the ciphersuites and
key fingerprints that have ever been used, by every server in the
Privacy Pass ecosystem.

The config store is an append-only database that supports revocation of
old configurations. This is done by limiting the number of active
configurations that a server can use at any given time. It should be
available at a publicly-broadcasted address so that both clients and
servers can access it. The database should preserve its history in an
audit-friendly manner.

The way that the config store is implemented can have a dramatic effect
on the privacy of the clients in the Privacy Pass protocol. We describe
in detail how such a store should be implemented in {{key-mgmt}}.

# Protocol integration policy {#integration}

We provide a number of common interfaces that both the clients and
servers implement. These interfaces should be contactable by entities in
the ecosystem, and provide a framework for generating and processing
data in the Privacy Pass protocol. The framework provides a policy that
states that these interfaces be implemented (for example, by clients and
servers) to be considered valid entities in the Privacy Pass ecosystem.
The interfaces wrap the Privacy Pass API functions detailed in
{{draft-davidson-pp-protocol}} to provide functionality in the many-many
ecosystem consisting of clients and servers.

The interfaces have three configurable fields. The `Visibility` field
indicates that the interface is either contactable externally
(`external`) or that it is activated internally by the entity at some
point (`internal`). The `Input` field determines valid input types of
that are received by the interface. The `Returns` field provides the
return type of the function. The `Steps` field notes high-level steps to
be taken when the interface is contacted.

Note: currently we live the implementation of errors up to the
implementer. By default, if any internal Privacy Pass protocol function
({{recap-pp-protocol}}) throws an error, then the interface should
panic. More fine-grained error reporting may be added in future versions
of this draft.

## Recap: Protocol API {#recap-pp-protocol}

The protocol document {{draft-davidson-pp-protocol}} specifically
details a number of public API functions that are used for constructing
the generic protocol. These functions can be split into server and
client functionality.

1. Server functionality:
   - `ServerSetup`: Generates server configuration and keys
   - `Issue`: Run on the contents of the client message in the
     issuance phase.
   - `Verify`: Run on the contents of the client message in the
     redemption phase.

2. Client functionality:
   - `ClientSetup`: Generates the client configuration based on the
     configuration used by a given server.
   - `Generate`: Generates public and private data associated with
     the contents of the client message in the issuance phase.
   - `Process`: Processes the contents of the server response in the
     issuance phase.
   - `Redeem`: Generates the data that forms the client message in
     the redemption phase.

We will use each of the functions internally in the description of the
interfaces that follows.

## Server interfaces {#server-interfaces}

Any implementation of a Privacy Pass Server MUST implement the following
contact points or interfaces. When the Server is contacted on these
interfaces with the required input data, it should take the steps
detailed. The inputs and responses for each of the interfaces correspond
to the data structures defined in {{draft-davidson-pp-protocol}}.

### SERVER_KEY_GEN {#interface-key-gen}

- Visibility: `internal`
- Input: a string, `id`, corresponding to a ciphersuite identifier (see
  {{draft-davidson-pp-protocol}} for valid configurations).
- Returns: a boolean `b`, indicating success.
- Steps:
  1. Run `(cfg, update) = ServerSetup(id)`.
  2. Construct a `config_update` message.
    1. The value `<server_id>` is the unique identifier for the Server.
    2. The value of `<expiry_time>` should be a point in the future
       within the window of allowed key rotation lengths (for example,
       those specified in {{parametrization}}).
    3. The value `<comm_id>` is a string used to distinguish between
       config entries corresponding to the same config, but where the
       key material has changed (e.g. after a key rotation).
    4. The value of `<supports>` should be set to an octet
       corresponding to the functionality that is provided. The value
       `0` indicates that no functionality is supported; `1` indicates
       that the server supports the issuance phase; `2` indicates
       support for the redemption phase; and `3` indicates support for
       both phases. If unspecified, this defaults to `3`.
    5. The value of `<config>` is set to be equal to `update`.
    5. The value `<signature>` is computed over the bytes of the rest of
       message contents, using the Server long-term secret signing key
       `k_sign`. This can be computed by running:

       ~~~
          data = <server_id> .. <config> .. <expiry> .. <supports>
          <signature> = sig_alg.sign(k_sign, data)
       ~~~

  3. Send the `config_update` message to the `GLOBAL_CONFIG_UPDATE`
     interface.
  4. Send a `server_config_store` message to the `SERVER_STORE_CONFIG`
     interface containing the value of `cfg`.

### SERVER_STORE_CONFIG {#interface-srv-store-config}

- Visibility: `internal`
- Input: a `server_config_store` message `msg` ({{msg-config-store}}).
- Returns: `null`
- Steps:
  1. Let `ex_cfg` correspond to the existing `ServerConfig` object keyed
     by `issue`.
  2. Store the bytes of `msg.config` in local storage, against the key
     `issue`.
  3. Store the bytes of `ex_cfg` in local storage against the key
     `redeem`.

### SERVER_CONFIG_RETRIEVAL {#interface-srv-config-retrieval}

- Visibility: `internal`
- Input: an octet `method` in `{1,2,3}`.
- Returns: A `server_config_retrieve` message `resp`
  ({{msg-config-retrieve}}).
- Steps:
  1. Let `storage` be the ID and the bytes of the server config
     currently stored in local storage, respectively.
  2. If `resp.config.supports != method && resp.config.supports != 3`,
     then return `null`.
  3. Let `resp` be a `server_config_retrieve` message, where
     `<configs>=[config]` for `config` stored in local storage against
     `issue`.
  4. If `method == 2`, append `ex_config` to `<configs>`, where
     `ex_config` is stored in local storage against the key `redeem`.
  5. Return `resp`.

### SERVER_HELLO {#interface-srv-hello}

- Visibility: `external`
- Input: a string, `client_addr`, corresponding to an address that the
  client can be contacted on.
- Return: `null`
- Steps:
  1. Send an empty message to the internal `SERVER_CONFIG_RETRIEVAL`
     interface, and let `cfgs=resp.configs` based on the
     `server_config_retrieve` response `resp`.
  2. Send a `server_hello` message to the `CLIENT_CONFIG_RETRIEVAL`
     interface for the client at `client_addr`. The `server_hello`
     message must satisfy the following:
     1. The value `<server_id>=server_id` is the unique identifier for
        the Server.
     2. The value of `<supports>` MUST be set to an octet corresponding
        to the supported methods.

### SERVER_ISSUE {#interface-srv-issue}

- Visibility: `external`
- Input: A `client_issue` message `msg` ({{msg-client-issue}})
- Returns: A `server_issue_resp` message
- Steps:
  1. Send the message `issue` to the internal
     `SERVER_CONFIG_RETRIEVAL` interface, and let
     `ciphersuite=msg.ciphersuites[0]` and `srv_cfg=msg.configs[0]`
     based on the `server_config_retrieve` response.
  2. Run the following:

     ~~~
        issue_resp = Issue(srv_cfg, msg.issue_data)
     ~~~

  3. Returns a `server_issue_resp` message with `<data>=issue_resp`
     message back to the caller `CLIENT_ISSUE_GEN` interface of the
     client associated with `client_issue.client_id`.

### SERVER_REDEEM {#interface-srv-redeem}

- Visibility: `external`
- Input: A `client_redeem` message `msg` ({{msg-client-redeem}})
- Returns: A `server_redeem_resp` message back to the calling
  `CLIENT_REDEEM` interface ({{msg-server-redeem-resp}}).
- Steps:
  1. Send the message `redeem` to the internal
     `SERVER_CONFIG_RETRIEVAL` interface, let `configs`
     be the returned array.
  2. Send `msg.message.data` to the `SERVER_DOUBLE_SPEND_CHECK`
     interface and, if the response is `true`, return an unsuccessful
     `server_redeem_resp` message to the client.
  3. Run the following:

     ~~~
        resp = Verify(configs[0],message)
        if (!resp.success) {
          resp = Verify(configs[1],message)
        }
     ~~~

  4. Send `msg.message.data` to the `SERVER_DOUBLE_SPEND_STORE`
     interface.
  5. The Server returns a `server_redeem_resp` message, with
     `<data>=resp` back to the `CLIENT_REDEEM` interface of the client
     associated with `client_redeem.client_id`.

### SERVER_DOUBLE_SPEND_CHECK {#interface-srv-spend-check}

- Visibility: `internal`
- Input: A byte string `data` of type `opaque<1..2^32-1>`
  ({{msg-client-redeem}}).
- Returns: A boolean value `b`.
- Steps:
  1. Return `true` if `data` exists in the double-spend index, and
     `false` otherwise.

### SERVER_DOUBLE_SPEND_STORE {#interface-srv-spend-store}

- Visibility: `internal`
- Input: A byte string `data` of type `opaque<1..2^32-1>`
  ({{msg-client-redeem}}).
- Returns: `null`.
- Steps:
  1. Store `data` in the double-spend index.

## Client interfaces {#client-interfaces}

The following interfaces MUST be implemented for any implementation of a
Client in the Privacy Pass ecosystem ({{ecosystem-clients}}).

### CLIENT_CONFIG_RETRIEVAL {#interface-cli-retrieval}

- Visibility: `external`
- Input: a `server_hello` message type denoted by `msg`,
  ({{msg-server-hello}}).
- Return: a boolean, indicating whether the config was successfully
  retrieved.
- Steps:
  1. Construct a `config_retrieval` message using
     `<server_id>=msg.server_id`.
  2. Send the `config_retrieval` message to the
     `GLOBAL_CONFIG_RETRIEVAL` interface, and receive a reply `resp` of
     type `config_retrieval_resp`.
  3. If `success` is set to `false`, return `false`.
  4. Parse `resp[0].supports` and check that it includes support
     for what is specified in `msg.supports`, otherwise return false.
  5. Parse `resp[1].supports` and check that it includes support
     for what is specified in `msg.supports`, otherwise return false.
  6. The value `<signature>` is verified over the bytes of the rest of
     message contents, using the Server long-term verification key
     `k_vrfy`. This can be computed by running the function below and
     checking that `ret==true`, otherwise returning false.

     ~~~
        data = <server_id> .. <ciphersuite> .. <comm_id>
                .. <config> .. <expiry> .. <supports>
        ret = sig_alg.verify(k_vrfy, data, <signature>)
     ~~~

  7. Construct a `client_token_retrieval` where

     ~~~
        ciphersuite = resp[0].ciphersuite
        comm_id = resp[0].comm_id
     ~~~

     and send it to the `CLIENT_TOKEN_RETRIEVAL` interface. Receive back
     `token` in a `client_token_retrieval_resp` message. Set
     `config_idx=0`.

  8. If `token == null`, construct a `client_token_retrieval` message
     where:

     ~~~
        ciphersuite = resp[1].ciphersuite
        comm_id = resp[1].comm_id
     ~~~

     and send it to the `CLIENT_TOKEN_RETRIEVAL` interface. Receive back
     `token` in a `client_token_retrieval_resp` message. Set
     `config_idx=1'`.

  9. If:

     ~~~
        token == null
          && (
            resp[0].supports == 1
            || resp[0].supports == 3
          )
     ~~~

     construct a `client_issue_generation` message and send it to the
     `CLIENT_ISSUE_GEN` interface, with:

      1. `<server_id> = msg.server_id`;
      2. `<config> = resp[0].config`;

  10. If:

     ~~~
        token != null
          && (
            resp[config_type].supports == 2
            || resp[config_type].supports == 3
          )
     ~~~

     construct a `client_redeem_generation` message and send it to the
     `CLIENT_REDEEM` interface. with:

      1. `<server_id> = msg.server_id`;
      2. `<token> = token`;

  11. If neither condition in (7) or (8) is satisfied, return false.
  12. Return true.

### CLIENT_ISSUE_GEN {#interface-cli-issue-gen}

- Visibility: `internal`
- Input: a message `msg` of type `client_issue_generation`
  ({{msg-client-issue-generation}}).
- Returns: `null`
- Steps:
  1. The client runs:

     ~~~
        cli_cfg = ClientSetup(msg.ciphersuite, msg.config)
     ~~~

  2. The client runs:

     ~~~
        issue_input = Generate(cli_cfg, m)
     ~~~

     where `m` is an integer corresponding to the number of tokens that
     should be generated.
  3. The client constructs a `client_issue_storage` message and sends it
     to the `CLIENT_ISSUE_STORAGE` interface, where
     `<server_id>=msg.server_id`,
     `<client_data>=issue_input.client_data`.
  4. The client constructs a `client_issue` message and sends it to the
     server corresponding to `<server_id>` with
     `<issue_data>=issue_input.msg_data`.
  5. Receives a `server_issue_resp` message back from client_data
     server, and sends this to the `CLIENT_ISSUE_FINISH` interface.

### CLIENT_ISSUE_FINISH {#interface-cli-issue-finish}

- Visibility: `internal`
- Input: a message `msg` of type `server_issue_resp`
  ({{msg-server-issue-resp}}).
- Returns: `null`
- Steps:
  1. The client sends an empty message to the `CLIENT_ISSUE_RETRIEVAL`
     interface and receives a `client_issue_retrieval` message `tmp` in
     response.
  2. The client sets `cli_cfg=tmp.config`.
  3. The client runs:

     ~~~
      tokens = Process(cli_cfg,(msg.evals, msg.proof),tmp.g_data)
     ~~~

  4. The client constructs a `client_token_storage` message and sends it
     to the `CLIENT_TOKEN_STORAGE` interface, where `<tokens>=tokens`.

### CLIENT_REDEEM {#interface-cli-redeem}

- Visibility: `internal`
- Input: a message `msg` of type `client_redeem_generation`
  ({{msg-client-redeem-generation}}).
- Returns: a boolean value `ret` indicating whether the server accepted
  the redemption, or not.
- Steps:
  1. The client runs:

     ~~~
        cli_cfg = ClientSetup(msg.ciphersuite, msg.config)
     ~~~

  2. The client generates arbitrary auxiliary data `aux` and runs:

     ~~~
        tag = Redeem(cli_cfg, msg.token, aux)
     ~~~

  3. The client constructs a `client_redeem` message and sends it to the
     `SERVER_REDEEM` interface of the Server referred to by
     `<server_id>`, with `<data>=msg.token.data` and `<aux>=aux`.

  4. The client returns the value boolean value indicated in the
     `RedemptionResponse` received in the server's `server_redeem_resp`
     message.

### CLIENT_ISSUE_STORAGE {#interface-cli-issue-storage}

- Visibility: `internal`
- Input: a `client_issue_storage` message `msg`
  ({{msg-client-issue-storage}}).
- Returns: `null`
- Steps:
  1. Stores the `ClientIssuanceProcessing` struct represented by
     `msg.client_data` in local storage, keyed by `server_id`,
     `ciphersuite` and `comm_id`.

### CLIENT_ISSUE_RETRIEVAL {#interface-cli-issue-retrieval}

- Visibility: `internal`
- Input: a `client_issue_retrieval` message `msg`
  ({{msg-client-issue-retrieval}}).
- Returns: a `client_issue_retrieval_resp` message
  ({{msg-client-issue-retrieval-resp}}).
- Steps:
  1. Retrieve `client_data` where `msg.server_id`, `msg.ciphersuite`
     and `msg.comm_id`.
  2. Return a `client_issue_retrieval` message containing `client_data`
     above to the `CLIENT_ISSUE_FINISH` interface.

### CLIENT_TOKEN_STORAGE {#interface-cli-token-storage}

- Visibility: `internal`
- Input: a `client_token_storage` message `msg`
  ({{msg-client-token-storage}}).
- Returns: `null`
- Steps:
  1. Stores the vector of `RedemptionToken` objects in local storage
     keyed by `server_id`, `ciphersuite` and `comm_id`.

### CLIENT_TOKEN_RETRIEVAL {#interface-cli-token-retrieval}

- Visibility: `internal`
- Input: a `client_token_retrieval` message `msg`
  ({{msg-client-token-retrieval}}).
- Returns: a `client_token_retrieval_resp` message.
- Steps:
  1. Retrieve all the available token `tokens` keyed by `msg.server_id`,
     `msg.ciphersuite` and `msg.comm_id`.
  2. If `tokens != null`, let `token = tokens.pop()`.
  3. Store the modified `tokens` object back in local storage by
     interacting with the `CLIENT_TOKEN_STORAGE` interface.
  4. Return a `client_token_retrieval` message containing the token
     value above (or `null` if `tokens == null`) to the
     `CLIENT_CONFIG_RETRIEVAL` interface.

## Global configuration registry interfaces {#config-interfaces}

### GLOBAL_CONFIG_UPDATE {#interface-cfg-update}

- Visibility: `external`
- Input: a `config_update` message `msg` ({{msg-config-update}}).
- Returns: `null`
- Steps:
  1. Creates an entry in the global config registry, keyed by
     `msg.server_id`, `msg.config.ciphersuite` and `msg.comm_id`.
     Therefore, the registry data block takes the form:

     ~~~
        server_id: msg.server_id
          ciphersuite: msg.config.ciphersuite
            comm_id: msg.comm_id
              config: msg.config
              expiry: msg.expiry
              signature: msg.signature
              supports: msg.supports
     ~~~

  2. Updates `server_id.previous` to be equal to a structure of the
     form:

     ~~~
        struct {
          Ciphersuite ciphersuite = current.ciphersuite
          int16 comm_id = current.comm_id
        }
     ~~~

     where the `Ciphersuite` struct is described in
     {{draft-davidson-pp-protocol}}.

  3. Updates `server_id.current` to be equal to a structure of the form:

     ~~~
        struct {
          Ciphersuite ciphersuite = msg.ciphersuite
          int16 comm_id = msg.comm_id
        }
     ~~~

  4. Appends the current time to the vector of datetime values in
     `server_id.modified`.

### GLOBAL_CONFIG_RETRIEVAL {#interface-cfg-retrieval}

- Visibility: `external`
- Input: a `config_retrieval` message `msg` ({{msg-config-update}}).
- Returns: a `config_retrieval_resp` message
  ({{msg-config-retrieval-resp}}).
- Steps:
  1. Retrieve the data structure `server_ds` from the global config
     registry, keyed by `msg.server_id`.
  2. Let `current=server_ds[current.ciphersuite][current.comm_id]`
  3. Let `previous=server_ds[previous.ciphersuite][previous.comm_id]`
  4. Return a `config_retrieval_resp` message of the form below, to the
     querying interface.

     ~~~
        cfg_0 = config_entry {
          ciphersuite: current.ciphersuite,
          comm_id: current.comm_id,
          config: current.config,
          expiry: current.expiry,
          signature: current.signature,
          supports: current.supports,
        };
        cfg_1 = config_entry {
          ciphersuite: current.ciphersuite,
          comm_id: current.comm_id,
          config: current.config,
          expiry: current.expiry,
          signature: current.signature,
          supports: current.supports,
        };
        resp = config_retrieval_resp {
          configs: [cfg_0, cfg_1],
        }
     ~~~

# Key management framework {#key-mgmt}

Rather than sending the result of the key initialisation procedure
directly to each client, it is preferable for a server to upload its
current configurations to a trusted, tamper-proof, history-preserving
registry. By trusted, we mean from the perspective of clients that use
the Privacy Pass protocol. Any new keys uploaded to the registry should
be appended to the list. Any keys that have expired can optionally be
labelled as so, but should never be removed. A trusted registry may hold
key commitments for multiple Privacy Pass service providers (servers).

As we discuss in {{privacy}}, the implementation of the key management
policy has a major impact on the privacy properties of the Privacy Pass
ecosystem that it belongs to.

To prevent unauthorized modification of the trusted registry, server's
should be required to identify and authenticate themselves before they
can append data to their configuration. Moreover, only parts of the
registry that correspond to the servers configuration can be modifiable.

We intend for the registry that we describe to be fulfilled by existing
frameworks, such as Key Transparency {{keytrans}} or other similar
architectures.

## Global configuration {#global}

As alluded to above, key management for the Privacy Pass ecosystem
should be controlled by a single global key configuration registry. This
registry must be available at a publicly-known address and MUST hold all
of the configuration data for all of the Privacy Pass servers in the
ecosystem. Supporting more than one configuration registry could lead to
privacy concerns.

The registry MUST support the interfaces constructed in
{{config-interfaces}}.

## Configuration structure {#config-structure}

The global config registry is organized as a key-value store
corresponding to all of the configurations supported by all of the
recognized servers that are part of the Privacy Pass ecosystem. The
structure of the configuration takes the form below.

~~~
server_id: <server_id_1>
  verification_key: <verification_key>
  current: <current>
  previous: <previous>
  modified: <modified>
  ciphersuite: <ciphersuite_1>
    comm_id: <comm_id_1>
      config: <config>
      expiry: <expiry>
      supports: <supports>
      signature: <signature>

    .
    .
    .

    comm_id: <comm_id_z>
      config: <config>
      expiry: <expiry>
      supports: <supports>
      signature: <signature>
  .
  .
  .

  ciphersuite: <ciphersuite_y>
    ...
.
.
.

server_id: <server_id_x>
  ...
~~~

Essentially, each server corresponds to a single `server_id` and
`ciphersuite` corresponds to the different ciphersuites that the server
can use. Each configuration is defined by the data in the `config`,
`expiry`, `supports` and `signature` fields. The `config` field contains
the data represented in the `ServerUpdate` struct
{{draft-davidson-pp-protocol}}, for example including the public key
`pub_key` of the server, and the value of `max_evals`.

Each server defines a separate verification key in the
`verification_key` field corresponding to the long-term signing key that
is used for signing each of the individual configurations and `comm_id`
values that it possesses.

The `current`, `previous` and `modified` fields are the only fields that
change during configuration updates. The `current` field refers to the
latest configuration to support token issuance. The `previous` field is
used for a single configuration that still permits redemption of tokens,
this is used for ensuring that key rotations are smooth for clients. The
`modified` field refers to a vector of all times when the configuration
was modified.

## Configuration updates #{config-update}

Whenever a server wants to rotate their current configuration, they must
create a request to append their new configuration to the trusted
registry. This request is handled by the global registry to update the
configuration, see the `GLOBAL_CONFIG_UPDATE` interface.

Each update results in adding a new config underneath an existing
`<ciphersuite>` with a new `<comm_id>` parameter, or a new
`<ciphersuite>` entry. The global config registry also updates, the
`current`, `previous` and `modified` fields to indicate that the change
has occurred.

For reasons that are addressed more closely in {{privacy}}, the global
configuration registry must ensure that the only configurations that
are used at any given time, are those referred to in `current` and
`previous`. This is done to ensure that the server is not able to serve
tokens to clients from multiple different configurations (which could be
used to decrease the size of client anonymity sets).

All fields apart from the three referenced above MUST never be modified.
If a server wants to rotate the long-term `verification_key` it must
create a new server identity.

## Client retrieval

Clients can either choose to:

- poll the trusted registry and import new keys, rejecting any that
  throw errors;
- retrieve the commitments for the server at the time at which they are
  used, throwing errors if no valid commitment is available.

In the interfaces in {{client-interfaces}} we default to assuming that
the client retrieves the latest configuration as and when it is needed.
See the `CLIENT_CONFIG_RETRIEVAL` interface
({{interface-cli-retrieval}}) for more details.

The client checks that the configuration is consistent with the data it
receives from the server. It also checks the validity of the `signature`
field on the configuration that it retrieves. Later we also discuss
optionally checking the values in `modified` for trying to identify
malicious server behavior.

## Key revocation

Currently, key revocation is only supported by rotating the current
configuration. In the future, we may consider adding an explicit
mechanism for revoking a specific configuration (for example the active
redemption configuration referred to by `server_id.previous`) without
rotating the current issuance key.

# Server running modes {#running-modes}

We provide an overview of some of the possible frameworks for
configuring the way that servers run in the Privacy Pass ecosystem. In
short, servers may be configured to provide symmetric issuance and
redemption with clients. While some servers may be configured as proxies
that accept Privacy Pass data and send it to another server that
actually processes issuance and/or redemption data.

The intention with providing each of these running modes is to cover the
different applications that utilize variants of the Privacy Pass
protocol. We RECOMMEND that any Privacy Pass server implementation
adheres to one of these frameworks.

## Single-Issuer Single-Verifier {#sisv}

The simplest way of considering the Privacy Pass protocol is in a
setting where the same server plays the role of issuer and verifier, we
call this "Single-Issuer Single-Verifier" (SISV). In SISV, we consider a
server S that publishes commitments for their secret key k, that a
client C has access to.

When S wants to issue tokens to C, they invoke the issuance protocol
where C generates their own inputs and S uses their secret key k. In
this setting, C can only perform token redemption with S. When a token
redemption is required, C and S invoke the redemption phase of the
protocol, where C uses an issued token from a previous exchange, and S
uses k as their input again.

In SISV, C proves that S has attested to the honesty of C at some point
in the past (without revealing exactly when). S can use this information
to inform it's own decision-making about C without having to recompute
the trust attestation task again.

## Single-Issuer Forwarding-Verifier {#sifv}

In this setting, each client C obtains issued tokens from a server S via
the issuance phase of the protocol. The difference is that clients can
prove that S has attested to their honesty in the past with any verifier
V. We still only consider S to hold their own secret key.

When C interacts with V, V can ask C to provide proof that the separate
issuer S has attested to their trust. The first stage of the redemption
phase of the protocol is invoked between C and V, which sees C send the
unused token (x,y,aux) to V. This message is then used in a redemption
exchange between V and S, where V plays the role of the client. Then S
sends the result of the redemption exchange to V, and V uses this result
to determine whether C has the correct trust attestation.

This configuration is known as "Single-Issuer Forwarding-Verifier" or
SIFV to refer to the verifier V who uses the output of the redemption
phase for their own decision-making.

## Single-Issue Asynchronous-Verifier {#siav}

This setting is inspired by recently proposed APIs such as {{TrustTokenAPI}}. It
is similar to the SIFV configuration, except that the verifiers V no
longer interact with the issuer S. Only C interacts with S, and this is
done asynchronously to the trust attestation request from V. Hence
"Asynchronous-Verifier" (SIAV).

When V invokes a redemption for C, C then invokes a redemption exchange
with S in a separate session. If verification is carried out
successfully by S, S instead returns a Signed Redemption Record (SRR)
that contains the following information:

~~~ json
"result": {
  "timestamp":"2019-10-09-11:06:11",
  "verifier": "V",
},
"signature":sig,
~~~

The `signature` field carries a signature evaluated over the contents of
`result` using a long-term signing key for the issuer S, of which the
corresponding public key is well-known to C and V. Then C can prove that
their trust attestation from S to V by sending the SRR to V. The SRR can
be verified by V by verifying the signature using the well-known public
key for S.

Such records can be cached to display again in the future. The issuer
can also add an expiry date to the record to determine when the client
must refresh the record.

## Bounded-Issuers {#bi-mode}

Each of the configurations above can be generalized to settings where a
bounded number of issuers are allowed, and verifiers can invoke trust
attestations for any of the available issuers. Subsequently, this leads
to three new configurations known as BISV, BIFV, BIAV.

As we will discuss later in {{privacy}}, configuring a large number of
issuers can lead to privacy concerns for the clients in the ecosystem.
Therefore, we are careful to ensure that the number of issuers is kept
strictly bounded by a fixed small number M. The actual issuers can be
replaced with different issuers as long as the total never exceeds M.
Moreover, issuer replacements also have an effect on client privacy that
is similar to when a key rotation occurs, so replacement should only be
permitted at similar intervals.

See {{privacy}} for more details about safe choices of M.

# Privacy considerations {#privacy}

In the Privacy Pass protocol {{draft-davidson-pp-protocol}}, redemption
tokens intentionally encode no special information into redemption
tokens to prevent a vendor from learning anything about the client. We
also have cryptographic guarantees via the VOPRF construction that a
vendor can learn nothing about a client beyond which issuers trust it.
Still there are ways that malicious servers can try and learn
identifying information about clients that it interacts with.

We discuss a number of privacy considerations relative to the Privacy
Pass ecosystem that we are constructing. In addition, we discuss
considerations arising from the specific ways of using the Privacy Pass
protocol in {{running-modes}}.

## User segregation {#segregation}

The goal of the Privacy Pass ecosystem is to construct an environment
where can easily measure (and maximize) relative anonymity of any client
that is part of it. An inherent feature of being part of this ecosystem
is that any client can only remain private relative to the entire space
of users using the protocol. In principle, we would hope that the server
can link any client redemption to any specific issuance invocation with
a probability that is equivalent to guessing. However, in practice, the
server can increase this probability using a number of techniques that
can segregate the user space into smaller sets.

### Server configuration rotation

Techniques to introduce segregation are closely linked to the type of
key schedule that is used by the server. When a server rotates their
key, any client that invokes the issuance protocol shortly afterwards
will be part of a small number of possible clients that can redeem. To
mechanize this attack strategy, a server could introduce a configuration
rotation policy which would force clients into smaller windows where a
given config is valid. This would mean that client privacy would only
have utility with respect to the smaller group of users that hold
redemption data for a particular key window.

We RECOMMEND that great care is taken over key rotations, in particular
server's should only invoke key rotation for fairly large periods of
time such as between 1 and 12 weeks. Key rotations represent a trade-off
between client privacy and continued server security. Therefore, it is
still important that key rotations occur on a fairly regular cycle to
reduce the harmfulness of a server key compromise.

As we describe in {{key-mgmt}}, a trusted registries for holding Privacy
Pass configurations is required for policing the key schedule that a
server uses. Clients may choose to inspect the history of the registry
before first accepting redemption tokens from the server. Concrete
suggestions include the following:

- If a server has updated the registry with many unexpired keys, or in
  very quick intervals a client SHOULD reject the configuration. The
  client can check this by checking the list of times when the server
  modified their own configuration in the vector `modified`. This
  prevents a server from segregating clients into smaller windows using
  the redemption data that they hold.
- If a server has only recently updated their configuration (within the
  last few minutes), then the client SHOULD refuse to use it. This
  prevents against a server that may try and deanonymize a specific
  client.

### Large numbers of issuers {#issuers}

Similarly to the configuration rotation issue raised above, if there are
a large number of issuers, similar user segregation can occur. In the
BISV, BIFV, BIAV configurations of using the Privacy Pass protocol
({{running-modes}}), a verifier OV can trigger redemptions for any of
the available issuers. Each redemption token that a client holds
essentially corresponds to a bit of information about the client that OV
can learn. Therefore, there is an exponential loss in privacy relative
to the number of issuers that there are.

For example, if there are 32 issuers, then OV learns 32 bits of
information about the client. If the distribution of issuer trust is
anything close to a uniform distribution, then this is likely to
uniquely identify any client amongst all other Internet users. Assuming
a uniform distribution is clearly the worst-case scenario, and unlikely
to be accurate, but it provides a stark warning against allowing too
many issuers at any one time.

As we noted in {{bi-mode}}, a strict bound should be applied to the
active number of issuers that are allowed at one time in the ecosystem.
We propose that allowing no more than 4 issuers at any one time is
highly preferable (leading to a maximum of 64 possible user
segregations). However, as highlighted in {{parametrization}}, having a
very large user base (> 5 million users), could potentially allow for
larger values. Issuer replacements should only occur with the same
frequency as config rotations as they can lead to similar losses in
privacy if clients still hold redemption tokens for previously active
issuers.

In addition, we RECOMMEND that trusted registries indicate at all times
which issuers are deemed to be active. If a client is asked to invoke
any Privacy Pass exchange for an issuer that is not declared active,
then the client SHOULD refuse to retrieve the server configuration
during the protocol.

#### Single global configuration authority

Any Privacy Pass ecosystem MUST only contain a single global authority
for controlling and managing server configurations.

This prevents servers from posting different configurations to different
global authorities that are all simultaneously trusted by the clients.
In such situations, the deanonymization potential would be similar to
providing multiple active configurations.

#### Maximum number of issuers inferred by client

We RECOMMEND that clients only store redemption tokens for a fixed
number of issuers at any one time. This number would ideally be less
than the number of permitted active issuers.

This prevents a malicious verifier from being able to invoke redemptions
for many issuers since the client would only be holding redemption
tokens for a small set of issuers. When a client is issued tokens from a
new issuer and already has tokens from the maximum number of issuers, it
simply deletes the oldest set of redemption tokens in storage and then
stores the newly acquired tokens.

### Additional token metadata

In {{draft-davidson-pp-protocol}}, it is permissible to add public and
private metadata bits to redemption tokens. While the core protocol
instantiation that is described does not include additional metadata,
future instantiations may use this functionality to provide redemption
verifiers with additional information about the user.

Note that any arbitrary bits of information can be used to further
segment the size of the user's anonymity set. Any issuer that wanted to
track a single user could add a single metadata bit to user tokens. For
the tracked user it would set the bit to `1`, and `0` otherwise. Adding
additional bits provides an exponential increase in tracking granularity
similarly to introducing more issuers (though with more potential
targeting).

For this reason, the amount of metadata used by an issuer in creating
redemption tokens must be taken into account together with the bits of
information that issuer's may learn about clients from the means listed
above. We discuss this more in {{parametrization}}.

## Tracking and identity leakage

Privacy losses may be encountered if too many redemptions are allowed in
a short burst. For instance, in the Internet setting, this may allow
non-terminating verifiers to learn more information from the metadata
that the client may hold (such as first-party cookies for other
domains). Mitigations for this issue are similar to those proposed in
{{issuers}} for tackling the problem of having large number of issuers.

In SIAV, cached SRRs and their associated issuer public keys have a
similar tracking potential to first party cookies in the browser
setting. These considerations will be covered in a separate document
detailing Privacy Pass protocol integration into the wider web
architecture {{draft-svaldez-pp-http-api}}.

## Client incentives for anonymity reduction

Clients may see an incentive in accepting all tokens that are issued by
a server, even if the tokens fail later verification checks. This is
because tokens effectively represent a form of currency that they can
later redeem for some sort of benefit. The verification checks that are
put in place are there to ensure that the client does not sacrifice
their anonymity. However, a client may judge the "monetary" benefit of
owning tokens to be greater than their own privacy.

Firstly, none of the interfaces that we have described permit this type
of behavior, as they utilize the underlying Privacy Pass API that
carries out this verification. A client behaving in this way would not
be compliant with the protocol.

Secondly, acting in this way only affects the privacy of the immediate
client. There is an exception if a large number of clients colluded to
accept bad data, then any client that didn't accept would be part of a
smaller anonymity set. However, such an situation would be identical to
the situation where the total number of clients in the ecosystem is
small. Therefore, the privacy impact would be equivalent; see
{{issuers}} for more details.

# Security considerations {#security}

We present a number of security considerations that prevent a malicious
actors from abusing the protocol.

## Double-spend protection

All issuing server should implement a robust storage-query mechanism for
checking that tokens sent by clients have not been spent before. Such
tokens only need to be checked for each issuer individually. But all
issuers must perform global double-spend checks to avoid clients from
exploiting the possibility of spending tokens more than once against
distributed token checking systems. For the same reason, the global data
storage must have quick update times. While an update is occurring it
may be possible for a malicious client to spend a token more than once.

## Configuration rotation

We highlighted previously that short configuration-cycles can be used to
reduce client privacy. However, regular key rotations are still
recommended to maintain good server key hygiene. The key material that
we consider to be important are:

- the Server secret key for issuing Privacy Pass data;
- the signing key used to sign configuration information;
- the signing key used to sign SRRs in the SIAV configuration.

We recommend that Privacy Pass secret keys are rotated from anywhere
between 1 and 12 weeks. With an active user-base, a week gives a fairly
large window for clients to participate in the Privacy Pass protocol and
thus enjoy the privacy guarantees of being part of a larger group. The
low ceiling of 12 weeks prevents a key compromise from being too
destructive. If a server realizes that a key compromise has occurred
then the server should revoke the previous key in the trusted registry
and specify a new key to be used.

For the two signing keys, these should both be well-known keys
associated with the issuer. Issuers may choose to use the same key for
both signing purposes. The rotation schedules for these keys can be much
longer, if necessary. Rotations of these keys results in the creation of
a new server identity.

## Token exhaustion

When a client holds tokens for an issuer, it is possible for any
verifier to invoke that client to redeem tokens for that issuer. This
can lead to an attack where a malicious verifier can force a client to
spend all of their tokens for a given issuer. To prevent this from
happening, methods should be put into place to prevent many tokens from
being redeemed at once.

For example, it may be possible to cache a redemption for the entity
that is invoking a token redemption. In SISV/SIFV, if the verifier
requests more tokens then the client simply returns the cached token
that it returned previously. This could also be handled by simply not
redeeming any tokens for the entity if a redemption had already occurred
in a given time window.

In SIAV, the client instead caches the SRR that it received in the
asynchronous redemption exchange with the issuer. If the same verifier
attempts another redemption request, then the client simply returns the
cached SRR. The SRRs can be revoked by the issuer, if need be, by
providing an expiry date or by signaling that records from a particular
window need to be refreshed.

# Protocol parametrization {#parametrization}

We provide a summary of the parameters that we use in the Privacy Pass
protocol ecosystem. These parameters are informed by both privacy and
security considerations that are highlighted in {{privacy}} and
{{security}}, respectively. These parameters are intended as a single
reference point for those implementing the protocol.

Firstly, let U be the total number of users, I be the total number of
issuers. We let M be the total number of metadata bits that are allowed
to be added by any given issuer. Assuming that each user accept tokens
from a uniform sampling of all the possible issuers, as a worst-case
analysis, this segregates users into a total of 2^I buckets. As such, we
see an exponential reduction in the size of the anonymity set for any
given user. This allows us to specify the privacy constraints of the
protocol below, relative to the setting of A.

| parameter | value |
|---|---|
| Minimum anonymity set size (A) | 5000 |
| Recommended key lifetime (L) | 2 - 24 weeks |
| Recommended key rotation frequency (F) | L/2 |
| Maximum additional metadata bits (M) | 1 |
| Maximum allowed issuers (I) | (log_2(U/A)-1)/2 |
| Maximum active issuance configurations | 1 |
| Maximum active redemption configurations | 2 |
| Minimum cryptographic security parameter | 128 bits |

## Justification

We make the following assumptions in these parameter choices.

- Inferring the identity of a user in a 5000-strong anonymity set is
  difficult.
- After 2 weeks, all clients in a system will have rotated to the new
  key.

In terms of additional metadata, the only concrete applications of
Privacy Pass that use additional metadata require just a single bit.
Therefore, we set the ceiling of permitted metadata to 1 bit for now,
this may be revisited in future revisions.

The maximum choice of I is based on the equation 1/2 * U/2^(2I) = A.
This is derived from the fact that permitting I issuers lead to 2^I
segregations of the total user-base U. Moreover, if we permit M = 1,
then this effectively halves the anonymity set for each issuer, and thus
we incur a factor of 2I in the exponent. By reducing I, we limit the
possibility of performing the attacks mentioned in {{segregation}}.

We must also account for each user holding issued data for more then one
possible active keys. While this may also be a vector for monitoring the
access patterns of clients, it is likely to unavoidable that clients
hold valid issuance data for the previous key epoch. This also means
that the server can continue to verify redemption data for a previously
used key. This makes the rotation period much smoother for clients.

For privacy reasons, it is recommended that key epochs are chosen that
limit clients to holding issuance data for a maximum of two keys. By
choosing F = L/2 then the minimum value of F is a week, since the
minimum recommended value of L is 2 weeks. Therefore, by the initial
assumption, then all users should only have access to only two keys at
any given time. This reduces the anonymity set by another half at most.

Finally, the minimum security parameter size is related to the
cryptographic security offered by the protocol that is run. This
parameter corresponds to the number of operations that any adversary has
in breaking one of the security guarantees in the Privacy Pass protocol
{{draft-davidson-pp-protocol}}. The existing protocol document contains
an instantiation based on verifiable oblivious pseudorandom functions
(VOPRFs) {{I-D.irtf-cfrg-voprf}}. Careful attention should be paid to
whether the available ciphersuites for a protocol instantiation meets
this criteria.

## Example parameterization

Using the specification above, we can give some example
parameterizations. For example, the current Privacy Pass browser
extension {{PPEXT}} has nearly 300000 active users (from Chrome and
Firefox). As a result, log_2(U/A) is approximately 6 and so the maximum
value of I should be 3.

If the value of U is much bigger (e.g. 5 million) then this would permit
I = (log_2(5000000/5000)-1)/2 ~= 4 issuers.

# Recommendations for identifying malicious behavior {#recs-srvr}

TODO: Come up with an effective deterrent for server's that are deemed
to misbehave by a client. Could we have a separate consensus where
clients can upload misbehavior references for servers that they deem to
be malicious?

# Extension integration policy {#extensions}

The Privacy Pass protocol and ecosystem are both intended to be
receptive to extensions that expand the current set of functionality. In
{{draft-davidson-pp-protocol}}, some points are made about how
implementing the Privacy Pass API can be instantiated using different
underlying primitives. The interfaces described in {{integration}}
utilize the API in such a way that internal changes should result in no
visible change to implementers of the Privacy Pass protocol.

As specified in {{draft-davidson-pp-protocol}}, all extensions to the
Privacy Pass protocol SHOULD be specified as separate documents that
modify the content of this document in some way. We provide guidance on
the type of modifications that are possible in the following.

Aside from the underlying protocol, extensions MAY modify the protocol
interfaces from the definition in this document. Such extensions MUST
document exactly which interfaces are changed and any new message
formats that arise. Any such extension should also come with a detailed
analysis of the privacy impacts of the extension, why these impacts are
justified, and guidelines on changes to the parametrization in
{{parametrization}}. Similarly, extensions MAY also add new Server
running modes, if applicable, to those that are documented in
{{running-modes}}.

We RECOMMEND that any extension to the Privacy Pass architecture does
not add new interfaces to those that are listed in {{integration}}. We
expect that any extension is expressible using the interfaces themselves
and reimplementing the existing functionality, if need be. Abiding by
this policy maintains a simplified execution chain that is easy to
reason about.

Extensions MUST NOT modify the format and/or structure of the global
configuration registry, other than specifying the data format of each of
the fields that are used. If an extension requires a modified
configuration registry, then such a change is interpreted to lie outside
of the Privacy Pass ecosystem, and is thus not supported.

# Existing applications {#applications}

The following is a non-exhaustive list of applications that currently
make use of the Privacy Pass protocol, or some variant of the underlying
functionality.

## Cloudflare challenge pages

Cloudflare uses an implementation of the Privacy Pass protocol for
allowing clients that have previously interacted with their Internet
challenge protection system to bypass future challenges {{PPSRV}}. These
challenges can be expensive for clients, and there have been cases where
bugs in the implementations can severely degrade client accessibility.

Clients must install a browser extension {{PPEXT}} that acts as the
Privacy Pass client in an exchange with Cloudflare's Privacy Pass
server, when an initial challenge solution is provided. The client
extension stores the issued tokens and presents a valid redemption token
when it sees future Cloudflare challenges. If the redemption token is
verified by the server, the client passes through the security mechanism
without completing a challenge.

## Trust Token API

The Trust Token API {{TrustTokenAPI}} has been devised as a generic API for
providing Privacy Pass functionality in the browser setting. The API is
intended to be implemented directly into browsers so that server's can
directly trigger the Privacy Pass workflow.

## Zero-knowledge Access Passes

The PrivateStorage API developed by Least Authority is a solution for
uploading and storing end-to-end encrypted data in the cloud. A recent
addition to the API {{PrivateStorage}} allows clients to generate
Zero-knowledge Access Passes (ZKAPs) attesting to the fact that the
client has paid for the storage space that it is using. The ZKAP
protocol is based heavily on the Privacy Pass redemption mechanism. The
client receives ZKAPs when it pays for storage space, and redeems the
passes when it interacts with the PrivateStorage API.

## Basic Attention Tokens

The browser Brave uses Basic Attention Tokens (BATs) to provide the
basis for a privacy-preserving rewards scheme {{Brave}}. The BATs are
essentially Privacy Pass redemption tokens that are provided by a
central Brave server when a client performs some action that triggers a
reward event (such as watching an advertisement). When the client
amasses BATs, it can redeem them with the Brave central server for
rewards.

## Token Based Services

Similarly to BATs, a more generic approach for providing anonymous peers
to purchase resources from anonymous servers has been proposed
{{OpenPrivacy}}. The protocol is based on a variant of Privacy Pass and
is intended to allow clients purchase (or pre-purchase) services such as
message hosting, by using Privacy Pass redemption tokens as a form of
currency. This is also similar to how ZKAPs are used.

--- back

# Message formats {#message-formats}

We detail an exhaustive list of the different message types used in the
Privacy Pass protocol. These messages are sent and received by the
interfaces detailed in {{integration}}. We intend for the messages to be
compatible typical message expression formats such as JSON.

## Server messages

### server_config_store {#msg-config-store}

~~~
struct {
  ServerConfig configs[2];
} server_config_store
~~~

### server_config_retrieve {#msg-config-retrieve}

~~~
struct {
  uint8 method;
  ServerConfig configs[2];
} server_config_retrieve
~~~

### server_hello {#msg-server-hello}

~~~
struct {
  opaque server_id<0..255>;
  uint8 supports;
} server_hello
~~~

### server_issue_resp {#msg-server-issue-resp}

~~~
struct {
  IssuanceResponse data;
} server_issue_resp
~~~

### server_redeem_resp {#msg-server-redeem-resp}

~~~
struct {
  RedemptionResponse data;
} server_redeem_resp
~~~

## Client message formats

### client_issue_generation {#msg-client-issue-generation}

~~~
struct {
  opaque server_id<0..255>;
  ServerUpdate config;
} client_issue_generation
~~~

### client_issue_storage {#msg-client-issue-storage}

~~~
struct {
  opaque server_id<0..255>
  Ciphersuite ciphersuite;
  opaque comm_id<0..2^16-1>;
  ClientIssuanceProcessing client_data;
} client_issue_storage
~~~

### client_issue {#msg-client-issue}

~~~
struct {
  opaque client_id<0..2^16-1>;
  IssuanceMessage issue_data;
} client_issue
~~~

### client_issue_retrieval {#msg-client-issue-retrieval}

~~~
struct {
  opaque server_id<0..255>;
  Ciphersuite ciphersuite;
  opaque comm_id<0..2^16-1>;
} client_issue_retrieval
~~~

### client_issue_retrieval_resp {#msg-client-issue-retrieval-resp}

~~~
struct {
  ClientIssuanceProcessing client_data;
} client_issue_retrieval_resp
~~~

### client_token_storage {#msg-client-token-storage}

~~~
struct {
  opaque server_id<0..255>;
  Ciphersuite ciphersuite;
  opaque comm_id<0..2^16-1>;
  RedemptionToken tokens[m];
} client_token_storage
~~~

### client_token_retrieval {#msg-client-token-retrieval}

~~~
struct {
  opaque server_id<0..255>;
  Ciphersuite ciphersuite;
  opaque comm_id<0..2^16-1>;
} client_token_retrieval
~~~

### client_token_retrieval_resp {#msg-client-token-retrieval-resp}

~~~
method: "client_token_retrieval_resp"
struct {
  RedemptionToken token;
} client_token_retrieval_resp
~~~

### client_redeem_generation {#msg-client-redeem-generation}

~~~
struct {
  opaque server_id<0..255>;
  ServeUpdate config;
  RedemptionToken token;
} client_redeem_generation
~~~

### client_redeem {#msg-client-redeem}

~~~
struct {
  opaque client_id<0..2^16-1>;
  RedemptionMessage message;
} client_redeem
~~~

## Global configuration interfaces

### config_update {#msg-config-update}

~~~
struct {
  opaque server_id<0..255>;
  opaque comm_id<0..2^16-1>;
  ServerUpdate config;
  datetime expiry;
  opaque signature<1..2^32-1>;
} config_update
~~~

### config_retrieval {#msg-config-retrieval}

~~~
struct {
  opaque server_id<0..255>;
} config_retrieval
~~~

### config_retrieval_resp {#msg-config-retrieval-resp}

~~~
struct {
  Ciphersuite ciphersuite;
  opaque comm_id<0..2^16-1>;
  ServerUpdate config;
  datetime expiry;
  opaque signature<1..2^32-1>;
  uint8 supports;
} config_entry

struct {
  config_entry configs[2];
} config_retrieval_resp
~~~
