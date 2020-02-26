---
title: "Privacy Pass: HTTP API"
abbrev: PP http api
docname: draft-pp-http-api-latest
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: S. Valdez
    name: Steven Valdez
    org: Google LLC
    email: svaldez@chromium.org


informative:
  RFC5785:
  RFC4648:
  draft-ietf-httpbis-header-structure-15:
  
--- abstract

This document specifies an integration for Privacy Pass over an HTTP API,
along with recommendations on how key commitments are stored and accessed
by HTTP-based consumers.

--- middle

# Introduction

The Privacy Pass protocol as described in {{draft-davidson-pp-protocol}}
can be integrated with a number of different settings, from server to
server communication to browsing the internet.

In this document, we will provide an API to use for integrating Privacy
Pass with an HTTP framework. Providing the format of HTTP requests and
responses needed to implement the Privacy Pass protocol.

### Terminology

The following terms are used throughout this document.

- Server: A service that provides access to a certain resource
  (typically denoted S)
- Client: An entity that seeks authorization from a server (typically
  denoted C)
- Key: Server VOPRF key
- Commitment: Alternative name for Server's public key.

### Protocol messages

Protocol messages are described in the TLS presentation language
[RFC8446] and will be encoded as raw bytes strings within the containing
headers.

## Layout

- {{wrapping}}: Describes the wrapping of messages within HTTP
  requests/responses.
- {{config-retrieval}}: Describes how HTTP clients retrieve server
  configurations.
- {{commitment}}: Describes how HTTP clients retrieve key commitments as
  part of the issuance/redemption actions.
- {{issuance}}: Describes how issuance requests are performed via a HTTP
  API.
- {{redemption}}: Describes how redemption requests are performed via a
  HTTP API.
- {{storage}}: Describes how HTTP clients should store and discard
  received Privacy Pass tokens.

## Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}.

# Privacy Pass HTTP API Wrapping {#wrapping}

Messages from HTTP-based clients to HTTP-based servers are performed as
GET and POST requests. The messages are sent via the
``Sec-Privacy-Pass`` header.

``Sec-Privacy-Pass`` is a Dictionary Structured Header
[draft-ietf-httpbis-header-structure-15]. The dictionary has two keys:

- ``type`` whose value is a String conveying the function that is being
  performed with this request.
- ``body`` whose value is a byte sequence containing a Privacy Pass
  protocol message.
  
Note that the requests may contain addition Headers, request data and
URL parameters that are not specified here, these extra fields should be
ignored, though may be used by the server to determine whether to
fulfill the requested issuance/redemption.

# Server Configuration Retrieval {#config-retrieval}

TODO: Is server configuration even necessary, it should be able to get
all this information from the key commitment retrieval.

Inputs:
- ``server_origin``: The origin to retrieve a server configuration for.

No outputs.

The client makes a GET request to
<``server_origin``>/.well-known/privacy-pass with a message of type
``config`` and an empty body. (TODO: Add well-known registration)

The server looks up the configuration associated with the origin
``server_origin`` and responds with a message of type ``config`` and a
body of:

~~~
struct {
    opaque server_id<1..2^16-1>;
    uint16 config_id;
    opaque version<1..2^8-1>;
}
~~~

The client 


## Requesting a server configuration

# Key Commitment Retrieval {#key-commitment}

# Privacy Pass Issuance {#issuance}

Inputs:
- ``server_origin``: The origin to retrieve a server configuration for.
- ``count``: The number of tokens to request issuance for.

Outputs:
- ``tokens``: A list of tokens that have been signed via the Privacy
  Pass protocol.

When a client wants to request tokens from a server, it should first
fetch a key commitment from the issuer via the process described in
{{key-commitment}}.

The client should then call the ``CLIENT_ISSUE_GEN`` interface
requesting ``count`` tokens storing the resulting ``issue_data``.

The client then makes a POST request to
<``server_origin``>/.well-known/privacy-pass with a message of type
``issue`` and a body of:

~~~
enum { Normal(0) } IssuanceType;

struct {
    IssuanceType type = 0;
    opaque issue_data<0..2^16-1> = client_issue.issue_data;
}
~~~

The server, upon receipt of the ``request`` should call the
``SERVER_ISSUE`` interface with the value of ``issue_data`` with a
result of ``server_issue_resp``.

The server should then respond to the POST request with a message of
type ``issue`` and a body of:

~~~
struct {
    IssuanceType type = request.type;
    uint16 config_id = server_issue_resp.config_id;
    opaque evals<1..2^16-1> = server_issue_resp.evals;
    opaque proof<1..2^16-1> = server_issue_resp.proof;
}
~~~


# Privacy Pass Redemption {#redemption}

# Privacy Pass Storage {#storage}


# Scraps


Token Issuance
Request
Issuance will look like an HTTP request with a new structured request header specifying a list of encoded tokens:

Sec-Trust-Token: <val>

where val is the base-64 encoding of TRUST_TOKEN_Client_BeginIssuance’s output.

The URL this is sent to is specified by the Javascript API. This new header will only be added to HTTPS destinations, and cookies will be attached according to normal UA policy (i.e. we must abide by users’ cookie settings).

Internally, the browser does a check for key commitments at issuance time. In the future, we might try to optimize the protocol flow to eliminate this round trip.
Response
Chrome will expect a response that has the following new header:

             Sec-Trust-Token: <val>

where val is the base-64 encoding of TRUST_TOKEN_Issuer_PerformIssuance‘s output.
Token Redemption
Request
A redemption request will look like a standard HTTP request with the following new request header.
Sec-Trust-Token: <val>

where val is the base-64 encoding of TRUST_TOKEN_Client_BeginRedemption’s output, called with a token popped from storage. 
Response
The response should be of the form
Sec-Trust-Token: <val>

where val is the base-64 encoding of TRUST_TOKEN_Issuer_PerformRedemption‘s output.
Key consistency checks
Issuance and redemption requests come in two separate HTTP requests: one for checking key consistency and one for actually redeeming a token. For privacy, these requests must be serialized.

Request: A key consistency check will just look like a GET request to the following URL (more details in the implementation section below):
<issuer origin>/.well-known/trust-token-keys

Response: The browser expects a response containing some configuration metadata and a collection of “key commitments”, each roughly (see below) of the form:
“<key_label>”: { "Y": <base64-encoded public key>,
                 "expiry": <expiry_date> }
