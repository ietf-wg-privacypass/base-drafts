# Privacy Pass IETF WG Charter

The Privacy Pass protocol provides a performant, application-layer
mechanism for token creation and anonymous redemption. Servers (Issuers)
create and later verify tokens that are redeemed by an ecosystem of
clients, such that:

- An Issuer cannot link a redeemed token to one of N previously created tokens
  using the same key with probability non-negligibly larger than 1/N.
- Clients can verify that a token created by an Issuer corresponds to a
  committed keypair.
- Tokens are unforgeable.
- The token issuance and redemption mechanisms are efficient.

The primary purpose of the Privacy Pass Working Group is to develop and
standardize a protocol that meets these requirements, influenced by
applications that have arisen from the wider community. The aims of the
Working Group can be split into three distinct goals:

First, specify an extensible protocol for creating and redeeming
anonymous and transferrable tokens. The protocol should permit suitable
cryptographic ciphersuites and security parameterization for
cryptographic agility. The cryptographic profile used by the protocol
participants will be determined by the specific instantiation of the
protocol, and it will be fixed for the duration of an Issuer's committed
keypair. We will work closely with
the CFRG in determining acceptable cryptographic ciphersuites and parameters
that satisfy the security and privacy properties of the protocol. The
Working Group will specify a preliminary set of extensions, including
Issuer-supplied metadata and cryptographic instantiations
that additionally support public verifiability of Issued tokens, and may
consider any
additional extensions that arise in the future. Security and privacy
properties of the protocol shall be well-documented. Formal analysis of
the protocol will ensure that the security and privacy properties of the
protocol are well-understood and well-documented.

Second, describe and develop protocol use cases and properties thereof.
This includes, though is not limited to:

1. Describing use cases and interfaces that allow the protocol to be
   used for those use cases.
2. Defining the privacy goals for each Client during protocol execution,
   along with expectations placed on the Issuers and the ecosystem at
   large.
3. Describing recommended parameterization(s) of variables associated with
   the protocol ecosystem that control the size of the anonymity set
   that the client belongs to.
4. Describing verification mechanisms for trusting Issuers and their
   corresponding keying material. Such mechanisms should prevent Issuers
   from presenting any key material that could be used to deanonymize
   clients.
5. Describing the procedure for including small amounts of metadata with
   Issued tokens, as well as the associated impacts on privacy.
6. Describing the risk and possible ramifications of Issuer
   centralization, and exploring possible mechanisms to mitigate these
   risks.

Third, and finally, specify a HTTP-layer API for the protocol. This
includes a common understanding of how Privacy Pass is integrated with
HTTP requests and responses for web-based applications.

The following milestones (along with the approximate dates of
completion) will be used to judge the progress of the working group:

- Specification of protocol & surrounding architecture - February 2021.
- Risk assessment for centralization in Privacy Pass deployments for
  multiple design options - February 2021
- Specification of application-layer requirements (including HTTP
  integration) - June 2021.
- Specification of HTTP browser API (in coordination with W3C) - October
  2021.

Note that the specifications developed by this working group will be
informed by the following initial drafts:

- draft-davidson-pp-protocol-00;
- draft-davidson-pp-architecture-00;
- draft-svaldez-pp-http-api-00.

These existing drafts may be further developed into the core
deliverables of the working group, supplemented by any additional
extensions. Alternatively, they may contribute indirectly to a future
set of documents that meet the core goals of the working group.
