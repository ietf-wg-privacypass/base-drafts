# Privacy Pass IETF WG Charter

The Privacy Pass protocol was first proposed in November 2017 as a performant
mechanism for providing privacy-preserving attestation of a previous successful
authorization between a human and a server.

The primary purpose of the Privacy Pass working group is to develop and
standardize the protocol, influenced by applications that have arisen from the
wider community. The main requirements of the working group are to develop a
protocol that satisfies the following properties:

- Issued tokens are unlinkable with other tokens corresponding to the same
  anonymity set.
- Tokens are unforgeable.
- The issuance and verification mechanisms are practically efficient.

The aims of the working group can be split into three distinct goals that we
describe below.

1. Develop the specification of the generic protocol:
   - Specify the full cryptographic authorization exchange and terminology along
     with suitable ciphersuites (and security parametrizations) for maintaining
     security for a meaningful time period.
       - The negotiation of ciphersuites is determined by the
         application-specific profile and out-of-scope for this protocol.
   - Describe the structure of protocol messages.
   - Describe a framework for extensions to the base protocol for achieving
     additional functionality, or for providing different security guarantees.

2. Develop the wider architecture for running the protocol
   - Construct interfaces that make the protocol suitable for integration with
     potential use-cases.
       - Including required functions for applications
   - Document potential applications of the protocol and of its official
     extensions
   - Define the privacy goals for each client during the exchange, along with
     expectations placed on the server and the ecosystem at large.
   - Analyze mechanisms for tracking via public key and expectations placed on
     server.
   - Privacy considerations of incentives for not verifying messages correctly
     (along with general threat model).

3. Develop document for Privacy Pass in HTTP?
   - Specify a common understanding of how Privacy Pass data is integrated with
     HTTP requests and responses for web-based applications.
   - Specify where key material stored, how it’s accessed, and associated
     security considerations

Each goal listed above will be fulfilled with an individual document that
addresses the necessary conditions. Once these documents are completed, this
working group will have concretized a standardized architecture for constructing
instances of the protocol. As a consequence, this will enable an ecosystem of
applications that depend on the authorization framework provided by Privacy
Pass.

In particular, by the time that the working group achieves consensus around
these documents, we hope to have a number of interoperable implementations, a
clear analysis of the security and privacy considerations, and a diverse
ecosystem of concrete applications.

Note that the specifications developed by this working group will be informed by
draft-irtf-cfrg-voprf which is currently owned by the Crypto Forum Research
Group (CFRG@IRTF). In addition, draft-privacy-pass will serve as a starting
point for the work of the working group.