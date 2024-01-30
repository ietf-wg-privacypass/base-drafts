![IETF-Badge-PRIVACY-PASS-Color@3x (1)](https://github.com/ietf-wg-privacypass/base-drafts/assets/191945/5254697a-1d66-4a19-93d5-ca36879d5c02)

# privacy-pass-ietf

The current home for material associated with Privacy Pass documentation associated with the IETF. Current WG documents are below:

- [Architecture](https://ietf-wg-privacypass.github.io/base-drafts/draft-ietf-privacypass-architecture.html) ([Datatracker Page](https://datatracker.ietf.org/doc/draft-ietf-privacypass-architecture/))
- [Auth Scheme](https://ietf-wg-privacypass.github.io/base-drafts/draft-ietf-privacypass-auth-scheme.html) ([Datatracker Page](https://datatracker.ietf.org/doc/draft-ietf-privacypass-auth-scheme/))
- [Issuance Protocol](https://ietf-wg-privacypass.github.io/base-drafts/draft-ietf-privacypass-protocol.html) ([Datatracker Page](https://datatracker.ietf.org/doc/draft-ietf-privacypass-protocol/))

Additional information:

- [WG Charter](/CHARTER.md)
- Mailing list: <privacy-pass@ietf.org>

# Existing implementations

| Implementation                                                             | Language | Token Types                   | Version   |
| -------------------------------------------------------------------------- | :------- | :-----------------------------| :-------- |
| [pat-app](https://github.com/cloudflare/pat-app)                           | Go       | VOPRF (P-384, SHA-384) (0x0001), Blind RSA (SHA-384, 2048-bit) (0x0002) | draft-06  |
| [privacypass](https://github.com/raphaelrobert/privacypass)                | Rust     | VOPRF (P-384, SHA-384) (0x0001), Blind RSA (SHA-384, 2048-bit) (0x0002) | draft-06  |
| [privacypass-ts](https://github.com/cloudflare/privacypass-ts)             | Typescript | Blind RSA (SHA-384, 2048-bit) (0x0002) | draft-11  |

## Building Drafts

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

This requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/master/doc/SETUP.md).


## Contributing

See the
[guidelines for contributions](/CONTRIBUTING.md).
