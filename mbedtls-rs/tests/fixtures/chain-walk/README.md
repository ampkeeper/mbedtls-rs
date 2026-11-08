# Chain-walk fixtures

Run `./regen.sh` here to regenerate the DER files with OpenSSL. Keys and CSRs are
created in a temporary directory and removed on exit. Every key is ECDSA P-256;
subjects and serials are fixed, while keys, signatures and issuance times change
on regeneration. Validity is 36,500 days from generation (about 100 years).

| DER | Subject | Issuer | Purpose |
| --- | --- | --- | --- |
| `r1.der` | Chain Walk R1 | R1 | First trust-list entry |
| `r2.der` | Chain Walk R2 | R2 | Second trust-list entry |
| `r2-by-r1.der` | Chain Walk R2 | R1 | Same subject/key as R2, cross-signed by R1 |
| `intermediate.der` | Chain Walk I | R2 | Served intermediate |
| `leaf.der` | Chain Walk L | I | Served leaf |
| `leaf-r1.der` | Chain Walk L1 | R1 | Direct test of first trust-list entry |
| `leaf-r2.der` | Chain Walk L2 | R2 | Direct test of second trust-list entry |

`chain_walk.rs` checks R2 wins with trust order R1, R2, whether or not the
cross-sign is served. With only R1 trusted, the cross-sign is required.
`cert_chain_no_copy.rs` independently checks both trust-list indices with directly
issued leaves. Tests follow Mbed TLS's date-check configuration without assuming
whether date checking is enabled.
