# LP-Covercrypt operational notes

## Access-structure persistence

LP-Covercrypt writes access structures as version V2. Each dimension contains a
reserved `$` attribute with its ordinary numeric identifier, encryption hint,
and status. The semantic bottom is represented by an omitted coordinate and is
not serialized as an administrator-visible attribute.

On deserialization, every dimension must contain an enabled `$`; in a hierarchy
it must be the greatest value. Attribute identifiers must also be unique across
the structure. Legacy V1 structures are rejected instead of being silently
reinterpreted. The prototype does not provide an automatic V1-to-V2 converter,
because adding a maximum changes the right universe and requires coordinated
master-key material.

## Structure evolution and user keys

`D::$` is future-extensible as a stored source policy. A serialized
`UserSecretKey` contains only the coordinates and secret components issued at
generation time; it does not contain the source policy. After adding an
attribute, `update_msk` creates the new MSK/MPK coordinates. `refresh_usk`
updates secret revisions only for coordinates already present in the user key,
so it cannot extend an old maximum-bearing key to a newly created coordinate.

The issuer must retain the canonical source policy outside the user key. A key
that should cover a value added after issuance must be regenerated from that
stored policy and redistributed. Ordinary refresh is insufficient.

## Migration from Covercrypt v15

Before enabling LP compilation, inventory the canonical source policy for every
issued key and review each omitted dimension:

1. If omission intentionally meant unrestricted access, rewrite it explicitly
   as `D::$`.
2. If omission meant absence, retain the omission.
3. Construct or migrate a V2 access structure. Preserve attribute identifiers
   and master-key material when old ciphertexts must remain in the same
   cryptographic domain; the current prototype does not automate this step.
4. Generate replacement user keys from the reviewed policies, distribute them,
   and retire or revoke the legacy keys. Changing the compiler does not narrow
   key bytes that have already been issued.

The ciphertext policy compiler and ciphertext wire format are unchanged. Old
ciphertexts remain usable without format conversion only when migration also
preserves their right identifiers and master-key domain. If a new MSK or new
identifiers are introduced, retain a legacy decryption domain or rewrap/re-encrypt
the affected ciphertexts.

## Benchmark

Run the paper benchmark with:

```sh
benches/run_evaluation.sh
```
