# License key rotation

EnAuth uses one keyring for irreversible license lookup hashes and a separate
keyring for reversible license display. Never reuse a secret between them.

## Migrating from `LICENSE_KEY_PEPPER`

Keep the old pepper temporarily and add independent current keys:

```ini
LICENSE_KEY_PEPPER=your-existing-pepper
LICENSE_LOOKUP_KEY_ID=lookup-v2
LICENSE_LOOKUP_KEY=a-new-random-secret-of-at-least-32-characters
LICENSE_LOOKUP_PREVIOUS_KEYS={"legacy-v1":"your-existing-pepper"}
LICENSE_ENCRYPTION_KEY_ID=enc-v2
LICENSE_ENCRYPTION_KEY=a-different-new-random-secret-of-at-least-32-characters
LICENSE_ENCRYPTION_PREVIOUS_KEYS={}
```

Successful license logins automatically replace the legacy lookup hash and
stored ciphertext. Keep the old pepper until every license that must remain
readable has migrated. Back up the database and all keyring values before any
rotation.

## Rotating again

Move the old current value into the matching `*_PREVIOUS_KEYS` JSON object,
choose a new unique key ID, generate a new secret, and restart EnAuth. Do not
remove a previous lookup key until all relevant licenses have authenticated.
Do not remove a previous encryption key while any ciphertext still names it.

Generate each secret independently, for example:

```bash
openssl rand -base64 48
```
