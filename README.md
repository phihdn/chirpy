# chirpy

## Generating Secret Keys

To generate a secure secret key for the application, you can use the following command:

```bash
openssl rand -base64 64
```

This will generate a 64-byte random key encoded in base64, which is suitable for use as a JWT secret or other cryptographic purposes.
