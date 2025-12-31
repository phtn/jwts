# JWT Service Key Generation

## HMAC (HS256/HS384/HS512)
- Uses `JWT_SECRET` environment variable (already documented).

## RSA (RS256/RS384/RS512)
Generate a 2048-bit RSA key pair:
```sh
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private.pem -pubout -out public.pem


```
Set environment variables:
```
JWT_PRIVATE_KEY=</absolute/path/to/private.pem>
JWT_PUBLIC_KEY=</absolute/path/to/public.pem>
```

## ECDSA (ES256/ES384/ES512)
Generate a P-256 ECDSA key pair:
```sh
openssl ecparam -name prime256v1 -genkey -noout -out ec256-private.pem
# JWT.IO
# Converting to PKCS #8
openssl pkcs8 -topk8 -inform PEM -outform PEM -in pem/ec256-private.pem -out pem/ec256-private-pk8.pem -nocrypt
openssl ec -in ec256-private.pem -pubout -out ec256-public.pem
```
Set environment variables:
```
JWT_EC_PRIVATE_KEY=</absolute/path/to/ec256-private.pem>
JWT_EC_PUBLIC_KEY=</absolute/path/to/ec256-public.pem>
```

## RSASSA-PSS (PS256/PS384/PS512)
Generate a 2048-bit RSA key pair (same as RSA):
```sh
openssl genpkey -algorithm RSA -out pss-private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in pss-private.pem -pubout -out pss-public.pem
```


Generate a ES384 key pair(P-384):
```zsh
openssl ecparam -genkey -name secp384r1 -noout -out ec384-private.pem
openssl ec -in ec384-private.pem -pubout -out ec384-public.pem
```
Set environment variables:
```
JWT_PSS_PRIVATE_KEY=</absolute/path/to/pss-private.pem>
JWT_PSS_PUBLIC_KEY=</absolute/path/to/pss-public.pem>
```

Use the appropriate `alg` in your /sign request: `HS256`, `RS256`, `ES256`, `PS256`, etc.
