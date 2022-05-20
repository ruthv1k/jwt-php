# JWT PHP

> Note : Uses HS256 algorithm only.

### Usage

Requires a 256 bit secret key, needs to be generated manually.

```php
$secret = 'R9YS96rZq0dD6m3NB72aeja6NqCph5y9';
```

#### Signing

```php
$data = [
    'email' => 'johndoe@example.com',
    'password' => 'cDzHz0fI8z'
];

$token = JWT::sign($data, $secret);
```

#### Verifying

```php
$token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImpvaG5kb2VAZXhhbXBsZS5jb20iLCJwYXNzd29yZCI6ImNEekh6MGZJOHoifQ.s_3pSzPZBK_xk9ESqSoNctRv-20VvF8CjkHNWxCO-eQ';

$result = JWT::verify($token, $secret);
```

> `verify` method returns `payload` if token is valid, else returns `'Invalid Token'`.
