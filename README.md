# PayPal-PHP-Encrypt

A small, dependency-free PHP library that produces an [Encrypted Website
Payments](https://www.paypal.com/cgi-bin/webscr?cmd=p/xcl/rec/ewp-techview-outside)
(EWP) payload for PayPal Payments Standard buttons.

Unlike most existing solutions, this library uses only PHP's built-in
`openssl_*` functions — **no `exec()` calls to the `openssl` CLI**. This makes
it safe to run on shared hosting and in containers where shelling out is
unavailable or undesirable.

## Requirements

- PHP **7.1+** (verified on 8.1–8.5)
- `openssl` extension
- OpenSSL build with **legacy provider** enabled — PayPal mandates 3DES, which
  is marked legacy in OpenSSL 3.x. On most distributions the legacy provider
  is enabled by default; if you see `unsupported cipher` errors, enable it in
  `openssl.cnf`.

## Installation

Drop `PayPalEncrypt.class.php` into your project and `require` it. No Composer
package, no autoloader needed.

```php
require_once __DIR__ . '/PayPalEncrypt.class.php';
```

## Certificate setup

The library expects three PEM files inside a `cert/` directory next to
`PayPalEncrypt.class.php`:

| File | What it is |
|------|------------|
| `project-prvkey.pem` | Your private key |
| `project-pubcert.pem` | Your public certificate (also uploaded to PayPal) |
| `paypal_cert_pem.pem` | PayPal's public certificate for your environment |

**Important:** sandbox and live PayPal use **different** public certificates.
Download the right one from the PayPal account where the button will be paid:
*Profile → Encrypted payment settings → PayPal public certificate*.

You can generate your own key/cert pair with:

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout project-prvkey.pem \
  -out    project-pubcert.pem \
  -days   3650 \
  -subj   "/CN=your-domain.example"
```

Then upload `project-pubcert.pem` to PayPal and note the **Cert ID** —
you'll need it as the `cert_id` parameter.

### Overriding the cert directory

By default the library reads `cert/` relative to its own file. To use a
different path, define `PAYPAL_API_DIR` **before** including the class:

```php
define('PAYPAL_API_DIR', '/var/secrets/paypal');
require_once __DIR__ . '/PayPalEncrypt.class.php';
// Will read /var/secrets/paypal/cert/*.pem
```

## Usage

```php
require_once __DIR__ . '/PayPalEncrypt.class.php';

$encrypter = new PayPalEncrypt();

$payload = $encrypter->encrypt([
    'cmd'           => '_xclick',
    'business'      => 'merchant@example.com',
    'cert_id'       => 'YOUR_CERT_ID_FROM_PAYPAL',
    'item_name'     => 'My Product',
    'item_number'   => 'SKU-42',
    'amount'        => '19.99',
    'currency_code' => 'USD',
    'return'        => 'https://your-site.example/thanks',
    'cancel_return' => 'https://your-site.example/cancel',
    'notify_url'    => 'https://your-site.example/ipn',
]);
```

`$payload` is a Base64-armored PKCS7 block ready to be embedded in a PayPal
button form:

```html
<form action="https://www.paypal.com/cgi-bin/webscr" method="post">
    <input type="hidden" name="cmd" value="_s-xclick">
    <input type="hidden" name="encrypted" value="<?= htmlspecialchars($payload) ?>">
    <input type="image" src="https://www.paypalobjects.com/en_US/i/btn/btn_buynow_LG.gif" alt="Buy Now">
</form>
```

For sandbox testing, post to `https://www.sandbox.paypal.com/cgi-bin/webscr`
and use the sandbox PayPal certificate.

Full list of supported `key => value` parameters:
[PayPal HTML Variables Reference](https://developer.paypal.com/docs/archive/paypal-payments-standard/integration-guide/Appx-websitestandard-htmlvariables/).

## How it works

`encrypt()` runs a three-step pipeline using temporary files (PHP's OpenSSL
bindings only accept file paths, not in-memory buffers):

1. Serialize `key=value\n` pairs to a temp file.
2. `openssl_pkcs7_sign()` with your private key + cert.
3. **Decode the signed S/MIME blob to raw DER** in place. This is a
   workaround for a long-standing OpenSSL bug in `SMIME_write_PKCS7` —
   without it, the next step produces output PayPal rejects.
   See the [BUGS section of the OpenSSL manual](https://docs.openssl.org/3.0/man3/SMIME_write_PKCS7/#bugs).
4. `openssl_pkcs7_encrypt()` with PayPal's public cert using 3DES.
5. Strip S/MIME headers and wrap in `-----BEGIN PKCS7-----` / `-----END PKCS7-----`
   PEM armor (PayPal expects PKCS7 PEM, not CMS).

### Extension point: `needsBinaryWorkaround()`

The decode-to-binary step (#3 above) is required because of an OpenSSL bug.
If that bug ever gets fixed and `openssl_pkcs7_sign()` starts emitting raw
DER directly, the workaround would silently destroy your signed data.

To future-proof, the workaround is gated by an overridable hook:

```php
class PayPalEncryptModern extends PayPalEncrypt {
    protected function needsBinaryWorkaround(): bool {
        return false;
    }
}
```

The default is `true` — current behavior is preserved.

## License

MIT — see [LICENSE](LICENSE).
