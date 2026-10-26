# Identity from a trusted proxy

The service never authenticates a caller itself. A proxy in front of it terminates TLS, verifies the
caller's client certificate against your CA, and passes the certificate's subject in one header.
The service reads WHO from that header and from nothing else.

## The one rule

The proxy **sets** the header from a verified certificate and **clears** it on every request that
has none. Then the header's presence is the proxy's statement, never the caller's: a caller who
types `X-Client-Identity: CN=someone@production` into a request without a certificate reaches the
service with an empty header and is refused with 401.

The service must be reachable only through the proxy: bind it to loopback or a private network.
Anything that can reach the service directly can forge the header — including another user's process
on the same host, so on a shared host put the service in its own network namespace or container.

## The CA

Use a CA that issues only these identities. The service accepts any certificate the proxy verifies
whose CN has the `app@env` shape, so a general-purpose CA lets anyone it has issued to in.
Revocation is the proxy's: with nginx, `ssl_crl`. Two consequences of the access model to weigh
when issuing:

- every identity, in any environment, can read every production blob — a `dev` certificate is not
  a lesser one for reading;
- the operator is recognised by its application name alone, in any environment: issue that name to
  your scheduled gc job and nobody else.

## The certificate

The subject CN is `application@environment`, e.g. `invoices@production`. The application part is
lower-case letters, digits and hyphens, starting with a letter; the environment is any name. The
service accepts the header as a bare `app@env` or as an RFC 2253 DN `CN=app@env`, so a subject with
only a CN works with nginx's `$ssl_client_s_dn` as it is.

One identity is special: the operator (`STORAGE_OPERATOR_APP`, default `infra-ops`) may run gc and
release any non-production scope (see The CA, above).

## nginx

```nginx
map $ssl_client_verify $client_identity {
    SUCCESS  $ssl_client_s_dn;
    default  "";
}

server {
    listen 443 ssl;
    server_name storage.example.org;

    ssl_certificate         /etc/ssl/storage.pem;
    ssl_certificate_key     /etc/ssl/storage.key;
    ssl_client_certificate  /etc/ssl/your-ca.pem;
    ssl_verify_client       optional;
    # ssl_crl              /etc/ssl/your-ca.crl;

    client_max_body_size    100m;   # nginx's default of 1m refuses ordinary uploads

    location / {
        proxy_set_header X-Client-Identity $client_identity;   # set, or cleared to ""
        proxy_pass http://127.0.0.1:8100;
    }
}
```

`ssl_verify_client optional` lets a request without a certificate through to be refused by the
service with a sentence saying what to bring; `on` refuses it at the TLS handshake instead. Either
is safe as long as the header is always set by the `map`.

## Another proxy

Any proxy works that can verify a client certificate and overwrite a request header. If it uses a
different header name, set `STORAGE_IDENTITY_HEADER` to it.

## Calling it

```
curl --cert app.pem --key app.key -F file=@report.pdf https://storage.example.org/v1/files
```
