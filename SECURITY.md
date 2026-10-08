# Security — hugmesh-admin-bff-api

## Authentication layers

This BFF is defended in depth by two independent layers:

1. **OAuth2 resource server (application layer).** Every request must carry a
   valid Casdoor-issued JWT (`spring.security.oauth2.resourceserver`), except the
   public paths: the health and info probes, `POST /bff/login`,
   `POST /bff/login/local`, `/bff/register/**`, `POST /bff/sessionOut` and
   `/bff/public/**`. `/bff/internal/**` needs a service principal instead: a Casdoor
   client-credentials JWT, or the in-cluster `X-Internal-Token`. The BFF
   independently re-validates the JWT before it mutates the `gateway_route_access`
   table (it is the only writer of that source of truth).

2. **Mutual TLS — the API-to-API trust boundary (transport layer).** In-cluster,
   the TLS handshake **requires a client certificate that chains to the cluster CA
   truststore**. Only services that were deployed and signed by our Vault/ESO PKI
   process hold such a certificate. A random pod, an `io`/external client, or
   anything not issued by our PKI presents no chaining cert, so its handshake is
   rejected before any byte of HTTP is read — it cannot open a connection to this API.

   mTLS decides who may connect. It does not say who the end user is. The
   fe-gateway presents its own cluster-CA client cert when it proxies browser
   traffic to this BFF, so that traffic passes the handshake. This is why
   `/bff/internal/**` also needs the service principal above: the transport cannot
   tell the gateway's own calls from a user's request that the gateway forwards.

## How the mTLS layer is wired

The cluster CA is the offline root from `hugmesh-generator/scripts/gen-keystores.sh`.
In-cluster, Vault PKI imports that CA and issues a short-lived leaf cert per app;
External Secrets Operator (ESO) syncs it into the `hugmesh-admin-bff-api-mtls`
`kubernetes.io/tls` Secret (`tls.crt` / `tls.key` / `ca.crt`). A keystore
initContainer (the equivalent of the gateway chart's `build-keystore`) assembles:

- `keystore.p12` — this service's own mTLS **identity** (key + cert chain),
- `truststore.p12` — the **cluster CA** trust anchor,

into an in-pod tmpfs and generates the store password there (it never enters git,
a Secret, or Vault). It writes the password to `/stores/application.properties`,
which the app loads through `SPRING_CONFIG_ADDITIONAL_LOCATION=file:/stores/`. The
deployment sets the env below so the running pod enforces client-cert verification. Because every in-cluster leaf chains to the same
cluster CA, the truststore validates them; ESO rotates the cert before expiry.

The gateway (`hugmesh-fe-gateway`/`hugmesh-be-gateway`) is the legitimate
caller: it presents its own ESO-issued client cert when proxying to this BFF, so
its handshake succeeds while everyone else's fails.

## Configuration (parameterized — safe by default)

`server.ssl.*` in `application.yml` is parameterized so local/dev/CI keep working:

| Property | Env var | Local/CI default | In-cluster value |
| --- | --- | --- | --- |
| `server.ssl.enabled` | `SSL_ENABLED` | `false` (plaintext) | `true` |
| `server.ssl.client-auth` | `SSL_CLIENT_AUTH` | `none` | `need` |
| `server.ssl.key-store` | `SSL_KEY_STORE` | `/stores/keystore.p12` | mounted PKCS12 keystore |
| `server.ssl.key-store-type` | `SSL_KEY_STORE_TYPE` | `PKCS12` | `PKCS12` |
| `server.ssl.key-store-password` | `SSL_KEY_STORE_PASSWORD` | _(empty)_ | in-pod-generated, read from `/stores/application.properties` |
| `server.ssl.trust-store` | `SSL_TRUST_STORE` | `/stores/truststore.p12` | mounted PKCS12 truststore (cluster CA) |
| `server.ssl.trust-store-type` | `SSL_TRUST_STORE_TYPE` | `PKCS12` | `PKCS12` |
| `server.ssl.trust-store-password` | `SSL_TRUST_STORE_PASSWORD` | _(empty)_ | in-pod-generated, read from `/stores/application.properties` |
| `server.ssl.enabled-protocols` | `SSL_ENABLED_PROTOCOLS` | `TLSv1.3` | `TLSv1.3` |

With the defaults, `server.ssl.enabled=false`, so the stores are never opened and
existing tests run unchanged. `client-auth` maps to Netty's `ClientAuth`:
`none → NONE`, `want → OPTIONAL`, `need → REQUIRE`. WebFlux/Netty reads these
properties directly; no custom `SslContext`/`HttpServer` bean is needed.

## Deployment requirement (owned by hugmesh-generator)

The deployment manifest for this BFF lives in `hugmesh-generator`
(`specs/cluster/manifests/admin-bff-api/deployment.yaml`), not in this repo. That
deployment already enforces mTLS. It has the `build-keystore` initContainer, the
`pki` (from `hugmesh-admin-bff-api-mtls`) and `stores` (tmpfs) volumes — as
`specs/cluster/charts/hugmesh-gateway/templates/deployment.yaml` does — and sets:

```
SSL_ENABLED=true
SSL_CLIENT_AUTH=need
SSL_KEY_STORE=/stores/keystore.p12
SSL_KEY_STORE_TYPE=PKCS12
SSL_TRUST_STORE=/stores/truststore.p12
SSL_TRUST_STORE_TYPE=PKCS12
SPRING_CONFIG_ADDITIONAL_LOCATION=file:/stores/
```

The store passwords are not in the pod spec. The `SSL_*_PASSWORD` variables stay
empty and the values come from `/stores/application.properties`. Any other
deployment must do the same.

The probes are not `httpGet`, because a kubelet probe presents no client cert and
`client-auth=need` would reject it. They run `curl` inside the pod, with the pod's
own cert and the cluster CA, against `https://hugmesh-admin-bff-api:8080/actuator/health/{readiness,liveness}`.
The gateway must present its client cert and call this BFF over `https://`. Turn
`client-auth=need` on only after the callers present certs, or in-cluster traffic
is rejected.

## Known gaps / open findings

### bff-exchange suspension bypass (found 2026-06-25, FIXED same day — PR #161)

`POST /bff/internal/session/exchange` used to return the custody JWT without checking
`access_suspension`. The gateway calls this endpoint before `BffSessionAuthFilter`,
so a banned/suspended account with an active `bff_` session could still be authorized
via the exchange path, even though the introspect path (`/session/introspect`)
correctly checked suspension.

**Status: fixed.** `InternalAccountController#exchange` now runs a `suspensionGate`
check against `SuspensionService` *before* the custody row is decrypted, returning
403 for an active suspension — see the [Internal](README.md#internal-service-to-service-mtls-bounded)
section of the README for the current code-level detail. At the application
defaults this surface is dark (`app.bff.custody-key` unset, so `/session/exchange`
503s). On 2026-06-25 that meant no live traffic depended on the bug. It is no longer
dark in-cluster: the generator deployment sets `APP_BFF_OIDC_ENABLED`,
`APP_BFF_CUSTODY_KEY` and `APP_BFF_EXCHANGE_ENABLED` in the deployment above, so the fix is now what protects live
sessions.
