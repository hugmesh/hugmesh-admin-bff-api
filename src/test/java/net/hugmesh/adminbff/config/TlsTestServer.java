package net.hugmesh.adminbff.config;

import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import javax.net.ssl.SSLPeerUnverifiedException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * An in-test HTTPS server (reactor-netty) on 127.0.0.1 with a chosen server certificate and
 * client-auth mode. Every request is answered {@code 200 {"slug":"<echo>"}} (enough for both
 * the federation and the ArgoCD client), and the server records, per request, the path, the
 * {@code Authorization} header and the subject of the client certificate the caller presented
 * (or {@code "<none>"}), so a test can prove WHICH identity reached it.
 */
public final class TlsTestServer implements AutoCloseable {

    /** One observed request. */
    public record Seen(String method, String uri, String authorization, String clientSubject) {
    }

    private final DisposableServer server;
    private final List<Seen> seen = new CopyOnWriteArrayList<>();

    private TlsTestServer(DisposableServer server) {
        this.server = server;
    }

    /**
     * Start a server presenting {@code serverLeaf} (chain {@code serverLeaf, chain...}).
     * {@code clientAuth} REQUIRE = federation-api's {@code SSL_CLIENT_AUTH=need}; NONE = a
     * server that asks for no client certificate (argocd-server). {@code clientCa} is the CA
     * a presented client certificate must chain to (ignored for NONE).
     */
    public static TlsTestServer start(TestPki.Issued serverLeaf, X509Certificate[] chain,
                                      ClientAuth clientAuth, X509Certificate clientCa) throws Exception {
        X509Certificate[] full = new X509Certificate[1 + chain.length];
        full[0] = serverLeaf.cert();
        System.arraycopy(chain, 0, full, 1, chain.length);
        SslContextBuilder b = SslContextBuilder.forServer(serverLeaf.keys().getPrivate(), full)
                .clientAuth(clientAuth);
        if (clientAuth != ClientAuth.NONE) {
            b.trustManager(clientCa);
        }
        SslContext ssl = b.build();
        TlsTestServer[] self = new TlsTestServer[1];
        DisposableServer s = HttpServer.create()
                .host("127.0.0.1")
                .port(0)
                .secure(spec -> spec.sslContext(ssl))
                .handle((req, res) -> {
                    String[] subject = {"<none>"};
                    req.withConnection(conn -> {
                        SslHandler h = conn.channel().pipeline().get(SslHandler.class);
                        if (h == null) return;
                        try {
                            Certificate[] peer = h.engine().getSession().getPeerCertificates();
                            if (peer.length > 0 && peer[0] instanceof X509Certificate x) {
                                subject[0] = x.getSubjectX500Principal().getName();
                            }
                        } catch (SSLPeerUnverifiedException e) {
                            subject[0] = "<none>";
                        }
                    });
                    self[0].seen.add(new Seen(req.method().name(), req.uri(),
                            req.requestHeaders().get("Authorization"), subject[0]));
                    return req.receive().aggregate().asString().defaultIfEmpty("")
                            .then(res.header("Content-Type", "application/json")
                                    .sendString(Mono.just("{\"slug\":\"echo\"}")).then());
                })
                .bindNow();
        self[0] = new TlsTestServer(s);
        return self[0];
    }

    /** {@code https://127.0.0.1:<port>} — the IP SAN the test leaves carry. */
    public String baseUrl() {
        return "https://127.0.0.1:" + server.port();
    }

    public List<Seen> seen() {
        return seen;
    }

    @Override
    public void close() {
        server.disposeNow();
    }
}
