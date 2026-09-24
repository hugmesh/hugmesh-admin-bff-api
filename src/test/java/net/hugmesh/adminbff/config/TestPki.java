package net.hugmesh.adminbff.config;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A throwaway in-test PKI for the outbound client-mTLS tests: a cluster-like CA, leaves it
 * signs (server with SAN {@code IP:127.0.0.1} / {@code DNS:localhost}, and a client identity),
 * a self-signed leaf (ArgoCD's stock {@code O=Argo CD} shape), and the PKCS12 key/trust stores
 * the pod's {@code build-keystore} initContainer would write. EC P-256 keys so generation is
 * fast; nothing here touches the network or the filesystem outside the caller's temp dir.
 */
public final class TestPki {

    private static final AtomicLong SERIAL = new AtomicLong(System.nanoTime());

    /** A key pair plus the certificate issued for it. */
    public record Issued(KeyPair keys, X509Certificate cert) {
    }

    private TestPki() {
    }

    /** A self-signed CA certificate (basicConstraints CA:true, keyCertSign). */
    public static Issued ca(String cn) throws Exception {
        KeyPair kp = keyPair();
        X500Name name = new X500Name("CN=" + cn);
        X509v3CertificateBuilder b = builder(name, name, kp);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return new Issued(kp, sign(b, kp));
    }

    /** A server leaf signed by {@code issuer}, valid for 127.0.0.1 and localhost. */
    public static Issued serverLeaf(Issued issuer, String cn) throws Exception {
        return leaf(issuer, cn, KeyPurposeId.id_kp_serverAuth);
    }

    /** A client leaf signed by {@code issuer} — the pod's PKI identity. */
    public static Issued clientLeaf(Issued issuer, String cn) throws Exception {
        return leaf(issuer, cn, KeyPurposeId.id_kp_clientAuth);
    }

    /**
     * A SELF-SIGNED server leaf (issuer == subject, not a CA) valid for 127.0.0.1 and localhost
     * — the shape of ArgoCD's stock {@code argocd-server} certificate ({@code O=Argo CD}).
     */
    public static Issued selfSignedServer(String subject) throws Exception {
        KeyPair kp = keyPair();
        X500Name name = new X500Name(subject);
        X509v3CertificateBuilder b = builder(name, name, kp);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        addServerNames(b);
        b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        return new Issued(kp, sign(b, kp));
    }

    /** PKCS12 keystore holding {@code leaf}'s key with the chain {@code leaf, issuers...}. */
    public static Path keyStore(Path dir, String file, String password, Issued leaf,
                                X509Certificate... issuers) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        Certificate[] chain = new Certificate[1 + issuers.length];
        chain[0] = leaf.cert();
        System.arraycopy(issuers, 0, chain, 1, issuers.length);
        ks.setKeyEntry("identity", leaf.keys().getPrivate(), password.toCharArray(), chain);
        return store(ks, dir.resolve(file), password);
    }

    /** PKCS12 truststore whose ONLY trusted entries are {@code anchors}. */
    public static Path trustStore(Path dir, String file, String password,
                                  X509Certificate... anchors) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        for (int i = 0; i < anchors.length; i++) {
            ks.setCertificateEntry("anchor-" + i, anchors[i]);
        }
        return store(ks, dir.resolve(file), password);
    }

    private static Issued leaf(Issued issuer, String cn, KeyPurposeId purpose) throws Exception {
        KeyPair kp = keyPair();
        X509v3CertificateBuilder b = builder(
                X500Name.getInstance(issuer.cert().getSubjectX500Principal().getEncoded()),
                new X500Name("CN=" + cn), kp);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purpose));
        if (purpose == KeyPurposeId.id_kp_serverAuth) {
            addServerNames(b);
        }
        return new Issued(kp, sign(b, issuer.keys()));
    }

    private static void addServerNames(X509v3CertificateBuilder b) throws Exception {
        b.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[] {
                new GeneralName(GeneralName.iPAddress, "127.0.0.1"),
                new GeneralName(GeneralName.dNSName, "localhost")}));
    }

    private static X509v3CertificateBuilder builder(X500Name issuer, X500Name subject, KeyPair kp) {
        Instant now = Instant.now();
        return new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(SERIAL.incrementAndGet()),
                Date.from(now.minus(1, ChronoUnit.HOURS)), Date.from(now.plus(1, ChronoUnit.DAYS)),
                subject, kp.getPublic());
    }

    private static X509Certificate sign(X509v3CertificateBuilder b, KeyPair signer) throws Exception {
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(b.build(cs));
    }

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    private static Path store(KeyStore ks, Path path, String password) throws Exception {
        try (OutputStream out = Files.newOutputStream(path)) {
            ks.store(out, password.toCharArray());
        }
        return path;
    }
}
