package net.hugmesh.adminbff.meshtoken;

import org.junit.jupiter.api.Test;

import java.util.function.UnaryOperator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** {@link MeshTokenPayload#check(long)} mirrors the Studio's {@code check_fields}, plus the ASCII wall. */
class MeshTokenPayloadTest {

    static final long NOW = 1762300800L + 10;

    static MeshTokenPayload ok() {
        return MeshTokenFixtures.goldenPayload();
    }

    static MeshTokenPayload with(UnaryOperator<Object[]> f) {
        MeshTokenPayload g = ok();
        Object[] a = {g.authKey(), g.domain(), g.expires(), g.id(), g.issued(), g.issuer(), g.loginServer(),
                g.mesh(), g.nodeName(), g.role(), g.shell()};
        a = f.apply(a);
        return new MeshTokenPayload((String) a[0], (String) a[1], (Long) a[2], (String) a[3], (Long) a[4],
                (String) a[5], (String) a[6], (String) a[7], (String) a[8], (String) a[9], (Boolean) a[10]);
    }

    static void refused(MeshTokenPayload p, String why) {
        assertThatThrownBy(() -> p.check(NOW)).as(why).isInstanceOf(MeshTokenPayload.InvalidPayloadException.class);
    }

    @Test
    void theGoldenGrantPasses() {
        assertThatCode(() -> ok().check(NOW)).doesNotThrowAnyException();
    }

    @Test
    void everyCheckFieldsRuleRefuses() {
        refused(with(a -> { a[7] = "Mesh"; return a; }), "upper-case mesh");
        refused(with(a -> { a[7] = "-x"; return a; }), "mesh starting with -");
        refused(with(a -> { a[1] = "localhost"; return a; }), "one-label domain");
        refused(with(a -> { a[1] = "Hugmesh.net"; return a; }), "upper-case domain");
        refused(with(a -> { a[9] = "owner"; return a; }), "unknown role");
        refused(with(a -> { a[9] = "user"; return a; }), "shell for user");
        refused(with(a -> { a[9] = "mod"; return a; }), "shell for mod");
        refused(with(a -> { a[6] = "http://hs.hugmesh.net"; return a; }), "plain http");
        refused(with(a -> { a[6] = "https://hs.hugmesh.net/x"; return a; }), "path");
        refused(with(a -> { a[6] = "https://hs.hugmesh.net:8488 --ssh"; return a; }), "flag smuggling");
        refused(with(a -> { a[6] = "https://hs.evil.org"; return a; }), "login server outside the domain");
        refused(with(a -> { a[6] = "https://evilhugmesh.net"; return a; }), "suffix without a dot");
        refused(with(a -> { a[0] = ""; return a; }), "empty auth key");
        refused(with(a -> { a[0] = "ab cd"; return a; }), "whitespace in auth key");
        refused(with(a -> { a[5] = "ssh-rsa AAAA"; return a; }), "not ed25519");
        refused(with(a -> { a[4] = 1577836799L; return a; }), "issued before 2020");
        refused(with(a -> { a[2] = (Long) a[4]; return a; }), "expires == issued");
        refused(with(a -> { a[2] = (Long) a[4] + 90L * 86400 + 1; return a; }), "over 90 days");
        refused(with(a -> { a[8] = "Bad Name"; return a; }), "node name");
        refused(with(a -> { a[3] = "XYZ"; return a; }), "id");
        assertThatThrownBy(() -> ok().check(1762905600L)).as("expired").isInstanceOf(
                MeshTokenPayload.InvalidPayloadException.class);
        assertThatThrownBy(() -> ok().check(1762300800L - 301)).as("issued in the future").isInstanceOf(
                MeshTokenPayload.InvalidPayloadException.class);
    }

    @Test
    void theAsciiWall_refusesAnythingThatWouldNeedEscaping() {
        refused(with(a -> { a[0] = "key\"x"; return a; }), "quote");
        refused(with(a -> { a[0] = "key\\x"; return a; }), "backslash");
        refused(with(a -> { a[0] = "key\u007fx"; return a; }), "DEL");
        refused(with(a -> { a[0] = "keyé"; return a; }), "non-ASCII");
        refused(with(a -> { a[8] = "n\u0000"; return a; }), "NUL");
    }

    @Test
    void ninetyDaysExactlyIsAllowed_andTheLoginServerMayBeTheDomainItself() {
        assertThatCode(() -> with(a -> { a[2] = (Long) a[4] + 90L * 86400; return a; }).check(NOW))
                .doesNotThrowAnyException();
        assertThatCode(() -> with(a -> { a[6] = "https://hugmesh.net"; return a; }).check(NOW))
                .doesNotThrowAnyException();
        assertThatCode(() -> with(a -> { a[8] = ""; a[3] = ""; return a; }).check(NOW))
                .doesNotThrowAnyException();
    }

    @Test
    void toString_neverPrintsTheAuthKey() {
        assertThat(ok().toString()).doesNotContain(MeshTokenFixtures.GOLDEN_AUTH_KEY).contains("<redacted>");
    }
}
