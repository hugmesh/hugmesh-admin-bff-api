package systems.hugmesh.adminbff.testreports;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import reactor.core.publisher.Flux;
import systems.hugmesh.commons.web.ApiException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Validates the report-bundle download: it produces a readable gzipped tar of the
 * stored bundle, RE-SCRUBS secrets in text entries on read, leaves binary entries
 * untouched, and refuses a path-traversal report_ref (containment under the PVC root).
 */
class TestReportArchiveTest {

    private byte[] drain(Flux<DataBuffer> body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DataBufferUtils.write(body, out).then().block();
        return out.toByteArray();
    }

    /** Untar a gzip stream into name→bytes (minimal USTAR reader for the test). */
    private Map<String, byte[]> untarGz(byte[] gz) throws Exception {
        Map<String, byte[]> entries = new HashMap<>();
        try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(gz))) {
            byte[] header = new byte[512];
            while (true) {
                int r = in.readNBytes(header, 0, 512);
                if (r < 512) break;
                boolean allZero = true;
                for (byte b : header) if (b != 0) { allZero = false; break; }
                if (allZero) break; // trailer
                int nameEnd = 0;
                while (nameEnd < 100 && header[nameEnd] != 0) nameEnd++;
                String name = new String(header, 0, nameEnd, StandardCharsets.UTF_8);
                String sizeOctal = new String(header, 124, 12, StandardCharsets.US_ASCII).trim()
                        .replace("\0", "").trim();
                long size = sizeOctal.isEmpty() ? 0 : Long.parseLong(sizeOctal, 8);
                byte[] data = in.readNBytes((int) size);
                entries.put(name, data);
                int pad = (int) ((512 - (size % 512)) % 512);
                if (pad > 0) in.readNBytes(pad);
            }
        }
        return entries;
    }

    @Test
    void download_buildsScrubbedTarGz(@TempDir Path root) throws Exception {
        Path bundle = Files.createDirectories(root.resolve("lean/run-1-abc1234"));
        Files.writeString(bundle.resolve("summary.json"),
                "{\"token\":\"eyJhbGciOiJ9.eyJzdWIiOiJhIn0.sig-secret-value\",\"passed\":40}");
        Files.writeString(bundle.resolve("junit.xml"),
                "<testsuite><system-out>password=hunter2longenough</system-out></testsuite>");
        Files.write(bundle.resolve("trace.png"), new byte[]{(byte) 0x89, 'P', 'N', 'G'});

        TestReportArchive archive = new TestReportArchive(root.toString());
        byte[] gz = drain(archive.download("lean/run-1-abc1234"));
        Map<String, byte[]> entries = untarGz(gz);

        assertThat(entries).containsKeys("summary.json", "junit.xml", "trace.png");

        String summary = new String(entries.get("summary.json"), StandardCharsets.UTF_8);
        assertThat(summary).contains("***REDACTED***").doesNotContain("sig-secret-value")
                .contains("\"passed\":40");
        String junit = new String(entries.get("junit.xml"), StandardCharsets.UTF_8);
        assertThat(junit).contains("***REDACTED***").doesNotContain("hunter2longenough");

        // binary screenshot is passed through byte-for-byte (not scrubbed).
        assertThat(entries.get("trace.png")).isEqualTo(new byte[]{(byte) 0x89, 'P', 'N', 'G'});
    }

    @Test
    void download_rejectsTraversalRef(@TempDir Path root) {
        TestReportArchive archive = new TestReportArchive(root.toString());
        assertThatThrownBy(() -> drain(archive.download("../../etc/secrets")))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("invalid report reference");
    }

    @Test
    void download_missingBundle_404(@TempDir Path root) {
        TestReportArchive archive = new TestReportArchive(root.toString());
        assertThatThrownBy(() -> drain(archive.download("lean/run-does-not-exist")))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("not found");
    }

    @Test
    void download_nullRef_404(@TempDir Path root) {
        TestReportArchive archive = new TestReportArchive(root.toString());
        assertThatThrownBy(() -> drain(archive.download(null)))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("no report artifact");
    }
}
