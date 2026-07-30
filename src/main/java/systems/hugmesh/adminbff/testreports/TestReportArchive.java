package systems.hugmesh.adminbff.testreports;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import systems.hugmesh.commons.web.ApiException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;
import java.util.zip.GZIPOutputStream;

/**
 * Reads a stored test-report bundle from the {@code test-reports} PVC and streams it
 * as a {@code tar.gz} download — the design's "GET /{id}/download (the stored report
 * artifact ... secrets scrubbed)". Reuses the role-secured download shape of the
 * backup feature, with two security disciplines layered on:
 *
 * <ol>
 *   <li><b>Path containment.</b> The {@code report_ref} from the {@code test_run} row
 *       is resolved UNDER the configured PVC root and the real path is asserted to
 *       still be inside the root — a {@code ../} traversal or an absolute ref is a
 *       400, never an escape off the volume.</li>
 *   <li><b>Read-time scrubbing.</b> Every text entry ({@link ReportScrubber#isText})
 *       is re-scrubbed through {@link ReportScrubber} as it is written into the tar,
 *       so even if a write-time scrub missed a secret the download cannot leak it.</li>
 * </ol>
 *
 * <p>The tar is written in the dependency-free USTAR format (no commons-compress on
 * the classpath) wrapped in {@code GZIPOutputStream}; the whole bundle is small
 * (junit.xml + summary.json + sanitized logs), so it is built on the bounded-elastic
 * scheduler into a single buffer and emitted reactively.
 */
@Component
public class TestReportArchive {

    private static final Logger log = LoggerFactory.getLogger(TestReportArchive.class);
    private static final DataBufferFactory BUFFERS = new DefaultDataBufferFactory();

    /** Hard cap so a runaway log directory cannot OOM the BFF building the archive. */
    private static final long MAX_BUNDLE_BYTES = 64L * 1024 * 1024;

    private final Path root;

    public TestReportArchive(@Value("${testreports.storage.dir:/var/hugmesh/test-reports}") String dir) {
        this.root = Path.of(dir).toAbsolutePath().normalize();
    }

    /**
     * Stream the bundle at {@code reportRef} as a gzipped tar. {@code reportRef} is the
     * PVC-relative path stored on the {@code test_run} row (e.g.
     * {@code lean/run-1718000000-abc1234/}). Errors map to the standard
     * {@code {error}} body: missing/empty ref or run not yet stored → 404; a traversal
     * ref → 400.
     */
    public Flux<DataBuffer> download(String reportRef) {
        return Mono.fromCallable(() -> buildTarGz(reportRef))
                .subscribeOn(Schedulers.boundedElastic())
                .map(BUFFERS::wrap)
                .flux();
    }

    private byte[] buildTarGz(String reportRef) throws IOException {
        if (reportRef == null || reportRef.isBlank()) {
            throw new ApiException(HttpStatus.NOT_FOUND, "no report artifact is stored for this run yet");
        }
        Path bundle = resolveContained(reportRef);
        if (!Files.isDirectory(bundle)) {
            throw new ApiException(HttpStatus.NOT_FOUND, "report bundle not found on storage");
        }

        ByteArrayOutputStream gzBytes = new ByteArrayOutputStream();
        long[] total = {0};
        try (GZIPOutputStream gz = new GZIPOutputStream(gzBytes);
             Stream<Path> walk = Files.walk(bundle)) {
            List<Path> files = new ArrayList<>(walk.filter(Files::isRegularFile)
                    .sorted(Comparator.comparing(Path::toString)).toList());
            for (Path f : files) {
                byte[] data = Files.readAllBytes(f);
                String rel = bundle.relativize(f).toString().replace('\\', '/');
                if (ReportScrubber.isText(rel)) {
                    data = ReportScrubber.scrub(new String(data, StandardCharsets.UTF_8))
                            .getBytes(StandardCharsets.UTF_8);
                }
                total[0] += data.length;
                if (total[0] > MAX_BUNDLE_BYTES) {
                    throw new ApiException(HttpStatus.UNPROCESSABLE_CONTENT,
                            "report bundle exceeds the download size limit");
                }
                writeTarEntry(gz, rel, data);
            }
            writeTarTrailer(gz);
        }
        return gzBytes.toByteArray();
    }

    /**
     * Resolve {@code reportRef} under the PVC root and assert the result is still
     * contained — defeats {@code ../} traversal and absolute-path refs.
     */
    private Path resolveContained(String reportRef) {
        Path candidate = root.resolve(reportRef).normalize();
        if (!candidate.startsWith(root)) {
            log.warn("[test-reports] rejected out-of-root report_ref '{}'", reportRef);
            throw ApiException.badRequest("invalid report reference");
        }
        return candidate;
    }

    // ── minimal USTAR tar writer (no external dependency) ─────────────────────

    private static void writeTarEntry(OutputStream out, String name, byte[] data) throws IOException {
        byte[] header = new byte[512];
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        // USTAR name field is 100 bytes; longer paths are truncated (our bundle paths
        // are short: run-<ts>-<commit>/logs/<suite>.log).
        int nameLen = Math.min(nameBytes.length, 100);
        System.arraycopy(nameBytes, 0, header, 0, nameLen);
        putOctal(header, 100, 8, 420);               // mode (0644 octal)
        putOctal(header, 108, 8, 0);                 // uid
        putOctal(header, 116, 8, 0);                 // gid
        putOctal(header, 124, 12, data.length);      // size
        putOctal(header, 136, 12, 0);                // mtime (deterministic)
        header[156] = '0';                           // typeflag: regular file
        System.arraycopy("ustar\0".getBytes(StandardCharsets.US_ASCII), 0, header, 257, 6);
        header[263] = '0';
        header[264] = '0';                           // version "00"
        // checksum: spaces while summing, then the octal sum.
        for (int i = 148; i < 156; i++) header[i] = ' ';
        int checksum = 0;
        for (byte b : header) checksum += (b & 0xff);
        putOctal(header, 148, 7, checksum);
        header[155] = ' ';

        out.write(header);
        out.write(data);
        int pad = (512 - (data.length % 512)) % 512;
        if (pad > 0) out.write(new byte[pad]);
    }

    private static void writeTarTrailer(OutputStream out) throws IOException {
        // two zero-filled 512-byte records terminate a tar archive.
        out.write(new byte[1024]);
    }

    private static void putOctal(byte[] buf, int offset, int length, long value) {
        // right-justified, null/space-terminated octal as USTAR expects.
        String octal = Long.toOctalString(value);
        int max = length - 1;
        if (octal.length() > max) octal = octal.substring(octal.length() - max);
        int pad = max - octal.length();
        for (int i = 0; i < pad; i++) buf[offset + i] = '0';
        byte[] o = octal.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(o, 0, buf, offset + pad, o.length);
        buf[offset + length - 1] = 0;
    }
}
