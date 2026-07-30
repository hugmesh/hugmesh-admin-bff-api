package systems.hugmesh.adminbff.imagegen;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import systems.hugmesh.commons.web.ApiException;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Streams a built image (or its NON-SECRET keys bundle) from the build-artifacts volume — the
 * image-generation mirror of
 * {@link systems.hugmesh.adminbff.testreports.TestReportArchive}, reusing its
 * path-containment discipline:
 *
 * <ul>
 *   <li><b>Path containment.</b> The {@code image_ref} / {@code keys_ref} from the
 *       {@code image_build} row is resolved UNDER the configured artifacts root and the
 *       normalized path is asserted to still be inside the root — a {@code ../} traversal or an
 *       absolute ref is a 400, never an escape off the volume.</li>
 *   <li><b>No-secret guarantee.</b> The KEYS bundle this serves is the build artifact the
 *       generator wrote to the build-artifacts folder (public keys / fingerprints / pointers),
 *       NOT the private dial key — that lives ONLY in Vault and is never written to a
 *       downloadable artifact. The keys download is additionally gated by
 *       {@code ssh_keys_allowed} + an admin step-up in the controller/service.</li>
 * </ul>
 *
 * <p>The artifact is streamed off the volume reactively in bounded chunks (so a multi-GiB image
 * never buffers in heap), on the bounded-elastic scheduler.
 */
@Component
public class ImageArtifactStore {

    private static final Logger log = LoggerFactory.getLogger(ImageArtifactStore.class);
    private static final DataBufferFactory BUFFERS = new DefaultDataBufferFactory();
    private static final int CHUNK = 64 * 1024;

    private final Path root;

    public ImageArtifactStore(
            @Value("${imagegen.artifacts.dir:/var/hugmesh/image-artifacts}") String dir) {
        this.root = Path.of(dir).toAbsolutePath().normalize();
    }

    /** Stream the artifact at {@code ref} (a volume-relative path stored on the build row).
     *  Missing/blank ref or absent file → 404; a traversal/absolute ref → 400. */
    public Flux<DataBuffer> stream(String ref) {
        return Mono.fromCallable(() -> resolveContained(ref))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(path -> DataBufferUtils.read(path, BUFFERS, CHUNK));
    }

    private Path resolveContained(String ref) {
        if (ref == null || ref.isBlank()) {
            throw new ApiException(HttpStatus.NOT_FOUND, "no artifact is stored for this build yet");
        }
        Path candidate = root.resolve(ref).normalize();
        if (!candidate.startsWith(root)) {
            log.warn("[imagegen] rejected out-of-root artifact ref '{}'", ref);
            throw ApiException.badRequest("invalid artifact reference");
        }
        if (!Files.isRegularFile(candidate)) {
            throw new ApiException(HttpStatus.NOT_FOUND, "artifact not found on storage");
        }
        return candidate;
    }
}
