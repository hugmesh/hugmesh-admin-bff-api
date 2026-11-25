package net.hugmesh.adminbff.domainregistry;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.regex.Pattern;

/**
 * FIRST-START IMPORT of the build-time domain list — operator decision 85c = D (2026-09-23,
 * hugmesh-generator#527): "Build time picks for a new mesh, and the admin-bff imports those".
 *
 * <h3>The problem it closes</h3>
 * On a brand-new mesh the build (the Studio / KEYS stick) chooses each domain's SELinux MCS pair
 * BEFORE any admin-bff exists, and first boot stamps those pairs onto the live cluster. The
 * admin-bff's own allocator ({@link McsCategoryAllocator}) hands out the LOWEST FREE slot of the
 * same reserved range, and it only knows what is in {@code domain_registry}. So an admin-bff that
 * started with an empty registry would give the next domain a pair the stick already put on a
 * running pod — two workloads sharing a category, which SELinux does not report (it fails OPEN).
 * Importing the stick's domains as the registry's first rows makes the allocator see those slots
 * as taken. Only one allocator is ever active: the build before the admin-bff exists, the
 * admin-bff after.
 *
 * <h3>When it runs</h3>
 * Once per start, and it does something ONLY when both hold:
 * <ol>
 *   <li>{@code app.domain-registry.import-path} is set (default unset: no-op);</li>
 *   <li>{@code domain_registry} is EMPTY. A non-empty registry is never imported into, and the
 *       file is not even read — so once the first start has imported, a stale or later-broken
 *       file can never block a restart.</li>
 * </ol>
 *
 * <h3>File format (this class defines the admin-bff side of the contract)</h3>
 * UTF-8 JSON: either the KEYS stick's {@code provision.json} (an object whose {@code domains} key
 * is the list — decision 85a = A puts it there) or a bare array of the same entries. One entry:
 * <pre>
 *   {"clusterDomain": "brandb.example",   required, lowercase DNS name
 *    "title":         "Brand B",          optional, stored as brand_title (decision 87e rules)
 *    "nsPrefix":      "brandb",           required, the slug (DomainSlug rules)
 *    "casdoorOrg":    "brandb",           optional
 *    "idp":           "own",              optional, own|superdomain (default superdomain)
 *    "selinuxLevel":  "s0:c256",          required, the EVEN category of a reserved slot
 *    "selinuxLevelPg":"s0:c257"}          required, exactly selinuxLevel + 1
 * </pre>
 * Other keys are ignored. The generator's {@code provision.json} has no {@code domains[]} yet
 * (decision 85a is unbuilt there); this is the shape it has to emit.
 *
 * <h3>All or nothing, and loud</h3>
 * EVERY entry is validated before anything is written, and every problem is reported at once. A
 * pair outside {@code s0:c256..s0:c1023}, a pair that is not one allocator slot
 * {@code (FLOOR+2n, FLOOR+2n+1)}, a duplicated pair, a duplicated domain or slug, a missing or
 * malformed required field, an unreadable file or unparseable JSON REFUSES THE WHOLE IMPORT and
 * inserts nothing. The rows are then inserted in ONE transaction, so a database-level failure
 * also leaves the registry empty.
 *
 * <p>A refusal makes the admin-bff REFUSE TO START (this runner throws, as
 * {@code InternalSurfaceTokenBootGuard} does for a missing internal token). That is deliberate:
 * the alternative — start with an empty registry and log an error — is exactly the state that
 * lets the allocator re-issue a live pair. A crash loop is visible in {@code kubectl}; a log line
 * is not. The fix is to correct the file or unset the property.
 *
 * <p>Two replicas starting together (the admin-bff HPA keeps at least two) can both see an empty
 * registry. The loser's transaction then trips a UNIQUE constraint and rolls back; if every
 * entry of the file is by then present with the same slug and pair, that is treated as "the
 * other replica imported it" and the start continues. Anything else still refuses to start.
 *
 * <p>Imported rows are stamped {@code created_by_subject = } {@value #IMPORT_SUBJECT}, enabled,
 * with no brand/org/caRef/meshTag/headscaleUrl (the entry does not carry them; a SUPERADMIN sets
 * them later). The per-domain {@code @system} notification account is NOT provisioned here — the
 * SUPERADMIN re-provision endpoint covers imported domains.
 */
@Component
public class DomainRegistryFirstStartImporter implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DomainRegistryFirstStartImporter.class);

    /** {@code created_by_subject} on every imported row. */
    public static final String IMPORT_SUBJECT = "system:first-start-import";

    /** A lowercase DNS name — hugmesh-domain-reconcile {@code _DR_DNS_NAME}, which refuses others. */
    private static final Pattern DNS_NAME = Pattern.compile(
            "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$");

    private static final int MAX_DOMAIN = 253;
    private static final int MAX_CASDOOR_ORG = 255;
    private static final Duration TIMEOUT = Duration.ofSeconds(60);

    private final DomainRegistryRepository repo;
    private final TransactionalOperator tx;
    private final String importPath;

    public DomainRegistryFirstStartImporter(
            DomainRegistryRepository repo,
            TransactionalOperator tx,
            @Value("${app.domain-registry.import-path:}") String importPath) {
        this.repo = repo;
        this.tx = tx;
        this.importPath = importPath == null ? "" : importPath.trim();
    }

    /** Thrown when the file cannot be imported; it stops the application from starting. */
    public static final class ImportRefused extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        ImportRefused(String message) {
            super(message);
        }

        ImportRefused(String message, Throwable cause) {
            super(message, cause);
        }
    }

    @Override
    public void run(ApplicationArguments args) {
        importIfConfigured();
    }

    /**
     * The whole first-start decision. Returns the number of rows imported (0 for every no-op).
     *
     * @throws ImportRefused when a configured file cannot be imported into an empty registry
     */
    public int importIfConfigured() {
        if (importPath.isEmpty()) {
            return 0;
        }
        if (!Boolean.TRUE.equals(repo.isEmpty().block(TIMEOUT))) {
            log.info("[domain-registry] first-start import skipped: domain_registry is not empty "
                    + "(import-path={} is only ever read into an empty registry)", importPath);
            return 0;
        }
        List<DomainRegistration> drafts = parse(Path.of(importPath));
        if (drafts.isEmpty()) {
            log.warn("[domain-registry] first-start import: {} lists no domains; nothing imported",
                    importPath);
            return 0;
        }
        return importDrafts(drafts);
    }

    /**
     * Insert the validated drafts in ONE transaction. On failure, accept the outcome only if a
     * concurrent replica has imported exactly these rows; otherwise refuse.
     */
    int importDrafts(List<DomainRegistration> drafts) {
        try {
            List<DomainRegistration> saved = Flux.fromIterable(drafts)
                    .concatMap(d -> repo.insert(d, IMPORT_SUBJECT))
                    .collectList()
                    .as(tx::transactional)
                    .block(TIMEOUT);
            int n = saved == null ? 0 : saved.size();
            for (DomainRegistration d : Objects.requireNonNullElse(saved, List.<DomainRegistration>of())) {
                log.warn("[domain-registry] AUDIT first-start import cluster_domain={} slug={} "
                                + "selinux_level={} selinux_level_pg={} from={}",
                        d.clusterDomain(), d.nsPrefix(), d.selinuxLevel(), d.selinuxLevelPg(),
                        importPath);
            }
            return n;
        } catch (RuntimeException e) {
            if (alreadyImportedByPeer(drafts)) {
                log.info("[domain-registry] first-start import: another replica imported the same "
                        + "{} domain(s) first; nothing to do", drafts.size());
                return 0;
            }
            throw new ImportRefused("first-start import of " + importPath + " failed and "
                    + "nothing was imported: " + e.getMessage(), e);
        }
    }

    /** Whether every draft is now stored with the same slug and MCS pair. */
    private boolean alreadyImportedByPeer(List<DomainRegistration> drafts) {
        for (DomainRegistration d : drafts) {
            DomainRegistration stored = repo.findByClusterDomain(d.clusterDomain()).block(TIMEOUT);
            if (stored == null
                    || !Objects.equals(stored.nsPrefix(), d.nsPrefix())
                    || !Objects.equals(stored.selinuxLevel(), d.selinuxLevel())
                    || !Objects.equals(stored.selinuxLevelPg(), d.selinuxLevelPg())) {
                return false;
            }
        }
        return true;
    }

    /**
     * Read and fully validate the file. Pure apart from the read; every problem is collected and
     * reported in one {@link ImportRefused}.
     */
    static List<DomainRegistration> parse(Path path) {
        JsonNode root;
        try {
            root = new ObjectMapper().readTree(Files.readString(path));
        } catch (IOException | RuntimeException e) {
            throw new ImportRefused("first-start import refused: cannot read " + path
                    + " as JSON (" + e.getMessage() + "); nothing was imported", e);
        }
        JsonNode list = root != null && root.isObject() ? root.get("domains") : root;
        if (list == null || !list.isArray()) {
            throw new ImportRefused("first-start import refused: " + path + " is neither a JSON "
                    + "array of domains nor an object with a 'domains' array; nothing was imported");
        }
        List<String> problems = new ArrayList<>();
        List<DomainRegistration> drafts = new ArrayList<>();
        Map<String, Integer> domains = new HashMap<>();
        Map<String, Integer> slugs = new HashMap<>();
        Map<Integer, Integer> slots = new HashMap<>();
        for (int i = 0; i < list.size(); i++) {
            DomainRegistration d = entry(i, list.get(i), problems);
            if (d == null) {
                continue;
            }
            duplicate("clusterDomain '" + d.clusterDomain() + "'", domains, d.clusterDomain(), i,
                    problems);
            duplicate("nsPrefix '" + d.nsPrefix() + "'", slugs, d.nsPrefix(), i, problems);
            duplicate("MCS pair (" + d.selinuxLevel() + ", " + d.selinuxLevelPg() + ")", slots,
                    McsCategoryAllocator.slotOf(d.selinuxLevel()).getAsInt(), i, problems);
            drafts.add(d);
        }
        if (!problems.isEmpty()) {
            throw new ImportRefused("first-start import of " + path + " refused, nothing was "
                    + "imported: " + String.join("; ", problems));
        }
        return List.copyOf(drafts);
    }

    private static <K> void duplicate(String what, Map<K, Integer> seen, K key, int index,
                                      List<String> problems) {
        Integer first = seen.putIfAbsent(key, index);
        if (first != null) {
            problems.add("domains[" + index + "]: " + what + " duplicates domains[" + first + "]");
        }
    }

    /** One validated draft, or {@code null} with its problems appended. */
    private static DomainRegistration entry(int i, JsonNode node, List<String> problems) {
        String at = "domains[" + i + "]";
        if (node == null || !node.isObject()) {
            problems.add(at + " is not an object");
            return null;
        }
        int before = problems.size();
        String domain = text(node, "clusterDomain", at, problems);
        String title = text(node, "title", at, problems);
        String slug = text(node, "nsPrefix", at, problems);
        String casdoorOrg = text(node, "casdoorOrg", at, problems);
        String idp = text(node, "idp", at, problems);
        String level = text(node, "selinuxLevel", at, problems);
        String levelPg = text(node, "selinuxLevelPg", at, problems);
        if (domain == null || domain.length() > MAX_DOMAIN || !DNS_NAME.matcher(domain).matches()) {
            problems.add(at + ".clusterDomain must be a lowercase DNS name of at most "
                    + MAX_DOMAIN + " characters: got " + quoted(domain));
        }
        DomainSlug.refusalReason(slug).ifPresent(r -> problems.add(at + ": " + r));
        if (title != null) {
            DomainBrandFields.titleRefusal(title).ifPresent(r -> problems.add(at + ".title: " + r));
        }
        if (casdoorOrg != null && casdoorOrg.length() > MAX_CASDOOR_ORG) {
            problems.add(at + ".casdoorOrg is longer than " + MAX_CASDOOR_ORG + " characters");
        }
        DomainIdp.refusalReason(idp).ifPresent(r -> problems.add(at + ": " + r));
        pairProblem(level, levelPg).ifPresent(r -> problems.add(at + ": " + r));
        if (problems.size() != before) {
            return null;
        }
        return new DomainRegistration(null, domain, null, null, null, slug,
                casdoorOrg == null || casdoorOrg.isEmpty() ? null : casdoorOrg, null, true,
                null, IMPORT_SUBJECT, null, false, false, 0L, DomainIdp.normalize(idp),
                level, levelPg, title == null || title.isEmpty() ? null : title, null);
    }

    /**
     * Why {@code (level, levelPg)} is not exactly one allocator slot, or empty when it is. This is
     * STRICTER than the repository's explicit-pair range check on purpose: the allocator only ever
     * issues {@code (FLOOR+2n, FLOOR+2n+1)}, and a pair in any other shape would let the next
     * allocation hand out a category this row already holds.
     */
    static java.util.Optional<String> pairProblem(String level, String levelPg) {
        if (level == null || levelPg == null) {
            return java.util.Optional.of("selinuxLevel and selinuxLevelPg are both required "
                    + "(the pair the build chose must be imported, or the allocator will reuse it)");
        }
        if (!McsCategoryAllocator.isInReservedRange(level)
                || !McsCategoryAllocator.isInReservedRange(levelPg)) {
            return java.util.Optional.of("MCS pair (" + level + ", " + levelPg + ") is outside the "
                    + "reserved per-domain range s0:c" + McsCategoryAllocator.FLOOR_CATEGORY
                    + "..s0:c" + McsCategoryAllocator.CEILING_CATEGORY);
        }
        OptionalInt slot = McsCategoryAllocator.slotOf(level);
        if (slot.isEmpty()
                || !McsCategoryAllocator.forSlot(slot.getAsInt()).levelPg().equals(levelPg.trim())
                || !level.equals(level.trim())
                || !levelPg.equals(levelPg.trim())) {
            return java.util.Optional.of("MCS pair (" + level + ", " + levelPg + ") is not an "
                    + "allocator slot: selinuxLevel must be the EVEN category s0:c("
                    + McsCategoryAllocator.FLOOR_CATEGORY + "+2n) and selinuxLevelPg exactly one "
                    + "above it");
        }
        return java.util.Optional.empty();
    }

    /** A string field, or {@code null} when absent/null; a non-string value is a problem. */
    private static String text(JsonNode node, String field, String at, List<String> problems) {
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) {
            return null;
        }
        if (!v.isTextual()) {
            problems.add(at + "." + field + " must be a string");
            return null;
        }
        return v.asText();
    }

    private static String quoted(String s) {
        return s == null ? "nothing" : "'" + s + "'";
    }
}
