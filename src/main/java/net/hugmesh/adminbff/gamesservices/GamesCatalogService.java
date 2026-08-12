package net.hugmesh.adminbff.gamesservices;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.dto.GameCatalogEntryRequest;
import net.hugmesh.adminbff.web.dto.GameDomainOfferRequest;

import java.util.Set;

/**
 * The SUPERADMIN control plane for the games app-store catalog (schema 090):
 * <ul>
 *   <li>CURATE the GLOBAL catalog — create / update / soft-disable
 *       {@link GameServerCatalogEntry} rows. The catalog is cross-domain, so these are
 *       UNSCOPED (the controller's {@code hasRole('SUPERADMIN')} is the gate).</li>
 *   <li>OFFER catalog servers to specific domains — create / update
 *       {@link GameServerDomainOffer} rows. The superadmin sets {@code offered_by_superadmin}
 *       (the creation gate) + the {@code max_instances} quota; the per-domain admin later
 *       flips {@code enabled_by_admin} (PR6). These are addressed by an EXPLICIT domain in
 *       the path (the superadmin acts on any brand), so they carry no PrincipalDomain.</li>
 * </ul>
 *
 * <p>Modelled on {@link net.hugmesh.adminbff.domainregistry.DomainRegistryService}:
 * find-before-insert idempotency (a duplicate is a clean 409, the DB UNIQUE index is the
 * race backstop), PATCH-style merge on update (null fields leave the current value),
 * soft-disable via flags (never DELETE), {@code created_by_subject} stamped from the
 * SUPERADMIN JWT subject.
 *
 * <p><b>Digest-pin invariant.</b> {@code create}/{@code update} of a catalog entry runs
 * {@link ImageRef#validate(String)} BEFORE any write — a tag-only reference is a clean 400
 * (arbitrary-container exec containment). The DB CHECK is the defence-in-depth backstop.
 */
@Service
public class GamesCatalogService {

    private static final Logger log = LoggerFactory.getLogger(GamesCatalogService.class);

    private static final Set<String> PROTOCOLS = Set.of(
            GameServerCatalogEntry.PROTOCOL_TCP, GameServerCatalogEntry.PROTOCOL_UDP,
            GameServerCatalogEntry.PROTOCOL_BOTH, GameServerCatalogEntry.PROTOCOL_NONE);

    private final GameServerCatalogRepository catalog;
    private final GameServerDomainOfferRepository offers;

    public GamesCatalogService(GameServerCatalogRepository catalog,
                               GameServerDomainOfferRepository offers) {
        this.catalog = catalog;
        this.offers = offers;
    }

    // ── GLOBAL CATALOG (superadmin-curated) ──────────────────────────────────────

    public Flux<GameServerCatalogEntry> listCatalog() {
        return catalog.findAll();
    }

    public Mono<GameServerCatalogEntry> getCatalog(String slug) {
        return catalog.findBySlug(slug)
                .switchIfEmpty(Mono.error(ApiException.notFound(
                        "no catalog entry for slug '" + slug + "'")));
    }

    /**
     * Curate a NEW catalog entry. Validates the digest-pin + protocol BEFORE any write,
     * then find-before-insert on the {@code slug} natural key (a duplicate is a 409, the
     * DB UNIQUE index is the race backstop). {@code enabled} defaults true.
     */
    public Mono<GameServerCatalogEntry> createCatalog(GameCatalogEntryRequest req,
                                                      String createdBySubject) {
        String slug = trim(req.slug());
        if (slug == null || slug.isBlank()) {
            return Mono.error(ApiException.badRequest("slug is required"));
        }
        String imageRef;
        String protocol;
        try {
            imageRef = ImageRef.validate(trim(req.imageRef()));
            protocol = validProtocol(req.protocol());
        } catch (IllegalArgumentException e) {
            return Mono.error(ApiException.badRequest(e.getMessage()));
        }
        if (isBlank(req.displayName())) {
            return Mono.error(ApiException.badRequest("displayName is required"));
        }
        if (isBlank(req.licenseSpdx())) {
            return Mono.error(ApiException.badRequest("licenseSpdx is required"));
        }
        GameServerCatalogEntry draft = new GameServerCatalogEntry(
                null, slug, trim(req.displayName()), imageRef, trim(req.licenseSpdx()),
                protocol, req.containerPort() == null ? 0 : req.containerPort(),
                req.consolePort(), req.summary(),
                !Boolean.FALSE.equals(req.enabled()),
                null, createdBySubject, null);
        return catalog.findBySlug(slug)
                .flatMap(existing -> Mono.<GameServerCatalogEntry>error(ApiException.conflict(
                        "catalog entry '" + slug + "' already exists")))
                .switchIfEmpty(Mono.defer(() -> catalog.insert(draft, createdBySubject)
                        .doOnNext(saved -> log.info(
                                "[games-catalog] curated slug={} license={} by={} (id={})",
                                saved.slug(), saved.licenseSpdx(), createdBySubject, saved.id()))
                        .onErrorResume(e -> catalog.findBySlug(slug)
                                .flatMap(now -> Mono.<GameServerCatalogEntry>error(ApiException.conflict(
                                        "catalog entry '" + slug + "' already exists")))
                                .switchIfEmpty(Mono.error(e)))));
    }

    /**
     * Update an existing catalog entry's MUTABLE descriptors (matched by {@code slug}).
     * Null request fields leave the current value (PATCH-style); {@code enabled:false} is
     * the soft-disable. A provided {@code imageRef} is re-validated (still must be
     * digest-pinned). The PK/{@code slug}/provenance are IMMUTABLE; 404 if no such slug.
     */
    public Mono<GameServerCatalogEntry> updateCatalog(String slug, GameCatalogEntryRequest req) {
        return catalog.findBySlug(slug)
                .switchIfEmpty(Mono.error(ApiException.notFound(
                        "no catalog entry for slug '" + slug + "'")))
                // Merge mutable request fields onto the current entry and persist.
                .flatMap(current -> mergeAndUpdateCatalogEntry(current, req));
    }

    // ── PER-DOMAIN OFFERS (superadmin offers a catalog slug to a domain) ─────────

    /** Every offer for one explicit domain (the SUPERADMIN per-domain offer surface). */
    public Flux<GameServerDomainOffer> listOffers(String domain) {
        return offers.findByDomain(domain);
    }

    /**
     * OFFER a catalog slug to a domain (the TIER-1 creation gate). The catalog slug must
     * exist (404 otherwise). Find-before-insert on {@code (domain, slug)} (a duplicate is a
     * 409). {@code offeredBySuperadmin} defaults true (offering it IS the gate flip);
     * {@code enabledByAdmin} defaults false (the domain admin enables later);
     * {@code maxInstances} defaults 1.
     */
    public Mono<GameServerDomainOffer> createOffer(String domain, GameDomainOfferRequest req,
                                                   String createdBySubject) {
        String slug = trim(req.slug());
        if (slug == null || slug.isBlank()) {
            return Mono.error(ApiException.badRequest("slug is required"));
        }
        int max = req.maxInstances() == null ? 1 : req.maxInstances();
        if (max < 0) {
            return Mono.error(ApiException.badRequest("maxInstances must be >= 0"));
        }
        GameServerDomainOffer draft = new GameServerDomainOffer(null, domain, slug,
                !Boolean.FALSE.equals(req.offeredBySuperadmin()),
                Boolean.TRUE.equals(req.enabledByAdmin()),
                max, null, createdBySubject, null);
        return catalog.findBySlug(slug)
                .switchIfEmpty(Mono.error(ApiException.notFound(
                        "no catalog entry for slug '" + slug + "' — curate it before offering")))
                .then(offers.find(domain, slug)
                        .flatMap(existing -> Mono.<GameServerDomainOffer>error(ApiException.conflict(
                                "domain '" + domain + "' is already offered '" + slug + "'")))
                        .switchIfEmpty(Mono.defer(() -> offers.insert(draft, createdBySubject)
                                .doOnNext(saved -> log.info(
                                        "[games-catalog] offered slug={} -> domain={} max={} by={} (id={})",
                                        saved.slug(), saved.domain(), saved.maxInstances(),
                                        createdBySubject, saved.id()))
                                .onErrorResume(e -> offers.find(domain, slug)
                                        .flatMap(now -> Mono.<GameServerDomainOffer>error(ApiException.conflict(
                                                "domain '" + domain + "' is already offered '" + slug + "'")))
                                        .switchIfEmpty(Mono.error(e))))));
    }

    /**
     * Update an existing offer's flags/quota (matched by {@code (domain, slug)}). Null
     * request fields leave the current value (PATCH-style); withdraw an offer by sending
     * {@code offeredBySuperadmin:false}. 404 if no such offer.
     */
    public Mono<GameServerDomainOffer> updateOffer(String domain, String slug,
                                                   GameDomainOfferRequest req) {
        return offers.find(domain, slug)
                .switchIfEmpty(Mono.error(ApiException.notFound(
                        "no offer of '" + slug + "' for domain '" + domain + "'")))
                // Merge mutable offer flags/quota onto the current offer and persist.
                .flatMap(current -> mergeAndUpdateOffer(current, req));
    }

    // ── helpers ──────────────────────────────────────────────────────────────────

    /** Merge mutable catalog-update request fields onto the current entry and persist. */
    private Mono<GameServerCatalogEntry> mergeAndUpdateCatalogEntry(GameServerCatalogEntry current,
                                                                     GameCatalogEntryRequest req) {
        String imageRef;
        String protocol;
        try {
            imageRef = req.imageRef() == null
                    ? current.imageRef() : ImageRef.validate(trim(req.imageRef()));
            protocol = req.protocol() == null
                    ? current.protocol() : validProtocol(req.protocol());
        } catch (IllegalArgumentException e) {
            return Mono.error(ApiException.badRequest(e.getMessage()));
        }
        GameServerCatalogEntry merged = new GameServerCatalogEntry(
                current.id(), current.slug(),
                req.displayName() == null ? current.displayName() : trim(req.displayName()),
                imageRef,
                req.licenseSpdx() == null ? current.licenseSpdx() : trim(req.licenseSpdx()),
                protocol,
                req.containerPort() == null ? current.containerPort() : req.containerPort(),
                req.consolePort() == null ? current.consolePort() : req.consolePort(),
                req.summary() == null ? current.summary() : req.summary(),
                req.enabled() == null ? current.enabled() : req.enabled(),
                current.createdAt(), current.createdBySubject(), current.updatedAt());
        return catalog.update(merged)
                .doOnNext(saved -> log.info("[games-catalog] updated slug={} enabled={} (id={})",
                        saved.slug(), saved.enabled(), saved.id()));
    }

    /** Merge mutable offer-update request flags/quota onto the current offer and persist. */
    private Mono<GameServerDomainOffer> mergeAndUpdateOffer(GameServerDomainOffer current,
                                                             GameDomainOfferRequest req) {
        int max = req.maxInstances() == null ? current.maxInstances() : req.maxInstances();
        if (max < 0) {
            return Mono.error(ApiException.badRequest("maxInstances must be >= 0"));
        }
        GameServerDomainOffer merged = new GameServerDomainOffer(
                current.id(), current.domain(), current.slug(),
                req.offeredBySuperadmin() == null
                        ? current.offeredBySuperadmin() : req.offeredBySuperadmin(),
                req.enabledByAdmin() == null
                        ? current.enabledByAdmin() : req.enabledByAdmin(),
                max, current.createdAt(), current.createdBySubject(), current.updatedAt());
        return offers.update(merged)
                .doOnNext(saved -> log.info("[games-catalog] offer slug={} domain={} offered={} max={}",
                        saved.slug(), saved.domain(), saved.offeredBySuperadmin(), saved.maxInstances()));
    }

    private String validProtocol(String protocol) {
        String p = protocol == null ? GameServerCatalogEntry.PROTOCOL_UDP : protocol.trim().toLowerCase();
        if (!PROTOCOLS.contains(p)) {
            throw new IllegalArgumentException(
                    "protocol must be one of tcp/udp/both/none");
        }
        return p;
    }

    private static String trim(String s) {
        return s == null ? null : s.trim();
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
