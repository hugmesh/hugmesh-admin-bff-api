package net.hugmesh.adminbff.account;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Stamp/read chokepoint for the {@code account.casdoor_sub} column (Liquibase
 * changeset 292) — the A5 part-B cross-carrier route-pin fix. See {@link
 * AccountCasdoorSubRow} for the full gap description; in one line: a route-access
 * {@code casdoor_user} pin written in Casdoor-UUID form matched a Casdoor-JWT
 * carrier (the JWT's raw {@code sub}) but never a native-login bff_ session for
 * the SAME human, because the introspect contract carried no sub — a UUID ALLOW
 * pin wrongly denied them, and a UUID DENY pin (a targeted ban) failed OPEN.
 *
 * <p>{@link #stamp} is called from the ONE native-login place the raw id_token is
 * decoded ({@code InternalAccountController#ensureAccount}, provider
 * {@code "casdoor"}), which re-runs on EVERY sign-in — so legacy rows (null
 * column) self-heal on their next native login, mirroring the roles re-sync.
 * Idempotent with a read-first fast path (the common repeat sign-in never
 * writes). No collision semantics and no uniqueness: the value is only ever
 * ADDED to the gateway's deny-wins pin-match identity set (see the changeset
 * comment for why UNIQUE would be wrong here).
 */
@Service
public class AccountCasdoorSubService {

    private final AccountCasdoorSubRepository repo;

    public AccountCasdoorSubService(AccountCasdoorSubRepository repo) {
        this.repo = repo;
    }

    /**
     * Persist the raw Casdoor {@code sub} UUID for {@code accountId}. Fast-paths to
     * a pure read when the persisted value already matches (the repeat-sign-in
     * shape). A null/blank {@code casdoorSub} is a NO-OP — never clears a
     * previously-stamped value (an id_token missing its {@code sub} claim is a
     * degenerate token; degrading to "keep what we know" beats erasing a working
     * pin identity). An unknown {@code accountId} no-ops at the UPDATE (0 rows),
     * exactly like {@code AccountLocalpartRepository}'s targeted writes.
     */
    public Mono<Void> stamp(String accountId, String casdoorSub) {
        if (casdoorSub == null || casdoorSub.isBlank()) {
            return Mono.empty();
        }
        String sub = casdoorSub.trim();
        return repo.findById(accountId)
                .defaultIfEmpty(new AccountCasdoorSubRow(accountId, null))
                .flatMap(row -> sub.equals(row.casdoorSub())
                        ? Mono.empty()
                        : repo.updateCasdoorSub(accountId, sub).then());
    }

    /** Read the persisted Casdoor {@code sub} UUID for an account id. Empty
     *  {@link Mono} when unset — a row that predates changeset 292, or one created
     *  off the casdoor mint path (google/discord invite accounts). Callers surface
     *  "unset" as null ({@code IntrospectResponse.casdoorSub}) and consumers MUST
     *  degrade to the pre-292 behavior on null — never guess a UUID. */
    public Mono<String> casdoorSubOf(String accountId) {
        return repo.findById(accountId)
                .mapNotNull(AccountCasdoorSubRow::casdoorSub)
                .filter(sub -> !sub.isBlank());
    }
}
