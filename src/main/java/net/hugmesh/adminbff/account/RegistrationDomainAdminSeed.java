package net.hugmesh.adminbff.account;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Duration;
import java.util.Set;

/**
 * Mirrors the {@code ADMIN_EMAILS} bootstrap invites into the domain the registration gate
 * actually queries, so a BRANDED deployment can still bootstrap its first admin.
 *
 * <h2>Why this exists — the two-sided contract behind auth-core issue #1</h2>
 *
 * <p>Domain-scoping the gate read ({@link RegistrationDomainResolver}) only holds together if
 * the WRITE side stamps the same domain. Every admin-managed write does:
 * {@code AdminController.invite} stamps the acting admin's {@link PrincipalDomain}. But there
 * is one write nobody administers — auth-core's {@code AccountStore.seedAdmins()}, an
 * {@code @PostConstruct} that runs on every boot and stamps a HARDCODED
 * {@link AccountStore#DEFAULT_DOMAIN} ({@code "default"}), because auth-core has no
 * {@code DomainRegistry} and no way to know which brand this deployment serves.
 *
 * <p>On an UNTENANTED install those two agree — {@link RegistrationDomainResolver#fallback()}
 * also answers {@code "default"} — and this class does nothing. On a BRANDED one they do not:
 *
 * <ul>
 *   <li>{@code app.tenancy.registration-domain=acme} → the gate reads {@code "acme"};</li>
 *   <li>{@code app.tenancy.issuers=https://id.acme.test=acme} (one named brand) →
 *       {@code knownDomains()} is {@code {"acme"}}, so the gate reads {@code "acme"}.</li>
 * </ul>
 *
 * <p>The gate is a plain SQL equality ({@code AllowlistRepository
 * .existsByProviderAndHandleAndDomain}) with no {@code "default"} widening, so the seeded row
 * is invisible and {@code POST /bff/register/google} for the bootstrap admin 403s
 * "email not invited by an admin". That is UNRECOVERABLE without direct SQL: {@code /bff/login}
 * answers "no account — register first" so no session can be minted, and the only other
 * allowlist writer, {@code AdminController.invite}, is {@code @PreAuthorize("hasRole('ADMIN')")}
 * — an admin must already exist to create the first admin. user-bff's SSO path is no escape
 * either: {@code AdminBffInternalClient} sends no {@code ?domain=}, so it lands on the same
 * {@code fallback()}.
 *
 * <h2>What it does</h2>
 *
 * <p>ADDS (never moves) the {@code ADMIN_EMAILS} rows in {@link RegistrationDomainResolver
 * #fallback()}'s domain. {@code inviteEmail} is {@code insertIfAbsent} over a composite PK that
 * already includes {@code domain}, so this is idempotent and the auth-core {@code "default"}
 * row survives — a rollback to the unscoped gate, or to an untenanted config, keeps working.
 *
 * <p>Two cases are deliberately skipped:
 * <ul>
 *   <li>{@code "default"} — auth-core's own seed already wrote exactly that row;</li>
 *   <li>{@link PrincipalDomain#NO_DOMAIN} — a multi-brand deployment with no pin, where there
 *       is no honest answer. It is logged at ERROR naming the knob, because on that deployment
 *       EVERY untokened registration fails closed, not just the admin's.</li>
 * </ul>
 *
 * <h2>Why {@link ObjectProvider}, not a plain constructor dependency</h2>
 *
 * <p>Same reason auth-core's {@code BffCookieAuthenticationWebFilter} documents for itself: a
 * hard {@code AccountStore} constructor parameter on a component-scanned {@code @Component}
 * fails to construct in every slice test whose context has no {@code AccountStore} bean, and
 * takes the whole context down with a {@code NoSuchBeanDefinitionException} (it did — it broke
 * {@code AccountStoreTest}'s 11 tests). {@code @ConditionalOnBean} is not the fix either;
 * Spring's own docs call it unreliable on a plain {@code @Component}. Resolving lazily inside
 * {@code @PostConstruct} means this bean ALWAYS constructs, and a context with no
 * {@code AccountStore} (or no resolver) simply has nothing to mirror.
 *
 * <p>Ordering is preserved: {@link ObjectProvider#getIfAvailable()} fully initialises the
 * {@link AccountStore} bean — including its own {@code @PostConstruct} seed — before returning
 * it, so the {@code "default"} rows always exist by the time this mirrors them.
 *
 * <p><b>Scope limit.</b> This covers the operator-declared bootstrap admins only. Invite rows
 * that predate a tenancy change also carry {@code "default"} (the changeset-220 back-fill) and
 * are NOT restamped: those deployments already have a working admin who can re-issue invites
 * in the new domain. See the upgrade note on {@code app.tenancy.registration-domain}.
 */
@Component
public class RegistrationDomainAdminSeed {

    private static final Logger log = LoggerFactory.getLogger(RegistrationDomainAdminSeed.class);

    /** Mirrors {@code AccountStore.seedAdmins()}'s own blocking budget. */
    private static final Duration SEED_TIMEOUT = Duration.ofSeconds(10);

    private final ObjectProvider<AccountStore> storeProvider;
    private final ObjectProvider<RegistrationDomainResolver> domainsProvider;

    public RegistrationDomainAdminSeed(ObjectProvider<AccountStore> storeProvider,
                                       ObjectProvider<RegistrationDomainResolver> domainsProvider) {
        this.storeProvider = storeProvider;
        this.domainsProvider = domainsProvider;
    }

    /**
     * Blocks intentionally, exactly as {@code AccountStore.seedAdmins()} does, and swallows a
     * datastore failure the same way: a boot must not die because the database is not up yet.
     */
    @PostConstruct
    public void seedIntoRegistrationDomain() {
        AccountStore store = storeProvider.getIfAvailable();
        RegistrationDomainResolver domains = domainsProvider.getIfAvailable();
        if (store == null || domains == null) {
            // A slice context with no account store / resolver: nothing to mirror.
            return;
        }

        String domain = domains.fallback();
        if (domain == null || domain.isBlank()) {
            // Only reachable behind a mocked resolver in a slice test; the real one is
            // documented never to return null.
            return;
        }

        if (PrincipalDomain.NO_DOMAIN.equals(domain)) {
            log.error("[registration-gate] this deployment serves two or more brands and "
                    + "app.tenancy.registration-domain is unset, so NO untokened registration "
                    + "can succeed — including the ADMIN_EMAILS bootstrap admin(s). Set "
                    + "APP_TENANCY_REGISTRATION_DOMAIN to the brand this admin-bff registers for.");
            return;
        }
        if (AccountStore.DEFAULT_DOMAIN.equals(domain)) {
            // Untenanted / single-issuer back-compat: auth-core's seed already wrote this row.
            return;
        }

        try {
            Set<String> admins = store.admins();
            if (admins == null || admins.isEmpty()) {
                return;
            }
            for (String email : admins) {
                store.inviteEmail(email, domain).block(SEED_TIMEOUT);
            }
            log.info("[registration-gate] mirrored {} bootstrap admin invite(s) into domain '{}' "
                    + "(auth-core seeds them as '{}', which this deployment's gate does not read)",
                    admins.size(), domain, AccountStore.DEFAULT_DOMAIN);
        } catch (Exception e) {
            log.warn("[registration-gate] bootstrap admin mirror into domain '{}' skipped "
                    + "(datastore unavailable): {}", domain, e.toString());
        }
    }
}
