package systems.hugmesh.adminbff.golive;

import java.util.List;
import java.util.Optional;

/**
 * The DECLARATIVE go-live PROVIDER CATALOG — the wizard-design's single source the four
 * interfaces (CLI / ncurses / Studio GUI / this admin web UI) read, so "a new provider is one
 * row, not four edits". This is the web-UI copy of the generator's
 * {@code scripts/golive-providers.conf} vocabulary: per provider, the exposure model it
 * serves, the DEEP-LINK the wizard opens in the operator's browser, the inputs it collects,
 * and the artifacts the generator engine emits for it.
 *
 * <p><b>Deep-link + autofill, NOT API drivers (v1 posture).</b> Per the pinned design, only
 * the single-token DDNS updaters are realistic thin API drivers; everything else is
 * deep-link + downloadable files + autofill. {@code apiDriver} records that split so the UI
 * can render "opens your provider's page" vs "configures automatically".
 *
 * <p><b>NO SECRETS.</b> Entries carry PUBLIC provider metadata only. The wizard's collected
 * tokens (tunnel token / DNS API token / DDNS token) route to the keys-USB/Vault paths on the
 * generator side — they NEVER transit or persist in the admin BFF.
 */
public final class GoLiveProviderCatalog {

    private GoLiveProviderCatalog() {
    }

    /** Wizard step-1 exposure models (the {@code exposure_model} CHECK vocabulary). */
    public static final String MODEL_TUNNEL = "tunnel";
    public static final String MODEL_PUBLIC_DNS = "public_dns";
    public static final String MODEL_FUNNEL = "funnel";

    /**
     * One catalog row. All fields are PUBLIC metadata (never a credential).
     *
     * @param key            the stable catalog key an intent's {@code provider} pins
     * @param label          the human name the wizard renders
     * @param exposureModel  which step-1 exposure model this provider serves
     * @param deepLink       the exact provider page the wizard deep-links (https, public)
     * @param requiredInputs the operator inputs the wizard collects for it (names only —
     *                       the VALUES route to keys-USB/Vault, never this BFF)
     * @param artifacts      the files/config the generator engine emits for it
     * @param apiDriver      true for the thin real-API integrations (DDNS single-token
     *                       updaters); false = deep-link + autofill + files only
     * @param notes          one-line UI hint
     */
    public record GoLiveProvider(
            String key,
            String label,
            String exposureModel,
            String deepLink,
            List<String> requiredInputs,
            List<String> artifacts,
            boolean apiDriver,
            String notes) {
    }

    /** The prioritized v1 catalog (the pinned design's provider list, in priority order). */
    public static final List<GoLiveProvider> PROVIDERS = List.of(
            new GoLiveProvider(
                    "cloudflare-tunnel", "Cloudflare Tunnel", MODEL_TUNNEL,
                    "https://one.dash.cloudflare.com/",
                    List.of("tunnelToken"),
                    List.of("keys/cloudflared/TUNNEL_TOKEN", "hostname-checklist"),
                    false,
                    "Flagship path — plumbing already baked (apps/12-cloudflared.yaml); the "
                            + "wizard deep-links the Zero-Trust tunnel page and routes the token "
                            + "to the keys layout. No inbound ports needed."),
            new GoLiveProvider(
                    // Catalog key unified with the generator's shell registry
                    // (GO_LIVE_PROVIDER_IDS in go-live-providers.sh), which already uses
                    // 'byo-domain'. Renamed from the original 'generic-registrar' so the two
                    // vocabularies share one identity; the host-agent reconcile shim
                    // (hugmesh-go-live-reconcile map_bff_provider) retains
                    // 'generic-registrar' as a LEGACY ALIAS for pre-rename exports / rows.
                    "byo-domain", "Bring-your-own-domain (any registrar)", MODEL_PUBLIC_DNS,
                    "https://www.iana.org/domains",
                    List.of("apexDomain", "ingressIpOrCname"),
                    List.of("record-set.txt", "zone-file.bind", "records.csv"),
                    false,
                    "Copy-paste record set + downloadable BIND zone/CSV for Namecheap / GoDaddy / "
                            + "Porkbun / Route53 and any other registrar. Covers everyone; no API."),
            new GoLiveProvider(
                    "duckdns", "DuckDNS (dynamic DNS)", MODEL_PUBLIC_DNS,
                    "https://www.duckdns.org/",
                    List.of("ddnsToken", "subdomain"),
                    List.of("ddns-agent.conf", "ddns-cron"),
                    true,
                    "Thin single-token update driver — the realistic 'real integration' for "
                            + "home/CGNAT operators."),
            new GoLiveProvider(
                    "cloudflare-ddns", "Cloudflare DNS (dynamic-DNS update)", MODEL_PUBLIC_DNS,
                    "https://dash.cloudflare.com/profile/api-tokens",
                    List.of("apiToken", "zoneName"),
                    List.of("ddns-agent.conf", "ddns-cron"),
                    true,
                    "Thin API driver over the Cloudflare DNS update endpoint (scoped token)."),
            new GoLiveProvider(
                    "tailscale-funnel", "Tailscale/Headscale Funnel", MODEL_FUNNEL,
                    "https://tailscale.com/kb/1223/funnel",
                    List.of(),
                    List.of("funnel-checklist"),
                    false,
                    "Tailnet-native exposure without public DNS or opened ports — the painless "
                            + "alternative to 80/443."),
            new GoLiveProvider(
                    "router-portforward", "Router port-forward (instructions)", MODEL_PUBLIC_DNS,
                    "https://192.168.1.1/",
                    List.of(),
                    List.of("port-forward-checklist"),
                    false,
                    "Pure instructions — per-vendor port-forward guidance. The wizard NEVER "
                            + "mutates a router (no UPnP writes)."));

    /** Catalog lookup by stable key. */
    public static Optional<GoLiveProvider> find(String key) {
        if (key == null) {
            return Optional.empty();
        }
        return PROVIDERS.stream().filter(p -> p.key().equals(key)).findFirst();
    }
}
