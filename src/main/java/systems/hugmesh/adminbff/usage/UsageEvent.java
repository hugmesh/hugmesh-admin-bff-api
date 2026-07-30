package systems.hugmesh.adminbff.usage;

/**
 * The usage event that crosses the Kafka bus (JSON value) and is persisted to
 * {@code hugmesh.usage_events} in ClickHouse. This is the contract the
 * producers (UIs / gateways / services) emit and the consumer
 * ({@code UsageEventConsumer}) reads:
 *
 * <pre>{@code {actor:String, role:"admin"|"user", action:String, module:String, ts:epochMillis}}</pre>
 *
 * <ul>
 *   <li>{@code role} = roles.contains("admin") ? "admin" : "user"</li>
 *   <li>{@code module} = MODULE_OF(action) (see {@link UsageService})</li>
 *   <li>{@code ts} = epoch millis the event occurred</li>
 * </ul>
 */
public record UsageEvent(String actor, String role, String action, String module, long ts) {
}
