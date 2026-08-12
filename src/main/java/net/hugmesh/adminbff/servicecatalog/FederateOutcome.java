package net.hugmesh.adminbff.servicecatalog;

/**
 * Federate response: the deployment that was federated + two honest mode indicators.
 *
 * <ul>
 *   <li>{@code federationReal=false} — the federation-api was NOT called
 *       ({@code NoopFederationModuleClient} / {@code app.appstore.federation.enabled=false}); the
 *       would-be register was logged only.</li>
 *   <li>{@code gitopsDescriptorPending=true} — the GitOps descriptor automation (writing the
 *       remote's ArgoCD descriptor so its manifest floor is reconciled) does NOT exist yet, so it
 *       is {@code true} regardless of {@code federationReal} until that automation lands.</li>
 * </ul>
 */
public record FederateOutcome(ServiceDeployment deployment, boolean federationReal,
                              boolean gitopsDescriptorPending) {}
