package net.hugmesh.adminbff.servicecatalog;

/**
 * Provision response: deployment entity + effector-mode indicator.
 * {@code effectorReal=false} means ArgoCD was NOT called (NoopArgoCdClient / dark mode).
 */
public record ProvisionOutcome(ServiceDeployment deployment, boolean effectorReal) {}
