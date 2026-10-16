package net.hugmesh.adminbff.notification.channel;

import reactor.core.publisher.Mono;

/**
 * Turns the outbox {@code target} (a Casdoor subject such as {@code org/alice}) into the
 * address the {@link EmailChannel} mails, for a subject that is not itself an email address.
 *
 * <p>The contract the channel relies on (each point has a test): an EMPTY result means "no
 * address on file" and the row is terminally {@link ChannelOutcome#SKIPPED}; an ERROR means
 * the lookup itself failed and the row is {@link ChannelOutcome#FAILED} (retried); a value
 * that is not email-shaped is treated as no address, so nothing malformed is ever handed to
 * the mail sender.
 *
 * <p><b>No production implementation exists.</b> The source for a real one is the account's
 * stored profile email, which the auth-core {@code CasdoorAdminClient} (2.5.1) cannot read:
 * it has no getter, so that implementation is a cross-repo change and is not wired here.
 * With no {@code RecipientEmailResolver} bean the channel behaves exactly as before: only a
 * subject that is already an address is mailed.
 */
@FunctionalInterface
public interface RecipientEmailResolver {

    /**
     * @param domain  the outbox row's domain
     * @param subject the outbox {@code target} subject
     * @return the address, or empty when none is on file
     */
    Mono<String> resolve(String domain, String subject);
}
