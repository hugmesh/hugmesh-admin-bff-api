package net.hugmesh.adminbff.notification.channel;

import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * In-memory fake of {@link RecipientEmailResolver} for tests: a fixed subject-to-address map,
 * a switch that makes the lookup fail, and a record of every lookup made.
 */
final class InMemoryRecipientEmailResolver implements RecipientEmailResolver {

    private final Map<String, String> addresses = new HashMap<>();
    private final List<String> lookups = Collections.synchronizedList(new ArrayList<>());
    private volatile boolean failing;

    InMemoryRecipientEmailResolver with(String subject, String address) {
        addresses.put(subject, address);
        return this;
    }

    InMemoryRecipientEmailResolver failing() {
        this.failing = true;
        return this;
    }

    List<String> lookups() {
        return lookups;
    }

    @Override
    public Mono<String> resolve(String domain, String subject) {
        lookups.add(domain + "|" + subject);
        if (failing) {
            return Mono.error(new IllegalStateException("profile lookup down"));
        }
        String a = addresses.get(subject);
        return a == null ? Mono.empty() : Mono.just(a);
    }
}
