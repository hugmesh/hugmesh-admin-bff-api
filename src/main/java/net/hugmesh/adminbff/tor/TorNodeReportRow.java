package net.hugmesh.adminbff.tor;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code tor_node_report} (Liquibase changeset 360) — the durable shape of a
 * {@link TorNodeReport}. {@code domain_onions} is the {@code <slug> <onion>} line encoding
 * of {@link TorNodeReport#domainOnions()} ({@link TorNodeReport#encodeDomainOnions}).
 * Written only through {@link TorNodeReportRowRepository#upsert}; never saved as an entity.
 */
@Table("tor_node_report")
public record TorNodeReportRow(
        @Id @Column("id") String id,
        @Column("machine_key_fp") String machineKeyFp,
        @Column("primary_onion") String primaryOnion,
        @Column("domain_onions") String domainOnions,
        @Column("first_reported_at") Instant firstReportedAt,
        @Column("last_reported_at") Instant lastReportedAt,
        @Column("report_count") long reportCount,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public TorNodeReportRow(String id, String machineKeyFp, String primaryOnion, String domainOnions,
                            Instant firstReportedAt, Instant lastReportedAt, long reportCount) {
        this(id, machineKeyFp, primaryOnion, domainOnions, firstReportedAt, lastReportedAt,
                reportCount, false);
    }

    TorNodeReport toDomain() {
        return new TorNodeReport(machineKeyFp, primaryOnion,
                TorNodeReport.decodeDomainOnions(domainOnions), firstReportedAt, lastReportedAt,
                reportCount);
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }
}
