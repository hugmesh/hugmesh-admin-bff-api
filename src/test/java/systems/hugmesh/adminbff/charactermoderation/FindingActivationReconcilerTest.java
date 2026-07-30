package systems.hugmesh.adminbff.charactermoderation;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.lease.AlwaysLeader;
import systems.hugmesh.adminbff.lease.LeaderElection;
import systems.hugmesh.adminbff.notification.NotificationCursorR2dbcRepository;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;
import systems.hugmesh.adminbff.testutil.R2dbcRepos;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The moderation→activation reconciler proven over a REAL Postgres (Testcontainers) with
 * the production Liquibase changelog applied — so the {@code notification_cursor}-table
 * REUSE (the per-surface federation {@code sinceId} watermark) round-trips on the same
 * engine production runs — and BOTH WebClient clients MOCKED (no live federation/user-bff).
 *
 * <p>Delineated against the SCOPE:
 * <ul>
 *   <li>MAPPING — {@code actioned→REJECTED} &amp; {@code dismissed→ACTIVE}.</li>
 *   <li>ROUTING — character-part → {@code parts} path, character-sticker → {@code stickers}
 *       path, keyed on the finding's {@code subjectRef}.</li>
 *   <li>CURSOR — advances past a CONTIGUOUS prefix of successful pushes and HALTS at the
 *       first failure; the failed id is re-polled next tick (and re-pushes harmlessly).</li>
 *   <li>LEADER — {@code isLeader()=false} → no poll, no push, cursor unchanged.</li>
 *   <li>EMPTY — an empty resolved page → no push + cursor unchanged.</li>
 *   <li>NEVER-HARD-FAIL — a failed federation poll for one surface never throws and never
 *       advances that surface's cursor.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
// A unique property forces a DISTINCT cached test context (hence a DISTINCT Postgres db)
// so this class — which writes notification_cursor rows — never shares a store with another
// @DataR2dbcTest that asserts on that table.
@org.springframework.test.context.TestPropertySource(properties =
        "test.context.key=finding-activation-reconciler")
class FindingActivationReconcilerTest {

    @Autowired DatabaseClient db;

    private FindingCursorRepository cursor;
    private FederationResolvedFindingsClient federation;
    private UserBffCharacterModerationClient userBff;
    private MeterRegistry meters;

    @BeforeEach
    void setup() {
        db.sql("DELETE FROM notification_cursor").fetch().rowsUpdated().block();
        cursor = new FindingCursorRepository(
                R2dbcRepos.of(db, NotificationCursorR2dbcRepository.class));
        federation = mock(FederationResolvedFindingsClient.class);
        userBff = mock(UserBffCharacterModerationClient.class);
        meters = new SimpleMeterRegistry();
    }

    private FindingActivationReconciler reconciler(LeaderElection leader) {
        return new FindingActivationReconciler(federation, userBff, cursor, leader, meters, 200);
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private ResolvedFindingDto finding(long id, String surface, long subjectRef, String status) {
        return new ResolvedFindingDto(id, surface, subjectRef, status, "mod-zoe", "brandx", "2026-06-26T00:00:00Z");
    }

    /** By default: BOTH surfaces return EMPTY. Override one with stubPage(...). */
    private void stubBothEmpty() {
        when(federation.fetchResolved(any(), any(), anyInt())).thenReturn(Mono.just(List.of()));
    }

    private void stubPage(String surface, Long sinceId, List<ResolvedFindingDto> page) {
        when(federation.fetchResolved(eq(surface), eq(sinceId), anyInt())).thenReturn(Mono.just(page));
    }

    private void stubPageAnySince(String surface, List<ResolvedFindingDto> page) {
        when(federation.fetchResolved(eq(surface), any(), anyInt())).thenReturn(Mono.just(page));
    }

    private Long cursorOf(String consumer) {
        return cursor.find(consumer).block();
    }

    private double metric(String name) {
        var m = meters.find(name).counter();
        return m == null ? 0d : m.count();
    }

    // ── MAPPING + ROUTING (parts): actioned→REJECTED on the parts path ──────
    @Test
    void part_actioned_mapsToRejected_onPartsPath_keyedOnSubjectRef() {
        stubBothEmpty();
        stubPageAnySince("character-part",
                List.of(finding(10L, "character-part", 777L, "actioned")));
        when(userBff.applyModeration(any(), anyLong(), any(), anyLong(), any()))
                .thenReturn(Mono.just(UserBffCharacterModerationClient.Outcome.APPLIED));

        reconciler(new AlwaysLeader()).runOnce().block();

        var kind = forClass(String.class);
        var subjectRef = forClass(Long.class);
        var status = forClass(String.class);
        var findingId = forClass(Long.class);
        verify(userBff, times(1)).applyModeration(kind.capture(), subjectRef.capture(),
                status.capture(), findingId.capture(), any());
        assertThat(kind.getValue()).isEqualTo("parts");
        assertThat(subjectRef.getValue()).isEqualTo(777L);
        assertThat(status.getValue()).isEqualTo("REJECTED");
        assertThat(findingId.getValue()).isEqualTo(10L);
        // cursor advanced to the (single) delivered id.
        assertThat(cursorOf(FindingCursorRepository.CONSUMER_PART)).isEqualTo(10L);
        assertThat(metric("character.moderation.reconcile.applied")).isEqualTo(1d);
    }

    // ── MAPPING + ROUTING (stickers): dismissed→ACTIVE on the stickers path ──
    @Test
    void sticker_dismissed_mapsToActive_onStickersPath() {
        stubBothEmpty();
        stubPageAnySince("character-sticker",
                List.of(finding(42L, "character-sticker", 5L, "dismissed")));
        when(userBff.applyModeration(any(), anyLong(), any(), anyLong(), any()))
                .thenReturn(Mono.just(UserBffCharacterModerationClient.Outcome.APPLIED));

        reconciler(new AlwaysLeader()).runOnce().block();

        var kind = forClass(String.class);
        var status = forClass(String.class);
        verify(userBff, times(1)).applyModeration(kind.capture(), eq(5L), status.capture(), eq(42L), any());
        assertThat(kind.getValue()).isEqualTo("stickers");
        assertThat(status.getValue()).isEqualTo("ACTIVE");
        assertThat(cursorOf(FindingCursorRepository.CONSUMER_STICKER)).isEqualTo(42L);
    }

    // ── CURSOR: advances past a contiguous-success prefix, HALTS at first failure ─
    @Test
    void cursorAdvancesPastContiguousSuccesses_andHaltsAtFirstFailure() {
        stubBothEmpty();
        // Three findings id ASC: 1 OK, 2 OK, 3 FAILS, 4 OK (but unreached this tick).
        stubPageAnySince("character-part", List.of(
                finding(1L, "character-part", 101L, "dismissed"),
                finding(2L, "character-part", 102L, "actioned"),
                finding(3L, "character-part", 103L, "dismissed"),
                finding(4L, "character-part", 104L, "actioned")));
        when(userBff.applyModeration(eq("parts"), anyLong(), any(), anyLong(), any()))
                .thenAnswer(inv -> {
                    long subj = inv.getArgument(1);
                    return Mono.just(subj == 103L
                            ? UserBffCharacterModerationClient.Outcome.FAILED
                            : UserBffCharacterModerationClient.Outcome.APPLIED);
                });

        reconciler(new AlwaysLeader()).runOnce().block();

        // Cursor advanced to id 2 (the contiguous prefix before the id-3 failure) — NOT past 3.
        assertThat(cursorOf(FindingCursorRepository.CONSUMER_PART)).isEqualTo(2L);
        // id 4 was NOT pushed this tick (page short-circuited at the id-3 halt).
        verify(userBff, never()).applyModeration(eq("parts"), eq(104L), any(), anyLong(), any());
        assertThat(metric("character.moderation.reconcile.push_failed")).isEqualTo(1d);
        assertThat(metric("character.moderation.reconcile.applied")).isEqualTo(2d);
    }

    // ── RETRY: next tick re-polls from the halted cursor; idempotent re-push ─
    @Test
    void nextTick_rePollsFromHaltedCursor_andDrainsTheRest() {
        stubBothEmpty();
        // Tick 1: page from sinceId 0 → id3 fails (cursor halts at 2).
        stubPage("character-part", 0L, List.of(
                finding(1L, "character-part", 101L, "dismissed"),
                finding(2L, "character-part", 102L, "actioned"),
                finding(3L, "character-part", 103L, "dismissed")));
        // Tick 2: federation re-polled from sinceId 2 (strict id>sinceId) → ids 3,4 now succeed.
        stubPage("character-part", 2L, List.of(
                finding(3L, "character-part", 103L, "dismissed"),
                finding(4L, "character-part", 104L, "actioned")));

        List<Long> failOnce = new ArrayList<>(List.of(103L)); // id3 fails the FIRST time only
        when(userBff.applyModeration(eq("parts"), anyLong(), any(), anyLong(), any()))
                .thenAnswer(inv -> {
                    long subj = inv.getArgument(1);
                    if (subj == 103L && failOnce.remove(Long.valueOf(103L))) {
                        return Mono.just(UserBffCharacterModerationClient.Outcome.FAILED);
                    }
                    return Mono.just(UserBffCharacterModerationClient.Outcome.APPLIED);
                });

        FindingActivationReconciler r = reconciler(new AlwaysLeader());
        r.runOnce().block(); // halts at 2
        assertThat(cursorOf(FindingCursorRepository.CONSUMER_PART)).isEqualTo(2L);

        r.runOnce().block(); // re-polls from 2, drains 3 then 4
        assertThat(cursorOf(FindingCursorRepository.CONSUMER_PART)).isEqualTo(4L);
        // federation was polled with sinceId=2 on the second tick (proves strict cursor reuse).
        verify(federation, times(1)).fetchResolved(eq("character-part"), eq(2L), anyInt());
    }

    // ── LEADER=false → no poll, no push, cursor unchanged ───────────────────
    @Test
    void notLeader_skipsEntirely_noPollNoPushNoCursor() {
        LeaderElection notLeader = new LeaderElection() {
            @Override public boolean isLeader() { return false; }
            @Override public String label() { return "test-not-leader"; }
        };

        reconciler(notLeader).runOnce().block();

        verify(federation, never()).fetchResolved(any(), any(), anyInt());
        verify(userBff, never()).applyModeration(any(), anyLong(), any(), anyLong(), any());
        assertThat(cursorOf(FindingCursorRepository.CONSUMER_PART)).isNull();
        assertThat(cursorOf(FindingCursorRepository.CONSUMER_STICKER)).isNull();
    }

    // ── EMPTY page → no push + cursor unchanged ─────────────────────────────
    @Test
    void emptyResolvedPage_noPush_andCursorUnchanged() {
        stubBothEmpty();

        reconciler(new AlwaysLeader()).runOnce().block();

        verify(userBff, never()).applyModeration(any(), anyLong(), any(), anyLong(), any());
        assertThat(cursorOf(FindingCursorRepository.CONSUMER_PART)).isNull();
        assertThat(cursorOf(FindingCursorRepository.CONSUMER_STICKER)).isNull();
    }

    // ── NEVER-HARD-FAIL: a failed federation poll never throws / never advances ─
    @Test
    void federationPollFailure_isSwallowed_andCursorUnchanged() {
        // part poll ERRORS; sticker poll is empty (the surfaces are independent).
        when(federation.fetchResolved(eq("character-part"), any(), anyInt()))
                .thenReturn(Mono.error(new RuntimeException("federation down")));
        when(federation.fetchResolved(eq("character-sticker"), any(), anyInt()))
                .thenReturn(Mono.just(List.of()));

        // must NOT throw out of runOnce.
        reconciler(new AlwaysLeader()).runOnce().block();

        verify(userBff, never()).applyModeration(any(), anyLong(), any(), anyLong(), any());
        assertThat(cursorOf(FindingCursorRepository.CONSUMER_PART)).isNull();
        assertThat(metric("character.moderation.reconcile.push_failed")).isGreaterThanOrEqualTo(1d);
    }

    // ── BOTH SURFACES in one tick: part + sticker each advance independently ─
    @Test
    void bothSurfaces_processedInOneTick_eachCursorAdvancesIndependently() {
        stubPageAnySince("character-part",
                List.of(finding(7L, "character-part", 700L, "actioned")));
        stubPageAnySince("character-sticker",
                List.of(finding(9L, "character-sticker", 900L, "dismissed")));
        when(userBff.applyModeration(any(), anyLong(), any(), anyLong(), any()))
                .thenReturn(Mono.just(UserBffCharacterModerationClient.Outcome.APPLIED));

        reconciler(new AlwaysLeader()).runOnce().block();

        verify(userBff).applyModeration(eq("parts"), eq(700L), eq("REJECTED"), eq(7L), any());
        verify(userBff).applyModeration(eq("stickers"), eq(900L), eq("ACTIVE"), eq(9L), any());
        assertThat(cursorOf(FindingCursorRepository.CONSUMER_PART)).isEqualTo(7L);
        assertThat(cursorOf(FindingCursorRepository.CONSUMER_STICKER)).isEqualTo(9L);
    }
}
