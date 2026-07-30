package systems.hugmesh.adminbff.usage;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The action→module mapping {@code UsageService.moduleOf} drives the admin Usage view
 * grouping. This pins the FORUM additions: forum-ui content actions and the admin-ui
 * Forum Console actions, plus the existing-entry + default-bucket invariants.
 */
class UsageServiceModuleMapTest {

    @ParameterizedTest
    @CsvSource({
            // forum-ui content actions (the forum-bff producer path emits these)
            "forum.post,                    forum-ui",
            "forum.reply,                   forum-ui",
            "forum.login,                   forum-ui",
            "forum.topic,                   forum-ui",
            // admin-ui Forum Console actions (recorded by ForumAdminController)
            "admin.forum.stats,             admin-ui",
            "admin.forum.usage,             admin-ui",
            "admin.forum.users,             admin-ui",
            "admin.forum.user,              admin-ui",
            "admin.forum.ban,               admin-ui",
            "admin.forum.unban,             admin-ui",
            "admin.forum.group,             admin-ui",
            "admin.forum.categories,        admin-ui",
            "admin.forum.category.create,   admin-ui",
            "admin.forum.moderation-queue,  admin-ui",
            "admin.forum.moderation.approve,admin-ui",
            "admin.forum.moderation.reject, admin-ui",
            "admin.forum.style.install,     admin-ui",
            "admin.forum.extension.install, admin-ui",
            "admin.forum.audit,             admin-ui",
    })
    void forumActionsMapToExpectedModule(String action, String module) {
        assertThat(UsageService.moduleOf(action)).isEqualTo(module);
    }

    @ParameterizedTest
    @CsvSource({
            "login,            login-ui",
            "admin.invite,     admin-ui",
            "mastodon.entitled,mastodon-ui",
            "matrix.entitled,  matrix-ui",
    })
    void existingActionsStillMapCorrectly(String action, String module) {
        assertThat(UsageService.moduleOf(action)).isEqualTo(module);
    }

    @ParameterizedTest
    @ValueSource(strings = {"unknown.action", "forum.unmapped", "whatever"})
    void unmappedActionFallsBackToHost(String action) {
        assertThat(UsageService.moduleOf(action)).isEqualTo("host");
    }
}
