package systems.hugmesh.adminbff.backup;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Scope vocabulary: case-insensitive parse, de-dupe + canonical lowercase join,
 *  and rejection of unknown / empty scope lists. */
class BackupScopeTest {

    @Test
    void normalise_lowercasesDedupesAndJoins() {
        assertThat(BackupScope.normalise(List.of("ETCD", "Postgres", "etcd")))
                .isEqualTo("etcd,postgres");
    }

    @Test
    void normalise_rejectsUnknownScope() {
        assertThatThrownBy(() -> BackupScope.normalise(List.of("etcd", "bogus")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("bogus");
    }

    @Test
    void normalise_rejectsEmpty() {
        assertThatThrownBy(() -> BackupScope.normalise(List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
