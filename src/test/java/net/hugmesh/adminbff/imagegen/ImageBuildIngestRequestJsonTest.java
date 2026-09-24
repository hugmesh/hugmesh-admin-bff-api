package net.hugmesh.adminbff.imagegen;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;
import net.hugmesh.adminbff.web.dto.ImageBuildIngestRequest;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Decision 73a = B (hugmesh-admin-bff-api#53): the ingest body can no longer name a K8s Secret.
 *
 * <p>The choice for a body that STILL sends {@code k8sSecretName} is IGNORE, not 400:
 * hugmesh-generator docker/build-image.sh sends {@code "k8sSecretName": null} in every terminal
 * report until its #368 change lands, and a 400 on the TERMINAL ingest would leave every real
 * build RUNNING forever. The ignore is EXPLICIT on the DTO, so it holds even under a mapper that
 * fails on unknown properties — pinned here with exactly such a mapper (Jackson 3, the WebFlux
 * codec's library in this Boot 4 app).
 */
class ImageBuildIngestRequestJsonTest {

    /** Byte-for-byte the key set build-image.sh send_ingest() writes (json.dump of its dict). */
    private static final String BUILD_IMAGE_SH_BODY = "{\"status\": \"COMPLETED\","
            + " \"imageRef\": \"build-b1/image.img\", \"keysRef\": \"build-b1/keys.tar\","
            + " \"deviceId\": \"dev-b1\", \"machineKeyFp\": null, \"hostname\": null,"
            + " \"dialUser\": \"bff-dial\", \"hostKeyPub\": null, \"hostKeyFp\": null,"
            + " \"dialPubFp\": \"SHA256:abc\", \"vaultRef\": null, \"k8sSecretName\": %s,"
            + " \"message\": \"image build completed\", \"error\": null}";

    private static final JsonMapper STRICT = JsonMapper.builder()
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).build();

    @Test
    void theDtoHasNoSecretNameComponent() {
        assertThat(Arrays.stream(ImageBuildIngestRequest.class.getRecordComponents())
                .map(java.lang.reflect.RecordComponent::getName))
                .doesNotContain("k8sSecretName")
                .contains("deviceId", "vaultRef", "dialPubFp");
    }

    @Test
    void todaysBuildImageShBody_withNullSecretName_isAccepted() {
        ImageBuildIngestRequest in = STRICT.readValue(
                BUILD_IMAGE_SH_BODY.formatted("null"), ImageBuildIngestRequest.class);
        assertThat(in.deviceId()).isEqualTo("dev-b1");
        assertThat(in.isCompleted()).isTrue();
    }

    @Test
    void aBodyNamingASecret_isAccepted_andTheNameReachesNothing() {
        ImageBuildIngestRequest in = STRICT.readValue(
                BUILD_IMAGE_SH_BODY.formatted("\"../../etc/evil\""), ImageBuildIngestRequest.class);
        // Nothing on the record can carry it (the dial row's name is derived in ImageBuildService,
        // see ImageBuildIngestNonSecretTest), and it is not echoed into any other component.
        assertThat(in.toString()).doesNotContain("evil");
    }
}
