package systems.hugmesh.adminbff.backup;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * A connected/mountable USB block device offered as a backup TARGET or restore
 * SOURCE. Discovered on the backup worker node (see {@link UsbDeviceProvider});
 * {@code id} is the stable device id the start-backup/restore request references.
 * {@code backups} lists any backup blobs already found on the device (so the
 * recovery view can list USB backups without a second round-trip).
 */
public record UsbDevice(
        String id,
        String label,
        @JsonProperty("mount_point") String mountPoint,
        @JsonProperty("size_bytes") Long sizeBytes,
        @JsonProperty("free_bytes") Long freeBytes,
        boolean writable,
        List<UsbBackup> backups) {

    /** A backup blob discovered on a USB device. {@code encrypted} is inferred
     *  from the file extension / sidecar the worker writes. */
    public record UsbBackup(
            String ref,
            @JsonProperty("created_at") String createdAt,
            @JsonProperty("size_bytes") Long sizeBytes,
            boolean encrypted) {
    }
}
