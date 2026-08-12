package net.hugmesh.adminbff.notification.channel;

/**
 * The terminal verdict of a {@link NotificationChannel#send} attempt — mirrors the in-app
 * reconciler's outcome trichotomy so the external-channel reconciler records the same
 * three {@code notification_delivery} statuses per channel.
 */
public enum ChannelOutcome {
    /** Posted to the channel — record {@code sent}. */
    SENT,
    /** Terminally not applicable for this recipient (e.g. the recipient has no Matrix
     *  account / no email on file). Record {@code skipped}; never retry. */
    SKIPPED,
    /** Transport error / channel down / timeout — record NOTHING; retry next tick. */
    FAILED
}
