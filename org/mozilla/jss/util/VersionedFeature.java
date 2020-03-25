package org.mozilla.jss.util;

/**
 * Representation of a feature supported only by recent enough NSS versions.
 *
 * This class controls access to data present only in later NSS versions. It
 * provides a mechanism for callers to access data when present, returning
 * null when the data isn't present. This lets callers make an informed decision
 * about whether or not the given data is available. In the even it isn't, a
 * recommended NSS version can be suggested.
 */
public class VersionedFeature<T> {
    /**
     * Whether or not this given field is present.
     */
    private boolean present;

    /**
     * Minimum NSS version this feature is present in.
     */
    private String version;

    /**
     * Version-locked value.
     */
    private T value;

    /**
     * Constructs this feature, knowing only the version it is present in;
     * defaults to false presence.
     */
    public VersionedFeature(String version) {
        this.version = version;
    }

    /**
     * Constructs this feature without a value.
     */
    public VersionedFeature(boolean present, String version) {
        this.present = present;
        this.version = version;
    }

    /**
     * Constructs this feature from a given value.
     */
    public VersionedFeature(boolean present, String version, T value) {
        this.present = present;
        this.version = version;
        if (present) {
            this.value = value;
        }
    }

    /**
     * Sets the value for the feature, when present.
     *
     * Also marks this feature as present.
     */
    public void setValue(T value) {
        this.value = value;
    }

    /**
     * Marks this feature as present.
     */
    public void markPresent() {
        present = true;
    }

    /**
     * Check whether or not this feature is present.
     */
    public boolean haveFeature() {
        return present;
    }

    /**
     * Get the minimum NSS version which contains this feature.
     */
    public String getMinimumVersion() {
        return version;
    }

    /**
     * Get the value, when present; returns null otherwise.
     */
    public T getValue() {
        if (present) {
            return value;
        }

        return null;
    }
}
