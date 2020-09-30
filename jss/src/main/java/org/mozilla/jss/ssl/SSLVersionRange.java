/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

import java.util.ArrayList;

public class SSLVersionRange {

    private SSLVersion minVersion;
    private SSLVersion maxVersion;

    /**
     * @deprecated Replaced with SSLVersion.SSL_3_0.
     */
    @Deprecated
    public static final int ssl3 = SocketBase.SSL_LIBRARY_VERSION_3_0;

    /**
     * @deprecated Replaced with SSLVersion.TLS_1_0.
     */
    @Deprecated
    public static final int tls1_0 = SocketBase.SSL_LIBRARY_VERSION_TLS_1_0;

    /**
     * @deprecated Replaced with SSLVersion.TLS_1_1.
     */
    @Deprecated
    public static final int tls1_1 = SocketBase.SSL_LIBRARY_VERSION_TLS_1_1;

    /**
     * @deprecated Replaced with SSLVersion.TLS_1_2.
     */
    @Deprecated
    public static final int tls1_2 = SocketBase.SSL_LIBRARY_VERSION_TLS_1_2;

    /**
     * @deprecated Replaced with SSLVersion.TLS_1_3.
     */
    @Deprecated
    public static final int tls1_3 = SocketBase.SSL_LIBRARY_VERSION_TLS_1_3;

    public SSLVersionRange(SSLVersion minVersion, SSLVersion maxVersion) throws IllegalArgumentException {

        if (minVersion.value() > maxVersion.value()) {
            throw new IllegalArgumentException("Arguments out of range");
        }

        this.minVersion = minVersion;
        this.maxVersion = maxVersion;
    }

    /**
     * Used by the C code, do not use it directly
     * @deprecated Replaced with SSLVersionRange(SSLVersion minVersion, SSLVersion maxVersion).
     * @param min_enum
     * @param max_enum
     * @throws IllegalArgumentException
     */
    @Deprecated
    public SSLVersionRange(int min_enum, int max_enum) throws IllegalArgumentException {
        this(SSLVersion.valueOf(min_enum), SSLVersion.valueOf(max_enum));
    }

    public SSLVersion getMinVersion() {
        return minVersion;
    }

    public SSLVersion getMaxVersion() {
        return maxVersion;
    }

    /**
     * @return enumeration value
     */
    public int getMinEnum() { return minVersion.value(); }

    /**
     * @return enumeration value
     */
    public int getMaxEnum() { return maxVersion.value(); }

    /**
     * Gets all of the SSLVersions in this range, including endpoints.
     *
     * @return All SSLVersions in this range
     */
    public SSLVersion[] getAllInRange() {
        ArrayList<SSLVersion> result = new ArrayList<SSLVersion>();
        for (SSLVersion v : SSLVersion.values()) {
            if (v.compareTo(this.minVersion) >= 0 && v.compareTo(this.maxVersion) <= 0) {
                result.add(v);
            }
        }

        return result.toArray(new SSLVersion[result.size()]);
    }

    /**
     * Bounds this SSLVersionRange by the given range.
     *
     * The resulting SSLVersionRange does not has a minimum less than
     * that of its bound and does not have a maximum greater than that
     * of its bound.
     */
    public SSLVersionRange boundBy(SSLVersionRange bound) {
        SSLVersion minimum = minVersion;
        SSLVersion maximum = maxVersion;

        if (minimum.compareTo(bound.getMinVersion()) < 0) {
            minimum = bound.getMinVersion();
        }

        if (maximum.compareTo(bound.getMaxVersion()) > 0) {
            maximum = bound.getMaxVersion();
        }

        return new SSLVersionRange(minimum, maximum);
    }
}
