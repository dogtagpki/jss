/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

public enum SSLVersion {

    /** Aliases ordering is as follows:
     *    [0] - JSS name
     *    [1] - JDK name
     */
    SSL_2_0(new String[] {"SSL2", "SSLv2"},   SocketBase.SSL_LIBRARY_VERSION_2, 0x0002),
    SSL_3_0(new String[] {"SSL3", "SSLv3"},   SocketBase.SSL_LIBRARY_VERSION_3_0, 0x0300),
    TLS_1_0(new String[] {"TLS1_0", "TLSv1"}, SocketBase.SSL_LIBRARY_VERSION_TLS_1_0, 0x0301),
    TLS_1_1(new String[] {"TLS1_1", "TLSv1.1"}, SocketBase.SSL_LIBRARY_VERSION_TLS_1_1, 0x0302),
    TLS_1_2(new String[] {"TLS1_2", "TLSv1.2"}, SocketBase.SSL_LIBRARY_VERSION_TLS_1_2, 0x0303),
    TLS_1_3(new String[] {"TLS1_3", "TLSv1.3"}, SocketBase.SSL_LIBRARY_VERSION_TLS_1_3, 0x0304);

    private String[] aliases;
    private int value;
    private int nssValue;

    private SSLVersion(String alias, int value, int nssValue) {
        this.aliases = new String[] {alias};
        this.value = value;
        this.nssValue = nssValue;
    }

    private SSLVersion(String[] aliases, int value, int nssValue) {
        this.aliases = aliases;
        this.value = value;
        this.nssValue = nssValue;
    }

    public String alias() {
        return aliases[0];
    }

    public String jdkAlias() {
        return aliases[1];
    }

    public String[] aliases() {
        return aliases;
    }

    public int value() {
        return value;
    }

    public static SSLVersion valueOf(int value) {
        for (SSLVersion version : SSLVersion.values()) {
            if (version.value == value) return version;

            // The only value we'd have issues with is the broken
            // SSLv2: this could either be SSLv2 or someone passing
            // the garbage value of SSL_ENABLE_TLS to us.
            if (version.nssValue == value) return version;
        }

        throw new IllegalArgumentException("Invalid SSLVersion value: " + value);
    }

    public boolean matchesAlias(String value) {
        for (String alias : aliases) {
            if (alias != null && alias.equalsIgnoreCase(value)) {
                return true;
            }
        }
        return false;
    }

    public static SSLVersion findByAlias(String alias) {

        alias = alias.toUpperCase();

        // find by alias
        for (SSLVersion version : SSLVersion.values()) {
            if (version.matchesAlias(alias)) {
                return version;
            }
        }

        // find by name
        return SSLVersion.valueOf(alias);
    }

    public static SSLVersion maxSupported() {
        SSLVersion result = null;
        for (SSLVersion v : SSLVersion.values()) {
            if (result == null || v.compareTo(result) > 0) {
                result = v;
            }
        }

        return result;
    }

    public static SSLVersion minSupported() {
        return SSLVersion.TLS_1_0;
    }
}
