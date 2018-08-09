/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

public enum SSLVersion {

    SSL_3_0 ("SSL3",   SocketBase.SSL_LIBRARY_VERSION_3_0),
    TLS_1_0 ("TLS1_0", SocketBase.SSL_LIBRARY_VERSION_TLS_1_0),
    TLS_1_1 ("TLS1_1", SocketBase.SSL_LIBRARY_VERSION_TLS_1_1),
    TLS_1_2 ("TLS1_2", SocketBase.SSL_LIBRARY_VERSION_TLS_1_2),
    TLS_1_3 ("TLS1_3", SocketBase.SSL_LIBRARY_VERSION_TLS_1_3);

    private String alias;
    private int value;

    private SSLVersion(String alias, int value) {
        this.alias = alias;
        this.value = value;
    }

    public String alias() {
        return alias;
    }

    public int value() {
        return value;
    }

    public static SSLVersion valueOf(int value) {
        for (SSLVersion version : SSLVersion.values()) {
            if (version.value == value) return version;
        }

        throw new IllegalArgumentException("Invalid SSLVersion value: " + value);
    }

    public static SSLVersion findByAlias(String alias) {

        alias = alias.toUpperCase();

        // find by alias
        for (SSLVersion version : SSLVersion.values()) {
            String a = version.alias.toUpperCase();
            if (a.equals(alias)) return version;
        }

        // find by name
        return SSLVersion.valueOf(alias);
    }
}
