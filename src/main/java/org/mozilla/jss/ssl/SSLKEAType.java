package org.mozilla.jss.ssl;

public enum SSLKEAType {
    ssl_kea_null (0),
    ssl_kea_rsa (1),
    ssl_kea_dh (2),
    ssl_kea_fortezza (3),
    ssl_kea_ecdh (4),
    ssl_kea_ecdh_psk (5),
    ssl_kea_dh_psk (6),
    ssl_kea_tls13_any (7);

    private int value;

    private SSLKEAType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static SSLKEAType valueOf(int value) {
        for (SSLKEAType type : SSLKEAType.values()) {
            if (type.value == value) {
                return type;
            }
        }

        return null;
    }
}
