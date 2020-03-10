package org.mozilla.jss.ssl;

public enum SSLAuthType {
    ssl_auth_null (0),
    ssl_auth_rsa_decrypt (1),
    ssl_auth_dsa (2),
    ssl_auth_kea (3),
    ssl_auth_ecdsa (4),
    ssl_auth_ecdh_rsa (5),
    ssl_auth_ecdh_ecdsa (6),
    ssl_auth_rsa_sign (7),
    ssl_auth_rsa_pss (8),
    ssl_auth_psk (9),
    ssl_auth_tls13_any (10);

    private int value;

    private SSLAuthType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static SSLAuthType valueOf(int value) {
        for (SSLAuthType type : SSLAuthType.values()) {
            if (type.value == value) {
                return type;
            }
        }

        return null;
    }
}
