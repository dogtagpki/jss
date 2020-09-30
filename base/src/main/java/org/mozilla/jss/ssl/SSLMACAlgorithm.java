package org.mozilla.jss.ssl;

public enum SSLMACAlgorithm {
    ssl_mac_null (0),
    ssl_mac_md5 (1),
    ssl_mac_sha (2),
    ssl_hmac_md5 (3),
    ssl_hmac_sha (4),
    ssl_hmac_sha256 (5),
    ssl_mac_aead (6),
    ssl_hmac_sha384 (7);

    private int value;

    private SSLMACAlgorithm(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static SSLMACAlgorithm valueOf(int value) {
        for (SSLMACAlgorithm alg : SSLMACAlgorithm.values()) {
            if (alg.value == value) {
                return alg;
            }
        }

        return null;
    }
}
