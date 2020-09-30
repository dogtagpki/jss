package org.mozilla.jss.ssl;

public enum SSLCipherAlgorithm {
    ssl_calg_null (0),
    ssl_calg_rc4 (1),
    ssl_calg_rc2 (2),
    ssl_calg_des (3),
    ssl_calg_3des (4),
    ssl_calg_idea (5),
    ssl_calg_fortezza (6),
    ssl_calg_aes (7),
    ssl_calg_camellia (8),
    ssl_calg_seed (9),
    ssl_calg_aes_gcm (10),
    ssl_calg_chacha20 (11);

    private int value;

    private SSLCipherAlgorithm(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static SSLCipherAlgorithm valueOf(int value) {
        for (SSLCipherAlgorithm alg : SSLCipherAlgorithm.values()) {
            if (alg.value == value) {
                return alg;
            }
        }

        return null;
    }
}
