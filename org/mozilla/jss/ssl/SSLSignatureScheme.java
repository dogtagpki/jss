package org.mozilla.jss.ssl;

public enum SSLSignatureScheme {
    ssl_sig_none (0),
    ssl_sig_rsa_pkcs1_sha1 (0x0201),
    ssl_sig_rsa_pkcs1_sha256 (0x0401),
    ssl_sig_rsa_pkcs1_sha384 (0x0501),
    ssl_sig_rsa_pkcs1_sha512 (0x0601),
    ssl_sig_ecdsa_secp256r1_sha256 (0x0403),
    ssl_sig_ecdsa_secp384r1_sha384 (0x0503),
    ssl_sig_ecdsa_secp521r1_sha512 (0x0603),
    ssl_sig_rsa_pss_rsae_sha256 (0x0804),
    ssl_sig_rsa_pss_rsae_sha384 (0x0805),
    ssl_sig_rsa_pss_rsae_sha512 (0x0806),
    ssl_sig_ed25519 (0x0807),
    ssl_sig_ed448 (0x0808),
    ssl_sig_rsa_pss_pss_sha256 (0x0809),
    ssl_sig_rsa_pss_pss_sha384 (0x080a),
    ssl_sig_rsa_pss_pss_sha512 (0x080b),
    ssl_sig_dsa_sha1 (0x0202),
    ssl_sig_dsa_sha256 (0x0402),
    ssl_sig_dsa_sha384 (0x0502),
    ssl_sig_dsa_sha512 (0x0602),
    ssl_sig_ecdsa_sha1 (0x0203),
    ssl_sig_rsa_pkcs1_sha1md5 (0x10101);

    private int value;

    private SSLSignatureScheme(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static SSLSignatureScheme valueOf(int value) {
        for (SSLSignatureScheme scheme : SSLSignatureScheme.values()) {
            if (scheme.value == value) {
                return scheme;
            }
        }

        return null;
    }
}
