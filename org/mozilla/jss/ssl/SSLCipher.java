/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

/**
 * SSL cipher.
 */
public enum SSLCipher {

    /**
     *
     * Note the following cipher-suites constants are not all implemented.
     * You need to call SSLSocket.getImplementedCiphersuites().
     *
     */

    SSL2_RC4_128_WITH_MD5                        (0xFF01),
    SSL2_RC4_128_EXPORT40_WITH_MD5               (0xFF02),
    SSL2_RC2_128_CBC_WITH_MD5                    (0xFF03),
    SSL2_RC2_128_CBC_EXPORT40_WITH_MD5           (0xFF04),
    SSL2_IDEA_128_CBC_WITH_MD5                   (0xFF05),
    SSL2_DES_64_CBC_WITH_MD5                     (0xFF06),
    SSL2_DES_192_EDE3_CBC_WITH_MD5               (0xFF07),

    /**
     * @deprecated Replaced with TLS_RSA_WITH_NULL_MD5.
     */
    @Deprecated
    SSL3_RSA_WITH_NULL_MD5                       (0x0001),
    TLS_RSA_WITH_NULL_MD5                        (0x0001),

    /**
     * @deprecated Replaced with TLS_RSA_WITH_NULL_SHA.
     */
    @Deprecated
    SSL3_RSA_WITH_NULL_SHA                       (0x0002),
    TLS_RSA_WITH_NULL_SHA                        (0x0002),

    SSL3_RSA_EXPORT_WITH_RC4_40_MD5              (0x0003),

    /**
     * @deprecated Replaced with TLS_RSA_WITH_RC4_128_MD5.
     */
    @Deprecated
    SSL3_RSA_WITH_RC4_128_MD5                    (0x0004),
    TLS_RSA_WITH_RC4_128_MD5                     (0x0004),

    /**
     * @deprecated Replaced with TLS_RSA_WITH_RC4_128_SHA.
     */
    @Deprecated
    SSL3_RSA_WITH_RC4_128_SHA                    (0x0005),
    TLS_RSA_WITH_RC4_128_SHA                     (0x0005),

    SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5          (0x0006),

    /**
     * @deprecated Replaced with TLS_RSA_WITH_IDEA_CBC_SHA.
     */
    @Deprecated
    SSL3_RSA_WITH_IDEA_CBC_SHA                   (0x0007),
    TLS_RSA_WITH_IDEA_CBC_SHA                    (0x0007),

    SSL3_RSA_EXPORT_WITH_DES40_CBC_SHA           (0x0008),

    /**
     * @deprecated Replaced with TLS_RSA_WITH_DES_CBC_SHA.
     */
    @Deprecated
    SSL3_RSA_WITH_DES_CBC_SHA                    (0x0009),
    TLS_RSA_WITH_DES_CBC_SHA                     (0x0009),

    /**
     * @deprecated Replaced with TLS_RSA_WITH_3DES_EDE_CBC_SHA.
     */
    @Deprecated
    SSL3_RSA_WITH_3DES_EDE_CBC_SHA               (0x000a),
    TLS_RSA_WITH_3DES_EDE_CBC_SHA                (0x000a),

    SSL3_DH_DSS_EXPORT_WITH_DES40_CBC_SHA        (0x000b),

    /**
     * @deprecated Replaced with TLS_DH_DSS_WITH_DES_CBC_SHA.
     */
    @Deprecated
    SSL3_DH_DSS_WITH_DES_CBC_SHA                 (0x000c),
    TLS_DH_DSS_WITH_DES_CBC_SHA                  (0x000c),

    /**
     * @deprecated Replaced with TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA.
     */
    @Deprecated
    SSL3_DH_DSS_WITH_3DES_EDE_CBC_SHA            (0x000d),
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA             (0x000d),

    SSL3_DH_RSA_EXPORT_WITH_DES40_CBC_SHA        (0x000e),

    /**
     * @deprecated Replaced with TLS_DH_RSA_WITH_DES_CBC_SHA.
     */
    @Deprecated
    SSL3_DH_RSA_WITH_DES_CBC_SHA                 (0x000f),
    TLS_DH_RSA_WITH_DES_CBC_SHA                  (0x000f),

    /**
     * @deprecated Replaced with TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA.
     */
    @Deprecated
    SSL3_DH_RSA_WITH_3DES_EDE_CBC_SHA            (0x0010),
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA             (0x0010),

    SSL3_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA       (0x0011),

    /**
     * @deprecated Replaced with TLS_DHE_DSS_WITH_DES_CBC_SHA.
     */
    @Deprecated
    SSL3_DHE_DSS_WITH_DES_CBC_SHA                (0x0012),
    TLS_DHE_DSS_WITH_DES_CBC_SHA                 (0x0012),

    /**
     * @deprecated Replaced with TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA.
     */
    @Deprecated
    SSL3_DHE_DSS_WITH_3DES_EDE_CBC_SHA           (0x0013),
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA            (0x0013),

    SSL3_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA       (0x0014),

    /**
     * @deprecated Replaced with TLS_DHE_RSA_WITH_DES_CBC_SHA.
     */
    @Deprecated
    SSL3_DHE_RSA_WITH_DES_CBC_SHA                (0x0015),
    TLS_DHE_RSA_WITH_DES_CBC_SHA                 (0x0015),

    /**
     * @deprecated Replaced with TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA.
     */
    @Deprecated
    SSL3_DHE_RSA_WITH_3DES_EDE_CBC_SHA           (0x0016),
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA            (0x0016),

    SSL3_DH_ANON_EXPORT_WITH_RC4_40_MD5          (0x0017),

    /**
     * @deprecated Replaced with TLS_DH_anon_WITH_RC4_128_MD5.
     */
    @Deprecated
    SSL3_DH_ANON_WITH_RC4_128_MD5                (0x0018),
    TLS_DH_anon_WITH_RC4_128_MD5                 (0x0018),

    SSL3_DH_ANON_EXPORT_WITH_DES40_CBC_SHA       (0x0019),

    /**
     * @deprecated Replaced with TLS_DH_anon_WITH_DES_CBC_SHA.
     */
    @Deprecated
    SSL3_DH_ANON_WITH_DES_CBC_SHA                (0x001a),
    TLS_DH_anon_WITH_DES_CBC_SHA                 (0x001a),

    /**
     * @deprecated Replaced with TLS_DH_anon_WITH_3DES_EDE_CBC_SHA.
     */
    @Deprecated
    SSL3_DH_ANON_WITH_3DES_EDE_CBC_SHA           (0x001b),
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA            (0x001b),

    /**
     * @deprecated As of NSS 3.11, FORTEZZA is no longer supported.
     */
    @Deprecated
    SSL3_FORTEZZA_DMS_WITH_NULL_SHA              (0x001c),

    /**
     * @deprecated As of NSS 3.11, FORTEZZA is no longer supported.
     */
    @Deprecated
    SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA      (0x001d),

    /**
     * @deprecated As of NSS 3.11, FORTEZZA is no longer supported.
     */
    @Deprecated
    SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA           (0x001e),

    SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA           (0xfeff),
    SSL_RSA_FIPS_WITH_DES_CBC_SHA                (0xfefe),

    TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA          (0x0062),
    TLS_RSA_EXPORT1024_WITH_RC4_56_SHA           (0x0064),

    TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA      (0x0063),
    TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA       (0x0065),
    TLS_DHE_DSS_WITH_RC4_128_SHA                 (0x0066),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256          (0x0067),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256          (0x006B),

    // New TLS cipher suites in NSS 3.4
    TLS_RSA_WITH_AES_128_CBC_SHA                 (0x002F),
    TLS_DH_DSS_WITH_AES_128_CBC_SHA              (0x0030),
    TLS_DH_RSA_WITH_AES_128_CBC_SHA              (0x0031),
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA             (0x0032),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA             (0x0033),

    /**
     * @deprecated Replaced with TLS_DH_anon_WITH_AES_128_CBC_SHA.
     */
    @Deprecated
    TLS_DH_ANON_WITH_AES_128_CBC_SHA             (0x0034),
    TLS_DH_anon_WITH_AES_128_CBC_SHA             (0x0034),

    TLS_RSA_WITH_AES_256_CBC_SHA                 (0x0035),
    TLS_DH_DSS_WITH_AES_256_CBC_SHA              (0x0036),
    TLS_DH_RSA_WITH_AES_256_CBC_SHA              (0x0037),
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA             (0x0038),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA             (0x0039),

    /**
     * @deprecated Replaced with TLS_DH_anon_WITH_AES_256_CBC_SHA.
     */
    @Deprecated
    TLS_DH_ANON_WITH_AES_256_CBC_SHA             (0x003A),
    TLS_DH_anon_WITH_AES_256_CBC_SHA             (0x003A),

    TLS_RSA_WITH_NULL_SHA256                     (0x003B),
    TLS_RSA_WITH_AES_128_CBC_SHA256              (0x003C),
    TLS_RSA_WITH_AES_256_CBC_SHA256              (0x003D),

    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA            (0x0041),
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA         (0x0042),
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA         (0x0043),
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA        (0x0044),
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA        (0x0045),

    /**
     * @deprecated Replaced with TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA.
     */
    @Deprecated
    TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA        (0x0046),
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA        (0x0046),

    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA            (0x0084),
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA         (0x0085),
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA         (0x0086),
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA        (0x0087),
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA        (0x0088),

    /**
     * @deprecated Replaced with TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA.
     */
    @Deprecated
    TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA        (0x0089),
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA        (0x0089),

    TLS_RSA_WITH_SEED_CBC_SHA                    (0x0096),

    TLS_RSA_WITH_AES_128_GCM_SHA256              (0x009C),
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256          (0x009E),
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256          (0x00A2),

    TLS_ECDH_ECDSA_WITH_NULL_SHA                 (0xc001, true),
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA              (0xc002, true),
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA         (0xc003, true),
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA          (0xc004, true),
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA          (0xc005, true),

    TLS_ECDHE_ECDSA_WITH_NULL_SHA                (0xc006, true),
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA             (0xc007, true),
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA        (0xc008, true),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA         (0xc009, true),
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA         (0xc00a, true),

    TLS_ECDH_RSA_WITH_NULL_SHA                   (0xc00b, true),
    TLS_ECDH_RSA_WITH_RC4_128_SHA                (0xc00c, true),
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA           (0xc00d, true),
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA            (0xc00e, true),
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA            (0xc00f, true),

    TLS_ECDHE_RSA_WITH_NULL_SHA                  (0xc010, true),
    TLS_ECDHE_RSA_WITH_RC4_128_SHA               (0xc011, true),
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA          (0xc012, true),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA           (0xc013, true),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA           (0xc014, true),

    TLS_ECDH_anon_WITH_NULL_SHA                  (0xc015, true),
    TLS_ECDH_anon_WITH_RC4_128_SHA               (0xc016, true),
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA          (0xc017, true),
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA           (0xc018, true),
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA           (0xc019, true),

    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256      (0xc023, true),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256        (0xc027, true),

    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256      (0xc02B, true),
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256       (0xc02D, true),
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256        (0xc02F, true),
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256         (0xc031, true);

    private int id;
    private boolean ecc;

    private SSLCipher(int id) {
        this.id = id;
    }

    private SSLCipher(int id, boolean ecc) {
        this.id = id;
        this.ecc = ecc;
    }

    public int getID() {
        return id;
    }

    public boolean isECC() {
        return ecc;
    }

    public static SSLCipher valueOf(int id) {
        for (SSLCipher cipher : SSLCipher.class.getEnumConstants()) {
            if (cipher.id == id) return cipher;
        }
        return null;
    }
}
