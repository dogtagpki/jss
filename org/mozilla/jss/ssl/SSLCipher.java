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

    SSL2_RC4_128_WITH_MD5                        (0xFF01, SSLVersion.SSL_2_0),
    SSL2_RC4_128_EXPORT40_WITH_MD5               (0xFF02, SSLVersion.SSL_2_0),
    SSL2_RC2_128_CBC_WITH_MD5                    (0xFF03, SSLVersion.SSL_2_0),
    SSL2_RC2_128_CBC_EXPORT40_WITH_MD5           (0xFF04, SSLVersion.SSL_2_0),
    SSL2_IDEA_128_CBC_WITH_MD5                   (0xFF05, SSLVersion.SSL_2_0),
    SSL2_DES_64_CBC_WITH_MD5                     (0xFF06, SSLVersion.SSL_2_0),
    SSL2_DES_192_EDE3_CBC_WITH_MD5               (0xFF07, SSLVersion.SSL_2_0),

    TLS_NULL_WITH_NULL_NULL                      (0x0000, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    /**
     * @deprecated Replaced with TLS_RSA_WITH_NULL_MD5.
     */
    @Deprecated
    SSL3_RSA_WITH_NULL_MD5                       (0x0001, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_RSA_WITH_NULL_MD5                        (0x0001, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    /**
     * @deprecated Replaced with TLS_RSA_WITH_NULL_SHA.
     */
    @Deprecated
    SSL3_RSA_WITH_NULL_SHA                       (0x0002, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_RSA_WITH_NULL_SHA                        (0x0002, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    SSL3_RSA_EXPORT_WITH_RC4_40_MD5              (0x0003, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),
    TLS_RSA_EXPORT_WITH_RC4_40_MD5               (0x0003, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),

    /**
     * @deprecated Replaced with TLS_RSA_WITH_RC4_128_MD5.
     */
    @Deprecated
    SSL3_RSA_WITH_RC4_128_MD5                    (0x0004, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_RSA_WITH_RC4_128_MD5                     (0x0004, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    /**
     * @deprecated Replaced with TLS_RSA_WITH_RC4_128_SHA.
     */
    @Deprecated
    SSL3_RSA_WITH_RC4_128_SHA                    (0x0005, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_RSA_WITH_RC4_128_SHA                     (0x0005, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5          (0x0006, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5           (0x0006, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),

    /**
     * @deprecated Replaced with TLS_RSA_WITH_IDEA_CBC_SHA.
     */
    @Deprecated
    SSL3_RSA_WITH_IDEA_CBC_SHA                   (0x0007, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1 }),
    TLS_RSA_WITH_IDEA_CBC_SHA                    (0x0007, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1 }),

    SSL3_RSA_EXPORT_WITH_DES40_CBC_SHA           (0x0008, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA            (0x0008, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),

    /**
     * @deprecated Replaced with TLS_RSA_WITH_DES_CBC_SHA.
     */
    @Deprecated
    SSL3_RSA_WITH_DES_CBC_SHA                    (0x0009, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1 }),
    TLS_RSA_WITH_DES_CBC_SHA                     (0x0009, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1 }),

    /**
     * @deprecated Replaced with TLS_RSA_WITH_3DES_EDE_CBC_SHA.
     */
    @Deprecated
    SSL3_RSA_WITH_3DES_EDE_CBC_SHA               (0x000a, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_RSA_WITH_3DES_EDE_CBC_SHA                (0x000a, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    SSL3_DH_DSS_EXPORT_WITH_DES40_CBC_SHA        (0x000b, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA         (0x000b, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),


    /**
     * @deprecated Replaced with TLS_DH_DSS_WITH_DES_CBC_SHA.
     */
    @Deprecated
    SSL3_DH_DSS_WITH_DES_CBC_SHA                 (0x000c, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1 }),
    TLS_DH_DSS_WITH_DES_CBC_SHA                  (0x000c, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1 }),

    /**
     * @deprecated Replaced with TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA.
     */
    @Deprecated
    SSL3_DH_DSS_WITH_3DES_EDE_CBC_SHA            (0x000d, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA             (0x000d, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    SSL3_DH_RSA_EXPORT_WITH_DES40_CBC_SHA        (0x000e, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA         (0x000e, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),

    /**
     * @deprecated Replaced with TLS_DH_RSA_WITH_DES_CBC_SHA.
     */
    @Deprecated
    SSL3_DH_RSA_WITH_DES_CBC_SHA                 (0x000f, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1 }),
    TLS_DH_RSA_WITH_DES_CBC_SHA                  (0x000f, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1 }),

    /**
     * @deprecated Replaced with TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA.
     */
    @Deprecated
    SSL3_DH_RSA_WITH_3DES_EDE_CBC_SHA            (0x0010, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA             (0x0010, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    SSL3_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA       (0x0011, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA        (0x0011, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),

    /**
     * @deprecated Replaced with TLS_DHE_DSS_WITH_DES_CBC_SHA.
     */
    @Deprecated
    SSL3_DHE_DSS_WITH_DES_CBC_SHA                (0x0012, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1 }),
    TLS_DHE_DSS_WITH_DES_CBC_SHA                 (0x0012, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1 }),

    /**
     * @deprecated Replaced with TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA.
     */
    @Deprecated
    SSL3_DHE_DSS_WITH_3DES_EDE_CBC_SHA           (0x0013, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA            (0x0013, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    SSL3_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA       (0x0014, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA        (0x0014, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),

    /**
     * @deprecated Replaced with TLS_DHE_RSA_WITH_DES_CBC_SHA.
     */
    @Deprecated
    SSL3_DHE_RSA_WITH_DES_CBC_SHA                (0x0015, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1 }),
    TLS_DHE_RSA_WITH_DES_CBC_SHA                 (0x0015, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1 }),

    /**
     * @deprecated Replaced with TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA.
     */
    @Deprecated
    SSL3_DHE_RSA_WITH_3DES_EDE_CBC_SHA           (0x0016, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA            (0x0016, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    SSL3_DH_ANON_EXPORT_WITH_RC4_40_MD5          (0x0017, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5           (0x0017, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),

    /**
     * @deprecated Replaced with TLS_DH_anon_WITH_RC4_128_MD5.
     */
    @Deprecated
    SSL3_DH_ANON_WITH_RC4_128_MD5                (0x0018, SSLVersion.SSL_3_0),
    TLS_DH_anon_WITH_RC4_128_MD5                 (0x0018, SSLVersion.SSL_3_0),

    SSL3_DH_ANON_EXPORT_WITH_DES40_CBC_SHA       (0x0019, SSLVersion.SSL_3_0),
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA        (0x0019, SSLVersion.SSL_3_0),

    /**
     * @deprecated Replaced with TLS_DH_anon_WITH_DES_CBC_SHA.
     */
    @Deprecated
    SSL3_DH_ANON_WITH_DES_CBC_SHA                (0x001a, SSLVersion.SSL_3_0),
    TLS_DH_anon_WITH_DES_CBC_SHA                 (0x001a, SSLVersion.SSL_3_0),

    /**
     * @deprecated Replaced with TLS_DH_anon_WITH_3DES_EDE_CBC_SHA.
     */
    @Deprecated
    SSL3_DH_ANON_WITH_3DES_EDE_CBC_SHA           (0x001b, SSLVersion.SSL_3_0),
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA            (0x001b, SSLVersion.SSL_3_0),

    /**
     * @deprecated As of NSS 3.11, FORTEZZA is no longer supported.
     */
    @Deprecated
    SSL3_FORTEZZA_DMS_WITH_NULL_SHA              (0x001c, SSLVersion.SSL_3_0),

    /**
     * @deprecated As of NSS 3.11, FORTEZZA is no longer supported.
     */
    @Deprecated
    SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA      (0x001d, SSLVersion.SSL_3_0),

    /**
     * @deprecated As of NSS 3.11, FORTEZZA is no longer supported.
     */
    @Deprecated
    SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA           (0x001e, SSLVersion.SSL_3_0),

    SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA           (0xfeff, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),
    SSL_RSA_FIPS_WITH_DES_CBC_SHA                (0xfefe, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),

    TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA          (0x0062, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),
    TLS_RSA_EXPORT1024_WITH_RC4_56_SHA           (0x0064, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),

    TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA      (0x0063, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),
    TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA       (0x0065, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),
    TLS_DHE_DSS_WITH_RC4_128_SHA                 (0x0066, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1 }),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256          (0x0067, new SSLVersion[] { SSLVersion.TLS_1_2 }),
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256          (0x006A, new SSLVersion[] { SSLVersion.TLS_1_2 }),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256          (0x006B, new SSLVersion[] { SSLVersion.TLS_1_2 }),

    // New TLS cipher suites in NSS 3.4
    TLS_RSA_WITH_AES_128_CBC_SHA                 (0x002F, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DH_DSS_WITH_AES_128_CBC_SHA              (0x0030, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DH_RSA_WITH_AES_128_CBC_SHA              (0x0031, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA             (0x0032, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA             (0x0033, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    /**
     * @deprecated Replaced with TLS_DH_anon_WITH_AES_128_CBC_SHA.
     */
    @Deprecated
    TLS_DH_ANON_WITH_AES_128_CBC_SHA             (0x0034, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1 }),
    TLS_DH_anon_WITH_AES_128_CBC_SHA             (0x0034, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1 }),

    TLS_RSA_WITH_AES_256_CBC_SHA                 (0x0035, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DH_DSS_WITH_AES_256_CBC_SHA              (0x0036, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DH_RSA_WITH_AES_256_CBC_SHA              (0x0037, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA             (0x0038, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA             (0x0039, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    /**
     * @deprecated Replaced with TLS_DH_anon_WITH_AES_256_CBC_SHA.
     */
    @Deprecated
    TLS_DH_ANON_WITH_AES_256_CBC_SHA             (0x003A, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DH_anon_WITH_AES_256_CBC_SHA             (0x003A, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    TLS_RSA_WITH_NULL_SHA256                     (0x003B, new SSLVersion[] { SSLVersion.TLS_1_2 }),
    TLS_RSA_WITH_AES_128_CBC_SHA256              (0x003C, new SSLVersion[] { SSLVersion.TLS_1_2 }),
    TLS_RSA_WITH_AES_256_CBC_SHA256              (0x003D, new SSLVersion[] { SSLVersion.TLS_1_2 }),

    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256          (0x0041, new SSLVersion[] { SSLVersion.TLS_1_2 }),
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA            (0x0041, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA         (0x0042, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA         (0x0043, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA        (0x0044, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA        (0x0045, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    /**
     * @deprecated Replaced with TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA.
     */
    @Deprecated
    TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA        (0x0046, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA        (0x0046, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA            (0x0084, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA         (0x0085, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA         (0x0086, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA        (0x0087, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA        (0x0088, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    /**
     * @deprecated Replaced with TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA.
     */
    @Deprecated
    TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA        (0x0089, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA        (0x0089, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    TLS_RSA_WITH_SEED_CBC_SHA                    (0x0096, new SSLVersion[] { SSLVersion.SSL_3_0, SSLVersion.TLS_1_0 }),

    TLS_RSA_WITH_AES_128_GCM_SHA256              (0x009C, SSLVersion.TLS_1_2),
    TLS_RSA_WITH_AES_256_GCM_SHA384              (0x009D, SSLVersion.TLS_1_2),
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256          (0x009E, SSLVersion.TLS_1_2),
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384          (0x009F, SSLVersion.TLS_1_2),
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256          (0x00A2, SSLVersion.TLS_1_2),
    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384          (0x00A3, SSLVersion.TLS_1_2),
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256          (0x00AA, SSLVersion.TLS_1_2),
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384          (0x00AB, SSLVersion.TLS_1_2),

    TLS_EMPTY_RENEGOTIATION_INFO_SCSV            (0x00FF),

    TLS_FALLBACK_SCSV                            (0x5600),

    TLS_ECDH_ECDSA_WITH_NULL_SHA                 (0xc001, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA              (0xc002, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA         (0xc003, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1 }),
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA          (0xc004, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA          (0xc005, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    TLS_ECDHE_ECDSA_WITH_NULL_SHA                (0xc006, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA             (0xc007, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA        (0xc008, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1 }),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA         (0xc009, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA         (0xc00a, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    TLS_ECDH_RSA_WITH_NULL_SHA                   (0xc00b, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_ECDH_RSA_WITH_RC4_128_SHA                (0xc00c, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA           (0xc00d, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA            (0xc00e, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA            (0xc00f, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    TLS_ECDHE_RSA_WITH_NULL_SHA                  (0xc010, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_ECDHE_RSA_WITH_RC4_128_SHA               (0xc011, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA          (0xc012, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA           (0xc013, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA           (0xc014, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    TLS_ECDH_anon_WITH_NULL_SHA                  (0xc015, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_ECDH_anon_WITH_RC4_128_SHA               (0xc016, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA          (0xc017, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA           (0xc018, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA           (0xc019, true, new SSLVersion[] { SSLVersion.TLS_1_0, SSLVersion.TLS_1_1, SSLVersion.TLS_1_2 }),

    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256      (0xc023, true, SSLVersion.TLS_1_2),
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384      (0xc024, true, SSLVersion.TLS_1_2),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256        (0xc027, true, SSLVersion.TLS_1_2),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384        (0xc028, true, SSLVersion.TLS_1_2),

    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256      (0xc02B, true, SSLVersion.TLS_1_2),
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384      (0xc02C, true, SSLVersion.TLS_1_2),
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256       (0xc02D, true, SSLVersion.TLS_1_2),
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256        (0xc02F, true, SSLVersion.TLS_1_2),
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384        (0xc030, true, SSLVersion.TLS_1_2),
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256         (0xc031, true, SSLVersion.TLS_1_2),

    /*
     * TLS 1.3
     */
    /* draft-ietf-tls-chacha20-poly1305-04 */
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   (0xCCA8, true, SSLVersion.TLS_1_2),
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA9, true, SSLVersion.TLS_1_2),
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256     (0xCCAA, SSLVersion.TLS_1_2),
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256   (0xCCAC, true, SSLVersion.TLS_1_2),
    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256     (0xCCAD, SSLVersion.TLS_1_2),


    TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256         (0xD001, true, SSLVersion.TLS_1_2),
    TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384         (0xD002, true, SSLVersion.TLS_1_2),

    /* Special TLS 1.3 cipher suites that really just specify AEAD */
    TLS_AES_128_GCM_SHA256                        (0x1301, false, SSLVersion.TLS_1_3),
    TLS_AES_256_GCM_SHA384                        (0x1302, false, SSLVersion.TLS_1_3),
    TLS_CHACHA20_POLY1305_SHA256                  (0x1303, false, SSLVersion.TLS_1_3);

    private int id;
    private boolean ecc;
    private SSLVersion[] versions;
    private boolean supported;

    private SSLCipher(int id) {
        /* Should only be used with TLS_EMPTY_RENEGOTIATION_INFO_SCSV and
         * TLS_FALLBACK_SCSV. */
        this(id, false, null, true);
    }

    private SSLCipher(int id, SSLVersion version) {
        this(id, false, new SSLVersion[] { version });
    }

    private SSLCipher(int id, SSLVersion[] versions) {
        this(id, false, versions);
    }

    private SSLCipher(int id, boolean ecc, SSLVersion version) {
        this(id, ecc, new SSLVersion[] { version });
    }

    private SSLCipher(int id, boolean ecc, SSLVersion[] versions) {
        this(id, ecc, versions, checkSupportedStatus(id));
    }

    private SSLCipher(int id, boolean ecc, SSLVersion[] versions, boolean supported) {
        this.id = id;
        this.ecc = ecc;
        this.versions = versions;
        this.supported = supported;
    }

    private static native boolean checkSupportedStatus(int id);

    public int getID() {
        return id;
    }

    public boolean isECC() {
        return ecc;
    }

    public boolean supportsTLSVersion(SSLVersion v) {
        if (versions == null) {
            return false;
        }

        for (SSLVersion version : versions) {
            if (version == v) {
                return true;
            }
        }

        return false;
    }

    public boolean isTLSv12() {
        return supportsTLSVersion(SSLVersion.TLS_1_2);
    }

    public boolean isTLSv13() {
        return supportsTLSVersion(SSLVersion.TLS_1_3);
    }

    public boolean isSupported() {
        return supported;
    }

    public boolean requiresRSACert() {
        return this.name().contains("_RSA_") && !this.name().contains("ECDH_RSA");
    }

    public boolean requiresECDSACert() {
        return this.name().contains("_ECDSA_") || this.name().contains("ECDH_RSA");
    }

    public boolean requiresDSSCert() {
        return this.name().contains("_DSS_");
    }

    public static SSLCipher valueOf(int id) {
        for (SSLCipher cipher : SSLCipher.class.getEnumConstants()) {
            if (cipher.id == id) return cipher;
        }
        return null;
    }
}
