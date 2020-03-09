package org.mozilla.jss.ssl;

import org.mozilla.jss.util.ECCurve;

public enum SSLNamedGroup {
    ssl_grp_ec_sect163k1(1),
    ssl_grp_ec_sect163r1(2),
    ssl_grp_ec_sect163r2(3),
    ssl_grp_ec_sect193r1(4),
    ssl_grp_ec_sect193r2(5),
    ssl_grp_ec_sect233k1(6),
    ssl_grp_ec_sect233r1(7),
    ssl_grp_ec_sect239k1(8),
    ssl_grp_ec_sect283k1(9),
    ssl_grp_ec_sect283r1(10),
    ssl_grp_ec_sect409k1(11),
    ssl_grp_ec_sect409r1(12),
    ssl_grp_ec_sect571k1(13),
    ssl_grp_ec_sect571r1(14),
    ssl_grp_ec_secp160k1(15),
    ssl_grp_ec_secp160r1(16),
    ssl_grp_ec_secp160r2(17),
    ssl_grp_ec_secp192k1(18),
    ssl_grp_ec_secp192r1(19),
    ssl_grp_ec_secp224k1(20),
    ssl_grp_ec_secp224r1(21),
    ssl_grp_ec_secp256k1(22),
    ssl_grp_ec_secp256r1(23, ECCurve.P256),
    ssl_grp_ec_secp384r1(24, ECCurve.P384),
    ssl_grp_ec_secp521r1(25, ECCurve.P521),
    ssl_grp_ec_curve25519(29),
    ssl_grp_ffdhe_2048(256),
    ssl_grp_ffdhe_3072(257),
    ssl_grp_ffdhe_4096(258),
    ssl_grp_ffdhe_6144(259),
    ssl_grp_ffdhe_8192(260),
    ssl_grp_none(65537),
    ssl_grp_ffdhe_custom(65538);

    private int value;
    private ECCurve curve;

    private SSLNamedGroup(int value) {
        this(value, null);
    }

    private SSLNamedGroup(int value, ECCurve curve) {
        this.curve = curve;
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public ECCurve getCurve() {
        return curve;
    }

    public static SSLNamedGroup valueOf(int value) {
        for (SSLNamedGroup group : SSLNamedGroup.values()) {
            if (group.value == value) {
                return group;
            }
        }

        return null;
    }

    public static SSLNamedGroup valueOf(ECCurve curve) {
        for (SSLNamedGroup group : SSLNamedGroup.values()) {
            if (group.curve == curve) {
                return group;
            }
        }

        return null;
    }
}
