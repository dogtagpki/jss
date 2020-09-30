package org.mozilla.jss.util;

import java.math.BigInteger;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;

import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;

/**
 * Database of common, public elliptic curves.
 *
 * Data taken from jss.pkcs11.PK11KeyPairGenerator, the OpenJDK CurveDB,
 * and djb's SafeCurves webpage.
 */
public enum ECCurve {
    P256(
        new String[] { "ansip256r1", "secp256r1", "nistp256", "P-256", "NIST P-256", "X9.62 prime256v1"}, // names
        new OBJECT_IDENTIFIER[] { ECOIDs.CURVE_ANSI_P256V1 }, // OIDs
        new ECFieldFp(new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)), // field
        new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16), // a
        new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16), // b
        new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16), // generator.X
        new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16), // generator.Y
        new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16), // order
        // OpenJDK lists this curve as having a cofactor of one, but NIST
        // doesn't share their cofactor.
        1 // cofactor
    ),
    P384(
        new String[] { "ansip384r1", "secp384r1", "nistp384", "P-384", "NIST P-384" }, // names
        new OBJECT_IDENTIFIER[] { ECOIDs.CURVE_SECG_P384R1 }, // OIDs
        new ECFieldFp(new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16)), // field
        new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", 16), // a
        new BigInteger("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16), // b
        new BigInteger("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16), // generator.X
        new BigInteger("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16), // generator.Y
        new BigInteger("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16), // order
        // OpenJDK lists this curve as having a cofactor of one, but NIST
        // doesn't share their cofactor.
        1 // cofactor
    ),
    P521(
        new String[] { "ansip521r1", "secp521r1", "nistp521", "P-521", "NIST P-521" }, // names
        new OBJECT_IDENTIFIER[] { ECOIDs.CURVE_SECG_P521R1 }, // OIDs
        new ECFieldFp(new BigInteger("1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)), // field
        new BigInteger("1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc", 16), // a
        new BigInteger("51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16), // b
        new BigInteger("c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16), // generator.X
        new BigInteger("11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16), // generator.Y
        new BigInteger("1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 16), // order
        // OpenJDK lists this curve as having a cofactor of one, but NIST
        // doesn't share their cofactor.
        1 // cofactor
    );

    // OIDs are defined at the bottom of this class.

    private String[] names;
    private OBJECT_IDENTIFIER[] oids;

    private ECField field;
    private BigInteger a;
    private BigInteger b;
    private BigInteger generatorX;
    private BigInteger generatorY;
    private BigInteger order;
    private int cofactor;

    private ECCurve(String[] names, OBJECT_IDENTIFIER[] oids, ECField field,
                    BigInteger a, BigInteger b, ECPoint generator,
                    BigInteger order, int cofactor)
    {
        this.names = names;
        this.oids = oids;
        this.field = field;
        this.a = a;
        this.b = b;
        this.generatorX = generator.getAffineX();
        this.generatorY = generator.getAffineY();
        this.order = order;
        this.cofactor = cofactor;
    }

    private ECCurve(String[] names, OBJECT_IDENTIFIER[] oids, ECField field,
                    BigInteger a, BigInteger b, BigInteger generatorX,
                    BigInteger generatorY, BigInteger order, int cofactor)
    {
        this.names = names;
        this.oids = oids;
        this.field = field;
        this.a = a;
        this.b = b;
        this.generatorX = generatorX;
        this.generatorY = generatorY;
        this.order = order;
        this.cofactor = cofactor;
    }

    public String[] getNames() {
        return names;
    }

    public OBJECT_IDENTIFIER[] getOIDs() {
        return oids;
    }

    public ECField getField() {
        return field;
    }

    public BigInteger getA() {
        return a;
    }

    public BigInteger getB() {
        return b;
    }

    public EllipticCurve getEC() {
        return new EllipticCurve(field, a, b);
    }

    public BigInteger getGeneratorX() {
        return generatorX;
    }

    public BigInteger getGeneratorY() {
        return generatorY;
    }

    public ECPoint getGenerator() {
        return new ECPoint(generatorX, generatorY);
    }

    public BigInteger getOrder() {
        return order;
    }

    public ECParameterSpec getECParameterSpec() {
        return new ECParameterSpec(getEC(), getGenerator(), getOrder(), getCofactor());
    }

    public int getCofactor() {
      return cofactor;
    }

    public static ECCurve fromOID(OBJECT_IDENTIFIER oid) {
        for (ECCurve curve : ECCurve.values()) {
            for (OBJECT_IDENTIFIER curve_oid : curve.oids) {
                if (curve_oid.equals(oid)) {
                    return curve;
                }
            }
        }

        return null;
    }

    public static ECCurve fromName(String name) {
        for (ECCurve curve : ECCurve.values()) {
            for (String curve_name : curve.names) {
                if (curve_name.equalsIgnoreCase(name)) {
                    return curve;
                }
            }
        }

        return null;
    }
}
