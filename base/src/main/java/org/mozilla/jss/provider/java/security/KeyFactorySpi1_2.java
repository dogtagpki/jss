/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.provider.java.security;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.CHOICE;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.TokenSupplierManager;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.pkcs11.PK11PrivKey;
import org.mozilla.jss.pkcs11.PK11PubKey;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.PrivateKeyInfo;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;
import org.mozilla.jss.util.ECCurve;

public class KeyFactorySpi1_2 extends java.security.KeyFactorySpi
{

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if( keySpec instanceof RSAPublicKeySpec ) {
            RSAPublicKeySpec spec = (RSAPublicKeySpec) keySpec;

            // Generate a DER RSA public key
            SEQUENCE seq = new SEQUENCE();
            seq.addElement( new INTEGER(spec.getModulus()));
            seq.addElement( new INTEGER(spec.getPublicExponent()));

            return PK11PubKey.fromRaw( PrivateKey.RSA, ASN1Util.encode(seq) );
        } else if( keySpec instanceof DSAPublicKeySpec ) {
            // We need to import both the public value and the PQG parameters.
            // The only way to get all that information in DER is to send
            // a full SubjectPublicKeyInfo. So we encode all the information
            // into an SPKI.

            DSAPublicKeySpec spec = (DSAPublicKeySpec) keySpec;

            SEQUENCE pqg = new SEQUENCE();
            pqg.addElement( new INTEGER(spec.getP()) );
            pqg.addElement( new INTEGER(spec.getQ()) );
            pqg.addElement( new INTEGER(spec.getG()) );
            OBJECT_IDENTIFIER oid = null;
            try {
                oid = SignatureAlgorithm.DSASignature.toOID();
            } catch(NoSuchAlgorithmException e ) {
                throw new RuntimeException("No such algorithm: " + e.getMessage(), e);
            }
            AlgorithmIdentifier algID = new AlgorithmIdentifier( oid, pqg );
            INTEGER publicValue = new INTEGER(spec.getY());
            byte[] encodedPublicValue = ASN1Util.encode(publicValue);
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(
                algID, new BIT_STRING(encodedPublicValue, 0) );

            return PK11PubKey.fromSPKI( ASN1Util.encode(spki) );
        } else if(keySpec instanceof ECPublicKeySpec ecPKSpec) {

            ECCurve curve = ECCurve.fromOrder(ecPKSpec.getParams().getOrder());
            if (curve == null) {
                throw new InvalidKeySpecException("Unsupported Elliptic Curve");
            }
            int pointSize = switch(curve) {
                case P256 -> 32;
                case P384 -> 48;
                case P521 -> 66;
                default -> 32;
            };

            OBJECT_IDENTIFIER oid = null;
            try {
                oid = SignatureAlgorithm.ECSignature.toOID();
            } catch(NoSuchAlgorithmException ex ) {
                throw new InvalidKeySpecException("Unsupported KeySpec type: " +
                                                  keySpec.getClass().getName());
            }
			
            AlgorithmIdentifier algID =
                new AlgorithmIdentifier(oid, curve.getOIDs()[0]);

            byte[] publicValueX = convertIntToBigEndian(ecPKSpec.getW().getAffineX(), pointSize);
            byte[] publicValueY = convertIntToBigEndian(ecPKSpec.getW().getAffineY(), pointSize);

            byte[] encodedPublicValue = new byte[1 + publicValueX.length + publicValueY.length];
            encodedPublicValue[0] = 0x04; //EC_UNCOMPRESSED_POINT
            for (int i = 0; i < publicValueX.length; i++) {
                encodedPublicValue[i + 1] = publicValueX[i];
            }
            for (int i = 0; i < publicValueY.length; i++) {
                encodedPublicValue[i + 1 + publicValueX.length] = publicValueY[i];
            }

            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algID, new BIT_STRING(encodedPublicValue, 0));
            return PK11PubKey.fromSPKI(ASN1Util.encode(spki));

        } else if( keySpec instanceof X509EncodedKeySpec ) {
            X509EncodedKeySpec spec = (X509EncodedKeySpec) keySpec;
            return PK11PubKey.fromSPKI( spec.getEncoded() );
        }
        throw new InvalidKeySpecException("Unsupported KeySpec type: " +
            keySpec.getClass().getName());
    }

    /**
     * We don't support RSAPrivateKeySpec because it doesn't have enough
     * information. You need to provide an RSAPrivateCrtKeySpec.
     */
    @Override
    protected java.security.PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException
    {
      try {
        if( keySpec instanceof RSAPrivateCrtKeySpec ) {
            //
            // PKCS #1 RSAPrivateKey
            //
            RSAPrivateCrtKeySpec spec = (RSAPrivateCrtKeySpec) keySpec;
            SEQUENCE privKey = new SEQUENCE();
            privKey.addElement( new INTEGER(0) ) ; // version
            privKey.addElement( new INTEGER(spec.getModulus()) );
            privKey.addElement( new INTEGER(spec.getPublicExponent()) );
            privKey.addElement( new INTEGER(spec.getPrivateExponent()) );
            privKey.addElement( new INTEGER(spec.getPrimeP()) );
            privKey.addElement( new INTEGER(spec.getPrimeQ()) );
            privKey.addElement( new INTEGER(spec.getPrimeExponentP()) );
            privKey.addElement( new INTEGER(spec.getPrimeExponentQ()) );
            privKey.addElement( new INTEGER(spec.getCrtCoefficient()) );

            AlgorithmIdentifier algID =
                new AlgorithmIdentifier( PrivateKey.RSA.toOID(), null );

            OCTET_STRING encodedPrivKey = new OCTET_STRING(
                ASN1Util.encode(privKey) );
            PrivateKeyInfo pki = new PrivateKeyInfo(
                new INTEGER(0),     // version
                algID,
                encodedPrivKey,
                (SET)null                // OPTIONAL SET OF Attribute
            );
            return PK11PrivKey.fromPrivateKeyInfo( ASN1Util.encode(pki),
                TokenSupplierManager.getTokenSupplier().getThreadToken() );
        } else if( keySpec instanceof DSAPrivateKeySpec ) {
            DSAPrivateKeySpec spec = (DSAPrivateKeySpec) keySpec;
            SEQUENCE pqgParams = new SEQUENCE();
            pqgParams.addElement(new INTEGER(spec.getP()));
            pqgParams.addElement(new INTEGER(spec.getQ()));
            pqgParams.addElement(new INTEGER(spec.getG()));
            AlgorithmIdentifier algID =
                new AlgorithmIdentifier( PrivateKey.DSA.toOID(), pqgParams );
            OCTET_STRING privateKey = new OCTET_STRING(
                ASN1Util.encode(new INTEGER(spec.getX())) );

            PrivateKeyInfo pki = new PrivateKeyInfo(
                    new INTEGER(0),     // version
                    algID,
                    privateKey,
                    null                // OPTIONAL SET OF Attribute
            );

            // Derive the public key from the private key
            BigInteger y = spec.getG().modPow(spec.getX(), spec.getP());
            byte[] yBA = y.toByteArray();
            // we need to chop off a leading zero byte
            if( y.bitLength() % 8 == 0 ) {
                byte[] newBA = new byte[yBA.length-1];
                assert(newBA.length > 0);
                System.arraycopy(yBA, 1, newBA, 0, newBA.length);
                yBA = newBA;
            }

            return PK11PrivKey.fromPrivateKeyInfo( ASN1Util.encode(pki),
                TokenSupplierManager.getTokenSupplier().getThreadToken(), yBA );
        } else if( keySpec instanceof PKCS8EncodedKeySpec ) {
            return PK11PrivKey.fromPrivateKeyInfo(
                (PKCS8EncodedKeySpec)keySpec,
                TokenSupplierManager.getTokenSupplier().getThreadToken() );
        }

        throw new InvalidKeySpecException("Unsupported KeySpec type: " +
            keySpec.getClass().getName());
      } catch(TokenException te) {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            te.printStackTrace(pw);
            throw new InvalidKeySpecException("TokenException: " +
                sw.toString());
      }
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
        throws InvalidKeySpecException
    {
        throw new InvalidKeySpecException(
            "Exporting raw key data is not supported. Wrap the key instead.");
    }

    /**
     * Translates key by calling getEncoded() to get its encoded form,
     * then importing the key from its encoding. Two formats are supported:
     * "X.509", which is decoded with an X509EncodedKeySpec;
     * and "PKCS#8", which is decoded with a PKCS8EncodedKeySpec.
     *
     * <p>This method is not well standardized: the documentation is very vague
     * about how the key is supposed to be translated. It is better
     * to move keys around by wrapping and unwrapping them; or by manually
     * translating to a KeySpec, then manually translating back to a Key.
     */
    @Override
    protected Key engineTranslateKey(Key key)
        throws InvalidKeyException
    {
        byte[] encoded = key.getEncoded();
        String format = key.getFormat();

          try {
            if( format.equals("SubjectPublicKeyInfo") ||
                format.equalsIgnoreCase("X.509"))
            {
                X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
                return engineGeneratePublic(spec);
            } else if( format.equals("PrivateKeyInfo") ||
                format.equalsIgnoreCase("PKCS#8"))
            {
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
                return engineGeneratePrivate(spec);
            }
          } catch(InvalidKeySpecException e) {
            throw new InvalidKeyException(e.getMessage());
          }
        throw new InvalidKeyException(
            "Unsupported encoding format: " + format);
    }


    private byte[] convertIntToBigEndian(BigInteger elem, int size) {
        byte[] arrayElem = elem.toByteArray();
        if(arrayElem.length > size) {
            arrayElem = Arrays.copyOfRange(arrayElem, arrayElem.length - size, arrayElem.length);
        }
        if(arrayElem.length < size) {
            byte[] temp = new byte[size];
            Arrays.fill(temp, (byte) 0);
            for (int i=0; i < arrayElem.length; i++) {
                temp[size - arrayElem.length + i] = arrayElem[i];
            }
            arrayElem = temp;
        }
        return arrayElem;
    }
}
