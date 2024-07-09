package org.mozilla.jss.pkcs11;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

import org.mozilla.jss.crypto.PrivateKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PK11RSAPrivateKey
    extends PK11PrivKey implements java.security.interfaces.RSAKey
{
    public static Logger logger = LoggerFactory.getLogger(PK11RSAPrivateKey.class);

    private static final long serialVersionUID = 1L;

    private PK11RSAPrivateKey() { super(null); }

    protected PK11RSAPrivateKey(byte[] pointer) {
        super(pointer);
    }

    @Override
    public PrivateKey.Type getType() {
        return PrivateKey.Type.RSA;
    }

    @Override
    public AlgorithmParameterSpec getParams() {
        PK11PubKey publicKey = getPublicKey();
        if (!(publicKey instanceof PK11RSAPublicKey)) {
            throw new RuntimeException("Unknown key type: expected the public key of an RSA key to be an PK11RSAPublicKey; got: " + publicKey);
        }

        PK11RSAPublicKey rsaPublicKey = (PK11RSAPublicKey)publicKey;
        return rsaPublicKey.getParams();
    }

    @Override
    public BigInteger getModulus() {
        logger.debug("PK11RSAPrivateKey: getModulus()");
        return new BigInteger(1, getModulusByteArray());
    }

    native byte[] getModulusByteArray();

    public BigInteger getPrivateExponent() {
        // !!!
        return null;
    }
}
