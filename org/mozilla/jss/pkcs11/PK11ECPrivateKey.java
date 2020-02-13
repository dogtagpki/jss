package org.mozilla.jss.pkcs11;

import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.math.BigInteger;

import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.util.EC;

public class PK11ECPrivateKey
    extends PK11PrivKey
    implements ECPrivateKey
{

    private static final long serialVersionUID = 1L;

    private PK11ECPrivateKey() { super(null); }

    protected PK11ECPrivateKey(byte[] pointer) {
        super(pointer);
    }

    public PrivateKey.Type getType() {
        return PrivateKey.Type.EC;
    }

    public ECParameterSpec getParams() {
        PK11PubKey publicKey = getPublicKey();
        if (!(publicKey instanceof PK11ECPublicKey)) {
            throw new RuntimeException("Unknown key type: expected the public key of an EC key to be an PK11ECPublicKey; got: " + publicKey);
        }

        PK11ECPublicKey ecPublicKey = (PK11ECPublicKey)publicKey;
        return ecPublicKey.getParams();
    }

    /**
     * Not implemented. NSS doesn't support extracting private key material
     * like this.
     */
    public BigInteger getS() {
        return null;
    }
}
