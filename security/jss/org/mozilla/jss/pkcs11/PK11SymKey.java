/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import org.mozilla.jss.crypto.*;
import org.mozilla.jss.util.Assert;

public final class PK11SymKey implements SymmetricKey {

    protected PK11SymKey(byte[] pointer) {
        Assert._assert(pointer!=null);
        keyProxy  = new SymKeyProxy(pointer);
    }

    private SymKeyProxy keyProxy;

    public SymmetricKey.Type getType() {
        KeyType kt = getKeyType();
        if(kt == KeyType.DES) {
            return DES;
        } else if(kt == KeyType.DES3) {
            return DES3;
        } else if(kt == KeyType.RC4) {
            return RC4;
        } else if(kt == KeyType.RC2) {
            return RC2;
        } else if(kt == KeyType.AES) {
            return AES;
        } else if(kt == KeyType.SHA1_HMAC) {
            return SHA1_HMAC;
        } else {
            Assert.notReached("Unrecognized key type");
            return DES;
        }
    }

    public native CryptoToken getOwningToken();

    /**
     * Returns key strength, measured as the number of bits of secret material.
     * <b>NOTE:</b> Due to a bug in the security library (333440), this
     *  may return a wrong answer for PBE keys that have embedded parity
     *  (like DES).  A DES key is 56 bits of information plus
     *  8 bits of parity, so it takes up 64 bits.  For a normal DES key,
     * this method will correctly return 56, but for a PBE-generated DES key,
     * the security library bug causes it to return 64.
     */
    public native int getStrength();


    /**
     * Returns the length of the key in bytes, as returned by
     * PK11_GetKeyLength().
     */
    public native int getLength();

    public native byte[] getKeyData()
        throws SymmetricKey.NotExtractableException;

    public native KeyType getKeyType();

    public String getAlgorithm() {
        return getKeyType().toString();
    }

    public byte[] getEncoded() {
        try {
            return getKeyData();
        } catch(SymmetricKey.NotExtractableException nee) {
            return null;
        }
    }

    public String getFormat() {
        return "RAW";
    }
}

class SymKeyProxy extends KeyProxy {

    public SymKeyProxy(byte[] pointer) {
        super(pointer);
    }

    protected native void releaseNativeResources();

    protected void finalize() throws Throwable {
        super.finalize();
    }
}
