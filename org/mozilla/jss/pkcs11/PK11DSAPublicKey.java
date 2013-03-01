/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import org.mozilla.jss.util.Assert;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.DSAParams;
import java.security.spec.DSAParameterSpec;
import java.math.BigInteger;

public final class PK11DSAPublicKey extends PK11PubKey implements DSAPublicKey {
    
    public PK11DSAPublicKey(byte[] pointer) {
        super(pointer);
    }

    public DSAParams getParams() {
      try {
        BigInteger P =  new BigInteger( getPByteArray() );
        BigInteger Q =  new BigInteger( getQByteArray() );
        BigInteger G =  new BigInteger( getGByteArray() );

        return new DSAParameterSpec(P, Q, G);
      } catch(NumberFormatException e) {
        Assert.notReached("Unable to decode DSA parameters");
        return null;
      }
    }

    public BigInteger getY() {
      try {
        return new BigInteger( getYByteArray() );
      } catch(NumberFormatException e) {
        Assert.notReached("Unable to decode DSA public value");
        return null;
      }
    }

    private native byte[] getPByteArray();
    private native byte[] getQByteArray();
    private native byte[] getGByteArray();
    private native byte[] getYByteArray();
}
