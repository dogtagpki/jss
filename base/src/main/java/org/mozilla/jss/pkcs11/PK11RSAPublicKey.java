/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import java.security.interfaces.RSAPublicKey;
import java.math.BigInteger;

public class PK11RSAPublicKey extends PK11PubKey implements RSAPublicKey {
    
    private static final long serialVersionUID = 1L;
    public PK11RSAPublicKey(byte[] pointer) {
        super(pointer);
    }

    @Override
    public BigInteger getModulus() {
      try {
        return new BigInteger(1, getModulusByteArray());
      } catch( NumberFormatException e) {
        return null;
      }
    }
    private native byte[] getModulusByteArray();

    @Override
    public BigInteger getPublicExponent() {
      try {
        return new BigInteger(1, getPublicExponentByteArray());
      } catch( NumberFormatException e) {
        return null;
      }
    }
    private native byte[] getPublicExponentByteArray();
}
