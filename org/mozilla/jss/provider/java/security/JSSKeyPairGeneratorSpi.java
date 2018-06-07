/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.provider.java.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.TokenRuntimeException;
import org.mozilla.jss.crypto.TokenSupplierManager;


class JSSKeyPairGeneratorSpi
    extends java.security.KeyPairGeneratorSpi
{

    private KeyPairGenerator kpg;

    protected JSSKeyPairGeneratorSpi(KeyPairAlgorithm alg) {
        super();
        CryptoToken token =
            TokenSupplierManager.getTokenSupplier().getThreadToken();
        try {
          try {
            kpg = token.getKeyPairGenerator(alg);
          } catch(java.security.NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(
                "Token '" + token.getName() + "' does not support algorithm " +
                alg.toString());
          }
        } catch(TokenException e) {
            throw new TokenRuntimeException(e.getMessage());
        }
    }

    public void initialize(AlgorithmParameterSpec params,
        SecureRandom random) throws InvalidAlgorithmParameterException
    {
        kpg.initialize(params, random);
    }

    public void initialize(int keysize, SecureRandom random) {
        kpg.initialize(keysize, random);
    }

    public KeyPair generateKeyPair()  {
      try {
        return kpg.genKeyPair();
      } catch(TokenException e) {
        throw new TokenRuntimeException(e.getMessage());
      }
    }

    public static class RSA extends JSSKeyPairGeneratorSpi {
        public RSA() {
            super(KeyPairAlgorithm.RSA);
        }
    }
    public static class DSA extends JSSKeyPairGeneratorSpi {
        public DSA() {
            super(KeyPairAlgorithm.DSA);
        }
    }
    public static class EC extends JSSKeyPairGeneratorSpi {
        public EC() {
            super(KeyPairAlgorithm.EC);
        }
    }
}
