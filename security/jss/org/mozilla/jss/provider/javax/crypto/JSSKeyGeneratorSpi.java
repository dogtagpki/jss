/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.provider.javax.crypto;

import java.io.CharConversionException;
import java.security.*;
import java.security.spec.*;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.TokenRuntimeException;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.SecretKeyFacade;
import org.mozilla.jss.crypto.TokenSupplierManager;
import javax.crypto.*;

class JSSKeyGeneratorSpi extends javax.crypto.KeyGeneratorSpi {
    private KeyGenerator keyGenerator= null;

    private JSSKeyGeneratorSpi() {}

    protected JSSKeyGeneratorSpi(KeyGenAlgorithm alg) {
      try {
        CryptoToken token =
            TokenSupplierManager.getTokenSupplier().getThreadToken();
        keyGenerator = token.getKeyGenerator(alg);
      } catch( TokenException te) {
            throw new TokenRuntimeException(te.getMessage());
      } catch(NoSuchAlgorithmException nsae) {
            throw new TokenRuntimeException(nsae.getMessage());
      }
    }

    protected void engineInit(int keysize,  SecureRandom random)
            throws InvalidParameterException
    {
      try {
        keyGenerator.initialize(keysize);
      } catch(InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException(e.getMessage());
      }
    }

    protected void engineInit( SecureRandom random)
            throws InvalidParameterException
    {
        // no-op. KeyGenerator.initialize isn't called if there
        // are no arguments.
    }

    protected void engineInit(AlgorithmParameterSpec params,
                    SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        keyGenerator.initialize(params);
    }

    protected SecretKey engineGenerateKey() {
      try {
        return new SecretKeyFacade( keyGenerator.generate() );
      } catch(IllegalStateException ise) {
        throw new TokenRuntimeException(
            "IllegalStateException: " + ise.getMessage());
      } catch(TokenException te) {
        throw new TokenRuntimeException( te.getMessage());
      } catch(CharConversionException cce) {
        throw new TokenRuntimeException(
            "CharConversionException: " + cce.getMessage());
      }
    }

    public static class DES extends JSSKeyGeneratorSpi {
        public DES() {
            super(KeyGenAlgorithm.DES);
        }
    }
    public static class DESede extends JSSKeyGeneratorSpi {
        public DESede() {
            super(KeyGenAlgorithm.DESede);
        }
    }
    public static class AES extends JSSKeyGeneratorSpi {
        public AES() {
            super(KeyGenAlgorithm.AES);
        }
    }
    public static class RC4 extends JSSKeyGeneratorSpi {
        public RC4() {
            super(KeyGenAlgorithm.RC4);
        }
    }
    public static class RC2 extends JSSKeyGeneratorSpi {
        public RC2() {
            super(KeyGenAlgorithm.RC2);
        }
    }

    /**
     * @deprecated This class name is misleading. This algorithm
     * is used for generating Password-Based Authentication keys
     * for use with HmacSHA1. Use PBAHmacSHA1 instead.
     */
    public static class HmacSHA1 extends JSSKeyGeneratorSpi {
        public HmacSHA1() {
            super(KeyGenAlgorithm.PBA_SHA1_HMAC);
        }
    }

    public static class PBAHmacSHA1 extends JSSKeyGeneratorSpi {
        public PBAHmacSHA1() {
            super(KeyGenAlgorithm.PBA_SHA1_HMAC);
        }
    }

}
