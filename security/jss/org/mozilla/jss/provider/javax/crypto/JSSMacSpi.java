/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.provider.javax.crypto;

import java.security.*;
import java.security.spec.*;
import org.mozilla.jss.crypto.JSSMessageDigest;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.TokenSupplierManager;
import org.mozilla.jss.crypto.JSSMessageDigest;
import org.mozilla.jss.crypto.SecretKeyFacade;
import org.mozilla.jss.crypto.HMACAlgorithm;
import org.mozilla.jss.crypto.TokenRuntimeException;

class JSSMacSpi extends javax.crypto.MacSpi {

    private JSSMessageDigest digest=null;
    private HMACAlgorithm alg;

    private JSSMacSpi() { }

    protected JSSMacSpi(HMACAlgorithm alg) {
      try {
        this.alg = alg;
        CryptoToken token =
            TokenSupplierManager.getTokenSupplier().getThreadToken();
        digest = token.getDigestContext(alg);
      } catch( DigestException de) {
            throw new TokenRuntimeException(de.getMessage());
      } catch(NoSuchAlgorithmException nsae) {
            throw new TokenRuntimeException(nsae.getMessage());
      }
    }


    public int engineGetMacLength() {
        return alg.getOutputSize();
    }

    public void engineInit(Key key, AlgorithmParameterSpec params)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
      try {
        if( ! (key instanceof SecretKeyFacade) ) {
            throw new InvalidKeyException("Must use a JSS key");
        }
        SecretKeyFacade facade = (SecretKeyFacade)key;
        digest.initHMAC(facade.key);
      } catch(DigestException de) {
        throw new InvalidKeyException(
            "DigestException: " + de.getMessage());
      }
    }

    public void engineUpdate(byte input) {
      try {
        digest.update(input);
      } catch(DigestException de) {
        throw new TokenRuntimeException("DigestException: " + de.getMessage());
      }
    }

    public void engineUpdate(byte[] input, int offset, int len) {
      try {
        digest.update(input, offset, len);
      } catch(DigestException de) {
        throw new TokenRuntimeException("DigestException: " + de.getMessage());
      }
    }

    public byte[] engineDoFinal() {
      try {
        return digest.digest();
      } catch(DigestException de) {
        throw new TokenRuntimeException("DigestException: " + de.getMessage());
      }
    }

    public void engineReset() {
      try {
        digest.reset();
      } catch(DigestException de) {
        throw new TokenRuntimeException("DigestException: " + de.getMessage());
      }
    }

    public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

    public static class HmacSHA1 extends JSSMacSpi {
        public HmacSHA1() {
            super(HMACAlgorithm.SHA1);
        }
    }

    public static class HmacSHA256 extends JSSMacSpi {
        public HmacSHA256() {
            super(HMACAlgorithm.SHA256);
        }
    }

    public static class HmacSHA384 extends JSSMacSpi {
        public HmacSHA384() {
            super(HMACAlgorithm.SHA384);
        }
    }

    public static class HmacSHA512 extends JSSMacSpi {
        public HmacSHA512() {
            super(HMACAlgorithm.SHA512);
        }
    }

}
