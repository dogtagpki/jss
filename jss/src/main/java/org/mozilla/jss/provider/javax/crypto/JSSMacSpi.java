/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.provider.javax.crypto;

import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import org.mozilla.jss.crypto.CMACAlgorithm;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.crypto.HMACAlgorithm;
import org.mozilla.jss.crypto.JSSMessageDigest;
import org.mozilla.jss.crypto.SecretKeyFacade;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenRuntimeException;
import org.mozilla.jss.crypto.TokenSupplierManager;

public class JSSMacSpi extends javax.crypto.MacSpi {

    private JSSMessageDigest digest=null;
    private DigestAlgorithm alg;

    protected JSSMacSpi(DigestAlgorithm alg) {
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
        SymmetricKey real_key;
        if (key instanceof SecretKeyFacade) {
            SecretKeyFacade facade = (SecretKeyFacade)key;
            real_key = facade.key;
        } else if (key instanceof SymmetricKey) {
            real_key = (SymmetricKey)key;
        } else {
            throw new InvalidKeyException("Must use a key created by JSS! Try exporting the key data and importing it via SecretKeyFactory.");
        }

        digest.initHMAC(real_key);
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

    public static class CmacAES extends JSSMacSpi {
        public CmacAES() {
            super(CMACAlgorithm.AES);
        }
    }
}
