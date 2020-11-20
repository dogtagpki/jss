/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.provider.javax.crypto;

import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

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
    private String keyName;

    protected JSSMacSpi(DigestAlgorithm alg, String keyName) {
      try {
        this.alg = alg;
        this.keyName = keyName;
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
        SymmetricKey real_key = null;
        if (key instanceof SecretKeyFacade) {
            SecretKeyFacade facade = (SecretKeyFacade)key;
            real_key = facade.key;
        } else if (key instanceof SymmetricKey) {
            real_key = (SymmetricKey)key;
        } else if (key.getEncoded() != null) {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(keyName, "Mozilla-JSS");
            SecretKeySpec spec = new SecretKeySpec(key.getEncoded(), keyName);
            Key manufactured = factory.generateSecret(spec);
            if (manufactured instanceof SecretKeyFacade) {
                SecretKeyFacade facade = (SecretKeyFacade)manufactured;
                real_key = facade.key;
            } else if (manufactured instanceof SymmetricKey) {
                real_key = (SymmetricKey)manufactured;
            } else {
                String msg = "Internal error while converting key: ";
                msg += "SecretKeyFactory gave unrecognized manufactured ";
                msg += "key type: " + manufactured.getClass().getName();
                throw new InvalidKeyException(msg);
            }
        } else {
            String msg = "Must use a key created by JSS; got ";
            msg += key.getClass().getName() + ". ";
            msg += "Try exporting the key data and importing it via ";
            msg += "SecretKeyFactory or use an exportable key type ";
            msg += "so JSS can do this automatically.";
            throw new InvalidKeyException(msg);
        }

        digest.initHMAC(real_key);
      } catch (DigestException de) {
        throw new InvalidKeyException("DigestException: " + de.getMessage(), de);
      } catch (NoSuchAlgorithmException nsae) {
        throw new InvalidKeyException("NoSuchAlgorithmException when importing key to JSS: " + nsae.getMessage(), nsae);
      } catch (NoSuchProviderException nspe) {
        throw new InvalidKeyException("NoSuchProviderException when importing key to JSS: " + nspe.getMessage(), nspe);
      } catch (InvalidKeySpecException ikse) {
        throw new InvalidKeyException("InvalidKeySpecException when importing key to JSS: " + ikse.getMessage(), ikse);
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
            super(HMACAlgorithm.SHA1, "HmacSHA1");
        }
    }

    public static class HmacSHA256 extends JSSMacSpi {
        public HmacSHA256() {
            super(HMACAlgorithm.SHA256, "HmacSHA256");
        }
    }

    public static class HmacSHA384 extends JSSMacSpi {
        public HmacSHA384() {
            super(HMACAlgorithm.SHA384, "HmacSHA384");
        }
    }

    public static class HmacSHA512 extends JSSMacSpi {
        public HmacSHA512() {
            super(HMACAlgorithm.SHA512, "HmacSHA512");
        }
    }

    public static class CmacAES extends JSSMacSpi {
        public CmacAES() {
            super(CMACAlgorithm.AES, "AES");
        }
    }
}
