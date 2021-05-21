/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.provider.java.security;

import java.security.DigestException;
import java.security.MessageDigestSpi;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.crypto.JSSMessageDigest;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.TokenRuntimeException;
import org.mozilla.jss.crypto.TokenSupplierManager;

public abstract class JSSMessageDigestSpi extends MessageDigestSpi {

    private JSSMessageDigest digest;

    protected JSSMessageDigestSpi(DigestAlgorithm alg) {
        super();
        CryptoToken token =
            TokenSupplierManager.getTokenSupplier().getThreadToken();
        try {
            CryptoManager cm = CryptoManager.getInstance();
            CryptoToken ikst = cm.getInternalKeyStorageToken();
            if( token.equals(ikst) ) {
                // InternalKeyStorageToken doesn't support message digesting
                token = cm.getInternalCryptoToken();
            }
            try {
              digest = token.getDigestContext(alg);
            } catch(java.security.NoSuchAlgorithmException e) {
                throw new UnsupportedOperationException(
                    "Token '" + token.getName() + "' does not support " +
                    "algorithm " + alg.toString());
            }
        } catch(TokenException e) {
            throw new TokenRuntimeException(e.getMessage());
        } catch(DigestException e1) {
            throw new TokenRuntimeException(e1.getMessage());
        } catch(NotInitializedException e2) {
            throw new TokenRuntimeException(e2.getMessage());
        }
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

    @Override
    public byte[] engineDigest() {
      try {
        return digest.digest();
      } catch(java.security.DigestException de) {
        throw new TokenRuntimeException(de.getMessage());
      }
    }

    @Override
    public int engineDigest(byte[] buf, int offset, int len)
        throws DigestException
    {
        return digest.digest(buf, offset, len);
    }

    @Override
    public int engineGetDigestLength() {
        return digest.getOutputSize();
    }

    @Override
    public void engineReset() {
      try {
        digest.reset();
      } catch(java.security.DigestException de) {
        throw new TokenRuntimeException(de.getMessage());
      }
    }

    @Override
    public void engineUpdate(byte input) {
      try {
        digest.update(input);
      } catch(java.security.DigestException de) {
        throw new TokenRuntimeException(de.getMessage());
      }
    }

    @Override
    public void engineUpdate(byte[] input, int offset, int len) {
      try {
        digest.update(input,offset,len);
      } catch(java.security.DigestException de) {
        throw new TokenRuntimeException(de.getMessage());
      }
    }

    public static class SHA1 extends JSSMessageDigestSpi {
        public SHA1() {
            super( DigestAlgorithm.SHA1 );
        }
    }
    public static class SHA256 extends JSSMessageDigestSpi {
        public SHA256() {
            super( DigestAlgorithm.SHA256 );
        }
    }
    public static class SHA384 extends JSSMessageDigestSpi {
        public SHA384() {
            super( DigestAlgorithm.SHA384 );
        }
    }
    public static class SHA512 extends JSSMessageDigestSpi {
        public SHA512() {
            super( DigestAlgorithm.SHA512 );
        }
    }
    public static class MD5 extends JSSMessageDigestSpi {
        public MD5() {
            super( DigestAlgorithm.MD5 );
        }
    }
    public static class MD2 extends JSSMessageDigestSpi {
        public MD2() {
            super( DigestAlgorithm.MD2 );
        }
    }
}
