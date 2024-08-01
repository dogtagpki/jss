/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Arrays;
import java.util.Date;
import java.util.Set;

import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class PK11Cert
        extends X509Certificate
        implements AutoCloseable
{
    public static Logger logger = LoggerFactory.getLogger(PK11Cert.class);

    // Internal X509CertImpl to handle java.security.cert.X509Certificate
    // methods.
    private X509CertImpl x509 = null;

    @Override
    public native byte[] getEncoded() throws CertificateEncodingException;

    //public native byte[] getUniqueID();

    @Override
    public String getNickname() {
        return nickname;
    }

    @Override
    public int hashCode() {
        try {
            return Arrays.hashCode(getEncoded());
        } catch (CertificateEncodingException cee) {
            throw new RuntimeException(cee.getMessage(), cee);
        }
    }

    @Override
    public boolean equals(Object other) {
        if (other == null || !(other instanceof PK11Cert)) {
            return false;
        }

        PK11Cert p_other = (PK11Cert) other;
        try {
            return Arrays.equals(getEncoded(), p_other.getEncoded());
        } catch (CertificateEncodingException cee) {
            throw new RuntimeException(cee.getMessage(), cee);
        }
    }

    /**
     * A class that implements Principal with a String.
     */
    protected static class StringPrincipal implements Principal {
        public StringPrincipal(String str) {
            this.str = str;
        }

        @Override
        public boolean
        equals(Object other) {
            if( ! (other instanceof StringPrincipal) ) {
                return false;
            }
            return getName().equals( ((StringPrincipal)other).getName() );
        }

        @Override
        public String getName() {
            return str;
        }
        @Override
        public int hashCode() {
            return str.hashCode();
        }

        @Override
        public String toString() {
            return str;
        }
        protected String str;
    }

    @Override
    public Principal
    getSubjectDN() {
        return new StringPrincipal( getSubjectDNString() );
    }

    @Override
    public Principal
    getIssuerDN() {
        return new StringPrincipal( getIssuerDNString() );
    }

    @Override
    public BigInteger
    getSerialNumber() {
        return new BigInteger( getSerialNumberByteArray() );
    }
    protected native byte[] getSerialNumberByteArray();

    protected native String getSubjectDNString();

    protected native String getIssuerDNString();

	@Override
    public native java.security.PublicKey getPublicKey();

	@Override
    public native int getVersion();

    /* Begin methods necessary for java.security.cert.X509Certificate */
    @Override
    public int getBasicConstraints() {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            return x509.getBasicConstraints();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public boolean[] getKeyUsage() {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            return x509.getKeyUsage();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public boolean[] getSubjectUniqueID() {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            return x509.getSubjectUniqueID();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public boolean[] getIssuerUniqueID() {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            return x509.getIssuerUniqueID();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public byte[] getSigAlgParams() {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            return x509.getSigAlgParams();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public String getSigAlgName() {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            return x509.getSigAlgName();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public String getSigAlgOID() {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            return x509.getSigAlgOID();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public byte[] getSignature() {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            return x509.getSignature();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            return x509.getTBSCertificate();
        } catch (CertificateEncodingException cee) {
            throw cee;
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public Date getNotAfter() {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            return x509.getNotAfter();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public Date getNotBefore() {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            return x509.getNotBefore();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public void checkValidity()
            throws CertificateExpiredException, CertificateNotYetValidException
    {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            x509.checkValidity();
        } catch (CertificateExpiredException cee) {
            throw cee;
        } catch (CertificateNotYetValidException cnyve) {
            throw cnyve;
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public void checkValidity(Date date)
            throws CertificateExpiredException, CertificateNotYetValidException
    {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            x509.checkValidity(date);
        } catch (CertificateExpiredException cee) {
            throw cee;
        } catch (CertificateNotYetValidException cnyve) {
            throw cnyve;
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public String toString() {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            return x509.toString();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public void verify(PublicKey key)
            throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException
    {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            x509.verify(key);
        } catch (NoSuchAlgorithmException nsae) {
            throw nsae;
        } catch (InvalidKeyException ike) {
            throw ike;
        } catch (NoSuchProviderException nspe) {
            throw nspe;
        } catch (SignatureException se) {
            throw se;
        } catch (CertificateException ce) {
            throw ce;
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public void verify(PublicKey key, String sigProvider)
            throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException
    {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            x509.verify(key, sigProvider);
        } catch (NoSuchAlgorithmException nsae) {
            throw nsae;
        } catch (InvalidKeyException ike) {
            throw ike;
        } catch (NoSuchProviderException nspe) {
            throw nspe;
        } catch (SignatureException se) {
            throw se;
        } catch (CertificateException ce) {
            throw ce;
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public byte[] getExtensionValue(String oid) {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            return x509.getExtensionValue(oid);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public Set<String> getCriticalExtensionOIDs() {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            return x509.getCriticalExtensionOIDs();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            return x509.getNonCriticalExtensionOIDs();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
        try {
            if (x509 == null) {
                x509 = new X509CertImpl(getEncoded());
            }

            return x509.hasUnsupportedCriticalExtension();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public void finalize() throws Throwable {
        close();
    }

    @Override
    public void close() throws Exception {
        if (certProxy != null) {
            try {
                certProxy.close();
            } finally {
                certProxy = null;
            }
        }

        // This object also contains a token proxy; these are reference
        // counted objects and long-lived; freeing them is of little benefit
        // as they'll persist as long as CryptoManager holds a copy of all
        // known tokens. However, we still need to attempt to release our
        // reference to them, otherwise the JVM will persist its reference
        // to them.
        if (tokenProxy != null) {
            try {
                tokenProxy.close();
            } finally {
                tokenProxy = null;
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////
    // PKCS #11 Cert stuff. Must only be called on certs that have
    // an associated slot.
    ///////////////////////////////////////////////////////////////////////
    public native byte[] getUniqueID();

    public native CryptoToken getOwningToken();

    ///////////////////////////////////////////////////////////////////////
    // Trust Management.  Must only be called on certs that live in the
    // internal database.
    ///////////////////////////////////////////////////////////////////////

    @Override
    public native void setTrust(int type, int trust);

    @Override
    public native int getTrust(int type);

	/////////////////////////////////////////////////////////////
	// Construction
	/////////////////////////////////////////////////////////////
	//PK11Cert(CertProxy proxy) {
    //    assert(proxy!=null);
	//	this.certProxy = proxy;
	//}

	PK11Cert(byte[] certPtr, byte[] slotPtr, String nickname) {
        assert(certPtr!=null);
        assert(slotPtr!=null);
		certProxy = new CertProxy(certPtr);
		tokenProxy = new TokenProxy(slotPtr);
		this.nickname = nickname;
	}

	/////////////////////////////////////////////////////////////
	// private data
	/////////////////////////////////////////////////////////////
	protected CertProxy certProxy;

	protected TokenProxy tokenProxy;

	protected String nickname;
}

class CertProxy extends org.mozilla.jss.util.NativeProxy {

    public static Logger logger = LoggerFactory.getLogger(CertProxy.class);

    public CertProxy(byte[] pointer) {
        super(pointer);
    }

    @Override
    protected native void releaseNativeResources();
}
