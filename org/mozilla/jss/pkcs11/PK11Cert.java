/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import java.util.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;

import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.util.Assert;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class PK11Cert
       extends java.security.cert.X509Certificate
       implements org.mozilla.jss.crypto.X509Certificate
{
    public static Logger logger = LoggerFactory.getLogger(PK11Cert.class);

    // Internal X509CertImpl to handle java.security.cert.X509Certificate
    // methods.
    private X509CertImpl x509 = null;

    @Override
    public native byte[] getEncoded() throws CertificateEncodingException;

    //public native byte[] getUniqueID();

    public String getNickname() {
        return nickname;
    }

    /**
     * A class that implements Principal with a String.
     */
    protected static class StringPrincipal implements Principal {
        public StringPrincipal(String str) {
            this.str = str;
        }

        public boolean
        equals(Object other) {
            if( ! (other instanceof StringPrincipal) ) {
                return false;
            }
            return getName().equals( ((StringPrincipal)other).getName() );
        }

        public String getName() {
            return str;
        }
        public int hashCode() {
            return str.hashCode();
        }

        public String toString() {
            return str;
        }
        protected String str;
    }

    public Principal
    getSubjectDN() {
        return new StringPrincipal( getSubjectDNString() );
    }

    public Principal
    getIssuerDN() {
        return new StringPrincipal( getIssuerDNString() );
    }

    public BigInteger
    getSerialNumber() {
        return new BigInteger( getSerialNumberByteArray() );
    }
    protected native byte[] getSerialNumberByteArray();

    protected native String getSubjectDNString();

    protected native String getIssuerDNString();

	public native java.security.PublicKey getPublicKey();

	public native int getVersion();

    /* Begin methods necessary for java.security.cert.X509Certificate */
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

    ///////////////////////////////////////////////////////////////////////
    // PKCS #11 Cert stuff. Must only be called on certs that have
    // an associated slot.
    ///////////////////////////////////////////////////////////////////////
    protected native byte[] getUniqueID();

    protected native CryptoToken getOwningToken();

    ///////////////////////////////////////////////////////////////////////
    // Trust Management.  Must only be called on certs that live in the
    // internal database.
    ///////////////////////////////////////////////////////////////////////
    /**
     * Sets the trust flags for this cert.
     *
     * @param type SSL, EMAIL, or OBJECT_SIGNING.
     * @param trust The trust flags for this type of trust.
     */
    protected native void setTrust(int type, int trust);

    /**
     * Gets the trust flags for this cert.
     *
     * @param type SSL, EMAIL, or OBJECT_SIGNING.
     * @return The trust flags for this type of trust.
     */
    protected native int getTrust(int type);

	/////////////////////////////////////////////////////////////
	// Construction
	/////////////////////////////////////////////////////////////
	//PK11Cert(CertProxy proxy) {
    //    Assert._assert(proxy!=null);
	//	this.certProxy = proxy;
	//}

	PK11Cert(byte[] certPtr, byte[] slotPtr, String nickname) {
        Assert._assert(certPtr!=null);
        Assert._assert(slotPtr!=null);
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

    protected native void releaseNativeResources();
}
