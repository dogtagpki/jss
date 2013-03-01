/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import org.mozilla.jss.crypto.*;
import org.mozilla.jss.util.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.math.BigInteger;

public class PK11Cert implements org.mozilla.jss.crypto.X509Certificate {

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

    public CertProxy(byte[] pointer) {
        super(pointer);
    }

    protected native void releaseNativeResources();

    protected void finalize() throws Throwable {
		Debug.trace(Debug.OBNOXIOUS, "finalizing a certificate");
        super.finalize();
    }
}
