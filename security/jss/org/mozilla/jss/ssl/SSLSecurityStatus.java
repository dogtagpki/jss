/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.*;
import org.mozilla.jss.crypto.X509Certificate;

/**
 * This class represents the known state of an SSL connection: what cipher
 * is being used, how secure it is, and who's on the other end.
 */
public class SSLSecurityStatus {
    int status;
    String cipher;
    int sessionKeySize;
    int sessionSecretSize;
    String issuer;
    String subject;
    String serialNumber;
    X509Certificate certificate; // Certificate may be null if client does not present certificate

    final public int STATUS_NOOPT    = -1;
    final public int STATUS_OFF      = 0;
    final public int STATUS_ON_HIGH  = 1;
    final public int STATUS_ON_LOW   = 2;
    /**
     * @deprecated As of NSS 3.11, FORTEZZA is no longer supported.
     * STATUS_FORTEZZA is a placeholder for backward compatibility.
     */
    final public int STATUS_FORTEZZA = 3;

	/**
	 * This constructor is called from the native SSL code
	 * It's not necessary for you to call this.
 	 */
    public SSLSecurityStatus(int status, String cipher,
			     int sessionKeySize, int sessionSecretSize,
			     String issuer, String subject,
			     String serialNumber, X509Certificate certificate) {
	String noCert = "no certificate";
	this.status = status;
	this.cipher = cipher;
	this.sessionKeySize = sessionKeySize;
	this.sessionSecretSize = sessionSecretSize;
        this.certificate = certificate;
	
	if(noCert.equals(issuer))
	    this.issuer = null;
	else
	    this.issuer = issuer;
	    
	if(noCert.equals(subject))
	   this.subject = null;
	else
	   this.subject = subject;
	   
	this.serialNumber = serialNumber;
    }

    /**
     * Query if security is enabled on this socket.
     */
    public boolean isSecurityOn() {
	return status > 0;
    }

    /**
     * Get exact security status of socket.
     */
    public int getSecurityStatus() {
	return status;
    }

    /**
     * Query which cipher is being used in this session.
     */
    public String getCipher() {
	return cipher;
    }

    /**
     * Query how many bits long the session key is.  More bits are better.
     */
    public int getSessionKeySize() {
	return sessionKeySize;
    }

    /**
     * To satisfy export restrictions, some of the session key may
     * be revealed. This function tells you how many bits are
     * actually secret.
     */
    public int getSessionSecretSize() {
	return sessionSecretSize;
    }

    /**
     * Get the distinguished name of the remote certificate's issuer
     */
    public String getRemoteIssuer() {
	return issuer;
    }

    /**
     * Get the distinguished name of the subject of the remote certificate
     */
    public String getRemoteSubject() {
	return subject;
    }

    /**
     * Get the serial number of the remote certificate
     */
    public String getSerialNumber() {
	return serialNumber;
    }

    /**
      * Retrieve certificate presented by the other other end
      * of the socket <p>Not Supported in NSS 2.0 Beta release.
      * <p> Can be null if peer did not present a certificate.
      */
    public X509Certificate getPeerCertificate() {
        return certificate;
    }

    /**
     * Get a pretty string to show to a user, summarizing the contents
     * of this object
     */
    public String toString() {
	String statusString;
	switch(status) {
	case STATUS_NOOPT:
	    statusString = "NOOPT";
	    break;
	case STATUS_OFF:
	    statusString = "OFF";
	    break;
	case STATUS_ON_HIGH:
	    statusString = "ON HIGH";
	    break;
	case STATUS_ON_LOW:
	    statusString = "ON LOW";
	    break;
	case STATUS_FORTEZZA:
	    statusString = "FORTEZZA";
	    break;
	default:
	    statusString = "unknown";
	    break;

	}

	return "Status: " + statusString + "\n" +
	    "Cipher: " + cipher + "\n" +
	    "Session key size: " + sessionKeySize + "\n" +
	    "Session secret size: " + sessionSecretSize + "\n" +
	    "Issuer: " + issuer + "\n" +
	    "Subject: " + subject + "\n" +
	    "Serial number: " + serialNumber + "\n";
    }
}
