/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.*;
import java.util.*;
import org.mozilla.jss.crypto.*;

/**
 * This is a test implementation of the certificate approval callback which
 * gets invoked when the server presents a certificate which is not
 * trusted by the client
 */
public class TestCertApprovalCallback
   implements SSLCertificateApprovalCallback {

	public boolean approve(
					org.mozilla.jss.crypto.X509Certificate servercert,
					SSLCertificateApprovalCallback.ValidityStatus status) {

		SSLCertificateApprovalCallback.ValidityItem item;

		System.out.println("in TestCertApprovalCallback.approve()");

		/* dump out server cert details */

		System.out.println("Peer cert details: "+
				"\n     subject: "+servercert.getSubjectDN().toString()+
				"\n     issuer:  "+servercert.getIssuerDN().toString()+
				"\n     serial:  "+servercert.getSerialNumber().toString()
				);

		/* iterate through all the problems */

		boolean trust_the_server_cert=false;

		Enumeration errors = status.getReasons();
		int i=0;
		while (errors.hasMoreElements()) {
			i++;
			item = (SSLCertificateApprovalCallback.ValidityItem) errors.nextElement();
			System.out.println("item "+i+
					" reason="+item.getReason()+
					" depth="+item.getDepth());
			org.mozilla.jss.crypto.X509Certificate cert = item.getCert();
			if (item.getReason() == 
				SSLCertificateApprovalCallback.ValidityStatus.UNTRUSTED_ISSUER) {
				trust_the_server_cert = true;
			}
				
			System.out.println(" cert details: "+
				"\n     subject: "+cert.getSubjectDN().toString()+
				"\n     issuer:  "+cert.getIssuerDN().toString()+
				"\n     serial:  "+cert.getSerialNumber().toString()
				);
		}


		if (trust_the_server_cert) {
			System.out.println("importing certificate.");
			try {
				InternalCertificate newcert = 
						org.mozilla.jss.CryptoManager.getInstance().
							importCertToPerm(servercert,"testnick");
				newcert.setSSLTrust(InternalCertificate.TRUSTED_PEER |
									InternalCertificate.VALID_PEER);
			} catch (Exception e) {
				System.out.println("thrown exception: "+e);
			}
		}

		
		/* allow the connection to continue.
			returning false here would abort the connection */
		return true;    
	}

}

