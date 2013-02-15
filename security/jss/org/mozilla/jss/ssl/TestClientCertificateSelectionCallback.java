/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.*;
import java.util.*;

/**
 * This interface is what you should implement if you want to
 * be able to decide whether or not you want to approve the peer's cert,
 * instead of having NSS do that.
 */
public class TestClientCertificateSelectionCallback
  	  implements SSLClientCertificateSelectionCallback {

	/**
	 *  this method will be called form the native callback code
	 *  when a certificate is requested. You must return a String
	 *  which is the nickname of the certificate you wish to present.
	 *
	 *  @param nicknames A Vector of Strings. These strings are an
	 *    aid to the user to select the correct nickname. This list is
	 *    made from the list of all certs which are valid, match the
	 *    CA's trusted by the server, and which you have the private
	 *    key of. If nicknames.length is 0, you should present an
	 *    error to the user saying 'you do not have any unexpired
	 *    certificates'.
	 *  @return You must return the nickname of the certificate you
	 *    wish to use. You can return null if you do not wish to send
     *    a certificate.
	 */
	public String select(Vector nicknames) {
		Enumeration e = nicknames.elements();
		String s="",first=null;

		System.out.println("in TestClientCertificateSelectionCallback.select()  "+s);
		while (e.hasMoreElements()) {
			s = (String)e.nextElement();
			if (first == null) {
				first = s;
			}
			System.out.println("  "+s);
		}
		return first;

	}

} 


