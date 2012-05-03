/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/*
 * SSLSecurityStatus.java
 * 
 * 
 */

package org.mozilla.jss.ssl;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.Vector;
import java.net.*;

/**
 * Implement this if you want to specify dynamically which certificate
 * should be presented for client authentication.
 */
public interface SSLClientCertificateSelectionCallback {

	/**
	 *  This method will be called from the native callback code
	 *  when a certificate is requested. You must return a String
	 *  which is the nickname of the certificate you wish to present.
	 *
	 *  @param nicknames A Vector of Strings. These strings are
     *    an aid to the user to select the correct nickname. This list is
	 *    made from the list of all certs which are valid, match the
	 *    CA's trusted by the server, and which you have the private
	 *    key of. If nicknames.length is 0, you should present an
	 *    error to the user saying 'you do not have any unexpired
	 *    certificates'.
	 *  @return You must return the nickname of the certificate you
	 *    wish to use. You can return null if you do not wish to send
     *    a certificate.
	 */
	public String select(Vector nicknames);

} 


