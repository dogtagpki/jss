
/*
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * The Original Code is the Netscape Security Services for Java.
 *
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are
 * Copyright (C) 2001 Netscape Communications Corporation.  All
 * Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable
 * instead of those above.  If you wish to allow use of your
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 */

package org.mozilla.jss.tests;

/*
 * AddCert.java will add and ASCII or DER formatted Cert
 *
 */
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkcs11.*;
import org.mozilla.jss.pkix.cert.*;
import java.io.*;
import java.security.cert.*;


public class AddCert {

    public static void main(String args[]) {
        try {
            if ( args.length < 2 ) {
                System.out.print("Usage: addCert <dbdir> <certfile>");
                System.out.println("<nickname>");
                System.out.print("If no nickname is specified we assume the");
                System.out.println("cert is a CA cert");
                return;
            }
            String dbdir = args[0];
            String certfile = args[1];
            String nickname = null;

            if (args.length == 3) {
                nickname = args[2];
            }

            CryptoManager.initialize(dbdir);
            CryptoManager cm = CryptoManager.getInstance();

            //read in the cert and convert to der
            FileInputStream fis = new FileInputStream(certfile);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            java.security.cert.Certificate jcert =
            cf.generateCertificate(fis);
            byte[] dercert = jcert.getEncoded();
            //convert to JSS certificate
            BufferedInputStream bis = new BufferedInputStream(new
                                    ByteArrayInputStream(dercert));
            org.mozilla.jss.pkix.cert.Certificate cert =
            (org.mozilla.jss.pkix.cert.Certificate)
            org.mozilla.jss.pkix.cert.Certificate.getTemplate().decode(bis);
            
            //Add Cert
            if (nickname == null)
                cm.importCACertPackage(ASN1Util.encode(cert));
            else
                cm.importCertPackage(ASN1Util.encode(cert),nickname);

        } catch ( Exception e ) {
            e.printStackTrace();
        }

    }

}

