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
 * ModifyTrust.java
 *
 */

import org.mozilla.jss.crypto.*;
import org.mozilla.jss.*;
import org.mozilla.jss.pkcs11.*;
import org.mozilla.jss.pkix.cert.*;

import java.io.*;
import org.mozilla.jss.asn1.*;
import java.util.StringTokenizer;

public class ModifyTrust {
    public static final String VALID_PEER          = "p";
    public static final String TRUSTED_PEER        = "P"; // CERTDB_TRUSTED
    public static final String VALID_CA            = "c";
    public static final String TRUSTED_CA          = "C";
    public static final String USER                = "u";
    public static final String TRUSTED_CLIENT_CA   = "T";
    public static final String NO_TRUST            = "N";

    /**
     *  Get the Trust String of the specified certificate.
     */
    public static String getTrust(
               org.mozilla.jss.crypto.X509Certificate cert){
        try {
            InternalCertificate ic = (InternalCertificate) cert;
            return(getTrustStr(ic.getSSLTrust(), true) + "," +
                   getTrustStr(ic.getEmailTrust()) + "," +
                   getTrustStr(ic.getObjectSigningTrust()));
        } catch ( Exception ex ) {
            return "";
        }
    }
    /**
       *  Get the Certificate Trust value based on the Trust type.
       */
    public static int getTrust(String trusttype){
        char[] trusttokens = new char[trusttype.length()];
        trusttype.getChars(0, trusttype.length(), trusttokens, 0);
        int trustval = 0;
        String truststr = "";

        for ( int i=0; i < trusttokens.length; i++ ) {
            truststr = new Character(trusttokens[i]).toString();
            int trust;
            if ( truststr.equals(ModifyTrust.VALID_PEER) ) {
                trust = PK11InternalCert.VALID_PEER;
            } else if ( truststr.equals(ModifyTrust.TRUSTED_PEER) ) {
                trust = PK11InternalCert.TRUSTED_PEER;
            } else if ( truststr.equals(ModifyTrust.VALID_CA) ) {
                trust = PK11InternalCert.VALID_CA;
            } else if ( truststr.equals(ModifyTrust.TRUSTED_CLIENT_CA) ) {
                trust = PK11InternalCert.TRUSTED_CLIENT_CA;
            } else if ( truststr.equals(ModifyTrust.TRUSTED_CA) ) {
                trust = PK11InternalCert.TRUSTED_CA;
            } else if ( truststr.equals(ModifyTrust.USER) ) {
                trust = PK11InternalCert.USER;
            } else if ( truststr.equals(ModifyTrust.NO_TRUST) ) {
                trust = 0;
            } else {
                continue;
            }
            if ( i == 0 ) {
                trustval = trust;
            } else {
                trustval = trustval | trust;
            }

        }
        return trustval;
    }

    /**
     *  Get the Trust String based on the trust value..
     */

    public static String getTrustStr(int trust){
        return getTrustStr(trust, false);
    }

    /**
     *  Get the Trust String based on the trust value.
     */
    public static String getTrustStr(int trust, boolean isSSLTrust){
        boolean isTrustedCA = false;
        boolean isTrustedClientCA = false;
        boolean isTrustedPeer = false;

        String truststr = "";
        if ( (PK11InternalCert.TRUSTED_CA & trust) ==
                      PK11InternalCert.TRUSTED_CA ) {
            truststr = truststr + ModifyTrust.TRUSTED_CA;
            isTrustedCA = true;
        }
        if ( (PK11InternalCert.TRUSTED_CLIENT_CA & trust) ==
             PK11InternalCert.TRUSTED_CLIENT_CA ) {
            truststr = truststr + ModifyTrust.TRUSTED_CLIENT_CA;
            if ( isSSLTrust ) {
                isTrustedClientCA = true;
            }
        }
        if ( (PK11InternalCert.TRUSTED_PEER & trust) ==
                       PK11InternalCert.TRUSTED_PEER ) {
            truststr = truststr + ModifyTrust.TRUSTED_PEER;
            isTrustedPeer = false;
        }
        if ( (PK11InternalCert.USER & trust) ==  PK11InternalCert.USER ) {
            truststr = truststr + ModifyTrust.USER;
        }
        if ( (PK11InternalCert.VALID_CA & trust) ==
                      PK11InternalCert.VALID_CA ) {
            if ( !isTrustedCA && !isTrustedClientCA ) {
                truststr = truststr + ModifyTrust.VALID_CA;
            }
        }
        if ( (PK11InternalCert.VALID_PEER & trust) ==
              PK11InternalCert.VALID_PEER ) {
            if ( !isTrustedPeer ) {
                truststr = truststr + ModifyTrust.VALID_PEER;
            }
        }

        return truststr;
    }

    /**
     * Change the Trust attributes of the specified certificate
     */
    public static X509Certificate changeCertificateTrust(X509Certificate cert,
                    String ssl, String email, String objsign) throws Exception
    {
        int ssltrust = getTrust(ssl);
        int emailtrust = getTrust(email);
        int objtrust = getTrust(objsign);
        System.out.println("Trust" + ssl + ssltrust + email + emailtrust +
                           objsign + objtrust);
        try {
            InternalCertificate ic = (InternalCertificate) cert;
            ic.setSSLTrust(ssltrust);
            ic.setEmailTrust(emailtrust);
            ic.setObjectSigningTrust(objtrust);
            return ic;
        } catch ( Exception ex ) {
            return cert;
        }
    }

    public static void main(String args[]) {
        try {
            if ( args.length != 3 ) {
System.out.println("Usage: ModifyTrust <dbdir> <nickname> <TrustFlags>");
System.out.println("Trust flags in form \"C,C,C,\" use N for no trust flag");
System.out.println("as in \"C,N,N\" to get \"C,,\"");
                return;
            }
            String dbdir = args[0];
            String nickname = args[1];
            String attrib = args[2];

            CryptoManager.initialize(dbdir);
            CryptoManager cm = CryptoManager.getInstance();

            StringTokenizer st = new StringTokenizer(attrib, ",");
            if ( st.countTokens() != 3 ) {
                System.out.println("Invalid trust attribute "+attrib+" specified ");
                return;
            }
            System.out.println("Finding Cert");
            org.mozilla.jss.crypto.X509Certificate cert =
            cm.findCertByNickname(nickname);
            System.out.println("Modify trust attributes");
            //changeCertificateTrustt will update the cert in DB not just memory
            //you do not have to call updateCertToPerm
            org.mozilla.jss.crypto.X509Certificate updatedCert =
            ModifyTrust.changeCertificateTrust(cert, st.nextToken().trim(),
                               st.nextToken().trim(), st.nextToken().trim());

        } catch ( Exception e ) {
            e.printStackTrace();
        }

    }

}

