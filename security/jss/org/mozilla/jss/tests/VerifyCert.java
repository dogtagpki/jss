/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.util.*;
import org.mozilla.jss.pkix.cert.*;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Iterator;

/**
* Verify Certificate test.
*/
public class VerifyCert {

    public void showCert( String certFile) {
        //Read the cert
        try {

            BufferedInputStream bis = new BufferedInputStream(
                                new FileInputStream(certFile) );

            Certificate cert = (Certificate)
                 Certificate.getTemplate().decode(bis);

            //output the cert
            CertificateInfo info = cert.getInfo();
            info.print(System.out);

//verify the signature of the cert only
//        cert.verify();
        } catch (Exception ex) {
            ex.printStackTrace();
            System.exit(1);
        }
    }

    private void usage() {

        System.out.println("Usage: java org.mozilla.jss.tests.VerifyCert");
        System.out.println("\noptions:\n\n<dbdir> <passwd> " +
                           "<nicknameOfCertinDB> <OCSPResponderURL> " +
                           "<OCSPCertNickname>\n");
        System.out.println("<dbdir> <passwd> " +
                           "<DerEncodeCertFile> <OCSPResponderURL> " +
                           "<OCSPCertNickname>\n");
        System.out.println("Note: <OCSPResponderURL> and " +
                           "<OCSPCertNickname> are optional.\n But if used, " +
                           "both Url/nickname must be specified.");
    }

    public static void main(String args[]) {

        try {
            VerifyCert vc = new VerifyCert();
            if ( args.length < 3 ) {
                vc.usage();
                return;
            }
            String dbdir = args[0];
            String password = args[1];
            String name = args[2];
            String ResponderURL = null;
            String ResponderNickname = null;
            //if OCSPResponderURL than must have OCSPCertificateNickname
            if (args.length == 4 || args.length > 5)   vc.usage();
            else if (args.length == 5) {
                ResponderURL= args[3];
                ResponderNickname = args[4];
            }

            //initialize JSS
            CryptoManager.InitializationValues vals = new
                                CryptoManager.InitializationValues(dbdir);

            //enable PKIX verify rather than the old NSS cert library, 
            //to verify certificates. 
            vals.PKIXVerify = true;
            
            // as a JSS test set the initialize for cooperate to true 
            // One would set this to true if one configured NSS with 
            // to use other PKCS11 modules.
            vals.cooperate = true;

            //      configure OCSP
            vals.ocspCheckingEnabled = true;
            if (ResponderURL != null && ResponderNickname != null) {
                vals.ocspResponderCertNickname = ResponderNickname;
                vals.ocspResponderURL = ResponderURL;
            }
            CryptoManager.initialize(vals);
            CryptoManager cm = CryptoManager.getInstance();
            PasswordCallback pwd = new Password(password.toCharArray());
            cm.setPasswordCallback(pwd);

            try {
                FileInputStream fin = new FileInputStream(name);
                byte[] pkg = new byte[fin.available()];
                fin.read(pkg);
                //display the cert
                vc.showCert(name);
                //validate the cert
                vc.validateDerCert(pkg, cm);
            } catch (java.io.FileNotFoundException e) {
                //assume name is a nickname of cert in the db
                vc.validateCertInDB(name, cm);
            }

        } catch ( Exception e ) {
            e.printStackTrace();
            System.exit(1);
        }
    }


    public void validateDerCert(byte[] pkg, CryptoManager cm){
        ArrayList usageList = new ArrayList();
        try {

            Iterator list = CryptoManager.CertUsage.getCertUsages();
            CryptoManager.CertUsage certUsage;
            while(list.hasNext()) {
                certUsage = (CryptoManager.CertUsage) list.next();
                if (
       !certUsage.equals(CryptoManager.CertUsage.UserCertImport) &&
       !certUsage.equals(CryptoManager.CertUsage.ProtectedObjectSigner) &&
       !certUsage.equals(CryptoManager.CertUsage.AnyCA) )
                    {
                        if (cm.isCertValid(pkg, true,
                            certUsage) == true) {
                            usageList.add(certUsage.toString());
                        }
                    }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (usageList.isEmpty()) {
            System.out.println("The certificate is not valid.");
        } else {
        System.out.println("The certificate is valid for " +
                           "the following usages:\n");
            Iterator iterateUsage = usageList.iterator();
            while (iterateUsage.hasNext()) {
                System.out.println("                       " 
                + iterateUsage.next());
            }
        }
    }

    public void validateCertInDB(String nickname, CryptoManager cm){
        ArrayList usageList = new ArrayList();

        try {

            Iterator list = CryptoManager.CertUsage.getCertUsages();
            CryptoManager.CertUsage certUsage;
            while(list.hasNext()) {
                certUsage = (CryptoManager.CertUsage) list.next();
                if (
       !certUsage.equals(CryptoManager.CertUsage.UserCertImport) &&
       !certUsage.equals(CryptoManager.CertUsage.ProtectedObjectSigner) &&
       !certUsage.equals(CryptoManager.CertUsage.AnyCA) )
                    {
                        if (cm.isCertValid(nickname, true,
                            certUsage) == true) {
                            usageList.add(certUsage.toString());
                        }
                    }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }


        if (usageList.isEmpty()) {
            System.out.println("The certificate is not valid.");
        } else {
            System.out.println("The certificate is valid for the " +
                               "following usages:\n");
            Iterator iterateUsage = usageList.iterator();
            while (iterateUsage.hasNext()) {
                System.out.println("                       " +
                                          iterateUsage.next());
            }
        }
    }

}
