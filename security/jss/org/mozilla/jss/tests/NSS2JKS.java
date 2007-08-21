/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape Security Services for Java.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 2001
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

/**
* Convert nss keystore to java keystore
*/

package org.mozilla.jss.tests;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;

import sun.security.pkcs11.SunPKCS11;


public class NSS2JKS {
    public static void main(String args[]) throws Exception {
        if (args.length != 4) {
            System.out.println("java NSS2JKS <ksloc> <kspwd> <pkcs11.cfg> <pk11pwd>");
            System.exit(1);
        }

        String ksloc = args[0];
        char[] kspwd = args[1].toCharArray();
        String pkcs11cfg = args[2];
        char[] pk11pwd = args[3].toCharArray();
       
        BufferedInputStream bin = null;
        try {
            loadNSSLibrary();
            Provider p = new SunPKCS11(pkcs11cfg);
            Security.addProvider(p);
            KeyStore fromKS = KeyStore.getInstance("PKCS11");
            fromKS.load(null, pk11pwd);

            KeyStore toKS = KeyStore.getInstance("JKS");
            bin = new BufferedInputStream(new FileInputStream(ksloc));
            toKS.load(bin, kspwd);
            

 	    Enumeration e = fromKS.aliases();
            while (e.hasMoreElements()) {
                String alias = (String)e.nextElement();
                System.out.println("Processing alias: " + alias);
                if (fromKS.isKeyEntry(alias)) {
                    Key key = fromKS.getKey(alias, kspwd);
                    Certificate[] chain = fromKS.getCertificateChain(alias);
                    for (int i = 0; i < pk11pwd.length; i++) 
                        System.out.print(pk11pwd[i]);
                    System.out.print("\n");
                    System.out.print(chain.length + "\n");
                    
                    System.out.print(key.toString() + "\n");

                    
                //if (chain != null && key != null)
                    //toKS.setKeyEntry(alias, key, pk11pwd, chain);
                } else {
                    Certificate cert = fromKS.getCertificate(alias);
                    toKS.setCertificateEntry(alias, cert);
                }
            }
            //BufferedOutputStream out = new BufferedOutputStream(ksloc);
            //toKS.store(out, kspwd);
        } finally {
            if (bin != null) {
                bin.close();
            }
        }
    }

    private static void loadNSSLibrary() {
        if (File.separatorChar == '/') {
            //System.loadLibrary("jss4");
            System.loadLibrary("nspr4");
            System.loadLibrary("plc4");
            System.loadLibrary("plds4");
        } else {
            // Window env
            System.loadLibrary("libnspr4");
            System.loadLibrary("libplc4");
            System.loadLibrary("libplds4");
        }
    }
}