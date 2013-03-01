/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.tests;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.util.Iterator;
import java.util.Set;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.pkix.cert.CertificateInfo;
import org.mozilla.jss.pkix.cert.Extension;

public class ListCerts {
    
    public static void main(String args[]) {
        
        try {
            
            if( args.length != 2 ) {
                System.out.println("Usage: ListCerts <dbdir> <nickname>");
                return;
            }
            String dbdir = args[0];
            String nickname = args[1];
            
            CryptoManager.initialize(dbdir);
            
            CryptoManager cm = CryptoManager.getInstance();
            
            X509Certificate[] certs = cm.findCertsByNickname(nickname);
            System.out.println(certs.length + " certs found with this nickname.");
            for(int i=0; i < certs.length; i++) {
                System.out.println("\nSubject: "+certs[i].getSubjectDN());
                Certificate cert =
                    (Certificate)ASN1Util.decode(Certificate.getTemplate(),
                    certs[i].getEncoded());
                CertificateInfo info = cert.getInfo();
                OBJECT_IDENTIFIER sigalg = info.getSignatureAlgId().getOID();
                System.out.println("Signature oid " +
                    info.getSignatureAlgId().getOID());
                
                SEQUENCE extensions = info.getExtensions();
                for (int j = 0; j < extensions.size(); j++) {
                    Extension ext = (Extension)extensions.elementAt(i);
                    OBJECT_IDENTIFIER oid = ext.getExtnId();
                    OCTET_STRING value = ext.getExtnValue();
                    System.out.println("Extension " + oid.toString());
                    if (ext.getCritical()) {
                        System.out.println("Critical extension: " 
                            + oid.toString());
                    } else {
                        System.out.println("NON Critical extension: " 
                            + oid.toString());
                    }
                }
                System.out.println("Convert to JDK cert");
                //Convert to JDK certificate
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                ByteArrayInputStream bais = new ByteArrayInputStream(
                    certs[i].getEncoded());
                java.security.cert.X509Certificate jdkCert =
                    (java.security.cert.X509Certificate)
                    cf.generateCertificate(bais);
                bais.close();
                
                System.out.println("Subject " + jdkCert.getSubjectDN());
                System.out.println("Signature oid " + jdkCert.getSigAlgName());
                /* non critical extensions */
                Set nonCritSet = jdkCert.getNonCriticalExtensionOIDs();
                if (nonCritSet != null && !nonCritSet.isEmpty()) {
                    for (Iterator j = nonCritSet.iterator(); j.hasNext();) {
                        String oid = (String)j.next();
                        System.out.println(oid);
                    }
                } else { System.out.println("no NON Critical Extensions"); }
                
                /* critical extensions */
                Set critSet = jdkCert.getCriticalExtensionOIDs();
                if (critSet != null && !critSet.isEmpty()) {
                    System.out.println("Set of critical extensions:");
                    for (Iterator j = critSet.iterator(); j.hasNext();) {
                        String oid = (String)j.next();
                        System.out.println(oid);
                    }
                } else { System.out.println("no Critical Extensions"); }
            }
            System.out.println("END");
            
        } catch( Exception e ) {
            e.printStackTrace();
            System.exit(1);
        }
        System.exit(0);
    }
}
