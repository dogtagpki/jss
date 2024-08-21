/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is a test implementation of the certificate approval callback which
 * gets invoked when the server presents a certificate which is not
 * trusted by the client.
 *
 * Note this implementation accepts all certificates!
 */
public class TestCertificateApprovalCallback
    implements SSLCertificateApprovalCallback {

    public static Logger logger = LoggerFactory.getLogger(TestCertificateApprovalCallback.class);

    @Override
    public boolean approve(
        X509Certificate servercert,
        SSLCertificateApprovalCallback.ValidityStatus status) {

        SSLCertificateApprovalCallback.ValidityItem item;

        logger.debug("in TestCertificateApprovalCallback.approve()");
            /* dump out server cert details */

        logger.debug("Peer cert details:");
        logger.debug("     subject: " + servercert.getSubjectDN());
        logger.debug("     issuer:  " + servercert.getIssuerDN());
        logger.debug("     serial:  " + servercert.getSerialNumber());

        /* iterate through all the problems */

        boolean trust_the_server_cert=false;

        Enumeration<ValidityItem> errors = status.getReasons();
        int i=0;
        while (errors.hasMoreElements()) {
            i++;
            item = errors.nextElement();
            logger.debug("item "+i+
                    " reason="+item.getReason()+
                    " depth="+item.getDepth());

            X509Certificate cert = item.getCert();
            if (item.getReason() ==
                SSLCertificateApprovalCallback.ValidityStatus.UNKNOWN_ISSUER) {
                trust_the_server_cert = true;
            }
            logger.debug(" cert details:");
            logger.debug("     subject: " + cert.getSubjectDN());
            logger.debug("     issuer:  " + cert.getIssuerDN());
            logger.debug("     serial:  " + cert.getSerialNumber());
        }

        if (trust_the_server_cert) {
            logger.debug("importing certificate.");

            try {
                CryptoManager cm = CryptoManager.getInstance();
                PK11Cert newcert = (PK11Cert) cm.importCertToPerm(
                        (org.mozilla.jss.crypto.X509Certificate) servercert,
                        "testnick");
                newcert.setSSLTrust(PK11Cert.TRUSTED_PEER | PK11Cert.VALID_PEER);
            } catch (Exception e) {
                System.out.println("thrown exception: "+e);
            }
        }


        /* allow the connection to continue.                 */
        /*   returning false here would abort the connection */
        /* don't do this in production code!                 */
        return true;
    }

}

