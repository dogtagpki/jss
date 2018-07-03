/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss;

import java.util.ArrayList;
import java.util.Iterator;

/**
 * CertificateUsage options for validation
 */
public final class CertificateUsage {

    private int usage;
    private String name;

    // certificateUsage, these must be kept in sync with nss/lib/certdb/certt.h
    private static final int certificateUsageCheckAllUsages = 0x0000;
    private static final int certificateUsageSSLClient = 0x0001;
    private static final int certificateUsageSSLServer = 0x0002;
    private static final int certificateUsageSSLServerWithStepUp = 0x0004;
    private static final int certificateUsageSSLCA = 0x0008;
    private static final int certificateUsageEmailSigner = 0x0010;
    private static final int certificateUsageEmailRecipient = 0x0020;
    private static final int certificateUsageObjectSigner = 0x0040;
    private static final int certificateUsageUserCertImport = 0x0080;
    private static final int certificateUsageVerifyCA = 0x0100;
    private static final int certificateUsageProtectedObjectSigner = 0x0200;
    private static final int certificateUsageStatusResponder = 0x0400;
    private static final int certificateUsageAnyCA = 0x0800;

    static private ArrayList<CertificateUsage> list = new ArrayList<>();

    private CertificateUsage() {
    }

    private CertificateUsage(int usage, String name) {
        this.usage = usage;
        this.name =  name;
        list.add(this);

    }
    public int getUsage() {
        return usage;
    }

    static public Iterator<CertificateUsage> getCertificateUsages() {
        return list.iterator();

    }
    public String toString() {
        return name;
    }

    public static final CertificateUsage CheckAllUsages = new CertificateUsage(certificateUsageCheckAllUsages, "CheckAllUsages");
    public static final CertificateUsage SSLClient = new CertificateUsage(certificateUsageSSLClient, "SSLClient");
    public static final CertificateUsage SSLServer = new CertificateUsage(certificateUsageSSLServer, "SSLServer");
    public static final CertificateUsage SSLServerWithStepUp = new CertificateUsage(certificateUsageSSLServerWithStepUp, "SSLServerWithStepUp");
    public static final CertificateUsage SSLCA = new CertificateUsage(certificateUsageSSLCA, "SSLCA");
    public static final CertificateUsage EmailSigner = new CertificateUsage(certificateUsageEmailSigner, "EmailSigner");
    public static final CertificateUsage EmailRecipient = new CertificateUsage(certificateUsageEmailRecipient, "EmailRecipient");
    public static final CertificateUsage ObjectSigner = new CertificateUsage(certificateUsageObjectSigner, "ObjectSigner");
    public static final CertificateUsage UserCertImport = new CertificateUsage(certificateUsageUserCertImport, "UserCertImport");
    public static final CertificateUsage VerifyCA = new CertificateUsage(certificateUsageVerifyCA, "VerifyCA");
    public static final CertificateUsage ProtectedObjectSigner = new CertificateUsage(certificateUsageProtectedObjectSigner, "ProtectedObjectSigner");
    public static final CertificateUsage StatusResponder = new CertificateUsage(certificateUsageStatusResponder, "StatusResponder");
    public static final CertificateUsage AnyCA = new CertificateUsage(certificateUsageAnyCA, "AnyCA");

    /*
            The folllowing usages cannot be verified:
               certUsageAnyCA
               certUsageProtectedObjectSigner
               certUsageUserCertImport
               certUsageVerifyCA
    */
    public static final int basicCertificateUsages = /*0x0b80;*/
            certificateUsageUserCertImport |
            certificateUsageVerifyCA |
            certificateUsageProtectedObjectSigner |
            certificateUsageAnyCA ;
}
