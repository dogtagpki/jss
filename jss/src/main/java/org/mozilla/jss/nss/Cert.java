package org.mozilla.jss.nss;

import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.CertificateRevokedException;

public class Cert {
    public static int MatchExceptionToNSSError(Exception excpt) {
        if (excpt == null) {
            return 0;
        }

        // Lower case, no spaces. Easier to find matches in
        // messy messages.
        String message = excpt.getMessage().toLowerCase().replaceAll("\\s+","");

        if (excpt instanceof CertificateEncodingException ||
            message.contains("encoding") ||
            excpt instanceof CertificateParsingException ||
            message.contains("parsing")) {
            return SECErrors.BAD_DER;
        }

        if (excpt instanceof CertificateExpiredException ||
            message.contains("expired")) {
            return SECErrors.EXPIRED_CERTIFICATE;
        }

        if (excpt instanceof CertificateNotYetValidException ||
            message.contains("notyetvalid") ||
            message.contains("notvalid")) {
            return SECErrors.CERT_NOT_VALID;
        }

        // Check for OCSP errors prior to using a generic revoked
        // reason.
        if (message.contains("ocsp")) {
            return SECErrors.REVOKED_CERTIFICATE_OCSP;
        }

        if (excpt instanceof CertificateRevokedException ||
            message.contains("revoked")) {
            return SECErrors.REVOKED_CERTIFICATE;
        }

        // The remaining messages don't have corresponding
        // exception classes.
        if (message.contains("issuer")) {
            return SECErrors.UNTRUSTED_ISSUER;
        }

        // Otherwise, use a generic error.
        return SECErrors.UNTRUSTED_CERT;
    }
}
