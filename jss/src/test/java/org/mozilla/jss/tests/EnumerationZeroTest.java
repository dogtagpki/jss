/**
 * Copyright (c) 2009 - 2018 Red Hat, Inc.
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * Red Hat trademarks are not licensed under GPLv2. No permission is
 * granted to use or replicate Red Hat trademarks that are incorporated
 * in this software or its documentation.
 *
 * Submitted by Alex Wood as an attachment to BZ#1582323. Used with
 * permission.
 */

package org.mozilla.jss.tests;

import org.mozilla.jss.JSSProvider;
import org.mozilla.jss.netscape.security.util.BitArray;
import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.x509.AuthorityKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLNumberExtension;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.KeyIdentifier;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.RevokedCertImpl;
import org.mozilla.jss.netscape.security.x509.RevokedCertificate;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/** Class to demonstrate DER encoding failure when using an ASN.1 enumerated type with a value of zero.
 *
 *  RFC 5280's section 5.3.1 lists the valid values for certificate revocation codes:
 *
 *  CRLReason ::= ENUMERATED {
 *       unspecified             (0),
 *       keyCompromise           (1),
 *       cACompromise            (2),
 *       affiliationChanged      (3),
 *       superseded              (4),
 *       cessationOfOperation    (5),
 *       certificateHold         (6),
 *            -- value 7 is not used
 *       removeFromCRL           (8),
 *       privilegeWithdrawn      (9),
 *       aACompromise           (10) }
 *
 */
public class EnumerationZeroTest {
    static {
        // Satellite 6 is only supported on 64 bit architectures
        Security.addProvider(new JSSProvider());
    }

    private EnumerationZeroTest() {

    }

    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }

        return sb.toString();
    }

    /**
     * Calculate the KeyIdentifier for an RSAPublicKey and place it in an AuthorityKeyIdentifier extension.
     *
     * Java encodes RSA public keys using the SubjectPublicKeyInfo type described in RFC 5280.
     * <pre>
     * SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *   algorithm            AlgorithmIdentifier,
     *   subjectPublicKey     BIT STRING  }
     *
     * AlgorithmIdentifier  ::=  SEQUENCE  {
     *   algorithm               OBJECT IDENTIFIER,
     *   parameters              ANY DEFINED BY algorithm OPTIONAL  }
     * </pre>
     *
     * A KeyIdentifier is a SHA-1 digest of the subjectPublicKey bit string from the ASN.1 above.
     *
     * @param key the RSAPublicKey to use
     * @return an AuthorityKeyIdentifierExtension based on the key
     * @throws IOException if we can't construct a MessageDigest object.
     */
    public static AuthorityKeyIdentifierExtension buildAuthorityKeyIdentifier(RSAPublicKey key)
        throws IOException {
        try {
            MessageDigest d = MessageDigest.getInstance("SHA-1");

            byte[] encodedKey = key.getEncoded();

            DerInputStream s = new DerValue(encodedKey).toDerInputStream();
            // Skip the first item in the sequence, AlgorithmIdentifier.
            // The parameter, startLen, is required for skipSequence although it's unused.
            s.skipSequence(0);
            // Get the subjectPublicKey bit string
            BitArray b = s.getUnalignedBitString();
            byte[] digest = d.digest(b.toByteArray());

            KeyIdentifier ki = new KeyIdentifier(digest);
            return new AuthorityKeyIdentifierExtension(ki, null, null);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IOException("Could not find SHA1 implementation", e);
        }
    }

    /**
     * Output the DER encoding of a CRLExtension for examination
     */
    public static void outputExtension(CRLReasonExtension ext) throws Exception {
        ByteArrayOutputStream resultBytesOut = new ByteArrayOutputStream();
        ext.encode(resultBytesOut);

        byte[] encodedBytes = resultBytesOut.toByteArray();
        System.out.print("Full encoded extension: " + toHex(encodedBytes));
        Extension reasonExt = new Extension(new DerValue(encodedBytes));
        System.out.print("\tEncoded CRL Reason: " + toHex(reasonExt.getExtensionValue()));
        DerValue reasonValue = new DerValue(reasonExt.getExtensionValue());
        System.out.println("\tReason value: " + reasonValue.getEnumerated());
    }

    /**
     * Build a CRL using JSS
     * @param useZero whether or not to try creating a CRLEntry with the reason set to "unspecified"
     * @return an X509CRL object
     * @throws Exception if anything goes wrong
     */
    public static X509CRL buildCrl(boolean useZero) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair kp = generator.generateKeyPair();

        List<RevokedCertificate> revokedCerts = new ArrayList<>();
        for (int i = 0; i <= 10; i++) {
            // 7 is an unused value in the enumeration
            if (i == 7 || (i == 0 && !useZero)) {
                continue;
            }

            CRLReasonExtension reasonExt = new CRLReasonExtension(RevocationReason.fromInt(i));
            outputExtension(reasonExt);

            CRLExtensions entryExtensions = new CRLExtensions();
            entryExtensions.add(reasonExt);

            revokedCerts.add(
                new RevokedCertImpl(BigInteger.valueOf((long) i), new Date(), entryExtensions));
        }

        CRLExtensions crlExtensions = new CRLExtensions();
        crlExtensions.add(new CRLNumberExtension(BigInteger.ONE));
        crlExtensions.add(buildAuthorityKeyIdentifier((RSAPublicKey) kp.getPublic()));

        X500Name issuer = new X500Name("CN=Test");

        Date now = new Date();

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_MONTH, 365);
        Date until = calendar.getTime();

        X509CRLImpl crlImpl = new X509CRLImpl(
            issuer,
            now,
            until,
            revokedCerts.toArray(new RevokedCertificate[] {}),
            crlExtensions
        );

        crlImpl.sign(kp.getPrivate(), "SHA256withRSA");

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        byte[] data = crlImpl.getEncoded();
        return (X509CRL) cf.generateCRL(new ByteArrayInputStream(data));
    }

    public static void main(String[] args) throws Exception {
        X509CRL crl = buildCrl(false);

        System.out.println(crl.toString());

        buildCrl(true);  // will throw exception
    }
}
