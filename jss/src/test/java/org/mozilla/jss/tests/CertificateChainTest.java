package org.mozilla.jss.tests;

import java.security.cert.X509Certificate;
import java.util.Base64;

import org.junit.Assert;
import org.junit.Test;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertificateChainTest {

    public static Logger logger = LoggerFactory.getLogger(CertificateChainTest.class);

    public X509Certificate rootCA;
    public X509Certificate subCA;
    public X509Certificate admin;

    public CertificateChainTest() throws Exception {

        // Subject DN: CN=Root CA Signing Certificate, O=EXAMPLE
        // Issuer DN: CN=Root CA Signing Certificate, O=EXAMPLE
        rootCA = new X509CertImpl(Base64.getDecoder().decode(
            "MIIDRjCCAi6gAwIBAgIJAMHiDXjnZ1J6MA0GCSqGSIb3DQEBCwUAMDgxEDAOBgNV" +
            "BAoMB0VYQU1QTEUxJDAiBgNVBAMMG1Jvb3QgQ0EgU2lnbmluZyBDZXJ0aWZpY2F0" +
            "ZTAeFw0xOTAzMDUxNzQzMjFaFw0yMDAzMDQxNzQzMjFaMDgxEDAOBgNVBAoMB0VY" +
            "QU1QTEUxJDAiBgNVBAMMG1Jvb3QgQ0EgU2lnbmluZyBDZXJ0aWZpY2F0ZTCCASIw" +
            "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMDv7ovkD+JVEdlLncYDnhzbLOz2" +
            "c3D37fobufnHHNwNOwfLZj8WdBCzwGJv+XGF+D2JIcKyYwYPR+HOg+xClhuuVleE" +
            "gMVvgxM+HcpM4heyBD2QczNo1dfXQRBy2AXvRn8Byh+Q6zbN7VoNu8ZaMQOxZx9m" +
            "EAiDZ7WxHVrEp2a4QrI6I9gKY6SyEHRzVT48JElLFokwhkMpF8vhgtj0Xxr5EEIY" +
            "yCMOzvZLtpeyH8PUri3Cv/hX1RZKjWqKLSJSKirnZLhZoEEzXtsOmoeeZBeRiabi" +
            "dPLsxqPfWFx4+BC7t5Vw5FaIt2mPh+q6bjZipO4uWz/p4a9wpqakuzgNsYUCAwEA" +
            "AaNTMFEwHQYDVR0OBBYEFCvlfY9OzAVsYpJEoqr7QfguO9v5MB8GA1UdIwQYMBaA" +
            "FCvlfY9OzAVsYpJEoqr7QfguO9v5MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcN" +
            "AQELBQADggEBAHB1lWjT6bP1jAkk6eTVwBU2pGoGoYMGV3fWQGOmWQP5T7+nHKkU" +
            "jNMRACoC2hFlypwX8qQ70V5O4U+qrnxDP3EaT1zPsOB0x4DIIrpFgudL9EqnSbJ0" +
            "kvSz3awwO8x/Nvx7TatCncmTw9c14eqek2puhcQWvxHzWkaDHd9WxPrZJFftbSsn" +
            "ZGK2A/ybDCnUA5BDeCSDb5gufTd8gbS4wS1NwYcbbrQyHnLJlFcIF4aLkbYuX1bn" +
            "cYp8pQv3pZ3C/ofA+yBJvPELTaHjDC40MTdjFFfMQTPZswBX2iimoGQ/ProBGg7+" +
            "rLg2uk5AHff3oo/V1X0SSzo3IpvHh0jhg9I="
        ));

        // Subject DN: CN=Subordinate CA Signing Certificate, O=EXAMPLE
        // Issuer DN: CN=Root CA Signing Certificate, O=EXAMPLE
        subCA = new X509CertImpl(Base64.getDecoder().decode(
            "MIIC8zCCAdsCCQCPJrl0/W/nMTANBgkqhkiG9w0BAQsFADA4MRAwDgYDVQQKDAdF" +
            "WEFNUExFMSQwIgYDVQQDDBtSb290IENBIFNpZ25pbmcgQ2VydGlmaWNhdGUwHhcN" +
            "MTkwMzA1MTg1MzMzWhcNMjAwMzA0MTg1MzMzWjA/MRAwDgYDVQQKDAdFWEFNUExF" +
            "MSswKQYDVQQDDCJTdWJvcmRpbmF0ZSBDQSBTaWduaW5nIENlcnRpZmljYXRlMIIB" +
            "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzop7/TcsWElVMjzjaaAcj5KH" +
            "c9H6rqhFmOsL/VYdbNzTkZD3i5DVB4sFFEHTMwEoKKpBKh9hkY8laRUWjtidDJu2" +
            "+NBPLJa+k0Q+KUWIQko1rtgSjmCN+oMZFh7Mo8fV1WLSBnNjwbUrMeRKxOaR/roa" +
            "YgIwH5Ra6cxsVHGngAfrjXPtiuFp7qjzUbbRBBRP2LpKDk45RzllSLhz09qgo135" +
            "by2zErfUsWoma+dzvfWVI27um2DEzHMMAHELZM6BSJEYaGUW+y4cHQuuhz6Bo1YY" +
            "L6RHp6RhuMzlILN7a/XznS6Zc8OV/hRlkZVUUha6tqSQ/uXNTaefa6sGrRWNdQID" +
            "AQABMA0GCSqGSIb3DQEBCwUAA4IBAQAKLJq6bCZ8f/bI1OAeRNE7eIZliDnTjLqM" +
            "M3sG9gkWCp1l7UD5CLAbCaL6jFEuBAvkr88LYS4A0vuMAmMVsiSsFRTZNLmazts7" +
            "NZARuOYmzuNb/SZzhOBgypo6G96cqLhslzFtxXs+zJic2lQEDu+5+pcZCyETWoBT" +
            "kD9sAM2dM1I9//05UTJ5mzuLFmW3rhSjsrOuYHJjwagUVVAYDrIqNgNb/XSlmWbu" +
            "d1t9sKHgHzN2H0DIsKaoupPhTDUABrDuG3mRn1gI2xu1RlluaXZB7ZpUZAB/hMTV" +
            "8JPbHZeV08qYlfWJqhnUAZ0YQOx0yi5D98uhYB6Is/msBQ/YIbEi"
        ));

        // Subject DN: UID=admin, O=EXAMPLE
        // Issuer DN: CN=Subordinate CA Signing Certificate, O=EXAMPLE
        admin = new X509CertImpl(Base64.getDecoder().decode(
            "MIIC5DCCAcwCCQCh59LykL9CDTANBgkqhkiG9w0BAQsFADA/MRAwDgYDVQQKDAdF" +
            "WEFNUExFMSswKQYDVQQDDCJTdWJvcmRpbmF0ZSBDQSBTaWduaW5nIENlcnRpZmlj" +
            "YXRlMB4XDTE5MDMwNTIwMDQxNloXDTIwMDMwNDIwMDQxNlowKTEQMA4GA1UECgwH" +
            "RVhBTVBMRTEVMBMGCgmSJomT8ixkAQEMBWFkbWluMIIBIjANBgkqhkiG9w0BAQEF" +
            "AAOCAQ8AMIIBCgKCAQEA7QR+I7nLeGFntCajqIETKZ2MtpXdnrU3nkJawKwi1xQp" +
            "lYhFoVIqGqiX1+LfopemmR1bv2hcLt9uce4FG8jtELEF5KuCdCT99BSi8iVU+w0z" +
            "s4kCfUj9HvIcFhUO0dhkyVI//ZDh16xOi5AS3jqB0PtjgYbdrmufxXQhnyoeY9CM" +
            "N/w8OmN7mx2xUIApFP2LldU21rNSvly2Q0JbVDN2q7EENViYovvELW7zALGT5l/u" +
            "wVUsdkdgKY2C0ZHCh+aUDvDogywIALJIRxjcCU3Udx8Vfq/+MZCNccj6CPeCxNFv" +
            "L/wNtu+MpboF1jwNZB5jK9FPr3lXaH1aDdxoBSDMVwIDAQABMA0GCSqGSIb3DQEB" +
            "CwUAA4IBAQApkTNJMiCOYi9MI79kHFbEESd/ae+TTvHAd7sBIe5u1v5yK5Ij2opK" +
            "orY+gCVwNQOUlR7P/FIaY4eLVfPswqr3pl6O/DyqcuMLZofOHAzPEIBPFV/Qxcu1" +
            "WB1SDnSW61Wx7khVnWJQPgbcPVHdgTSS4vmUOw3YAsFAqzczth6bw/5sD19WLVu6" +
            "OYTSFGiofFLZXkidxZ7DIP2TUsaFJUEOkdoXlAImaHGpsCB/NXj2bWRmbzxcnMxd" +
            "jxttLewQofszMM0extB95n1KFv/bzbD+m9NM+aqvLOrzOg5rlcE5cbU07DVIycYs" +
            "fszFfR+9FvzA/AOpUzHg8y+ZX1rUts5f"
        ));
    }

    @Test
    public void testDefaultConstructor() throws Exception {

        CertificateChain chain = new CertificateChain();

        Assert.assertEquals(0, chain.getCertificates().size());
    }

    @Test
    public void testConstructorWithNullCert() throws Exception {

        try {
            new CertificateChain((X509Certificate) null);

            Assert.fail("Creating CertificateChain with null cert should fail");

        } catch (IllegalArgumentException e) {
            Assert.assertEquals("Missing input certificate", e.getMessage());
        }
    }

    @Test
    public void testConstructorWithRootCA() throws Exception {

        CertificateChain chain = new CertificateChain(rootCA);

        Assert.assertEquals(1, chain.getCertificates().size());
        Assert.assertEquals(rootCA, chain.getCertificates().get(0));
    }

    @Test
    public void testConstructorWithNullCertArray() throws Exception {

        try {
            new CertificateChain((X509Certificate[]) null);

            Assert.fail("Creating CertificateChain with null cert array should fail");

        } catch (IllegalArgumentException e) {
            Assert.assertEquals("Missing input certificates", e.getMessage());
        }
    }

    @Test
    public void testConstructorWithEmptyCertArray() throws Exception {

        CertificateChain chain = new CertificateChain(new X509Certificate[] {});

        Assert.assertEquals(0, chain.getCertificates().size());
    }

    @Test
    public void testConstructorWithOneCert() throws Exception {

        CertificateChain chain = new CertificateChain(new X509Certificate[] { rootCA });

        Assert.assertEquals(1, chain.getCertificates().size());
        Assert.assertEquals(rootCA, chain.getCertificates().get(0));
    }

    @Test
    public void testConstructorWithTwoCerts() throws Exception {

        CertificateChain chain = new CertificateChain(new X509Certificate[] { rootCA, subCA });

        Assert.assertEquals(2, chain.getCertificates().size());
        Assert.assertEquals(rootCA, chain.getCertificates().get(0));
        Assert.assertEquals(subCA, chain.getCertificates().get(1));
    }

    @Test
    public void testGetterMethods() throws Exception {

        CertificateChain chain = new CertificateChain(new X509Certificate[] { rootCA, subCA, admin });

        Assert.assertEquals(3, chain.getCertificates().size());

        Assert.assertEquals(rootCA, chain.getFirstCertificate());

        Assert.assertEquals(rootCA, chain.getCertificate(0));
        Assert.assertEquals(subCA, chain.getCertificate(1));
        Assert.assertEquals(admin, chain.getCertificate(2));

        try {
            chain.getCertificate(3);

            Assert.fail("Getting cert #3 should fail");

        } catch (IndexOutOfBoundsException e) {
            // failed as expected
        }

        X509Certificate[] certs = chain.getChain();

        Assert.assertEquals(3, certs.length);

        Assert.assertEquals(rootCA, certs[0]);
        Assert.assertEquals(subCA, certs[1]);
        Assert.assertEquals(admin, certs[2]);
    }

    @Test
    public void testSorting() throws Exception {

        CertificateChain chain = new CertificateChain(new X509Certificate[] { admin, subCA, rootCA });
        chain.sort();

        Assert.assertEquals(3, chain.getCertificates().size());

        Assert.assertEquals(rootCA, chain.getCertificate(0));
        Assert.assertEquals(subCA, chain.getCertificate(1));
        Assert.assertEquals(admin, chain.getCertificate(2));
    }
}
