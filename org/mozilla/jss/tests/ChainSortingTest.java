package org.mozilla.jss.tests;

import java.security.cert.X509Certificate;

import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Test;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ChainSortingTest {

    public static Logger logger = LoggerFactory.getLogger(ChainSortingTest.class);

    public X509Certificate rootCA;
    public X509Certificate subCA;
    public X509Certificate admin;
    public X509Certificate agent;

    public ChainSortingTest() throws Exception {

        // Subject DN: CN=Root CA Signing Certificate, O=EXAMPLE
        // Issuer DN: CN=Root CA Signing Certificate, O=EXAMPLE
        rootCA = new X509CertImpl(Base64.decodeBase64(
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
        subCA = new X509CertImpl(Base64.decodeBase64(
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
        admin = new X509CertImpl(Base64.decodeBase64(
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

        // Subject DN: UID=agent, O=EXAMPLE
        // Issuer DN: CN=Subordinate CA Signing Certificate, O=EXAMPLE
        agent = new X509CertImpl(Base64.decodeBase64(
            "MIIC5DCCAcwCCQCh59LykL9CDjANBgkqhkiG9w0BAQsFADA/MRAwDgYDVQQKDAdF" +
            "WEFNUExFMSswKQYDVQQDDCJTdWJvcmRpbmF0ZSBDQSBTaWduaW5nIENlcnRpZmlj" +
            "YXRlMB4XDTE5MDMwNTIwMzU1NVoXDTIwMDMwNDIwMzU1NVowKTEQMA4GA1UECgwH" +
            "RVhBTVBMRTEVMBMGCgmSJomT8ixkAQEMBWFnZW50MIIBIjANBgkqhkiG9w0BAQEF" +
            "AAOCAQ8AMIIBCgKCAQEA7c4d93Gw4c0eW88ALqlUP01qkTzwRFLGKExbeBAwAGIY" +
            "0c/c9sHFkRkEO5Fm+BeaX0qqdF5D7dk+yTJcnvbLa4YP0MC+iOBIAmRk9CZmfArM" +
            "GE6dmMtt2pmQb38VlyY+3Cmjhz779rfzepAkSdmeLFTUW1I1KUIZDUovuu58Ak6j" +
            "7V0Ri3V2iI8z5zLRqg1Ko517+vsr2nKeAUO+g2Zbcu8qb6uS3Qq7mrHaHg7ZZb+M" +
            "yyqdqmMmLW1SQnITyqVXV/KH3mbAfsdQPopODhdH1LpuEw9xU9hVG6tn+ihytPsU" +
            "7txSW2nFC3iSzL8FK1RSerWAN93hLHVf5q5XXVk87QIDAQABMA0GCSqGSIb3DQEB" +
            "CwUAA4IBAQCWPtQEoUMoSJY+gqnoJNqq7DzprBQOaBMV5KKA+Fo4mSn6MUetFLPl" +
            "/HD1Knub2DEEuALPq5H3O71Jfy1cscAq3sD9Zl2jPP4FvrC0ypQl/Q5bG/8QDM9p" +
            "1INSAdyzPsTY+Y/mKChF3HNCzssnDWWDzHr6gSI7wnlDrE2QQGdHIn2Znx4P47RH" +
            "MTFX3xumo1b8nTyjdJ2aW8T80i30SejDkmnN9XBp14D7fheGOlKeP2lCt5GDpkcF" +
            "mT4YgcaVtSxMQBn7QhWV3534BqAjE5a32DEuJ6SnZph1GaDFy/kMXbjV/n9igHDs" +
            "b5s4gPC9eTB38qG0y+8TDATxvJ7s2OOM"
        ));
    }

    @Test
    public void testNulLChain() throws Exception {

        logger.info("Testing null chain");

        X509Certificate[] input = null;
        X509Certificate[] output = Cert.sortCertificateChain(input);

        X509Certificate[] expected = null;
        Assert.assertArrayEquals(expected, output);
    }

    @Test
    public void testEmptyChain() throws Exception {

        logger.info("Testing empty chain");

        X509Certificate[] input = {};
        X509Certificate[] output = Cert.sortCertificateChain(input);

        X509Certificate[] expected = {};
        Assert.assertArrayEquals(expected, output);
    }

    @Test
    public void testOneLevelChain() throws Exception {

        logger.info("Testing one-level chain");

        X509Certificate[] input = { rootCA };
        X509Certificate[] output = Cert.sortCertificateChain(input);

        X509Certificate[] expected = { rootCA };
        Assert.assertArrayEquals(expected, output);
    }

    @Test
    public void testTwoLevelOrderedChain() throws Exception {

        logger.info("Testing two-level ordered chain");

        X509Certificate[] input = { rootCA, subCA };
        X509Certificate[] output = Cert.sortCertificateChain(input);

        X509Certificate[] expected = { rootCA, subCA };
        Assert.assertArrayEquals(expected, output);
    }

    @Test
    public void testTwoLevelUnorderedChain() throws Exception {

        logger.info("Testing two-level unordered chain");

        X509Certificate[] input = { subCA, rootCA };
        X509Certificate[] output = Cert.sortCertificateChain(input);

        X509Certificate[] expected = { rootCA, subCA };
        Assert.assertArrayEquals(expected, output);
    }

    @Test
    public void testThreeLevelOrderedChain() throws Exception {

        logger.info("Testing three-level ordered chain");

        X509Certificate[] input = { rootCA, subCA, admin };
        X509Certificate[] output = Cert.sortCertificateChain(input);

        X509Certificate[] expected = { rootCA, subCA, admin };
        Assert.assertArrayEquals(expected, output);
    }

    @Test
    public void testThreeLevelUnorderedChain() throws Exception {

        logger.info("Testing three-level unordered chain");

        X509Certificate[] input = { admin, subCA, rootCA };
        X509Certificate[] output = Cert.sortCertificateChain(input);

        X509Certificate[] expected = { rootCA, subCA, admin };
        Assert.assertArrayEquals(expected, output);
    }

    @Test
    public void testThreeLevelReverseChain() throws Exception {

        logger.info("Testing three-level reverse chain");

        X509Certificate[] input = { subCA, rootCA, admin };
        X509Certificate[] output = Cert.sortCertificateChain(input, true);

        X509Certificate[] expected = { admin, subCA, rootCA };
        Assert.assertArrayEquals(expected, output);
    }

    @Test
    public void testPartialChain() throws Exception {

        logger.info("Testing partial chain");

        X509Certificate[] input = { admin, subCA };
        X509Certificate[] output = Cert.sortCertificateChain(input);

        X509Certificate[] expected = { subCA, admin };
        Assert.assertArrayEquals(expected, output);
    }

    @Test
    public void testDuplicateChain() throws Exception {

        logger.info("Testing chain with duplicate certificates");

        X509Certificate[] input = { rootCA, subCA, subCA, admin };

        try {
            Cert.sortCertificateChain(input);
            Assert.fail();

        } catch (Exception e) {
            String message = e.getMessage();

            String expected = "Duplicate certificate: " + subCA.getSubjectDN();
            Assert.assertEquals(expected, message);
        }
    }

    @Test
    public void testBranchedChain() throws Exception {

        logger.info("Testing branched chain");

        X509Certificate[] input = { rootCA, subCA, admin, agent};

        try {
            Cert.sortCertificateChain(input);
            Assert.fail();

        } catch (Exception e) {
            String message = e.getMessage();

            String expected = "Branched chain: " + subCA.getSubjectDN();
            Assert.assertEquals(expected, message);
        }
    }

    @Test
    public void testBrokenChain() throws Exception {

        logger.info("Testing broken chain");

        X509Certificate[] input = { rootCA, admin };

        try {
            Cert.sortCertificateChain(input);
            Assert.fail();

        } catch (Exception e) {
            String message = e.getMessage();

            String expected = "Multiple leaf certificates: [" +
                    rootCA.getSubjectDN() + "], [" + admin.getSubjectDN() + "]";
            Assert.assertEquals(expected, message);
        }
    }
}
