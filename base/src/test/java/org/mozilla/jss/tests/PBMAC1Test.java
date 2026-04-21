/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.netscape.security.pkcs.PKCS12Util.MacType;
import org.mozilla.jss.pkcs12.AuthenticatedSafes;
import org.mozilla.jss.pkcs12.MacData;
import org.mozilla.jss.pkcs12.PFX;
import org.mozilla.jss.util.Password;
import java.util.Calendar;
import java.util.Date;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.netscape.security.pkcs.PKCS12;
import org.mozilla.jss.netscape.security.pkcs.PKCS12Util;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.pkix.cert.CertificateInfo;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;
import org.mozilla.jss.tests.FilePasswordCallback;

/**
 * Test PBMAC1 (RFC 9579) MAC computation for PKCS#12.
 */
public class PBMAC1Test {

    public static void main(String[] args) {
        try {
            if (args.length != 2) {
                System.out.println("Usage: java org.mozilla.jss.tests.PBMAC1Test <dbdir> <passwordfile>");
                System.exit(1);
            }

            try {
                CryptoManager.initialize(args[0]);
            } catch(AlreadyInitializedException e) {
                // already initialized, it's ok
            }

            CryptoManager cm = CryptoManager.getInstance();
            cm.setPasswordCallback(new FilePasswordCallback(args[1]));

            System.out.println("Testing PBMAC1 MAC computation...\n");

            // Test with SHA-256
            testPBMAC1("SHA-256", DigestAlgorithm.SHA256, 32);

            // Test with SHA-384
            testPBMAC1("SHA-384", DigestAlgorithm.SHA384, 48);

            // Test with SHA-512
            testPBMAC1("SHA-512", DigestAlgorithm.SHA512, 64);

            // Test repeatability (same inputs = same output)
            testRepeatability();

            // Test legacy path
            testLegacyMAC();

            //Test creating and verifying actual p12 file

            testCreateP12WithPBMAC1(args[0]);

            System.out.println("\nAll PBMAC1 and Legacy MAC and p12 tests PASSED!");

        } catch (Exception e) {
            System.err.println("PBMAC1 test FAILED: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void testPBMAC1(String name, DigestAlgorithm digest, int expectedMacLen)
        throws Exception {
        System.out.println("Testing PBMAC1 with HMAC-" + name + "...");

        Password password = new Password("testPassword123".toCharArray());
        byte[] salt = new byte[20];
        fillTestSalt(salt);
        int iterations = 100000;

        // Create minimal AuthenticatedSafes (empty is fine for MAC testing)
        AuthenticatedSafes authSafes = new AuthenticatedSafes();
        authSafes.addSafeContents(new SEQUENCE());

        // Create PFX and configure for PBMAC1
        PFX pfx = new PFX(authSafes);
        pfx.setMacType(MacType.PBMAC1);
        pfx.setMacDigest(digest);

        // Compute MAC using real API
        pfx.computeMacData(password, salt, iterations);

        // Get the MacData and verify
        MacData macData = pfx.getMacData();
        if (macData == null || macData.getMac() == null) {
            throw new Exception("PBMAC1 MAC computation failed - MacData is null");
        }

        // Verify MAC output length
        byte[] macValue = macData.getMac().getDigest().toByteArray();
        if (macValue.length != expectedMacLen) {
            throw new Exception("PBMAC1 MAC length mismatch: expected " + expectedMacLen +
                              " bytes, got " + macValue.length + " bytes");
        }

        System.out.println("  ✓ MAC length correct: " + macValue.length + " bytes");
        System.out.println("  ✓ PBMAC1 with HMAC-" + name + " PASSED\n");

        password.clear();
    }

    private static void testRepeatability() throws Exception {
        System.out.println("Testing PBMAC1 repeatability (same inputs = same output)...");

        Password password1 = new Password("samePassword".toCharArray());
        Password password2 = new Password("samePassword".toCharArray());

        byte[] salt = new byte[16];
        fillTestSalt(salt);
        int iterations = 100000;

        // Create identical AuthenticatedSafes
        AuthenticatedSafes authSafes1 = new AuthenticatedSafes();
        authSafes1.addSafeContents(new SEQUENCE());

        AuthenticatedSafes authSafes2 = new AuthenticatedSafes();
        authSafes2.addSafeContents(new SEQUENCE());

        // Compute MAC twice with same configuration
        PFX pfx1 = new PFX(authSafes1);
        pfx1.setMacType(MacType.PBMAC1);
        pfx1.setMacDigest(DigestAlgorithm.SHA256);
        pfx1.computeMacData(password1, salt, iterations);
        byte[] mac1 = pfx1.getMacData().getMac().getDigest().toByteArray();

        PFX pfx2 = new PFX(authSafes2);
        pfx2.setMacType(MacType.PBMAC1);
        pfx2.setMacDigest(DigestAlgorithm.SHA256);
        pfx2.computeMacData(password2, salt, iterations);
        byte[] mac2 = pfx2.getMacData().getMac().getDigest().toByteArray();

        // Verify both MACs are identical
        if (mac1.length != mac2.length) {
            throw new Exception("MAC lengths differ");
        }

        for (int i = 0; i < mac1.length; i++) {
            if (mac1[i] != mac2[i]) {
                throw new Exception("MACs differ at byte " + i);
            }
        }

        System.out.println("  ✓ Repeatability verified - same inputs produce same MAC");
        System.out.println("  ✓ Repeatability test PASSED\n");

        password1.clear();
        password2.clear();
    }

    private static void testLegacyMAC() throws Exception {
        System.out.println("Testing Legacy MAC (backward compatibility)...");

        Password password = new Password("legacyPassword".toCharArray());
        byte[] salt = new byte[16];
        fillTestSalt(salt);
        int iterations = 100000;

        // Create AuthenticatedSafes
        AuthenticatedSafes authSafes = new AuthenticatedSafes();
        authSafes.addSafeContents(new SEQUENCE());

        // Create PFX - DON'T set MacType (should default to LEGACY)
        PFX pfx = new PFX(authSafes);

        // Compute MAC using default (legacy) algorithm
        pfx.computeMacData(password, salt, iterations);

        // Verify MAC was created
        MacData macData = pfx.getMacData();
        if (macData == null || macData.getMac() == null) {
            throw new Exception("Legacy MAC computation failed - MacData is null");
        }

        // Verify MAC length (SHA-256 = 32 bytes, which is the legacy default)
        byte[] macValue = macData.getMac().getDigest().toByteArray();
        if (macValue.length != 32) {
            throw new Exception("Legacy MAC length unexpected: " + macValue.length);
        }

        System.out.println("  ✓ Legacy MAC created successfully");
        System.out.println("  ✓ MAC length: " + macValue.length + " bytes (SHA-256)");
        System.out.println("  ✓ Legacy MAC test PASSED\n");

        password.clear();
    }

    /**
     * Fill salt array with test values.
     * For tests only - real code should use SecureRandom.
     */
    private static void fillTestSalt(byte[] salt) {
        for (int i = 0; i < salt.length; i++) {
            salt[i] = (byte) i;
        }
    }

private static void testCreateP12WithPBMAC1(String dbdir) throws Exception {
      System.out.println("Testing PKCS#12 file creation with PBMAC1...");

      CryptoManager cm = CryptoManager.getInstance();

      // 1. Generate test cert and key
      String nickname = "PBMAC1-Test" + System.currentTimeMillis();
      java.security.KeyPair pair = generateTestCertAndKey("RSA", 2048, nickname);

      System.out.println("  ✓ Generated 2048-bit RSA cert/key: " + nickname);

      // 2. Get the imported certificate
      X509Certificate nssCert = cm.findCertByNickname(nickname);

      // 3. Create PKCS12 object and add cert/key
      PKCS12 pkcs12 = new PKCS12();
      PKCS12Util util = new PKCS12Util();
      util.loadCertFromNSS(pkcs12, nssCert, true, false);

      System.out.println("  ✓ Created PKCS12 object");

      // 4. Export to file with PBMAC1
      util.setMacType(MacType.PBMAC1);
      util.setMacDigest(DigestAlgorithm.SHA256);

      Password password = new Password("test123".toCharArray());
      String filename = dbdir + "/test-pbmac1.p12";
      util.storeIntoFile(pkcs12, filename, password);

      System.out.println("  ✓ Exported to: " + filename);
      System.out.println("  ✓ MAC type: PBMAC1 with HMAC-SHA256");

      // 5. Delete cert/key from database
      CryptoStore store = cm.getInternalKeyStorageToken().getCryptoStore();
      store.deleteCert(nssCert);

      System.out.println("  ✓ Deleted cert/key from database");

      // 6. Verify cert is gone
      try {
          cm.findCertByNickname(nickname);
          throw new Exception("Cert still exists after deletion!");
      } catch (ObjectNotFoundException e) {
          // Expected - cert is gone
          System.out.println("  ✓ Verified cert was deleted");
      }

      // 7. Re-import from PKCS#12 file
      PKCS12 pkcs12imported = util.loadFromFile(filename, password);
      util.storeIntoNSS(pkcs12imported, password, false);

      System.out.println("  ✓ Re-imported from PKCS#12 file");

      // 8. Verify cert/key are restored
      X509Certificate restoredCert = cm.findCertByNickname(nickname);
      if (restoredCert == null) {
          throw new Exception("Cert not restored from PKCS#12!");
      }

      System.out.println("  ✓ Cert/key successfully restored");

      // 9. Final cleanup
      store.deleteCert(restoredCert);
      password.clear();

      System.out.println("  ✓ PKCS#12 round-trip test PASSED\n");
  }

    private static java.security.KeyPair generateTestCertAndKey(
      String keyType, int keySize, String nickname) throws Exception {

      CryptoManager cm = CryptoManager.getInstance();

      // Generate keypair
      java.security.KeyPairGenerator kpg =
          java.security.KeyPairGenerator.getInstance(keyType, "Mozilla-JSS");
      kpg.initialize(keySize);
      java.security.KeyPair pair = kpg.genKeyPair();

      // Select signature algorithm based on key type
      SignatureAlgorithm sigAlg;
      if (keyType.equals("RSA")) {
          sigAlg = SignatureAlgorithm.RSASignatureWithSHA256Digest;
      } else if (keyType.equals("EC")) {
          sigAlg = SignatureAlgorithm.ECSignatureWithSHA256Digest;
      } else {
          throw new IllegalArgumentException("Unsupported key type: " + keyType);
      }

      // Create self-signed certificate
      Name subject = new Name();
      subject.addCountryName("US");
      subject.addOrganizationName("Mozilla");
      subject.addCommonName(nickname);

      Calendar cal = Calendar.getInstance();
      Date notBefore = cal.getTime();
      cal.add(Calendar.YEAR, 1);
      Date notAfter = cal.getTime();

      // AlgorithmIdentifier construction differs by key type
      AlgorithmIdentifier sigAlgID;
      if (keyType.equals("RSA")) {
          sigAlgID = new AlgorithmIdentifier(sigAlg.toOID(), null);
      } else {
          sigAlgID = new AlgorithmIdentifier(sigAlg.toOID());
      }

      SubjectPublicKeyInfo spki = (SubjectPublicKeyInfo) ASN1Util.decode(
          new SubjectPublicKeyInfo.Template(), pair.getPublic().getEncoded());

      CertificateInfo info = new CertificateInfo(
          CertificateInfo.v3,
          new INTEGER(1),
          sigAlgID,
          subject,  // issuer
          notBefore,
          notAfter,
          subject,  // subject (self-signed)
          spki);

      Certificate cert = new Certificate(info, pair.getPrivate(), sigAlg);

      // Import cert into NSS database
      cm.importCertPackage(ASN1Util.encode(cert), nickname);

      return pair;
  }

}
