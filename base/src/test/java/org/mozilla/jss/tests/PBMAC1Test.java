/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.pkcs12.AuthenticatedSafes;
import org.mozilla.jss.pkcs12.MacType;
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

import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BMPString;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.pkcs12.CertBag;
import org.mozilla.jss.pkcs12.SafeBag;

/**
 * Test PBMAC1 (RFC 9879) MAC computation for PKCS#12.
 */
public class PBMAC1Test {

    /**
    * Runs all PBMAC1 tests.
    *
    * @param args dbdir and password file path
    */
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

            // Test classic path
            testClassicMAC();

            //Test creating and verifying actual p12 file

            testCreateP12WithPBMAC1(args[0]);

            // Test creating an actual P12 with classic everything
            testCreateP12WithClassicMAC(args[0]);

            // Test creating a P12 with class MaC but KWP encryption.
            testCreateP12WithKWP(args[0], MacType.CLASSIC);

            // Test cerating a P12 with pbmac1 and KWP encryption.
            testCreateP12WithKWP(args[0], MacType.PBMAC1);

            //Test some rfc verifications

            testRFC9879Vectors();

            System.out.println("\nAll PBMAC1 and Classic MAC and p12 tests PASSED!");

        } catch (Exception e) {
            System.err.println("PBMAC1 test FAILED: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
    * Test PBMAC1 with a specific digest algorithm.
    *
    * @param name Display name for the digest
    * @param digest The digest algorithm to test
    * @param expectedMacLen Expected MAC output length in bytes
    */
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

    /**
    * Verifies that identical inputs produce identical PBMAC1 output.
    */
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

    /**
    * Verifies classic MAC path still works with default settings.
    */
    private static void testClassicMAC() throws Exception {
        System.out.println("Testing Classic MAC (backward compatibility)...");

        Password password = new Password("classicPassword".toCharArray());
        byte[] salt = new byte[16];
        fillTestSalt(salt);
        int iterations = 100000;

        // Create AuthenticatedSafes
        AuthenticatedSafes authSafes = new AuthenticatedSafes();
        authSafes.addSafeContents(new SEQUENCE());

        // Create PFX - DON'T set MacType (should default to CLASSIC)
        PFX pfx = new PFX(authSafes);

        // Compute MAC using default (classic) algorithm
        pfx.computeMacData(password, salt, iterations);

        // Verify MAC was created
        MacData macData = pfx.getMacData();
        if (macData == null || macData.getMac() == null) {
            throw new Exception("Classic MAC computation failed - MacData is null");
        }

        // Verify MAC length (SHA-256 = 32 bytes, which is the classic default)
        byte[] macValue = macData.getMac().getDigest().toByteArray();
        if (macValue.length != 32) {
            throw new Exception("Classic MAC length unexpected: " + macValue.length);
        }

        System.out.println("  ✓ Classic MAC created successfully");
        System.out.println("  ✓ MAC length: " + macValue.length + " bytes (SHA-256)");
        System.out.println("  ✓ Classic MAC test PASSED\n");

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

    /**
    * Tests full PKCS#12 round-trip: create, export with PBMAC1, delete, re-import.
    *
    * @param dbdir Path to the NSS database directory
    */
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

  /**
   * Tests PKCS#12 file creation with classic MAC (backward compatibility).
   *
   * @param dbdir Path to the NSS database directory
   */
  private static void testCreateP12WithClassicMAC(String dbdir) throws Exception {
          System.out.println("Testing PKCS#12 file creation with classic MAC...");

          CryptoManager cm = CryptoManager.getInstance();

          String nickname = "Classic-Test" + System.currentTimeMillis();
          java.security.KeyPair pair = generateTestCertAndKey("RSA", 2048, nickname);

          System.out.println("  ✓ Generated 2048-bit RSA cert/key: " + nickname);

          X509Certificate nssCert = cm.findCertByNickname(nickname);

          PKCS12 pkcs12 = new PKCS12();
          PKCS12Util util = new PKCS12Util();
          util.loadCertFromNSS(pkcs12, nssCert, true, false);

          // Don't set MacType - use default (CLASSIC)
          Password password = new Password("test123".toCharArray());
          String filename = dbdir + "/test-classic.p12";
          util.storeIntoFile(pkcs12, filename, password);

          System.out.println("  ✓ Exported to: " + filename);
          System.out.println("  ✓ MAC type: Classic (SHA-256 HMAC)");

          CryptoStore store = cm.getInternalKeyStorageToken().getCryptoStore();
          store.deleteCert(nssCert);

          PKCS12 pkcs12imported = util.loadFromFile(filename, password);
          util.storeIntoNSS(pkcs12imported, password, false);

          System.out.println("  ✓ Re-imported from PKCS#12 file");

          X509Certificate restoredCert = cm.findCertByNickname(nickname);
          if (restoredCert == null) {
              throw new Exception("Cert not restored from PKCS#12!");
          }

          System.out.println("  ✓ Cert/key successfully restored");

          store.deleteCert(restoredCert);
          password.clear();

          System.out.println("  ✓ Classic MAC PKCS#12 round-trip test PASSED\n");
      }

    /**
    * Generates a self-signed test certificate and keypair in the NSS database.
    *
    * @param keyType Key algorithm (RSA or EC)
    * @param keySize Key size in bits
    * @param nickname Certificate nickname
    * @return The generated keypair
    */
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

    /**
    * Test PBMAC1 verification against RFC 9879 Appendix A test vectors.
    * All test vectors use password "1234".
    */
    private static void testRFC9879Vectors() throws Exception {
        System.out.println("Testing RFC 9879 Appendix A test vectors...\n");

        // A.1: SHA-256 HMAC and PRF (MUST support)
        String vectorA1 =
            "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"
          + "3QQITk9UIFVTRUQCAQE=";

        // A.4: Invalid - Incorrect Iteration Count (MUST reject)
        String vectorA4 =
            "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"
          + "3QQITk9UIFVTRUQCAggA";

        Password password = new Password("1234".toCharArray());

        // Test valid vector (MUST pass)
        testRFC9879Vector("A.1 (SHA-256 HMAC+PRF)", vectorA1, password, true);

        // Test invalid vector (MUST fail)
        testRFC9879Vector("A.4 (incorrect iteration count)", vectorA4, password, false);

        password.clear();
        System.out.println("  RFC 9879 test vectors PASSED\n");
    }

    /**
     * Verifies a single RFC 9879 test vector.
     *
     * @param name Display name for the test vector
     * @param base64Data Base64-encoded PKCS#12 data
     * @param password Password for verification
     * @param expectValid True if verification should succeed
   */
    private static void testRFC9879Vector(String name, String base64Data,
            Password password, boolean expectValid) throws Exception {
        System.out.println("  Testing RFC 9879 vector " + name + "...");

        byte[] p12Bytes = java.util.Base64.getDecoder().decode(base64Data);

        PFX.Template pfxTemplate = new PFX.Template();
        PFX pfx = (PFX) pfxTemplate.decode(
            new java.io.ByteArrayInputStream(p12Bytes));

        StringBuffer reason = new StringBuffer();
        boolean verified = pfx.verifyAuthSafes(password, reason);

        if (expectValid && !verified) {
            throw new Exception("RFC 9879 vector " + name +
                " should verify but failed: " + reason);
        } else if (!expectValid && verified) {
            throw new Exception("RFC 9879 vector " + name +
                " should fail verification but passed");
        }

        System.out.println("    " + (expectValid ? "verified" : "correctly rejected") +
            (reason.length() > 0 ? " (" + reason + ")" : ""));
    }

    /**
      * Tests PKCS#12 file creation using non-legacy KWP encryption
      * for the private key, mirroring the KRA non-legacy recovery path.
      *
      * @param dbdir Path to the NSS database directory
      * @param macType The MAC type (CLASSIC or PBMAC1)
    */
    private static void testCreateP12WithKWP(String dbdir, MacType macType) throws Exception {
          System.out.println("Testing PKCS#12 file creation with KWP encryption + " + macType.name() + " MAC...");

          CryptoManager cm = CryptoManager.getInstance();
          CryptoToken ct = cm.getInternalKeyStorageToken();

          // 1. Generate test cert and key
          String nickname = "KWP-Test" + System.currentTimeMillis();
          java.security.KeyPair pair = generateTestCertAndKey("RSA", 2048, nickname);

          System.out.println("  Generated 2048-bit RSA cert/key: " + nickname);

          // 2. Get the certificate and private key
          X509Certificate nssCert = cm.findCertByNickname(nickname);
          org.mozilla.jss.crypto.PrivateKey priKey =
              (org.mozilla.jss.crypto.PrivateKey) pair.getPrivate();

          // 3. Encrypt private key using KWP path (non-legacy)
          Password pass = new Password("test123".toCharArray());
          EncryptionAlgorithm encAlg = EncryptionAlgorithm.fromString("AES/None/PKCS5Padding/Kwp/256");
          if (encAlg == null) {
              throw new Exception("KWP algorithm unavailable; this test would not exercise the KWP path");
          }

          byte[] epkiBytes = ct.getCryptoStore().getEncryptedPrivateKeyInfo(
              null /* no passConverter for non-legacy */,
              pass,
              encAlg,
              0 /* iterations (use default) */,
              priKey);

          if (epkiBytes == null) {
              throw new Exception("getEncryptedPrivateKeyInfo returned null");
          }

          System.out.println("  Encrypted private key with: " + encAlg);

          ASN1Value key = new ANY(epkiBytes);

          // 4. Build cert bag
          byte[] localKeyId = createLocalKeyId(nssCert);
          SET certAttrs = createBagAttrs(nickname, localKeyId);
          ASN1Value cert = new OCTET_STRING(nssCert.getEncoded());
          SafeBag certBag = new SafeBag(SafeBag.CERT_BAG,
              new CertBag(CertBag.X509_CERT_TYPE, cert),
              certAttrs);

          SEQUENCE encSafeContents = new SEQUENCE();
          encSafeContents.addElement(certBag);

          // 5. Build key bag
          SET keyAttrs = createBagAttrs(nickname, localKeyId);
          SafeBag keyBag = new SafeBag(
              SafeBag.PKCS8_SHROUDED_KEY_BAG, key, keyAttrs);

          SEQUENCE safeContents = new SEQUENCE();
          safeContents.addElement(keyBag);

          // 6. Build AuthenticatedSafes and PFX
          AuthenticatedSafes authSafes = new AuthenticatedSafes();
          authSafes.addSafeContents(safeContents);
          authSafes.addSafeContents(encSafeContents);

          PFX pfx = new PFX(authSafes);
          pfx.setMacType(macType);
          pfx.setMacDigest(DigestAlgorithm.SHA256);

          pfx.computeMacData(pass, null, 100000);

          // 7. Write to file
          String filename = dbdir + "/test-kwp-" + macType.name().toLowerCase() + ".p12";
          java.io.FileOutputStream fos = new java.io.FileOutputStream(filename);
          pfx.encode(fos);
          fos.close();

          System.out.println("  Exported to: " + filename);

          // 8. Cleanup
          CryptoStore store = ct.getCryptoStore();
          store.deleteCert(nssCert);
          pass.clear();

          System.out.println("  PKCS#12 with KWP encryption test PASSED\n");
      }

      /**
       * Creates a local key ID from a certificate's SHA-1 fingerprint.
       *
       * @param cert The certificate
       * @return The SHA-1 digest of the encoded certificate
      */
      private static byte[] createLocalKeyId(X509Certificate cert)
          throws Exception {
          java.security.MessageDigest md =
              java.security.MessageDigest.getInstance("SHA-1");
          return md.digest(cert.getEncoded());
      }

      /**
       * Creates PKCS#12 bag attributes with friendly name and local key ID.
       *
       * @param nickname The friendly name
       * @param localKeyId The local key ID
       * @return The attribute SET
      */
      private static SET createBagAttrs(String nickname, byte[] localKeyId)
          throws Exception {
          SET attrs = new SET();

          SEQUENCE nicknameAttr = new SEQUENCE();
          nicknameAttr.addElement(SafeBag.FRIENDLY_NAME);
          SET nicknameSet = new SET();
          nicknameSet.addElement(new BMPString(nickname));
          nicknameAttr.addElement(nicknameSet);
          attrs.addElement(nicknameAttr);

          SEQUENCE localKeyIdAttr = new SEQUENCE();
          localKeyIdAttr.addElement(SafeBag.LOCAL_KEY_ID);
          SET localKeyIdSet = new SET();
          localKeyIdSet.addElement(new OCTET_STRING(localKeyId));
          localKeyIdAttr.addElement(localKeyIdSet);
          attrs.addElement(localKeyIdAttr);

          return attrs;
      }

}
