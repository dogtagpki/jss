//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//

package org.mozilla.jss.tests;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
import javax.crypto.KEM;

import org.mozilla.jss.crypto.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.util.PasswordCallback;

/**
 * ML-KEM key wrapping tests.
 *
 * Tests wrapping/unwrapping of various private key types using
 * AES-256 keys derived from ML-KEM-768 encapsulation with
 * AES-KWP (CKM_AES_KEY_WRAP_KWP) for HSM/FIPS compatibility.
 * This validates the PQC key archival/recovery flow for KRA.
 */

public class MLKEMKeyWrapping {

    public static void main(String args[]) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: MLKEMKeyWrapping <passwordfile>");
            System.exit(1);
        }

        // CryptoManager is already initialized via java.security configuration.
        // The NSS database location is determined by the java.security provider
        // configuration, not by command-line arguments.
        CryptoManager cm = CryptoManager.getInstance();

        // Login to key storage token if not already logged in
        CryptoToken keyToken = cm.getInternalKeyStorageToken();
        if (!keyToken.isLoggedIn()) {
            PasswordCallback passwordCallback = new FilePasswordCallback(args[0]);
            keyToken.login(passwordCallback);
        }

        // Generate ML-KEM-768 keypair for deriving wrapping key
        System.out.println("Generating ML-KEM-768 keypair for key wrapping...");
        KeyPairGenerator kpgKEM = keyToken.getKeyPairGenerator(KeyPairAlgorithm.MLKEM);
        kpgKEM.initialize(new NamedParameterSpec("ML-KEM-768"));
        kpgKEM.temporaryPairs(true);
        kpgKEM.sensitivePairs(true);
        KeyPair kemPair = kpgKEM.genKeyPair();
        PublicKey kemPub = kemPair.getPublic();
        PrivateKey kemPriv = (PrivateKey) kemPair.getPrivate();

        // Encapsulate to derive AES-256 wrapping key
        System.out.println("Deriving AES-256 wrapping key via ML-KEM-768 encapsulation...");
        KEM kem = KEM.getInstance("ML-KEM", "Mozilla-JSS");
        KEM.Encapsulator encapsulator = kem.newEncapsulator(kemPub);
        KEM.Encapsulated encap = encapsulator.encapsulate(0, 32, "AES-ECB");
        byte[] encapsulation = encap.encapsulation();
        SymmetricKey wrappingKey = (SymmetricKey) encap.key();

        // Test 1: Wrap/unwrap RSA-2048 private key
        System.out.println("\n=== Test 1: (ML-KEM & AES-KWP) Wrapping RSA-2048 private key ===");
        testWrapUnwrapRSA(keyToken, wrappingKey);

        // Test 2: Wrap/unwrap EC P-256 private key
        System.out.println("\n=== Test 2: (ML-KEM & AES-KWP) Wrapping EC P-256 private key ===");
        testWrapUnwrapEC(keyToken, wrappingKey);

        // Test 3: Wrap/unwrap ML-KEM-1024 private key
        System.out.println("\n=== Test 3: (ML-KEM & AES-KWP) Wrapping ML-KEM-1024 private key ===");
        testWrapUnwrapMLKEM(keyToken, wrappingKey);

        // Test 4: Wrap/unwrap ML-DSA-44 private key (smallest ML-DSA variant)
        System.out.println("\n=== Test 4: (ML-KEM & AES-KWP) Wrapping ML-DSA-44 private key ===");
        testWrapUnwrapMLDSA44(keyToken, wrappingKey);

        // Verify decapsulation recovers same wrapping key
        System.out.println("\n=== Verifying decapsulation ===");
        KEM.Decapsulator decapsulator = kem.newDecapsulator(kemPriv);
        SymmetricKey recoveredKey = (SymmetricKey) decapsulator.decapsulate(encapsulation, 0, 32, "AES-ECB");

        // Prove the recovered key matches the original wrapping key by encrypting with one
        // and decrypting with the other
        byte[] probe = Cipher.pad(new byte[] { 0x01, 0x02, 0x03, 0x04 },
                EncryptionAlgorithm.AES_256_ECB.getBlockSize());

        Cipher encryptor = keyToken.getCipherContext(EncryptionAlgorithm.AES_256_ECB);
        encryptor.initEncrypt(wrappingKey);
        byte[] encryptedProbe = encryptor.doFinal(probe);

        Cipher decryptor = keyToken.getCipherContext(EncryptionAlgorithm.AES_256_ECB);
        decryptor.initDecrypt(recoveredKey);
        byte[] decryptedProbe = decryptor.doFinal(encryptedProbe);

        if (!java.util.Arrays.equals(probe, decryptedProbe)) {
            throw new Exception("Decapsulation recovered a different wrapping key");
        }
        System.out.println("Decapsulation successful - wrapping key recovered and verified");

        System.out.println("\nAll ML-KEM key wrapping tests passed!");
    }

    /**
     * Test wrapping/unwrapping RSA-2048 private key with ML-KEM-derived AES-256
     */
    private static void testWrapUnwrapRSA(CryptoToken keyToken, SymmetricKey wrappingKey)
            throws Exception {
        // Generate RSA keypair
        KeyPairGenerator kpgRSA = keyToken.getKeyPairGenerator(KeyPairAlgorithm.RSA);
        kpgRSA.initialize(Policy.RSA_MINIMUM_KEY_SIZE);
        kpgRSA.temporaryPairs(true);
        kpgRSA.sensitivePairs(true);  // Required in FIPS mode after PQC operations
        KeyPair rsaPair = kpgRSA.genKeyPair();
        PublicKey rsaPub = rsaPair.getPublic();
        PrivateKey rsaPriv = (PrivateKey) rsaPair.getPrivate();

        System.out.println("Generated RSA-" + Policy.RSA_MINIMUM_KEY_SIZE + " keypair");
        System.out.println("Original RSA private key ID: ");
        displayByteArray(rsaPriv.getUniqueID());

        // Wrap RSA private key with AES-KWP (using standard PKCS#11 mechanism for HSM compatibility)
        KeyWrapper keyWrap = keyToken.getKeyWrapper(KeyWrapAlgorithm.AES_KEY_WRAP_PAD_KWP);
        keyWrap.initWrap(wrappingKey, null);
        byte[] wrappedKey = keyWrap.wrap(rsaPriv);
        System.out.println("Wrapped RSA private key (" + wrappedKey.length + " bytes)");

        // Unwrap RSA private key
        keyWrap.initUnwrap(wrappingKey, null);
        PrivateKey unwrappedRSA = keyWrap.unwrapTemporaryPrivate(wrappedKey, PrivateKey.RSA, rsaPub);
        System.out.println("Unwrapped RSA private key ID: ");
        displayByteArray(unwrappedRSA.getUniqueID());

        // Verify by signing data with unwrapped key
        verifyRSAKey(keyToken, unwrappedRSA, rsaPub);
        System.out.println("RSA wrap/unwrap test PASSED");
    }

    /**
     * Test wrapping/unwrapping EC P-256 private key with ML-KEM-derived AES-256
     */
    private static void testWrapUnwrapEC(CryptoToken keyToken, SymmetricKey wrappingKey)
            throws Exception {
        // Generate EC P-256 keypair
        KeyPairGenerator kpgEC = keyToken.getKeyPairGenerator(KeyPairAlgorithm.EC);
        kpgEC.initialize(256);  // P-256
        kpgEC.temporaryPairs(true);
        kpgEC.sensitivePairs(true);  // Required in FIPS mode after PQC operations
        KeyPair ecPair = kpgEC.genKeyPair();
        PublicKey ecPub = ecPair.getPublic();
        PrivateKey ecPriv = (PrivateKey) ecPair.getPrivate();

        System.out.println("Generated EC P-256 keypair");
        System.out.println("Original EC private key ID: ");
        displayByteArray(ecPriv.getUniqueID());

        // Wrap EC private key with AES-KWP (using standard PKCS#11 mechanism for HSM compatibility)
        KeyWrapper keyWrap = keyToken.getKeyWrapper(KeyWrapAlgorithm.AES_KEY_WRAP_PAD_KWP);
        keyWrap.initWrap(wrappingKey, null);
        byte[] wrappedKey = keyWrap.wrap(ecPriv);
        System.out.println("Wrapped EC private key (" + wrappedKey.length + " bytes)");

        // Unwrap EC private key
        keyWrap.initUnwrap(wrappingKey, null);
        PrivateKey unwrappedEC = keyWrap.unwrapTemporaryPrivate(wrappedKey, PrivateKey.EC, ecPub);
        System.out.println("Unwrapped EC private key ID: ");
        displayByteArray(unwrappedEC.getUniqueID());

        // Verify by signing data with unwrapped key
        verifyECKey(keyToken, unwrappedEC, ecPub);
        System.out.println("EC wrap/unwrap test PASSED");
    }

    /**
     * Test wrapping/unwrapping ML-KEM-1024 private key with ML-KEM-768-derived AES-256
     */
    private static void testWrapUnwrapMLKEM(CryptoToken keyToken, SymmetricKey wrappingKey)
            throws Exception {
        // Generate ML-KEM-1024 keypair
        KeyPairGenerator kpgKEM = keyToken.getKeyPairGenerator(KeyPairAlgorithm.MLKEM);
        kpgKEM.initialize(new NamedParameterSpec("ML-KEM-1024"));
        kpgKEM.temporaryPairs(true);
        kpgKEM.sensitivePairs(true);
        KeyPair kemPair = kpgKEM.genKeyPair();
        PublicKey kemPub = kemPair.getPublic();
        PrivateKey kemPriv = (PrivateKey) kemPair.getPrivate();

        System.out.println("Generated ML-KEM-1024 keypair");
        System.out.println("Original ML-KEM private key ID: ");
        displayByteArray(kemPriv.getUniqueID());

        // Wrap ML-KEM private key with AES-KWP (using standard PKCS#11 mechanism for HSM compatibility)
        KeyWrapper keyWrap = keyToken.getKeyWrapper(KeyWrapAlgorithm.AES_KEY_WRAP_PAD_KWP);
        keyWrap.initWrap(wrappingKey, null);
        byte[] wrappedKey = keyWrap.wrap(kemPriv);
        System.out.println("Wrapped ML-KEM private key (" + wrappedKey.length + " bytes)");

        // Unwrap ML-KEM private key
        keyWrap.initUnwrap(wrappingKey, null);
        PrivateKey unwrappedKEM = keyWrap.unwrapTemporaryPrivate(wrappedKey, PrivateKey.MLKEM1024, kemPub);
        System.out.println("Unwrapped ML-KEM private key ID: ");
        displayByteArray(unwrappedKEM.getUniqueID());

        // Verify by performing decapsulation with unwrapped key
        verifyMLKEMKey(keyToken, unwrappedKEM, kemPub);
        System.out.println("ML-KEM wrap/unwrap test PASSED");
    }

    /**
     * Test wrapping/unwrapping ML-DSA-44 private key with ML-KEM-derived AES-256
     *
     * Note: ML-DSA-44 is the smallest ML-DSA variant (~2560 bytes) and currently
     * the largest that NSS will successfully wrap. Larger variants (ML-DSA-65 and
     * ML-DSA-87) fail with SEC_ERROR_OUTPUT_LEN even with larger buffer sizes.
     */
    private static void testWrapUnwrapMLDSA44(CryptoToken keyToken, SymmetricKey wrappingKey)
            throws Exception {
        // Generate ML-DSA-44 keypair
        KeyPairGenerator kpgDSA = keyToken.getKeyPairGenerator(KeyPairAlgorithm.MLDSA);
        kpgDSA.initialize(new NamedParameterSpec("ML-DSA-44"));
        kpgDSA.temporaryPairs(true);
        kpgDSA.sensitivePairs(true);
        KeyPair dsaPair = kpgDSA.genKeyPair();
        PublicKey dsaPub = dsaPair.getPublic();
        PrivateKey dsaPriv = (PrivateKey) dsaPair.getPrivate();

        System.out.println("Generated ML-DSA-44 keypair");
        System.out.println("Original ML-DSA private key ID: ");
        displayByteArray(dsaPriv.getUniqueID());

        // Wrap ML-DSA private key with AES-KWP (using standard PKCS#11 mechanism for HSM compatibility)
        KeyWrapper keyWrap = keyToken.getKeyWrapper(KeyWrapAlgorithm.AES_KEY_WRAP_PAD_KWP);
        keyWrap.initWrap(wrappingKey, null);
        byte[] wrappedKey = keyWrap.wrap(dsaPriv);
        System.out.println("Wrapped ML-DSA private key (" + wrappedKey.length + " bytes)");

        // Unwrap ML-DSA private key
        keyWrap.initUnwrap(wrappingKey, null);
        PrivateKey unwrappedDSA = keyWrap.unwrapTemporaryPrivate(wrappedKey, PrivateKey.MLDSA44, dsaPub);
        System.out.println("Unwrapped ML-DSA private key ID: ");
        displayByteArray(unwrappedDSA.getUniqueID());

        // Verify by signing data with unwrapped key
        verifyMLDSAKey(keyToken, unwrappedDSA, dsaPub);
        System.out.println("ML-DSA wrap/unwrap test PASSED");
    }

    /**
     * Verify RSA key by signing and verifying data
     */
    private static void verifyRSAKey(CryptoToken token, PrivateKey privKey, PublicKey pubKey)
            throws Exception {
        byte[] data = "Test data for RSA signature".getBytes(StandardCharsets.UTF_8);

        Signature signer = token.getSignatureContext(SignatureAlgorithm.RSASignatureWithSHA256Digest);
        signer.initSign(privKey);
        signer.update(data);
        byte[] signature = signer.sign();

        Signature verifier = token.getSignatureContext(SignatureAlgorithm.RSASignatureWithSHA256Digest);
        verifier.initVerify(pubKey);
        verifier.update(data);
        boolean valid = verifier.verify(signature);

        if (!valid) {
            throw new Exception("RSA signature verification failed");
        }
        System.out.println("RSA signature verification successful");
    }

    /**
     * Verify EC key by signing and verifying data
     */
    private static void verifyECKey(CryptoToken token, PrivateKey privKey, PublicKey pubKey)
            throws Exception {
        byte[] data = "Test data for EC signature".getBytes(StandardCharsets.UTF_8);

        Signature signer = token.getSignatureContext(SignatureAlgorithm.ECSignatureWithSHA256Digest);
        signer.initSign(privKey);
        signer.update(data);
        byte[] signature = signer.sign();

        Signature verifier = token.getSignatureContext(SignatureAlgorithm.ECSignatureWithSHA256Digest);
        verifier.initVerify(pubKey);
        verifier.update(data);
        boolean valid = verifier.verify(signature);

        if (!valid) {
            throw new Exception("EC signature verification failed");
        }
        System.out.println("EC signature verification successful");
    }

    /**
     * Verify ML-KEM key by performing encapsulation/decapsulation
     */
    private static void verifyMLKEMKey(CryptoToken token, PrivateKey privKey, PublicKey pubKey)
            throws Exception {
        KEM kem = KEM.getInstance("ML-KEM", "Mozilla-JSS");

        // Encapsulate
        KEM.Encapsulator enc = kem.newEncapsulator(pubKey);
        KEM.Encapsulated encap = enc.encapsulate(0, 32, "AES-ECB");
        byte[] ciphertext = encap.encapsulation();
        SymmetricKey sharedSecret1 = (SymmetricKey) encap.key();

        // Decapsulate with unwrapped key
        KEM.Decapsulator dec = kem.newDecapsulator(privKey);
        SymmetricKey sharedSecret2 = (SymmetricKey) dec.decapsulate(ciphertext, 0, 32, "AES-ECB");

        // Verify both keys can encrypt/decrypt the same data
        byte[] plaintext = new byte[] {
            (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04,
            (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08,
            (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c,
            (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10
        };
        byte[] plaintextPad = Cipher.pad(plaintext, EncryptionAlgorithm.AES_256_ECB.getBlockSize());

        Cipher encryptor = token.getCipherContext(EncryptionAlgorithm.AES_256_ECB);
        encryptor.initEncrypt(sharedSecret1);
        byte[] cipherData = encryptor.doFinal(plaintextPad);

        Cipher decryptor = token.getCipherContext(EncryptionAlgorithm.AES_256_ECB);
        decryptor.initDecrypt(sharedSecret2);
        byte[] recovered = decryptor.doFinal(cipherData);
        byte[] recoveredUnpad = Cipher.unPad(recovered, EncryptionAlgorithm.AES_256_ECB.getBlockSize());

        if (!java.util.Arrays.equals(plaintext, recoveredUnpad)) {
            throw new Exception("ML-KEM encapsulation/decapsulation failed");
        }
        System.out.println("ML-KEM encapsulation/decapsulation successful");
    }

    /**
     * Verify ML-DSA-44 key by signing and verifying data
     */
    private static void verifyMLDSAKey(CryptoToken token, PrivateKey privKey, PublicKey pubKey)
            throws Exception {
        byte[] data = "Test data for ML-DSA signature".getBytes(StandardCharsets.UTF_8);

        Signature signer = token.getSignatureContext(SignatureAlgorithm.MLDSA44);
        signer.initSign(privKey);
        signer.update(data);
        byte[] signature = signer.sign();

        Signature verifier = token.getSignatureContext(SignatureAlgorithm.MLDSA44);
        verifier.initVerify(pubKey);
        verifier.update(data);
        boolean valid = verifier.verify(signature);

        if (!valid) {
            throw new Exception("ML-DSA signature verification failed");
        }
        System.out.println("ML-DSA signature verification successful");
    }

    /**
     * Display byte array in hex format
     */
    private static void displayByteArray(byte[] ba) {
        if (ba == null) {
            System.out.println("[null]");
            return;
        }
        System.out.print("[" + ba.length + " bytes] ");
        for (int i = 0; i < ba.length && i < 16; i++) {  // Show first 16 bytes
            System.out.printf("%02x ", ba[i] & 0xff);
        }
        if (ba.length > 16) {
            System.out.print("...");
        }
        System.out.println("");
    }
}
