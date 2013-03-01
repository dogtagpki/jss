/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.SecretDecoderRing;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.TokenException;
import java.io.*;

/**
 * Encrypts data with the SecretDecoderRing.
 */
public class Encryptor {

    private CryptoToken token;
    private byte[] keyID;
    private SecretKey key;
    private EncryptionAlgorithm alg;
    private KeyManager keyManager;

    /**
     * The default encryption algorithm, currently DES3_CBC.
     */
    public static final EncryptionAlgorithm DEFAULT_ENCRYPTION_ALG
        = EncryptionAlgorithm.DES3_CBC;

    static final String PROVIDER = "Mozilla-JSS";
    static final String RNG_ALG = "pkcs11prng";

    /**
     * Creates an Encryptor on the given CryptoToken, using the key with
     * the given keyID and algorithm
     * @param token The CryptoToken to use for encryption. The key must
     *  reside on this token.
     * @param keyID The keyID of the key to use for encryption. This key
     *  must have been generated on this token with KeyManager.
     * @param alg The EncryptionAlgorithm this key will be used for.
     * @throws InvalidKeyException If no key exists on this token with this
     *  keyID.
     */
    public Encryptor(CryptoToken token, byte[] keyID, EncryptionAlgorithm alg)
            throws TokenException, InvalidKeyException
    {
        this.token = token;
        this.keyID = keyID;
        this.alg = alg;
        this.keyManager = new KeyManager(token);

        // make sure this key exists on the token
        key = keyManager.lookupKey(alg, keyID);
        if( key == null ) {
            throw new InvalidKeyException("Key not found");
        }

        // make sure key matches algorithm
        // !!! not sure how to do this
    }

    /**
     * Encrypts a byte array.
     * @param plaintext The plaintext bytes to be encrypted.
     * @return The ciphertext. This is actually a DER-encoded Encoding
     *  object. It contains the keyID, AlgorithmIdentifier, and the encrypted
     *  plaintext. It is compatible with the SDRResult created by NSS's
     *  SecretDecoderRing.
     */
    public byte[] encrypt(byte[] plaintext) throws
            CryptoManager.NotInitializedException,
            GeneralSecurityException,
            InvalidBERException
    {
        CryptoManager cm = CryptoManager.getInstance();

        CryptoToken savedToken = cm.getThreadToken();

        try {
            cm.setThreadToken(token);

            //
            // generate an IV
            //
            byte[] iv = new byte[alg.getIVLength()];
            SecureRandom rng = SecureRandom.getInstance(RNG_ALG,
                PROVIDER);
            rng.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            //
            // do the encryption
            //
            Cipher cipher = Cipher.getInstance(alg.toString(),PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] paddedPtext = 
                org.mozilla.jss.crypto.Cipher.pad(
                    plaintext, alg.getBlockSize() );
            byte[] rawCtext = cipher.doFinal(paddedPtext);

            //
            // package the encrypted content and IV
            //
            Encoding encoding =
                new Encoding(keyID, iv, alg.toOID(), rawCtext);

            return ASN1Util.encode(encoding);

        } catch(IllegalStateException ise ) {
            throw new GeneralSecurityException(ise.toString());
        } finally {
            cm.setThreadToken(savedToken);
        }
    }
}
