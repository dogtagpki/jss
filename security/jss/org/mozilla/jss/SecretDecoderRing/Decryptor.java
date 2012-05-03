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
 * Decrypts data with the SecretDecoderRing.
 */
public class Decryptor {
    private CryptoToken token;
    private KeyManager keyManager;

    /**
     * Creates a Decryptor for use with the given CryptoToken.
     */
    public Decryptor(CryptoToken token) {
        this.token = token;
        this.keyManager = new KeyManager(token);
    }

    /**
     * Decrypts the given ciphertext. It must have been created previously
     * with the SecretDecoderRing, either the JSS version or the NSS version.
     * The key used for decryption must exist on the token that was passed
     * into the constructor. The token will be searched for a key whose keyID
     * matches the keyID in the encoded SecretDecoderRing result.
     *
     * @param ciphertext A DER-encoded Encoding object, created from a previous
     *  call to Encryptor.encrypt(), or with the NSS SecretDecoderRing.
     * @return The decrypted plaintext.
     * @throws InvalidKeyException If no key can be found with the matching
     *  keyID.
     */
    public byte[] decrypt(byte[] ciphertext)
        throws CryptoManager.NotInitializedException,
        GeneralSecurityException, TokenException
    {
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken savedToken = cm.getThreadToken();

        try {
            cm.setThreadToken(token);

            //
            // decode ASN1
            //
            Encoding encoding = (Encoding)
                ASN1Util.decode(Encoding.getTemplate(), ciphertext);

            //
            // lookup the algorithm
            //
            EncryptionAlgorithm alg = EncryptionAlgorithm.fromOID(
                encoding.getEncryptionOID() );

            //
            // Lookup the key
            //
            SecretKey key = keyManager.lookupKey(alg, encoding.getKeyID());
            if( key == null ) {
                throw new InvalidKeyException("No matching key found");
            }

            //
            // do the decryption
            //
            IvParameterSpec ivSpec = new IvParameterSpec(encoding.getIv());

            Cipher cipher = Cipher.getInstance(alg.toString(),
                Encryptor.PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

            byte[] paddedPtext = cipher.doFinal(encoding.getCiphertext());
            return org.mozilla.jss.crypto.Cipher.unPad(paddedPtext,
                alg.getBlockSize() );
        } catch(InvalidBERException ibe) {
            throw new GeneralSecurityException(ibe.toString());
        } catch(IllegalStateException ise) {
            throw new GeneralSecurityException(ise.toString());
        } catch(org.mozilla.jss.crypto.BadPaddingException bpe) {
            throw new javax.crypto.BadPaddingException(bpe.getMessage());
        } finally {
            cm.setThreadToken(savedToken);
        }
    }

}
