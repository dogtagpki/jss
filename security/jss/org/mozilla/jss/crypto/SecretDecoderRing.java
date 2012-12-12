/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import java.io.UnsupportedEncodingException;

/**
 * This is a special-purpose interface for NSS. It is used for encrypting
 * data with a secret key stored in the NSS key database (which is in turn
 * protected with a password). It thus provides a quick, convenient way
 * to encrypt stuff your application wants to keep around for its own use:
 * for example, the list of web passwords stored in the web browser.
 *
 * <p>A dedicated key is used to encrypt all SecretDecoderRing data.
 * The same key is used for all SDR data, and not for any other data.
 * This key will be generated the first time it is needed.
 *
 * <p>The cipher used is DES3-EDE (Triple-DES) in CBC mode. The ciphertext
 * is DER-encoded in the following ASN.1 data structure:
 * <pre>
 *    SEQUENCE {
 *      keyid       OCTET STRING,
 *      alg         AlgorithmIdentifier,
 *      ciphertext  OCTET STRING }
 * </pre>
 *
 * <p>You must set the password on the Internal Key Storage Token
 *   (aka software token, key3.db) before you use the SecretDecoderRing.
 */
public class SecretDecoderRing {

    public static final String encodingFormat = "UTF-8";

    /**
     * Encrypts the given plaintext with the Secret Decoder Ring key stored
     * in the NSS key database.
     */
    public native byte[] encrypt(byte[] plaintext)
        throws TokenException;

    /**
     * Encrypts the given plaintext string with the Secret Decoder Ring key
     * stored in the NSS key database.
     */
    public byte[] encrypt(String plaintext) throws TokenException {
      try {
        return encrypt(plaintext.getBytes(encodingFormat));
      } catch(UnsupportedEncodingException e) {
        // this shouldn't happen, because we use a universally-supported
        // charset
        throw new RuntimeException(e.getMessage());
      }
    }

    /**
     * Decrypts the given ciphertext with the Secret Decoder Ring key stored
     * in the NSS key database.
     */
    public native byte[] decrypt(byte[] ciphertext)
        throws TokenException;

    /**
     * Decrypts the given ciphertext with the Secret Decoder Ring key stored
     * in the NSS key database, returning the original plaintext string.
     */
    public String decryptToString(byte[] ciphertext)
            throws TokenException {
      try {
        return new String(decrypt(ciphertext), encodingFormat);
      } catch(UnsupportedEncodingException e) {
        // this shouldn't happen, because we use a universally-supported
        // charset
        throw new RuntimeException(e.getMessage());
      }
    }
}
