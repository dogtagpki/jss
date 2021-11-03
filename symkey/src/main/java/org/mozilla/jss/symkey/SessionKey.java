// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.mozilla.jss.symkey;

import org.mozilla.jss.pkcs11.PK11SymKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This object contains the OS independent interfaces.
 */
public class SessionKey {

    public static Logger logger = LoggerFactory.getLogger(SessionKey.class);

    static {
        loadLibrary();
    }

    private static void loadLibrary() {

        try {
            logger.debug("SessionKey: loading JSS symkey library from java.library.path");
            System.loadLibrary("jss-symkey");
            return;

        } catch (UnsatisfiedLinkError e) {
            logger.warn("Unable to load JSS symkey library from java.library.path: " + e.getMessage());
        }

        try {
            logger.debug("SessionKey: loading 64-bit JSS symkey library");
            System.load("/usr/lib64/jss/libjss-symkey.so");
            return;

        } catch (UnsatisfiedLinkError e) {
            logger.warn("Unable to load 64-bit JSS symkey library: " + e.getMessage());
        }

        try {
            logger.debug("SessionKey: loading 32-bit JSS symkey library");
            System.load("/usr/lib/java/libjss-symkey.so");
            return;

        } catch (UnsatisfiedLinkError e) {
            logger.warn("Unable to load 32-bit JSS symkey library: " + e.getMessage());
        }

        logger.error("Unable to load JSS symkey library");
        System.exit(-1);
    }

    // external calls from RA
    public static native byte[] ComputeKeyCheck(PK11SymKey desKey); /* byte data[] ); */

   //SCP02/GP211 methods

    public static native byte[] ComputeSessionKeySCP02(String tokenName,
            String keyName,
            byte[] keyInfo,
            byte nistSP800_108KdfOnKeyVersion,    // AC: KDF SPEC CHANGE
            boolean nistSP800_108KdfUseCuidAsKdd, // AC: KDF SPEC CHANGE
            byte[] CUID,
            byte[] KDD,
            byte[] devKeyArray,
            byte[] sequenceCounter,
            byte[] derivationConstant,
            String useSoftToken,
            String keySet,
            String sharedSecretKeyName);

    public static native byte[] ComputeSessionKey(String tokenName,
            String keyName,
            byte[] card_challenge,
            byte[] host_challenge,
            byte[] keyInfo,
            byte nistSP800_108KdfOnKeyVersion,    // AC: KDF SPEC CHANGE
            boolean nistSP800_108KdfUseCuidAsKdd, // AC: KDF SPEC CHANGE
            byte[] CUID,
            byte[] KDD,                           // AC: KDF SPEC CHANGE
            byte[] macKeyArray,
            String useSoftToken,
            String keySet,
            String sharedSecretKeyName);

    public static native byte[] ComputeEncSessionKey(String tokenName,
            String keyName,
            byte[] card_challenge,
            byte[] host_challenge,
            byte[] keyInfo,
            byte nistSP800_108KdfOnKeyVersion,    // AC: KDF SPEC CHANGE
            boolean nistSP800_108KdfUseCuidAsKdd, // AC: KDF SPEC CHANGE
            byte[] CUID,
            byte[] KDD,                           // AC: KDF SPEC CHANGE
            byte[] encKeyArray,
            String useSoftToken,
            String keySet);

    /* AC: KDF SPEC CHANGE; unused method with no JNI implementation
    public static native PK11SymKey ComputeKekSessionKey(String tokenName,
            String keyName,
            byte[] card_challenge,
            byte[] host_challenge,
            byte[] keyInfo,
            byte[] CUID,
            byte[] kekKeyArray,
            String useSoftToken,
            String keySet);
    */

    public static native PK11SymKey ComputeKekKey(String tokenName,
            String keyName,
            byte[] card_challenge,
            byte[] host_challenge,
            byte[] keyInfo,
            byte nistSP800_108KdfOnKeyVersion,    // AC: KDF SPEC CHANGE
            boolean nistSP800_108KdfUseCuidAsKdd, // AC: KDF SPEC CHANGE
            byte[] CUID,
            byte[] KDD,                           // AC: KDF SPEC CHANGE
            byte[] kekKeyArray,
            String useSoftToken, String keySet);

    public static native byte[] ECBencrypt(PK11SymKey key,
            PK11SymKey desKey); //byte[] data );

    public static native PK11SymKey GenerateSymkey(String tokenName);

    /*
     * DRM_SUPPORT_DEBUG
     */

    // public static native PK11SymKey bytes2PK11SymKey( byte[] symKeyBytes );

    public static native byte[] ComputeCryptogram(String tokenName,
            String keyName,
            byte[] card_challenge,
            byte[] host_challenge,
            byte[] keyInfo,
            byte nistSP800_108KdfOnKeyVersion,    // AC: KDF SPEC CHANGE
            boolean nistSP800_108KdfUseCuidAsKdd, // AC: KDF SPEC CHANGE
            byte[] CUID,
            byte[] KDD,                           // AC: KDF SPEC CHANGE
            int type,
            byte[] authKeyArray,
            String useSoftToken, String keySet);

    public static native byte[] EncryptData(String tokenName,
            String keyName,
            byte[] in,
            byte[] keyInfo,
            byte nistSP800_108KdfOnKeyVersion,    // AC: KDF SPEC CHANGE
            boolean nistSP800_108KdfUseCuidAsKdd, // AC: KDF SPEC CHANGE
            byte[] CUID,
            byte[] KDD,                           // AC: KDF SPEC CHANGE
            byte[] kekKeyArray,
            String useSoftToken, String keySet);

    public static native byte[] DiversifyKey(String tokenName,
            String newTokenName,
            String oldMasterKeyName,
            String newMasterKeyName,
            byte[] oldKeyInfo,          // AC: KDF SPEC CHANGE
          // AC: BUGFIX for key versions higher than 09:  We need to specialDecode keyInfo parameters before sending them into symkey!  This means the parameters must be jbyteArray's
          //     -- Changed parameter "jstring keyInfo" to "jbyteArray newKeyInfo"
            byte[] newKeyInfo,
            byte nistSP800_108KdfOnKeyVersion,    // AC: KDF SPEC CHANGE
            boolean nistSP800_108KdfUseCuidAsKdd, // AC: KDF SPEC CHANGE
            byte[] CUIDValue,
            byte[] KDD,                           // AC: KDF SPEC CHANGE
            byte[] kekKeyArray,
            String useSoftToken, String keySet,byte protocol);

    // internal calls from config TKS keys tab
    public static native String GenMasterKey(String token,
            String keyName);

    public static native String DeleteSymmetricKey(String token,
            String keyName);

    public static native String ListSymmetricKeys(String token);

    //  set when called from the config TKS tab to create master key
    //  get when called from the RA to create session key
    public static native void SetDefaultPrefix(String masterPrefix);

    // Functions that the TPS may use during processing to manipulate sym keys in such a way not available in JSS

    // Return a names Sym Key, in this case will be the shared secret in practice.
    public static native PK11SymKey GetSymKeyByName(String tokenName, String keyName);

    // TKS sends over the session key(s) wrapped with shared secret. TPS now does this unwrapping and creates the session keys
    // with functionality only available now in NSS. This is all to preserve exact functional parity with the current TKS.
    public static native PK11SymKey UnwrapSessionKeyWithSharedSecret(String tokenName, PK11SymKey sharedSecret,
            byte[] sessionKeyArray);

    public static native PK11SymKey DeriveDESKeyFrom3DesKey(String tokenName, PK11SymKey key3Des,long alg);
}
