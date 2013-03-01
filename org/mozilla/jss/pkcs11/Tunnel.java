/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.SignatureSpi;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.util.Password;

final class Tunnel {

    private static class CryptoTunnel extends org.mozilla.jss.crypto.Tunnel
    {
        public static Signature
        constructSignature(SignatureAlgorithm alg, SignatureSpi engine) {
            return ConstructSignature(alg, engine);
        }
    }

    private static class UtilTunnel extends org.mozilla.jss.util.Tunnel
    {
        public static byte[]
        getPasswordByteCopy(Password pw) {
            return GetPasswordByteCopy(pw);
        }
    }

    static Signature
    constructSignature(SignatureAlgorithm alg, SignatureSpi engine) {
        return CryptoTunnel.constructSignature(alg, engine);
    }

    static byte[]
    getPasswordByteCopy(Password pw) {
        return UtilTunnel.getPasswordByteCopy(pw);
    }
}
