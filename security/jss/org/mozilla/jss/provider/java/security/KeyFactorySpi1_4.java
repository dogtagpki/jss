/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.provider.java.security;

import java.security.PublicKey;
import java.security.spec.*;
import org.mozilla.jss.crypto.InvalidKeyFormatException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkcs11.PK11PubKey;
import java.security.Key;
import java.security.InvalidKeyException;
import javax.crypto.spec.DHPublicKeySpec;

public class KeyFactorySpi1_4 extends KeyFactorySpi1_2
{

    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if( keySpec instanceof DHPublicKeySpec ) {
            DHPublicKeySpec spec = (DHPublicKeySpec) keySpec;

            // Generate a DER DH public key
            INTEGER pubval = new INTEGER( spec.getY() );

            return PK11PubKey.fromRaw( PrivateKey.DiffieHellman,
                        ASN1Util.encode(pubval));
        } else {
            return super.engineGeneratePublic(keySpec);
        }
    }

}
