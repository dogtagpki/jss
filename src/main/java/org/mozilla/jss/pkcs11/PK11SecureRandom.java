/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

/**
 * A random number generator for PKCS #11.
 *
 * @see org.mozilla.jss.CryptoManager
 */
public final
class PK11SecureRandom implements org.mozilla.jss.crypto.JSSSecureRandom
{
    ////////////////////////////////////////////////////
    // construction and finalization
    ////////////////////////////////////////////////////

    public
    PK11SecureRandom() {}

    ////////////////////////////////////////////////////
    //  public routines
    ////////////////////////////////////////////////////

    @Override
    public synchronized native void
    setSeed( byte[] seed );

    @Override
    public void
    setSeed( long seed )
    {
        byte[] data = new byte[8];

        // convert long into 8-byte byte array
        for( int i = 0; i < 8; i++ ) {
             data[i] = ( byte ) ( seed >> ( 8 * i ) );
        }

        setSeed( data );
    }

    @Override
    public synchronized native void
    nextBytes( byte bytes[] );
}

