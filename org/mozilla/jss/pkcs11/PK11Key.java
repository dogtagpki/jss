/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import org.mozilla.jss.crypto.*;
import org.mozilla.jss.util.*;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;
import java.util.Hashtable;
import java.security.NoSuchAlgorithmException;
import org.mozilla.jss.crypto.SignatureAlgorithm;


abstract class PK11Key {

    //////////////////////////////////////////////////////////
    // Public Interface
    ///////////////////////////////////////////////////////////
    /**
     * Subclasses that support encoding can overload this method.
     */
    public byte[] getEncoded() {
        return null;
    }

    /**
     * Subclasses that support encoding can overload this method.
     */
    public String getFormat() {
        return null;
    }

    /////////////////////////////////////////////////////////////
    // Construction
    /////////////////////////////////////////////////////////////
    protected PK11Key() {}
        

    /////////////////////////////////////////////////////////////
    // Implementation
    /////////////////////////////////////////////////////////////
    // **HACK**
    // Override serialization methods so that we don't get serialized,
    // even though we are supposed to support it as an implementation of Key.
    private void writeObject(ObjectOutputStream out) throws IOException {
        Assert._assert(false, "PKCS#11 Key is not really serializable");
    }

    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException {
        Assert._assert(false, "PKCS#11 Key is not really serializable");
    }


    /////////////////////////////////////////////////////////////
    // Members
    /////////////////////////////////////////////////////////////
    protected KeyProxy keyProxy;

}
