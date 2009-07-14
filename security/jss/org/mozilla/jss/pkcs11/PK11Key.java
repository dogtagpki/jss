/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape Security Services for Java.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1998-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

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
