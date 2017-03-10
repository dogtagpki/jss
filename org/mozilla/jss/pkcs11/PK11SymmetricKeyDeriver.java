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
import org.mozilla.jss.util.Assert;
import sun.security.pkcs11.wrapper.*;
import java.security.InvalidKeyException;


/*This operation is pkcs11 based only */

public class PK11SymmetricKeyDeriver implements SymmetricKeyDeriver {

    private PK11Token token = null;
    private SymmetricKey baseKey = null;
    private SymmetricKey secondaryKey = null;
    private long deriveMechanism = 0;
    private long targetMechanism = 0;
    private long operation = 0;
    private long keySize = 0;
    private byte[] param = null;
    private byte[] iv = null;

    public PK11SymmetricKeyDeriver(PK11Token token)
    {
        this.token = token;
    }

    /* Use with the encrypt type mechanisms 

    Example: initDerive(
                    symKey, (PKCS11Constants.CKM_DES3_ECB_ENCRYPT_DATA) 4354L, derivationData, null,
                    PKCS11Constants.CKM_DES3_ECB, PKCS11Constants.CKA_DERIVE, 16);


   */
    public void initDerive(SymmetricKey baseKey, long deriveMech, byte[] param, byte[] iv, 
                              long targetMech, long operation, long keySize) throws InvalidKeyException
    {
        reset();

        if(baseKey == null) {
            throw new InvalidKeyException("Key is null");
        }

        this.baseKey = baseKey;
        this.deriveMechanism = deriveMech;
        this.targetMechanism = targetMech;
        this.operation = operation;

        if ( param != null) {
            this.param = new byte[param.length];
            System.arraycopy(param,0,this.param,0,param.length);
        }

        if ( iv != null) {
            this.iv = new byte[iv.length];
            System.arraycopy(iv,0,this.iv,0,iv.length);
        }

        this.keySize = keySize;

    }

    /* Use with key extraction and key concatanation mechanisms
       
    Example Extraction:
       param: byte array that has the bit position of where to extract
     initDerive(
                derivedKey, PKCS11Constants.CKM_EXTRACT_KEY_FROM_KEY,param,null,
                PKCS11Constants.CKA_ENCRYPT, PKCS11Constants.CKA_DERIVE,8);

    Example Concat:

    initDerive(
               baseSymKey,secondarySymKey, PKCS11Constants.CKM_CONCATENATE_BASE_AND_KEY,null,null,
               PKCS11Constants.CKM_DES3_ECB, PKCS11Constants.CKA_DERIVE,0);

    */ 

    public void initDerive(SymmetricKey baseKey, SymmetricKey secondaryKey, long deriveMech, 
        byte[] param, byte[] iv, long targetMech, long operation, long keySize) throws InvalidKeyException
    {
        reset();

        if ( baseKey == null || secondaryKey == null) {
            throw new InvalidKeyException("Key is null");
        }

        initDerive(baseKey, deriveMech, param,iv,targetMech,operation,keySize);
        this.secondaryKey = secondaryKey;

    }


    public SymmetricKey derive()
         throws TokenException
    {
        SymmetricKey result = deriveSymKey(this.baseKey,this.secondaryKey,this.deriveMechanism, this.param, this.iv, this.targetMechanism, this.operation,this.keySize);
        return result;
    }

    private SymmetricKey
    deriveSymKey(SymmetricKey baseKey, SymmetricKey secondaryKey, long deriveMechanism, byte[] param, byte[] iv, long targetMechanism, long operation, long keySize)
        throws TokenException, IllegalStateException
    {
        return nativeDeriveSymKey(token, baseKey, secondaryKey,deriveMechanism, param, iv, targetMechanism, operation, keySize);
    }

    public native SymmetricKey nativeDeriveSymKey(PK11Token token, SymmetricKey baseKey, SymmetricKey secondaryKey, long deriveMechanism, byte[] param, byte[] iv,
        long targetMechanism, long operation, long keySize);

    private void reset() {
        baseKey = null;
        secondaryKey = null;
        deriveMechanism = 0;
        targetMechanism = 0;
        operation = 0;
        keySize = 0;
        param = null;
        iv = null;
   }
}
