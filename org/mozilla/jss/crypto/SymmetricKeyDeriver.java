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

package org.mozilla.jss.crypto;

import java.security.spec.AlgorithmParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.InvalidKeyException;

public interface SymmetricKeyDeriver {

   /* Use with the encrypt type mechanisms
      Example: initDerive(
                    symKey,  (PKCS11Constants.CKM_DES3_ECB_ENCRYPT_DATA) 4354L, derivationData, null,
                    PKCS11Constants.CKM_DES3_ECB, PKCS11Constants.CKA_DERIVE, 16);
   */

    public abstract void initDerive(SymmetricKey baseKey, 
        long deriveMech, byte[] param, byte[] iv, long targetMech, long operation, long keySize)
        throws InvalidKeyException;



    /* Use with key extraction and key concatanation mechanisms
  
    Example:
       param: byte array that has the bit position of where to extract
     initDerive(
                derivedKey, PKCS11Constants.CKM_EXTRACT_KEY_FROM_KEY,param,null,
                PKCS11Constants.CKA_ENCRYPT, PKCS11Constants.CKA_DERIVE,8);
 
 
    initDerive(
               baseSymKey,secondarySymKey, PKCS11Constants.CKM_CONCATENATE_BASE_AND_KEY,null,null,
               PKCS11Constants.CKM_DES3_ECB, PKCS11Constants.CKA_DERIVE,0);
 
    */ 

    public abstract void initDerive(SymmetricKey baseKey, 
        SymmetricKey secondaryKey, long deriveMech, byte[] param, byte[] iv, long targetMech, long operation, long keySize)
        throws InvalidKeyException; 

   public abstract SymmetricKey  derive()
       throws TokenException;
}
