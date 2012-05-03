/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;
import java.security.spec.AlgorithmParameterSpec;

public final class PK11ParameterSpec implements AlgorithmParameterSpec 
{
   public PK11ParameterSpec(byte [] derBlob)
   {
      blob = derBlob;
   }

   public byte [] getEncoded()
   {
     return blob;
   }
   private byte [] blob;

}
