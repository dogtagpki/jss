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
package org.mozilla.jss.asn1;

import java.io.OutputStream;
import java.io.InputStream;
import java.io.IOException;

public class NULL implements ASN1Value {

    public static final Tag TAG = new Tag(Tag.Class.UNIVERSAL, 5);
    public Tag getTag() {
        return TAG;
    }
    public static final Form FORM = Form.PRIMITIVE;

    public void encode(OutputStream ostream) throws IOException {
        encode(TAG, ostream);
    }

    public void encode(Tag implicitTag, OutputStream ostream)
        throws IOException
    {
        ASN1Header head = new ASN1Header(implicitTag, FORM, 0);
        head.encode(ostream);
    }

    private static final NULL instance = new NULL();
    public static NULL getInstance() {
        return instance;
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

public static class Template implements ASN1Template {

    public Tag getTag() {
        return NULL.TAG;
    }
    public boolean tagMatch(Tag tag) {
        return( tag.equals(NULL.TAG) );
    }

    public ASN1Value decode(InputStream istream)
        throws IOException, InvalidBERException
    {
        return decode(getTag(), istream);
    }

    public ASN1Value decode(Tag implicitTag, InputStream istream)
        throws IOException, InvalidBERException
    {
      try {
        ASN1Header head = new ASN1Header(istream);

        head.validate(implicitTag, FORM);
        if( head.getContentLength() != 0 ) {
            throw new InvalidBERException("Invalid length ("+
                head.getContentLength()+") for NULL; only 0 is permitted");
        }

        return new NULL();

      } catch(InvalidBERException e) {
        throw new InvalidBERException(e, "NULL");
      }
    }
} // end of Template

}
