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
package org.mozilla.jss.pkix.cmc;

import org.mozilla.jss.asn1.*;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import org.mozilla.jss.util.Assert;

/**
 * ExtendedFailInfo per rfc 5272
 *    It is to be used in CMCStatusInfoV2 as a CHOICE of otherInfo
 *
 * <pre>
 *      ExtendedFailInfo ::= SEQUENCE {
 *          failInfoOID        OBJECT IDENTIFIER,
 *          failInfoValue       ANY DEFINED BY failInfoOID }
 * </pre>
 *
 * @author Christina Fu (cfu)
 */
public class ExtendedFailInfo implements ASN1Value {

    private OBJECT_IDENTIFIER failInfoOID;
    private ANY failInfoValue;

    public static final Tag TAG = SEQUENCE.TAG;
    public Tag getTag() {
        return TAG;
    }

    private ExtendedFailInfo() { }

    public ExtendedFailInfo(OBJECT_IDENTIFIER failInfoOID, ASN1Value failInfoValue) {
        this.failInfoOID = failInfoOID;
        if( failInfoValue instanceof ANY ) {
            this.failInfoValue = (ANY) failInfoValue;
        } else {
            byte[] encoded = ASN1Util.encode(failInfoValue);
            try {
              this.failInfoValue = (ANY) ASN1Util.decode(ANY.getTemplate(), encoded);
            } catch( InvalidBERException e ) {
              Assert.notReached("InvalidBERException while decoding as ANY");
            }
        }
    }

    public OBJECT_IDENTIFIER getOID() {
        return failInfoOID;
    }

    /**
     * Returns the failInfoValue of this ExtendedFailInfo, encoded as an ANY.
     */
    public ANY getValue() {
        return failInfoValue;
    }

    public void encode(OutputStream ostream) throws IOException {
        encode(TAG, ostream);
    }

    public void encode(Tag implicit, OutputStream ostream)
        throws IOException
    {
        SEQUENCE seq = new SEQUENCE();
        seq.addElement(failInfoOID);
        seq.addElement(failInfoValue);

        seq.encode(implicit, ostream);
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A Template for decoding an ExtendedFailInfo.
     */
    public static class Template implements ASN1Template {

        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        public ASN1Value decode(InputStream istream)
            throws IOException, InvalidBERException
        {
            return decode(TAG, istream);
        }

        public ASN1Value decode(Tag implicit, InputStream istream)
            throws IOException, InvalidBERException
        {
            SEQUENCE.Template seqt = new SEQUENCE.Template();

            seqt.addElement( new OBJECT_IDENTIFIER.Template()   );
            seqt.addElement( new ANY.Template()                 );

            SEQUENCE seq = (SEQUENCE) seqt.decode(implicit, istream);

            // The template should have enforced this
            Assert._assert(seq.size() == 2);

            return new ExtendedFailInfo( (OBJECT_IDENTIFIER) seq.elementAt(0),
                                            seq.elementAt(1) );
        }
    }

}
