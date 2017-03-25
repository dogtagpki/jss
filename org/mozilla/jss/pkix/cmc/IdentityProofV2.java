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
import org.mozilla.jss.pkix.primitive.*;
import java.io.*;

/**
 * CMC <i>IdentityProofV2</i>:
 *   per rfc 5272
 * <pre>
 *     IdentityProofV2 ::= SEQUENCE {
 *         hashAlgID      AlgorithmIdentifier,
 *         macAlgId       AlgorithmIdentifier,
 *         witness        OCTET STRING
 *     }
 * </pre>
 *
 * @author Christina Fu (cfu)
 */
public class IdentityProofV2 implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////
    private AlgorithmIdentifier hashAlgID;
    private AlgorithmIdentifier macAlgId;
    private OCTET_STRING witness;
    private SEQUENCE sequence;  // for DER encoding

    public AlgorithmIdentifier getHashAlgID() {
        return hashAlgID;
    }

    public AlgorithmIdentifier getMacAlgId() {
        return macAlgId;
    }

    public OCTET_STRING getWitness() {
        return witness;
    }

    ///////////////////////////////////////////////////////////////////////
    // constructors
    ///////////////////////////////////////////////////////////////////////
    private IdentityProofV2() { }

    public IdentityProofV2(
            AlgorithmIdentifier hashAlgID,
            AlgorithmIdentifier macAlgId,
            OCTET_STRING witness)
    {
        if(  hashAlgID==null || macAlgId==null ||
                witness==null ) {
            throw new IllegalArgumentException("IdentityProofV2 constructor"
                +" parameter is null");
        }

        this.hashAlgID = hashAlgID;
        this.macAlgId = macAlgId;
        this.witness = witness;

        sequence = new SEQUENCE();
        sequence.addElement(hashAlgID);
        sequence.addElement(macAlgId);
        sequence.addElement(witness);
    }

    ///////////////////////////////////////////////////////////////////////
    // DER encoding
    ///////////////////////////////////////////////////////////////////////

    private static final Tag TAG = SEQUENCE.TAG;

    public Tag getTag() {
        return TAG;
    }

    public void encode(OutputStream ostream) throws IOException {
        sequence.encode(ostream);
    }

    public void encode(Tag implicitTag, OutputStream ostream)
            throws IOException {
        sequence.encode(implicitTag, ostream);
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A Template for decoding BER-encoded IdentityProofV2 items.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();

            seqt.addElement( AlgorithmIdentifier.getTemplate() );
            seqt.addElement( AlgorithmIdentifier.getTemplate() );
            seqt.addElement( OCTET_STRING.getTemplate() );
        }

        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        public ASN1Value decode(InputStream istream)
                throws InvalidBERException, IOException {
            return decode(TAG, istream);
        }

        public ASN1Value decode(Tag implicitTag, InputStream istream)
                throws InvalidBERException, IOException {

            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            return new IdentityProofV2(
                            (AlgorithmIdentifier) seq.elementAt(0),
                            (AlgorithmIdentifier) seq.elementAt(1),
                            (OCTET_STRING) seq.elementAt(2) );
        }
    }
}
