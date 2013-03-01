/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.crmf;

import org.mozilla.jss.asn1.*;
import java.io.*;
import org.mozilla.jss.pkix.primitive.AVA;
import org.mozilla.jss.util.Assert;

/**
 * A CRMF <code>Control</code>.
 */
public class Control extends AVA implements ASN1Value {

    // general CRMF OIDs
        public static final OBJECT_IDENTIFIER
    id_pkix = new OBJECT_IDENTIFIER( new long[] { 1, 3, 6, 1, 5, 5, 7 } );
        public static final OBJECT_IDENTIFIER
    id_pkip = id_pkix.subBranch( 5 );
        public static final OBJECT_IDENTIFIER
    id_regCtrl = id_pkip.subBranch( 1 );
        

    // Control OIDs
        public static final OBJECT_IDENTIFIER
    id_regCtrl_regToken = id_regCtrl.subBranch(1);
        public static final OBJECT_IDENTIFIER
    id_regCtrl_authenticator = id_regCtrl.subBranch(2);
        public static final OBJECT_IDENTIFIER
    id_regCtrl_pkiPublicationInfo = id_regCtrl.subBranch(3);
        public static final OBJECT_IDENTIFIER
    id_regCtrl_pkiArchiveOptions = id_regCtrl.subBranch(4);
        public static final OBJECT_IDENTIFIER
    id_regCtrl_oldCertID = id_regCtrl.subBranch(5);
        public static final OBJECT_IDENTIFIER
    id_regCtrl_protocolEncrKey = id_regCtrl.subBranch(6);

    public Control(OBJECT_IDENTIFIER oid, ASN1Value value) {
        super(oid, value);
    }

    /**
     * Returns the value of this control as a UTF8String, if it actually
     *  is a UTF8String.
     */
    public UTF8String getUTF8String() throws InvalidBERException {
        return (UTF8String) getValue().decodeWith(UTF8String.getTemplate());
    }

    /**
     * Returns the value of this control as a PKIArchiveOptions, if it
     *  actually is a PKIArchiveOptions.
     */
    public PKIArchiveOptions getPKIArchiveOptions() throws InvalidBERException {
        return (PKIArchiveOptions) getValue().decodeWith(
                    PKIArchiveOptions.getTemplate() );
    }

    /**
     * Returns the value of this control as a PKIPublicationInfo, if it
     *  actually is a PKIPublicationInfo.
     */
    public PKIPublicationInfo getPKIPublicationInfo()
            throws InvalidBERException {
        return (PKIPublicationInfo) getValue().decodeWith(
                    PKIPublicationInfo.getTemplate() );
    }

    /**
     * A template class for decoding a Control from a BER stream.
     */
    public static class Template extends AVA.Template implements ASN1Template {
        private SEQUENCE.Template seqTemplate;

        public Template() {
            seqTemplate = new SEQUENCE.Template();
            seqTemplate.addElement( new OBJECT_IDENTIFIER.Template() );
            seqTemplate.addElement( new ANY.Template()               );
        }

        public ASN1Value decode(InputStream istream)
            throws IOException, InvalidBERException
        {
            return decode(TAG, istream);
        }

        public ASN1Value decode(Tag implicit, InputStream istream)
            throws IOException, InvalidBERException
        {
            SEQUENCE seq = (SEQUENCE) seqTemplate.decode(implicit, istream);
            OBJECT_IDENTIFIER oid = (OBJECT_IDENTIFIER) seq.elementAt(0);
            ANY any = (ANY) seq.elementAt(1);

            return new Control( oid, any );
        }
    }
}
