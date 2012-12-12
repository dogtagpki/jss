/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs7;

import java.io.*;
import org.mozilla.jss.asn1.*;
import java.util.Vector;
import org.mozilla.jss.util.Assert;
import java.math.BigInteger;
import java.io.ByteArrayInputStream;

public class EnvelopedData implements ASN1Value {
    public static final Tag TAG = SEQUENCE.TAG;
    public Tag getTag() {
        return TAG;
    }

    private INTEGER              version;
    private SET                  recipientInfos;
    private EncryptedContentInfo         encryptedContentInfo;

    private SEQUENCE sequence = new SEQUENCE();

    public INTEGER getVersion() {
        return version;
    }
    public SET getRecipientInfos() {
        return recipientInfos;
    }
    public EncryptedContentInfo getEncryptedContentInfo() {
        return encryptedContentInfo;
    }


     
    private EnvelopedData() {
        }

    /**
     * Create a EnvelopedData ASN1 object. 
     */

    public EnvelopedData(  INTEGER version, SET recipientInfos,
                        EncryptedContentInfo encryptedContentInfo) {

        this.version = version;
        this.recipientInfos = recipientInfos;
        this.encryptedContentInfo = encryptedContentInfo;
  
        sequence.addElement(version);
        sequence.addElement(recipientInfos);
        sequence.addElement(encryptedContentInfo);
    }

    public void encode(OutputStream ostream) throws IOException {
        encode(getTag(),ostream);
    }

    public void encode(Tag tag, OutputStream ostream) throws IOException {
        sequence.encode(tag,ostream);
    }


    /**
     * A template file for decoding a EnvelopedData blob
     *
     */

    public static class Template implements ASN1Template {
        public Tag getTag() {
            return EnvelopedData.TAG;
        }

        public boolean tagMatch(Tag tag) {
            return (tag.equals(EnvelopedData.TAG));
        }

        public ASN1Value decode(InputStream istream) 
            throws IOException, InvalidBERException
            {
                return decode(getTag(),istream);
            }

        public ASN1Value decode(Tag implicitTag, InputStream istream)
            throws IOException, InvalidBERException
            {
                SEQUENCE.Template seqt = new SEQUENCE.Template();
                seqt.addElement(new INTEGER.Template());
                seqt.addElement(new SET.OF_Template(new RecipientInfo.Template()));
                seqt.addElement(new EncryptedContentInfo.Template());

                SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag,istream);
                Assert._assert(seq.size() ==3);

                return new EnvelopedData(
                    (INTEGER)               seq.elementAt(0),
                    (SET)                   seq.elementAt(1),
                    (EncryptedContentInfo)  seq.elementAt(2)
                    );
            }
    } // end of template

}
