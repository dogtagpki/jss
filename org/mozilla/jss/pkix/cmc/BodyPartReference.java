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
 * Portions created by the Initial Developer are Copyright (C) 2004
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

import org.mozilla.jss.util.Assert;
import org.mozilla.jss.asn1.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.BitSet;

/**
 * CMC <i>BodyPartReference</i>:
 * <pre>
 *      BodyPartReference::= CHOICE { 
 *          bodyPartID       BodyPartID
 *          bodyPartPath     SEQUENCE SIZE (1..MAX) OF BodyPartID, 
 *     } 
 *
 * @author Christina Fu (cfu)
 * </pre>
 */
public class BodyPartReference implements ASN1Value {
    public static final INTEGER BODYIDMAX = new INTEGER("4294967295");

    /**
     * The type of BodyPartReference.
     */
    public static class Type {
        private Type() { }

        static Type BodyPartID = new Type();
        static Type BodyPartPath = new Type();
    }
    public static Type BodyPartID = Type.BodyPartID;
    public static Type BodyPartPath = Type.BodyPartPath;

    ///////////////////////////////////////////////////////////////////////
    // Members
    ///////////////////////////////////////////////////////////////////////
    private Type type;
    private INTEGER bodyPartID;
    private SEQUENCE bodyPartPath; 

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    private BodyPartReference() { }

    /**
     * @param type The type of the BodyPartReference
     * @param bodyPartID A BodyPartID. 
     * @param bodyPartPath The sequence of bodyPartIDs.
     */
    public BodyPartReference(Type type,
            INTEGER bodyPartID,
            SEQUENCE bodyPartPath) {
        this.bodyPartID = bodyPartID;
        this.bodyPartPath = bodyPartPath;
    }

    /**
     * Adds a BodyPartID to the bodyPartPath SEQUENCE.
     */
    public void addBodyPartId(int id) {
        INTEGER id1 = new INTEGER(id);
        Assert._assert(id1.compareTo(BODYIDMAX) <= 0);
        bodyPartPath.addElement( id1 );
    }

    ///////////////////////////////////////////////////////////////////////
    // member access
    ///////////////////////////////////////////////////////////////////////

    /**
     * Returns the type of BodyPartReference: <ul>
     * <li><code>BodyPartID</code>
     * <li><code>BodyPartPath</code>
     * </ul>
     */
    public Type getType() {
        return type;
    }

    public INTEGER getBodyPartID() {
        return bodyPartID;
    }

    public SEQUENCE getBodyPartPath() {
        return bodyPartPath;
    }
    ///////////////////////////////////////////////////////////////////////
    // decoding/encoding
    ///////////////////////////////////////////////////////////////////////

    public Tag getTag() {
        //return the subType's tag
        if (type == BodyPartID ) {
            return INTEGER.TAG;
        } else {
            Assert._assert( type == BodyPartPath);
            return SEQUENCE.TAG;
        }
    }

    public void encode(OutputStream ostream) throws IOException {
        if (type == BodyPartID ) {
            bodyPartID.encode(ostream);
        } else {
            Assert._assert( type == BodyPartPath);
            bodyPartPath.encode(ostream);
        }
    }

    public void encode(Tag implicitTag, OutputStream ostream)
        throws IOException
    {
        encode(ostream);
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }


    /**
     * A Template for decoding a BodyPartReference.
     */
    public static class Template implements ASN1Template {

        private CHOICE.Template choicet;

        public Template() {
            choicet = new CHOICE.Template();
            choicet.addElement( INTEGER.getTemplate() );
            choicet.addElement( new SEQUENCE.OF_Template(INTEGER.getTemplate()) );
        }

        public boolean tagMatch(Tag tag) {
            return choicet.tagMatch(tag);
        }

        public ASN1Value decode(InputStream istream)
                throws InvalidBERException, IOException {
            CHOICE c = (CHOICE) choicet.decode(istream);

            if( c.getTag().equals(INTEGER.TAG) ) {
                return new BodyPartReference(BodyPartID, (INTEGER) c.getValue() , null);
            } else {
                Assert._assert( c.getTag().equals(SEQUENCE.TAG) );
                return new BodyPartReference(BodyPartPath, null, (SEQUENCE) c.getValue());
            }
        }

        public ASN1Value decode(Tag implicitTag, InputStream istream)
                throws InvalidBERException, IOException {
            //A CHOICE cannot be implicitly tagged
            return decode(istream);
        }
    }
}
