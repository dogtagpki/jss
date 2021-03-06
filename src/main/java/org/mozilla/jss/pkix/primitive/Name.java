/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.pkix.primitive;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.CharConversionException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.PrintableString;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;

/**
 * An X.500 Name.
 */
public class Name implements ASN1Value {

    SEQUENCE rdns;

    /**
     * Creates an empty Name.
     */
    public Name() {
        rdns = new SEQUENCE();
    }

    /**
     * Creates a name from a sequence of relative distinguished names.
     */
    Name( SEQUENCE rdns ) {
        this.rdns = rdns;
    }

    /**
     * Adds a relative distinguished name to the Name.
     *
     * @param name A relative distinguished name (RDN) to be added to the Name.
     */
    public void addElement( RDN name ) {
        rdns.addElement( name );
    }

    /**
     * Adds a relative distinguished name containing a single AVA.
     *
     * @param ava An AttributeValueAssertion, which will be inserted as
     *  the sole element of a new RDN, which will be stored in the Name.
     */
    public void addElement( AVA ava ) {
        rdns.addElement( new RDN( ava ) );
    }

    /**
     * Inserts the given RDN at the given index in the Name.
     */
    public void insertElementAt( RDN name, int idx ) {
        rdns.insertElementAt( name, idx);
    }

    /**
     * Returns the RDN at the given index in the Name.
     */
    public RDN elementAt( int idx ) {
        return (RDN) rdns.elementAt(idx);
    }

    /**
     * Removes the Name element at the given index.
     */
    public void removeElementAt( int idx ) {
        rdns.removeElementAt( idx );
    }

    /**
     * Returns the number of RDNs in the Name.
     */
    public int size() {
        return rdns.size();
    }

    public static final Tag TAG = SEQUENCE.TAG;
    @Override
    public Tag getTag() {
        return TAG;
    }

    @Override
    public void encode(OutputStream ostream) throws IOException {
        rdns.encode(ostream);
    }

    @Override
    public void encode(Tag implicit, OutputStream ostream)
        throws IOException
    {
        rdns.encode(implicit, ostream);
    }

    /**
     * The OID for the common name (CN) attribute.
     */
    public static final OBJECT_IDENTIFIER commonName =
        new OBJECT_IDENTIFIER( new long[]{ 2, 5, 4, 3 } );
    /**
     * The OID for the country name (C) attribute.
     */
    public static final OBJECT_IDENTIFIER countryName =
        new OBJECT_IDENTIFIER( new long[]{ 2, 5, 4, 6 } );
    /**
     * The OID for the locality name (L) attribute.
     */
    public static final OBJECT_IDENTIFIER localityName =
        new OBJECT_IDENTIFIER( new long[]{ 2, 5, 4, 7 } );
    /**
     * The OID for the state or province name (S) attribute.
     */
    public static final OBJECT_IDENTIFIER stateOrProvinceName =
        new OBJECT_IDENTIFIER( new long[]{ 2, 5, 4, 8 } );
    /**
     * The OID for the organization name (O) attribute.
     */
    public static final OBJECT_IDENTIFIER organizationName =
        new OBJECT_IDENTIFIER( new long[]{ 2, 5, 4, 10 } );
    /**
     * The OID for the organizational unit name (OU) attribute.
     */
    public static final OBJECT_IDENTIFIER organizationalUnitName =
        new OBJECT_IDENTIFIER( new long[]{ 2, 5, 4, 11 } );


    /**
     * Adds a common name (CN) to the Name.
     * @param CN The common name.
     *      It will be formatted according to the IETF PKIX rules for
     *      directory strings.
     */
    public void addCommonName(String CN) throws CharConversionException {
        addElement( new AVA( commonName, new DirectoryString(CN) ) );
    }

    /**
     * Adds a country name (C) to the Name. It must be exactly two characters.
     * @param C The country name.
     *      It will be formatted according to the IETF PKIX rules for
     *      directory strings.
     * @exception IllegalArgumentException If C.length() != 2.
     */
    public void addCountryName(String C) throws CharConversionException {
        if( C.length() != 2 ) {
            throw new IllegalArgumentException("Country name must be exactly"+
                " 2 characters");
        }
        addElement( new AVA( countryName, new DirectoryString(C) ) );
    }

    /**
     * Adds a locality name (L) to the Name.
     * @param L The locality name.
     *      It will be formatted according to the IETF PKIX rules for
     *      directory strings.
     */
    public void addLocalityName(String L) throws CharConversionException {
        addElement( new AVA( localityName, new DirectoryString(L) ) );
    }

    /**
     * Adds a state or province name (S) to the Name.
     * @param S The state or province name.
     *      It will be formatted according to the IETF PKIX rules for
     *      directory strings.
     */
    public void addStateOrProvinceName(String S)
        throws CharConversionException
    {
        addElement( new AVA( stateOrProvinceName, new DirectoryString(S) ) );
    }

    /**
     * Adds an organization name (O) to the Name.
     * @param O The organization name.
     *      It will be formatted according to the IETF PKIX rules for
     *      directory strings.
     */
    public void addOrganizationName(String O) throws CharConversionException {
        addElement( new AVA( organizationName, new DirectoryString(O) ) );
    }

    /**
     * Adds an organizational unit name (OU) to the Name.
     * @param OU The organizational unit name.
     *      It will be formatted according to the IETF PKIX rules for
     *      directory strings.
     */
    public void addOrganizationalUnitName(String OU)
        throws CharConversionException
    {
        addElement( new AVA( organizationalUnitName,
                             new DirectoryString(OU) ) );
    }

    private String typeToString( OBJECT_IDENTIFIER type ) {
        if( type.equals(commonName) ) {
            return "CN";
        } else if( type.equals(countryName) ) {
            return "C";
        } else if( type.equals(localityName) ) {
            return "L";
        } else if( type.equals(stateOrProvinceName) ) {
            return "S";
        } else if( type.equals(organizationName) ) {
            return "O";
        } else if( type.equals(organizationalUnitName) ) {
            return "OU";
        } else {
            return null;
        }
    }

    private String AVAToString(AVA ava) throws InvalidBERException
    {
        OBJECT_IDENTIFIER oid = ava.getOID();
        String type = typeToString( oid );
        if( type == null ) {
            return "";
        } else {
            return type + "=" + ava.getValue().decodeWith(DirectoryString.getTemplate());
        }
    }

    public String getRFC1485() throws InvalidBERException {
        StringBuffer buf = new StringBuffer(80);
        for( int r = 0; r < rdns.size(); r++ ) {
            if( r > 0) {
                buf.append(", ");
            }
            buf.append( AVAToString( ((RDN)rdns.elementAt(r)).at(0)) );
        }
        return buf.toString();
    }

    private static final Name.Template templateInstance = new Name.Template();
    public static Name.Template getTemplate() {
        return templateInstance;
    }

    public static void main(String args[]) {

      try {

        if(args.length == 0) {
            Name name = new Name();
            OBJECT_IDENTIFIER oid;

            oid = new OBJECT_IDENTIFIER( new long[]{ 2, 5, 4, 10 } );
            AVA ava = new AVA( oid, new PrintableString("Netscape") );
            name.addElement( ava );

            oid = new OBJECT_IDENTIFIER( new long[]{ 2, 5, 4, 3} );
            ava = new AVA( oid, new PrintableString("moi"));
            name.addElement( ava );

            name.encode(System.out);
        } else {

            Name.Template temp = new Name.Template();
            Name name;

            FileInputStream fis = new FileInputStream(args[0]);
            try (BufferedInputStream bis = new BufferedInputStream(fis)) {
                name = (Name) temp.decode(bis);
            }

            System.out.println("Got name.");

            for( int i = 0; i < name.size(); i++ ) {
                AVA a = name.elementAt(i).at(0);
                PrintableString.Template pst = new PrintableString.Template();
                PrintableString ps = (PrintableString)
                    pst.decode( new ByteArrayInputStream(
                        a.getValue().getEncoded() ) );
                System.out.println("OID: "+a.getOID()+", String: "+ps);
            }
            System.out.println("End of name");
        }
      } catch( Exception e) {
            e.printStackTrace();
      }
    }


public static class Template implements ASN1Template {
    @Override
    public boolean tagMatch(Tag tag) {
        return TAG.equals(tag);
    }

    @Override
    public ASN1Value decode(InputStream istream)
        throws IOException, InvalidBERException
    {
        return decode(TAG, istream);
    }

    @Override
    public ASN1Value decode(Tag implicit, InputStream istream)
        throws IOException, InvalidBERException
    {
        SEQUENCE.OF_Template seqt = new SEQUENCE.OF_Template(
            new RDN.Template() );
        SEQUENCE seq = (SEQUENCE) seqt.decode(implicit, istream);
        return new Name( seq );
    }
}

}
