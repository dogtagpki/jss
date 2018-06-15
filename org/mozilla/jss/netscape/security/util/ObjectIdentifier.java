// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.mozilla.jss.netscape.security.util;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Hashtable;
import java.util.StringTokenizer;

/**
 * Represent an ISO Object Identifier.
 *
 * <P>
 * Object Identifiers are arbitrary length hierarchical identifiers. The individual components are numbers, and they
 * define paths from the root of an ISO-managed identifier space. You will sometimes see a string name used instead of
 * (or in addition to) the numerical id. These are synonyms for the numerical IDs, but are not widely used since most
 * sites do not know all the requisite strings, while all sites can parse the numeric forms.
 *
 * <P>
 * So for example, JavaSoft has the sole authority to assign the meaning to identifiers below the 1.3.6.1.4.42.2.17 node
 * in the hierarchy, and other organizations can easily acquire the ability to assign such unique identifiers.
 *
 * @version 1.23
 *
 * @author David Brownell
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 */
final public class ObjectIdentifier implements Serializable {
    /** use serialVersionUID from JDK 1.1. for interoperability */
    private static final long serialVersionUID = 8697030238860181294L;

    /**
     * Constructs an object identifier from a string. This string
     * should be of the form 1.23.34.45.56 etc.
     */
    public ObjectIdentifier(String oid) {
        if (oid == null)
            return;

        int ch = '.';
        int start = 0;
        int end = 0;

        // Calculate length of oid
        componentLen = 0;
        while ((end = oid.indexOf(ch, start)) != -1) {
            start = end + 1;
            componentLen += 1;
        }
        componentLen += 1;
        components = new BigInteger[componentLen];

        start = 0;
        int i = 0;
        String comp = null;
        while ((end = oid.indexOf(ch, start)) != -1) {
            comp = oid.substring(start, end);
            components[i++] = new BigInteger(comp);
            start = end + 1;
        }
        comp = oid.substring(start);
        components[i] = new BigInteger(comp);
    }

    /**
     * Constructs an object ID from an array of integers. This
     * is used to construct constant object IDs.
     */
    public ObjectIdentifier(int values[]) {
        try {
            componentLen = values.length;
            BigInteger[] tmp = new BigInteger[componentLen];

            for (int i = 0; i < componentLen; i++) {
                tmp[i] = BigInteger.valueOf(values[i]);
            }

            components = tmp.clone();
        } catch (Throwable t) {
            System.out.println("X509.ObjectIdentifier(), no cloning!");
        }
    }

    public ObjectIdentifier(BigInteger values[]) {
        try {
            componentLen = values.length;

            componentLen = values.length;
            BigInteger[] tmp = new BigInteger[componentLen];

            for (int i = 0; i < componentLen; i++) {
                tmp[i] = new BigInteger(values[i].toString());
            }

            components = tmp.clone();

        } catch(Throwable t) {
            System.out.println("X509.ObjectIdentifier(), no cloning!");
        }
    }

    /**
     * Constructs an object ID from an array of longs This
     * is used to construct constant object IDs.
     */
    public ObjectIdentifier(long values[]) {
        try {
            componentLen = values.length;
            BigInteger[] tmp = new BigInteger[componentLen];

            for (int i = 0; i < componentLen; i++) {
                tmp[i] = BigInteger.valueOf(values[i]);
            }

            components = tmp.clone();
        } catch (Throwable t) {
            System.out.println("X509.ObjectIdentifier(), no cloning!");
        }
    }


    /**
     * Constructs an object ID from an ASN.1 encoded input stream.
     * The encoding of the ID in the stream uses "DER", a BER/1 subset.
     * In this case, that means a triple { typeId, length, data }.
     *
     * <P>
     * <STRONG>NOTE:</STRONG> When an exception is thrown, the input stream has not been returned to its "initial"
     * state.
     *
     * @param in DER-encoded data holding an object ID
     * @exception IOException indicates a decoding error
     */
    public ObjectIdentifier(DerInputStream in)
            throws IOException {
        byte type_id;
        int bufferEnd;

        /*
         * Object IDs are a "universal" type, and their tag needs only
         * one byte of encoding.  Verify that the tag of this datum
         * is that of an object ID.
         *
         * Then get and check the length of the ID's encoding.  We set
         * up so that we can use in.available() to check for the end of
         * this value in the data stream.
         */
        type_id = (byte) in.getByte();
        if (type_id != DerValue.tag_ObjectId)
            throw new IOException(
                    "X509.ObjectIdentifier() -- data isn't an object ID"
                            + " (tag = " + type_id + ")");

        bufferEnd = in.available() - in.getLength() - 1;
        if (bufferEnd < 0)
            throw new IOException(
                    "X509.ObjectIdentifier() -- not enough data");

        initFromEncoding(in, bufferEnd);
    }

    /*
     * Build the OID from the rest of a DER input buffer; the tag
     * and length have been removed/verified
     */
    ObjectIdentifier(DerInputBuffer buf) throws IOException {
        initFromEncoding(new DerInputStream(buf), 0);
    }



    /*
     * Helper function -- get the OID from a stream, after tag and
     * length are verified.
     */
    private void initFromEncoding(DerInputStream in, int bufferEnd)
            throws IOException {

        /*
         * Now get the components ("sub IDs") one at a time.  We fill a
         * temporary buffer, resizing it as needed.
         */
        BigInteger component;
        boolean first_subid = true;

        for (components = new BigInteger[allocationQuantum], componentLen = 0; in.available() > bufferEnd;) {
            component = getComponentBigInt(in);

            if (first_subid) {
                long X, Y;

                /*
                 * The ISO root has three children (0, 1, 2) and those nodes
                 * aren't allowed to assign IDs larger than 39.  These rules
                 * are memorialized by some special casing in the BER encoding
                 * of object IDs ... or maybe it's vice versa.
                 *
                 * NOTE:  the allocation quantum is large enough that we know
                 * we don't have to reallocate here!
                 */
                if (component.intValue() < 40)
                    X = 0;
                else if (component.intValue() < 80)
                    X = 1;
                else
                    X = 2;
                Y = component.intValue() - (X * 40);

                components[0] = BigInteger.valueOf(X);
                components[1] = BigInteger.valueOf(Y);
                componentLen = 2;

                first_subid = false;

            } else {

                /*
                 * Other components are encoded less exotically.  The only
                 * potential trouble is the need to grow the array.
                 */
                if (componentLen >= components.length) {
                    BigInteger tmp_components[];

                    tmp_components = new BigInteger[components.length
                            + allocationQuantum];
                    System.arraycopy(components, 0, tmp_components, 0,
                            components.length);
                    components = tmp_components;
                }
                components[componentLen++] = component;
            }
        }

        /*
         * Final sanity check -- if we didn't use exactly the number of bytes
         * specified, something's quite wrong.
         */
        if (in.available() != bufferEnd) {
            throw new IOException(
                    "X509.ObjectIdentifier() -- malformed input data");
        }
    }

    /*
     * n.b. the only public interface is DerOutputStream.putOID()
     */
    void encode(DerOutputStream out) throws IOException {
        DerOutputStream bytes = new DerOutputStream();
        int i;

        /* We can use the int here because we know we are dealing
           with small numbers for the first byte
        */
        bytes.write((components[0].intValue() * 40) + components[1].intValue());
        for (i = 2; i < componentLen; i++)
            putComponentBigInt(bytes, components[i]);

        /*
         * Now that we've constructed the component, encode
         * it in the stream we were given.
         */
        out.write(DerValue.tag_ObjectId, bytes);
    }

    /*
     * Tricky OID component parsing technique ... note that one bit
     * per octet is lost, this returns at most 28 bits of component.
     * Also, notice this parses in big-endian format.
     */
    private static BigInteger getComponentBigInt(DerInputStream in)
            throws IOException {

        BigInteger retval = BigInteger.valueOf(0);
        int tmp;

        while (true) {
            retval = retval.shiftLeft(7);
            tmp = in.getByte();
            retval = retval.or(BigInteger.valueOf(tmp & 0x07f));
            if ((tmp & 0x080) == 0)
                return retval;
        }

    }

    /*
     * Reverse of the above routine.  Notice it needs to emit in
     * big-endian form, so it buffers the output until it's ready.
     * (Minimum length encoding is a DER requirement.)
     */
    private static void putComponentBigInt(DerOutputStream out, BigInteger val)
            throws IOException {
        int i;
        int blockSize = 100;
        byte buf[] = new byte[blockSize];

        BigInteger bigInt7f = BigInteger.valueOf(0x7f);

        BigInteger cur =  new BigInteger(val.toString());
        for (i = 0;; i++) {
            buf[i] = (cur.and(bigInt7f).byteValue());
            cur = cur.shiftRight(7);
            if (cur.compareTo(BigInteger.ZERO) == 0 )
                break;
        }
        for (; i > 0; --i)
            out.write(buf[i] | 0x080);
        out.write(buf[0]);
    }

    // XXX this API should probably facilitate the JDK sort utility

    /**
     * Compares this identifier with another, for sorting purposes.
     * An identifier does not precede itself.
     *
     * @param other identifer that may precede this one.
     * @return true iff <em>other</em> precedes this one
     *         in a particular sorting order.
     */
    public boolean precedes(ObjectIdentifier other) {
        int i;

        // shorter IDs go first
        if (other == this || componentLen < other.componentLen)
            return false;
        if (other.componentLen < componentLen)
            return true;

        // for each component, the lesser component goes first
        for (i = 0; i < componentLen; i++) {
            if (other.components[i].compareTo(components[i]) > 0)
                return true;
        }

        // identical IDs don't precede each other
        return false;
    }

    public boolean equals(Object other) {
        if (other instanceof ObjectIdentifier)
            return equals((ObjectIdentifier) other);
        else
            return false;
    }

    /**
     * Compares this identifier with another, for equality.
     *
     * @return true iff the names are identical.
     */
    public boolean equals(ObjectIdentifier other) {
        int i;

        if (other == this)
            return true;
        if (componentLen != other.componentLen)
            return false;
        for (i = 0; i < componentLen; i++) {
            if (components[i].compareTo(other.components[i]) != 0 )
                return false;
        }
        return true;
    }

    public int hashCode() {
        int h = 0;
        int oflow = 0;

        for (int i = 0; i < componentLen; i++) {
            oflow = (h & 0xff800000) >> 23;
            h <<= 9;
            h += components[i].intValue();
            h ^= oflow;
        }
        return h;
    }

    /**
     * Returns a string form of the object ID. The format is the
     * conventional "dot" notation for such IDs, without any
     * user-friendly descriptive strings, since those strings
     * will not be understood everywhere.
     */
    public String toString() {
        StringBuffer retval = new StringBuffer();

        int i;

        for (i = 0; i < componentLen; i++) {
            if (i != 0)
                retval.append(".");
            retval.append(components[i]);
        }
        return retval.toString();
    }

    /*
     * To simplify, we assume no individual component of an object ID is
     * larger than 64 bits.  Then we represent the path from the root as
     * an array that's (usually) only filled at the beginning.
     */
    private BigInteger components[]; // path from root
    private int componentLen; // how much is used.

    private static final int allocationQuantum = 5; // >= 2

    /**
     * Netscape Enhancement:
     * This function implements a object identifier factory. It
     * should help reduces in-memory Object Identifier object.
     * This function also provide additional checking on the OID.
     * A valid OID should start with 0, 1, or 2.
     *
     * Notes:
     * This function never returns null. IOException is raised
     * in error conditions.
     */
    public static Hashtable<String, ObjectIdentifier> mOIDs = new Hashtable<String, ObjectIdentifier>();

    public static ObjectIdentifier getObjectIdentifier(String oid)
            throws IOException {
        int value;

        if (oid == null)
            throw new IOException("empty object identifier");

        oid = oid.trim();

        ObjectIdentifier thisOID = mOIDs.get(oid);
        if (thisOID != null)
            return thisOID;

        StringTokenizer token = new StringTokenizer(oid, ".");
        value = new Integer(token.nextToken()).intValue();
        /* First token should be 0, 1, 2 */
        if (value >= 0 && value <= 2) {
            value = new Integer(token.nextToken()).intValue();
            /* Second token should be 0 <= && >= 39 */
            if (value >= 0 && value <= 39) {
                thisOID = new ObjectIdentifier(oid);
                if (thisOID.toString().equals(oid)) {
                    mOIDs.put(oid, thisOID);
                    return thisOID;
                }
                throw new IOException("invalid oid " + oid);
            } else
                throw new IOException("invalid oid " + oid);
        } else
            throw new IOException("invalid oid " + oid);
    }

    public static ObjectIdentifier getObjectIdentifier(int values[])
            throws IOException {
        StringBuffer retval = new StringBuffer();
        int i;

        for (i = 0; i < values.length; i++) {
            if (i != 0)
                retval.append(".");
            retval.append(values[i]);
        }
        return getObjectIdentifier(retval.toString());
    }

    public static void main(String[] args) {

        long[] oid_components_long = { 1L, 3L,6L,1L,4L,1L,5000L,9L,1L,1L,1526913300628L, 1L};
        int[] oid_components_int =  { 1, 3,6,1,4,1,2312,9,1,1,15269, 1, 1};
        BigInteger[] oid_components_big_int = { new BigInteger("1"), new BigInteger("3"), new BigInteger("6"), new BigInteger("1"),
                new BigInteger("4"), new BigInteger("1"), new BigInteger("2312"),
                new BigInteger("9"), new BigInteger("1"),
                new BigInteger("152691330062899999999999997777788888888888888889999999999999999"), new BigInteger("1")
        };

        String oidIn = "1.3.6.1.4.1.2312.9.1.152691330062899999999999997777788888888888888889999999999999999.1";
        ObjectIdentifier oid = new ObjectIdentifier(oidIn);

        ObjectIdentifier fromDer = null;
        ObjectIdentifier fromStaticMethod = null;
        ObjectIdentifier fromComponentList = null;
        ObjectIdentifier  fromComponentListInt = null;
        ObjectIdentifier fromComponentListBigInt = null;

        System.out.println("oid: " + oid.toString());

        DerOutputStream out = new DerOutputStream();

        try {
            oid.encode(out);
            DerInputStream  in = new DerInputStream(out.toByteArray());
            fromDer = new ObjectIdentifier(in);

            System.out.println("fromDer: " + fromDer.toString());

            fromStaticMethod = ObjectIdentifier.getObjectIdentifier(oidIn);

            System.out.println("fromStaticMethod: " + fromStaticMethod.toString());

            fromComponentList = new ObjectIdentifier(oid_components_long);

            System.out.println("fromComponentList: " + fromComponentList.toString());

            fromComponentListInt = new ObjectIdentifier(oid_components_int);

            System.out.println("fromComponentListInt: " + fromComponentListInt);

            fromComponentListBigInt = new ObjectIdentifier(oid_components_big_int);

            System.out.println("fromComponentListBigInt: " + fromComponentListBigInt);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
