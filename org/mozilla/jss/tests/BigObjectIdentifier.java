package org.mozilla.jss.tests;

import java.io.IOException;
import java.math.BigInteger;

import org.mozilla.jss.netscape.security.util.*;

public class BigObjectIdentifier {
    public static void main(String[] args) throws Exception {

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
    }
}
