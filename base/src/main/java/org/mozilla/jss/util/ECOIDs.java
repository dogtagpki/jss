package org.mozilla.jss.util;

import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;

public class ECOIDs {
    // OID Base Arcs
    public static final OBJECT_IDENTIFIER ANSI_X962_PRIME_CURVE = new OBJECT_IDENTIFIER( new long[] { 1, 2, 840, 10045, 3, 1 } );
    public static final OBJECT_IDENTIFIER ANSI_X962_BINARY_CURVE = new OBJECT_IDENTIFIER( new long[] { 1, 2, 840, 10045, 3, 0 } );
    public static final OBJECT_IDENTIFIER SECG_EC_CURVE = new OBJECT_IDENTIFIER( new long[] { 1, 3, 132, 0 } );

    // ANSI Prime curves
    public static final OBJECT_IDENTIFIER CURVE_ANSI_P192V1 = ANSI_X962_PRIME_CURVE.subBranch(1);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_P192V2 = ANSI_X962_PRIME_CURVE.subBranch(2);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_P192V3 = ANSI_X962_PRIME_CURVE.subBranch(3);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_P239V1 = ANSI_X962_PRIME_CURVE.subBranch(4);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_P239V2 = ANSI_X962_PRIME_CURVE.subBranch(5);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_P239V3 = ANSI_X962_PRIME_CURVE.subBranch(6);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_P256V1 = ANSI_X962_PRIME_CURVE.subBranch(7);

    // ANSI Binary curves
    public static final OBJECT_IDENTIFIER CURVE_ANSI_PNB163V1 = ANSI_X962_BINARY_CURVE.subBranch(1);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_PNB163V2 = ANSI_X962_BINARY_CURVE.subBranch(2);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_PNB163V3 = ANSI_X962_BINARY_CURVE.subBranch(3);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_PNB176V1 = ANSI_X962_BINARY_CURVE.subBranch(4);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_TNB191V1 = ANSI_X962_BINARY_CURVE.subBranch(5);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_TNB191V2 = ANSI_X962_BINARY_CURVE.subBranch(6);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_TNB191V3 = ANSI_X962_BINARY_CURVE.subBranch(7);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_ONB191V4 = ANSI_X962_BINARY_CURVE.subBranch(8);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_ONB191V5 = ANSI_X962_BINARY_CURVE.subBranch(9);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_PNB208W1 = ANSI_X962_BINARY_CURVE.subBranch(10);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_TNB239V1 = ANSI_X962_BINARY_CURVE.subBranch(11);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_TNB239V2 = ANSI_X962_BINARY_CURVE.subBranch(12);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_TNB239V3 = ANSI_X962_BINARY_CURVE.subBranch(13);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_ONB239V4 = ANSI_X962_BINARY_CURVE.subBranch(14);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_ONB239V5 = ANSI_X962_BINARY_CURVE.subBranch(15);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_PNB272W1 = ANSI_X962_BINARY_CURVE.subBranch(16);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_PNB304W1 = ANSI_X962_BINARY_CURVE.subBranch(17);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_TNB359V1 = ANSI_X962_BINARY_CURVE.subBranch(18);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_PNB368W1 = ANSI_X962_BINARY_CURVE.subBranch(19);
    public static final OBJECT_IDENTIFIER CURVE_ANSI_TNB431R1 = ANSI_X962_BINARY_CURVE.subBranch(20);

    // SEG Prime curves
    public static final OBJECT_IDENTIFIER CURVE_SECG_P112R1 = SECG_EC_CURVE.subBranch(6);
    public static final OBJECT_IDENTIFIER CURVE_SECG_P112R2 = SECG_EC_CURVE.subBranch(7);
    public static final OBJECT_IDENTIFIER CURVE_SECG_P128R1 = SECG_EC_CURVE.subBranch(28);
    public static final OBJECT_IDENTIFIER CURVE_SECG_P128R2 = SECG_EC_CURVE.subBranch(29);
    public static final OBJECT_IDENTIFIER CURVE_SECG_P160K1 = SECG_EC_CURVE.subBranch(9);
    public static final OBJECT_IDENTIFIER CURVE_SECG_P160R1 = SECG_EC_CURVE.subBranch(8);
    public static final OBJECT_IDENTIFIER CURVE_SECG_P160R2 = SECG_EC_CURVE.subBranch(30);
    public static final OBJECT_IDENTIFIER CURVE_SECG_P192K1 = SECG_EC_CURVE.subBranch(31);
    public static final OBJECT_IDENTIFIER CURVE_SECG_P224K1 = SECG_EC_CURVE.subBranch(32);
    public static final OBJECT_IDENTIFIER CURVE_SECG_P224R1 = SECG_EC_CURVE.subBranch(33);
    public static final OBJECT_IDENTIFIER CURVE_SECG_P256K1 = SECG_EC_CURVE.subBranch(10);
    public static final OBJECT_IDENTIFIER CURVE_SECG_P384R1 = SECG_EC_CURVE.subBranch(34);
    public static final OBJECT_IDENTIFIER CURVE_SECG_P521R1 = SECG_EC_CURVE.subBranch(35);

    // SEG Binary curves
    public static final OBJECT_IDENTIFIER CURVE_SECG_T113R1 = SECG_EC_CURVE.subBranch(4);
    public static final OBJECT_IDENTIFIER CURVE_SECG_T113R2 = SECG_EC_CURVE.subBranch(5);
    public static final OBJECT_IDENTIFIER CURVE_SECG_T131R1 = SECG_EC_CURVE.subBranch(22);
    public static final OBJECT_IDENTIFIER CURVE_SECG_T131R2 = SECG_EC_CURVE.subBranch(23);
    public static final OBJECT_IDENTIFIER CURVE_SECG_T163K1 = SECG_EC_CURVE.subBranch(1);
    public static final OBJECT_IDENTIFIER CURVE_SECG_T163R1 = SECG_EC_CURVE.subBranch(2);
    public static final OBJECT_IDENTIFIER CURVE_SECG_T163R2 = SECG_EC_CURVE.subBranch(15);
    public static final OBJECT_IDENTIFIER CURVE_SECG_T193R1 = SECG_EC_CURVE.subBranch(24);
    public static final OBJECT_IDENTIFIER CURVE_SECG_T193R2 = SECG_EC_CURVE.subBranch(25);
    public static final OBJECT_IDENTIFIER CURVE_SECG_T233K1 = SECG_EC_CURVE.subBranch(26);
    public static final OBJECT_IDENTIFIER CURVE_SECG_T233R1 = SECG_EC_CURVE.subBranch(27);
    public static final OBJECT_IDENTIFIER CURVE_SECG_T239K1 = SECG_EC_CURVE.subBranch(3);
    public static final OBJECT_IDENTIFIER CURVE_SECG_T283K1 = SECG_EC_CURVE.subBranch(16);
    public static final OBJECT_IDENTIFIER CURVE_SECG_T283R1 = SECG_EC_CURVE.subBranch(17);
    public static final OBJECT_IDENTIFIER CURVE_SECG_T409K1 = SECG_EC_CURVE.subBranch(36);
    public static final OBJECT_IDENTIFIER CURVE_SECG_T409R1 = SECG_EC_CURVE.subBranch(37);
    public static final OBJECT_IDENTIFIER CURVE_SECG_T571K1 = SECG_EC_CURVE.subBranch(38);
    public static final OBJECT_IDENTIFIER CURVE_SECG_T571R1 = SECG_EC_CURVE.subBranch(39);
}
