package org.mozilla.jss.util;

import java.math.BigInteger;
import java.util.Arrays;

import java.security.spec.ECPoint;
import java.security.spec.ECParameterSpec;

import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.util.ECCurve;

import org.mozilla.jss.netscape.security.util.Utils;

public class EC {
    public static ECPoint decodeNSSPoint(byte[] data) {
        int index = 0;

        // JSS likes to prepend a zero to "help" BigInteger users. We've
        // since removed the BigInteger from call tree.
        if (data[index] == 0x00) {
            index += 1;
        }

        // CKA_EC_POINT is defined by PKCS#11 to be the DER-encoding of
        // ANSI X9.62 ECPoint value Q. ASNI X9.62 defines the ECPoint
        // conversion process in Section 4.3.6 Point-to-Octet-String
        // Conversion and Section 4.3.7 Octet-String-to-Point Conversion.
        //
        // We handle only the uncompressed forms for now.
        if (data[index] == 0x04) {
            index += 1;

            // In the uncompressed form, the length is 2l+1 (or, with JSS's
            // padding, 2l+2), where l is the length of a point element.
            int total_length = data.length - index;

            // Remaining length should be even by above.
            assert((total_length & 1) == 0);

            // Length of the point is now half of the total_length.
            int point_length = total_length / 2;

            // X coordinate is the first half of the data.
            BigInteger x1 = new BigInteger(1, Arrays.copyOfRange(data, index, index + point_length));

            // Y coordinate is the second half of the data.
            index += point_length;
            BigInteger y1 = new BigInteger(1, Arrays.copyOfRange(data, index, index + point_length));

            // We should now be at the end of the buffer; there should be
            // no trailing data.
            assert(index + point_length == data.length);

            return new ECPoint(x1, y1);
        }

        // Handling of other forms is complicated and depends on the
        // underlying curve; we might not have that information here.
        throw new RuntimeException("Unrecognized CKA_EC_POINT encoding form: " + data[index]);
    }

    public static ECParameterSpec decodeNSSOID(byte[] data) {
        int offset = 0;
        if (data[offset] == 0x00) {
            offset += 1;
        }

        ASN1Value value;
        try {
            value = ASN1Util.decode(OBJECT_IDENTIFIER.getTemplate(), Arrays.copyOfRange(data, offset, data.length));
            if (!(value instanceof OBJECT_IDENTIFIER)) {
                throw new RuntimeException("Unrecognized byte data: " + Utils.HexEncode(data));
            }
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage() + "\nData: " + Utils.HexEncode(data), e);
        }

        OBJECT_IDENTIFIER oid = (OBJECT_IDENTIFIER)value;
        ECCurve curve = ECCurve.fromOID(oid);

        if (curve == null) {
            throw new RuntimeException("Unrecognized curve: " + Utils.HexEncode(data) + " == OID " + oid);
        }

        return curve.getECParameterSpec();
    }
}
