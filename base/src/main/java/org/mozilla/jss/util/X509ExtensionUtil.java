package org.mozilla.jss.util;

/**
 * Small, generic helper for working with raw X.509 extension values as
 * returned by java.security.cert.X509Certificate#getExtensionValue(String).
 *
 * That method always returns the DER encoding of an OCTET STRING wrapping
 * the extension's actual content -- this is standard X.509 behavior, true
 * for any extension, not specific to any one OID. Some extensions (e.g.
 * RFC 8737's acmeIdentifier) define their own content as *also* being an
 * OCTET STRING, requiring a second unwrap to reach the real payload. This
 * class only does one layer at a time, deliberately -- callers decide how
 * many times to call it based on the specific extension they're parsing.
 */
public class X509ExtensionUtil {

    /**
     * Strip one layer of DER OCTET STRING encoding (tag 0x04) and return
     * its content bytes.
     *
     * Supports short-form and long-form DER lengths (up to 4 length-of-length
     * bytes), which is sufficient for anything that fits in a certificate
     * extension.
     */
    public static byte[] unwrapExtensionValue(byte[] der) {
        if (der == null || der.length < 2) {
            throw new IllegalArgumentException("Input too short to be a DER OCTET STRING");
        }
        if ((der[0] & 0xFF) != 0x04) {
            throw new IllegalArgumentException(
                "Expected DER OCTET STRING tag (0x04), got: " + String.format("0x%02X", der[0]));
        }

        int lengthByte = der[1] & 0xFF;
        int contentOffset;
        int contentLength;

        if ((lengthByte & 0x80) == 0) {
            // Short form: length is the byte itself.
            contentLength = lengthByte;
            contentOffset = 2;
        } else {
            // Long form: low 7 bits say how many following bytes encode the length.
            int numLengthBytes = lengthByte & 0x7F;
            if (numLengthBytes == 0 || numLengthBytes > 4) {
                throw new IllegalArgumentException(
                    "Unsupported DER length-of-length: " + numLengthBytes);
            }
            if (der.length < 2 + numLengthBytes) {
                throw new IllegalArgumentException("Truncated DER length field");
            }

            long parsedLength = 0;
            for (int i = 0; i < numLengthBytes; i++) {
                parsedLength = (parsedLength << 8) | (der[2 + i] & 0xFF);
            }
            if (parsedLength > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("DER length too large: " + parsedLength);
            }
            contentLength = (int) parsedLength;
            contentOffset = 2 + numLengthBytes;
        }

        if ((long) der.length != (long) contentOffset + contentLength) {
            throw new IllegalArgumentException("Truncated DER content");
        }

        byte[] result = new byte[contentLength];
        System.arraycopy(der, contentOffset, result, 0, contentLength);
        return result;
    }
}
