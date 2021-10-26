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
// (C) 2016 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.mozilla.jss.netscape.security.pkcs;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.pkcs11.PK11Cert;

public class PKCS12 {

    // PKI OID: 2.16.840.1.113730.5
    public final static OBJECT_IDENTIFIER PKI_OID = new OBJECT_IDENTIFIER("2.16.840.1.113730.5");

    // PKCS #12 OID: 2.16.840.1.113730.5.1
    public final static OBJECT_IDENTIFIER PKCS12_OID = PKI_OID.subBranch(1);

    // PKCS #12 attributes OID: 2.16.840.1.113730.5.1.1
    public final static OBJECT_IDENTIFIER PKCS12_ATTRIBUTES_OID = PKCS12_OID.subBranch(1);

    // Certificate trust flags OID: 2.16.840.1.113730.5.1.1.1
    public final static OBJECT_IDENTIFIER CERT_TRUST_FLAGS_OID = PKCS12_ATTRIBUTES_OID.subBranch(1);

    /**
     * @deprecated Use PK11Cert.VALID_PEER instead.
     */
    @Deprecated
    public final static int TERMINAL_RECORD   = PK11Cert.VALID_PEER;

    /**
     * @deprecated Use PK11Cert.TRUSTED_PEER instead.
     */
    @Deprecated
    public final static int TRUSTED           = PK11Cert.TRUSTED_PEER;

    /**
     * @deprecated Use PK11Cert.SEND_WARN instead.
     */
    @Deprecated
    public final static int SEND_WARN         = PK11Cert.SEND_WARN;

    /**
     * @deprecated Use PK11Cert.VALID_CA instead.
     */
    @Deprecated
    public final static int VALID_CA          = PK11Cert.VALID_CA;

    /**
     * @deprecated Use PK11Cert.TRUSTED_CA instead.
     */
    @Deprecated
    public final static int TRUSTED_CA        = PK11Cert.TRUSTED_CA;

    /**
     * @deprecated Use PK11Cert.NS_TRUSTED_CA instead.
     */
    @Deprecated
    public final static int NS_TRUSTED_CA     = PK11Cert.NS_TRUSTED_CA;

    /**
     * @deprecated Use PK11Cert.USER instead.
     */
    @Deprecated
    public final static int USER              = PK11Cert.USER;

    /**
     * @deprecated Use PK11Cert.TRUSTED_CLIENT_CA instead.
     */
    @Deprecated
    public final static int TRUSTED_CLIENT_CA = PK11Cert.TRUSTED_CLIENT_CA;

    /**
     * @deprecated Use PK11Cert.INVISIBLE_CA instead.
     */
    @Deprecated
    public final static int INVISIBLE_CA      = PK11Cert.INVISIBLE_CA;

    /**
     * @deprecated Use PK11Cert.GOVT_APPROVED_CA instead.
     */
    @Deprecated
    public final static int GOVT_APPROVED_CA  = PK11Cert.GOVT_APPROVED_CA;

    public static boolean isFlagEnabled(int flag, int flags) {
        return (flag & flags) > 0;
    }

    // based on printflags() in secutil.c in NSS
    public static String encodeFlags(int flags) {

        StringBuffer sb = new StringBuffer();

        if (isFlagEnabled(VALID_CA, flags) && !isFlagEnabled(TRUSTED_CA, flags) && !isFlagEnabled(TRUSTED_CLIENT_CA, flags))
            sb.append("c");

        if (isFlagEnabled(TERMINAL_RECORD, flags) && !isFlagEnabled(TRUSTED, flags))
            sb.append("p");

        if (isFlagEnabled(TRUSTED_CA, flags))
            sb.append("C");

        if (isFlagEnabled(TRUSTED_CLIENT_CA, flags))
            sb.append("T");

        if (isFlagEnabled(TRUSTED, flags))
            sb.append("P");

        if (isFlagEnabled(USER, flags))
            sb.append("u");

        if (isFlagEnabled(SEND_WARN, flags))
            sb.append("w");

        if (isFlagEnabled(INVISIBLE_CA, flags))
            sb.append("I");

        if (isFlagEnabled(GOVT_APPROVED_CA, flags))
            sb.append("G");

        return sb.toString();
    }

    // based on CERT_DecodeTrustString() in certdb.c in NSS
    public static int decodeFlags(String flags) throws Exception {

        int value = 0;

        for (char c : flags.toCharArray()) {
            switch (c) {
            case 'p':
                value = value | TERMINAL_RECORD;
                break;

            case 'P':
                value = value | TRUSTED | TERMINAL_RECORD;
                break;

            case 'w':
                value = value | SEND_WARN;
                break;

            case 'c':
                value = value | VALID_CA;
                break;

            case 'T':
                value = value | TRUSTED_CLIENT_CA | VALID_CA;
                break;

            case 'C' :
                value = value | TRUSTED_CA | VALID_CA;
                break;

            case 'u':
                value = value | USER;
                break;

            case 'i':
                value = value | INVISIBLE_CA;
                break;
            case 'g':
                value = value | GOVT_APPROVED_CA;
                break;

            default:
                throw new Exception("Invalid trust flag: " + c);
            }
        }

        return value;
    }

    Map<BigInteger, PKCS12KeyInfo> keyInfosByID = new LinkedHashMap<BigInteger, PKCS12KeyInfo>();

    Map<BigInteger, PKCS12CertInfo> certInfosByID = new LinkedHashMap<BigInteger, PKCS12CertInfo>();
    Map<BigInteger, PKCS12CertInfo> certInfosByKeyID = new LinkedHashMap<BigInteger, PKCS12CertInfo>();

    public PKCS12() {
    }

    public Collection<PKCS12KeyInfo> getKeyInfos() {
        return keyInfosByID.values();
    }

    public void addKeyInfo(PKCS12KeyInfo keyInfo) {
        keyInfosByID.put(new BigInteger(1, keyInfo.getID()), keyInfo);
    }

    public PKCS12KeyInfo getKeyInfoByID(byte[] id) {
        return keyInfosByID.get(new BigInteger(1, id));
    }

    public PKCS12KeyInfo removeKeyInfoByID(byte[] id) {
        return keyInfosByID.remove(new BigInteger(1, id));
    }

    public Collection<PKCS12CertInfo> getCertInfos() {
        return certInfosByID.values();
    }

    public void addCertInfo(PKCS12CertInfo certInfo, boolean replace) {
        BigInteger id = new BigInteger(1, certInfo.getID());

        if (!replace && certInfosByID.containsKey(id))
            return;

        certInfosByID.put(id, certInfo);

        byte[] keyID = certInfo.getKeyID();
        if (keyID == null) return;

        certInfosByKeyID.put(new BigInteger(1, keyID), certInfo);
    }

    public PKCS12CertInfo getCertInfoByID(byte[] id) {
        return certInfosByID.get(new BigInteger(1, id));
    }

    public PKCS12CertInfo getCertInfoByKeyID(byte[] keyID) {
        return certInfosByKeyID.get(new BigInteger(1, keyID));
    }

    public Collection<PKCS12CertInfo> getCertInfosByFriendlyName(String friendlyName) {

        Collection<PKCS12CertInfo> result = new ArrayList<PKCS12CertInfo>();

        for (PKCS12CertInfo certInfo : certInfosByID.values()) {
            if (!friendlyName.equals(certInfo.getFriendlyName())) continue;
            result.add(certInfo);
        }

        return result;
    }

    public void removeCertInfoByFriendlyName(String friendlyName) throws Exception {

        Collection<PKCS12CertInfo> result = getCertInfosByFriendlyName(friendlyName);

        if (result.isEmpty()) {
            throw new Exception("Certificate not found: " + friendlyName);
        }

        for (PKCS12CertInfo certInfo : result) {

            BigInteger id = new BigInteger(1, certInfo.getID());
            certInfosByID.remove(id);

            byte[] keyID = certInfo.getKeyID();
            if (keyID == null) continue;

            certInfosByKeyID.remove(new BigInteger(1, keyID));
            keyInfosByID.remove(new BigInteger(1, keyID));
        }
    }
}
