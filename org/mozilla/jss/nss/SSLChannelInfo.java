package org.mozilla.jss.nss;

import java.lang.StringBuilder;

import org.mozilla.jss.ssl.*;
import org.mozilla.jss.netscape.security.util.Utils;

/**
 * Class representing the SSLChannelInfo struct from NSS's sslt.h.
 *
 * This class is a data class; it contains public fields rather than
 * getters/setters. It usually should be constructed via a call to
 * org.mozilla.jss.nss.SSL.GetChannelInfo(SSLFDProxy inst) rather than
 * directly constructing an instance.
 *
 * Note that calling GetChannelInfo prior to the handshake completing on
 * the socket usually won't work or will give incomplete or inconclusive
 * results. Use SSL.GetPreliminaryChannelInfo instead and see the
 * corresponding class, SSLPreliminaryChannelInfo.
 *
 * Field names match that in the NSS equivalent struct. The only omitted field
 * is sessionIDLength, since sessionID.length suffices and Java byte arrays
 * are of fixed, known length.
 */
public class SSLChannelInfo {
    /**
     * Which protocol version is used by this SSL socket.
     */
    public SSLVersion protocolVersion;

    /**
     * Which cipher suite is used by this SSL socket.
     */
    public SSLCipher cipherSuite;

    /**
     * How many bits are in the authentication key.
     *
     * NSS describes this as follows:
     *
     * The strength of the key used to authenticate the peer.  Before
     * interpreting this value, check authType, signatureScheme, and
     * peerDelegCred, to determine the type of the key and how it was used.
     *
     * Typically, this is the length of the key from the peer's end-entity
     * certificate.  If delegated credentials are used (i.e., peerDelegCred is
     * PR_TRUE), then this is the strength of the delegated credential key.
     */
    public int authKeyBits;

    /**
     * How many bits are in the key exchange key.
     *
     * NSS describes this as follows:
     *
     * key exchange algorithm info
     */
    public int keaKeyBits;

    /**
     * When the session was created, in seconds since Jan 1, 1970.
     */
    public long creationTime;

    /**
     * When the session was last accessed, in seconds since Jan 1, 1970.
     */
    public long lastAccessTime;

    /**
     * When the session expires, in seconds since Jan 1, 1970.
     */
    public long expirationTime;

    /**
     * Identifier for this session.
     *
     * Up to 32 bytes.
     */
    public byte[] sessionID;

    /**
     * Compression method used in this session.
     *
     * This field was added in NSS 3.12.5.
     */
    public SSLCompressionMethod compressionMethod;

    /**
     * Whether or not an extended master secret was used for TLS versions less
     * than 1.3.
     *
     * This field was added in NSS 3.21.
     */
    public boolean extendedMasterSecretUsed;

    /**
     * Whether or not early data was accepted.
     *
     * This field was added in NSS 3.25.
     *
     * NSS has this to say:
     *
     * This field only has meaning in TLS versions greater than or equal to
     * 1.3, and indicates on the client side that the server accepted early
     * (0-RTT) data.
     */
    public boolean earlyDataAccepted;

    /**
     * Key exchange algorithm info.
     *
     * This field has the same meaning as in SSLCipherSuiteInfo.
     *
     * This field was added in NSS 3.28.
     */
    public SSLKEAType keaType;

    /**
     * When keaType is an EC-based cipher, name of the group used in this
     * cipher.
     *
     * This field has the same meaning as in SSLCipherSuiteInfo.
     *
     * This field was added in NSS 3.28.
     */
    public SSLNamedGroup keaGroup;

    /**
     * Symmetric cipher algorithm info.
     *
     * This field has the same meaning as in SSLCipherSuiteInfo.
     *
     * This field was added in NSS 3.28.
     */
    public SSLCipherAlgorithm symCipher;

    /**
     * MAC algorithm info.
     *
     * This field has the same meaning as in SSLCipherSuiteInfo.
     *
     * This field was added in NSS 3.28.
     *
     * NSS gives the following description of this field in
     * SSLCipherSuiteInfo:
     *
     * AEAD ciphers don't have a MAC. For an AEAD cipher, macAlgorithmName
     * is "AEAD", macAlgorithm is ssl_mac_aead, and macBits is the length in
     * bits of the authentication tag.
     */
    public SSLMACAlgorithm macAlgorithm;

    /**
     * Authentication type for the cipher suite.
     *
     * This field has the same meaning as in SSLCipherSuiteInfo.
     *
     * This field was added in NSS 3.28.
     *
     * NSS gives the following description of this field in
     * SSLCipherSuiteInfo:
     *
     * This reports the correct authentication type for the cipher suite, use
     * this instead of |authAlgorithm|.
     */
    public SSLAuthType authType;

    /**
     * Signature scheme used.
     *
     * This field was added in NSS 3.28.
     */
    public SSLSignatureScheme signatureScheme;

    /**
     * This field controls whether or not we have the following three fields:
     *
     *  - originalKeaGroup,
     *  - resumed, and
     *  - peerDelegCred.
     *
     * When this field is true, the values of these fields can be trusted.
     * Otherwise, their values should be ignored.
     *
     * The corresponding fields are present when the NSS version used to
     * compile JSS and the runtime version of NSS match, and both have these
     * fields.
     */
    public boolean haveNSS334;

    /**
     * This field holds the key exchange algorithm group during the initial
     * handshake.
     *
     * This field was added in NSS 3.34.
     *
     * NSS has the following description of this field:
     *
     * When the session was resumed this holds the key exchange group of the
     * original handshake.
     */
    public SSLNamedGroup originalKeaGroup;

    /**
     * Whether or not this session was resumed.
     *
     * This field was added in NSS 3.34.
     */
    public boolean resumed;

    /**
     * Whether or not the peer used a delegated credential for authentication.
     *
     * This field was added in NSS 3.34.
     */
    public boolean peerDelegCred;

    /**
     * Constructor used by SSL.GetChannelInfo(...).
     *
     * This translates between ints and enum constants.
     */
    public SSLChannelInfo(int protocolVersion, int cipherSuite,
        int authKeyBits, int keaKeyBits, long creationTime,
        long lastAccessTime, long expirationTime, byte[] sessionID,
        int compressionMethod, boolean extendedMasterSecretUsed,
        boolean earlyDataAccepted, int keaType, int keaGroup, int symCipher,
        int macAlgorithm, int authType, int signatureScheme,
        boolean haveNSS334, int originalKeaGroup, boolean resumed, boolean peerDelegCred)
    {
        try {
            this.protocolVersion = SSLVersion.valueOf(protocolVersion);
        } catch (IllegalArgumentException iae) {
            this.protocolVersion = null;
        }
        this.cipherSuite = SSLCipher.valueOf(cipherSuite);

        this.authKeyBits = authKeyBits;
        this.keaKeyBits = keaKeyBits;

        this.creationTime = creationTime;
        this.lastAccessTime = lastAccessTime;
        this.expirationTime = expirationTime;
        this.sessionID = sessionID;

        this.compressionMethod = SSLCompressionMethod.valueOf(compressionMethod);

        this.extendedMasterSecretUsed = extendedMasterSecretUsed;

        this.earlyDataAccepted = earlyDataAccepted;

        this.keaType = SSLKEAType.valueOf(keaType);
        this.keaGroup = SSLNamedGroup.valueOf(keaGroup);
        this.symCipher = SSLCipherAlgorithm.valueOf(symCipher);
        this.macAlgorithm = SSLMACAlgorithm.valueOf(macAlgorithm);
        this.authType = SSLAuthType.valueOf(authType);
        this.signatureScheme = SSLSignatureScheme.valueOf(signatureScheme);

        this.haveNSS334 = haveNSS334;

        this.originalKeaGroup = SSLNamedGroup.valueOf(originalKeaGroup);
        this.resumed = resumed;

        this.peerDelegCred = peerDelegCred;
    }

    /**
     * Returns a string representation of the data in this data structure.
     */
    public String toString() {
        StringBuilder result = new StringBuilder("SSLChannelInfo:");
        result.append("\n- protocolVersion: " + protocolVersion);
        result.append("\n- cipherSuite: " + cipherSuite);
        result.append("\n- authKeyBits: " + authKeyBits);
        result.append("\n- keaKeyBits: " + keaKeyBits);
        result.append("\n- creationTime: " + creationTime);
        result.append("\n- lastAccessTime: " + lastAccessTime);
        result.append("\n- expirationTime: " + expirationTime);
        result.append("\n- sessionID: " + Utils.HexEncode(sessionID));
        result.append("\n- compressionMethod: " + compressionMethod);
        result.append("\n- extendedMasterSecretUsed: " + extendedMasterSecretUsed);
        result.append("\n- earlyDataAccepted: " + earlyDataAccepted);
        result.append("\n- keaType: " + keaType);
        result.append("\n- keaGroup: " + keaGroup);
        result.append("\n- symCipher: " + symCipher);
        result.append("\n- macAlgorithm: " + macAlgorithm);
        result.append("\n- authType: " + authType);
        result.append("\n- signatureScheme: " + signatureScheme);
        if (haveNSS334) {
            result.append("\n- originalKeaGroup: " + originalKeaGroup);
            result.append("\n- resumed: " + resumed);
            result.append("\n- peerDelegCred: " + peerDelegCred);
        }

        return result.toString();
    }
}
