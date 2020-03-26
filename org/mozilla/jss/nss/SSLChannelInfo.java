package org.mozilla.jss.nss;

import java.lang.StringBuilder;

import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.ssl.*;
import org.mozilla.jss.netscape.security.util.Utils;

/**
 * Class representing the SSLChannelInfo struct from NSS's sslt.h.
 *
 * This class is a data class; it contains public getters and no
 * setters. It usually should be constructed via a call to
 * org.mozilla.jss.nss.SSL.GetChannelInfo(SSLFDProxy inst) rather than
 * directly constructing an instance.
 *
 * Note that calling GetChannelInfo prior to the handshake completing on
 * the socket usually won't work or will give incomplete or inconclusive
 * results. Use SSL.GetPreliminaryChannelInfo instead and see the
 * corresponding class, SSLPreliminaryChannelInfo.
 *
 * Field and getter names match that in the NSS equivalent struct. The only
 * omitted field is sessionIDLength, since sessionID.length suffices and Java
 * byte arrays are of fixed, known length.
 */
public class SSLChannelInfo {
    /**
     * Which protocol version is used by this SSL socket.
     */
    private SSLVersion protocolVersion;

    /**
     * Which cipher suite is used by this SSL socket.
     */
    private SSLCipher cipherSuite;

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
    private int authKeyBits;

    /**
     * How many bits are in the key exchange key.
     *
     * NSS describes this as follows:
     *
     * key exchange algorithm info
     */
    private int keaKeyBits;

    /**
     * When the session was created, in seconds since Jan 1, 1970.
     */
    private long creationTime;

    /**
     * When the session was last accessed, in seconds since Jan 1, 1970.
     */
    private long lastAccessTime;

    /**
     * When the session expires, in seconds since Jan 1, 1970.
     */
    private long expirationTime;

    /**
     * Identifier for this session.
     *
     * Up to 32 bytes.
     */
    private byte[] sessionID;

    /**
     * Compression method used in this session.
     *
     * This field was added in NSS 3.12.5.
     */
    private SSLCompressionMethod compressionMethod;

    /**
     * Whether or not an extended master secret was used for TLS versions less
     * than 1.3.
     *
     * This field was added in NSS 3.21.
     */
    private boolean extendedMasterSecretUsed;

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
    private boolean earlyDataAccepted;

    /**
     * Key exchange algorithm info.
     *
     * This field has the same meaning as in SSLCipherSuiteInfo.
     *
     * This field was added in NSS 3.28.
     */
    private SSLKEAType keaType;

    /**
     * When keaType is an EC-based cipher, name of the group used in this
     * cipher.
     *
     * This field has the same meaning as in SSLCipherSuiteInfo.
     *
     * This field was added in NSS 3.28.
     */
    private SSLNamedGroup keaGroup;

    /**
     * Symmetric cipher algorithm info.
     *
     * This field has the same meaning as in SSLCipherSuiteInfo.
     *
     * This field was added in NSS 3.28.
     */
    private SSLCipherAlgorithm symCipher;

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
    private SSLMACAlgorithm macAlgorithm;

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
    private SSLAuthType authType;

    /**
     * Signature scheme used.
     *
     * This field was added in NSS 3.28.
     */
    private SSLSignatureScheme signatureScheme;

    /**
     * This field controls whether or not we have the following two fields:
     *
     *  - originalKeaGroup, and
     *  - resumed.
     *
     * When this field is true, the values of these fields can be trusted.
     * Otherwise, their values should be ignored.
     *
     * The corresponding fields are present when the NSS version used to
     * compile JSS and the runtime version of NSS match, and both have these
     * fields.
     */
    private boolean haveNSS334;

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
    private SSLNamedGroup originalKeaGroup;

    /**
     * Whether or not this session was resumed.
     *
     * This field was added in NSS 3.34.
     */
    private boolean resumed;

    /**
     * This field controls whether or not we have the peerDelegCred field.
     *
     * When this field is true, the values of these fields can be trusted.
     * Otherwise, their values should be ignored.
     *
     * The corresponding fields are present when the NSS version used to
     * compile JSS and the runtime version of NSS match, and both have these
     * fields.
     */
    private boolean haveNSS345;

    /**
     * Whether or not the peer used a delegated credential for authentication.
     *
     * This field was added in NSS 3.45.
     */
    private boolean peerDelegCred;

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
        boolean haveNSS334, int originalKeaGroup, boolean resumed,
        boolean haveNSS345, boolean peerDelegCred)
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

        if (haveNSS334) {
            this.originalKeaGroup = SSLNamedGroup.valueOf(originalKeaGroup);
            this.resumed = resumed;
        }

        this.haveNSS345 = haveNSS345;

        if (haveNSS345) {
            this.peerDelegCred = peerDelegCred;
        }
    }

    /**
     * Gets the value of protocolVersion.
     *
     * See also: protocolVersion
     */
    public SSLVersion getProtocolVersion() { return protocolVersion; }

    /**
     * Gets the value of cipherSuite.
     *
     * See also: cipherSuite.
     */
    public SSLCipher getCipherSuite() { return cipherSuite; }

    /**
     * Gets the value of authKeyBits.
     *
     * See also: authKeyBits.
     */
    public int getAuthKeyBits() { return authKeyBits; }

    /**
     * Gets the value of keaKeyBits.
     *
     * See also: keaKeyBits.
     */
    public int getKeaKeyBits() { return keaKeyBits; }

    /**
     * Gets the value of creationTime.
     *
     * See also: creationTime.
     */
    public long getCreationTime() { return creationTime; }

    /**
     * Gets the value of lastAccessTime.
     *
     * See also: lastAccessTime.
     */
    public long getLastAccessTime() { return lastAccessTime; }

    /**
     * Gets the value of expirationTime.
     *
     * See also: expirationTime.
     */
    public long getExpirationTime() { return expirationTime; }

    /**
     * Gets the value of sessionID.
     *
     * See also: sessionID.
     */
    public byte[] getSessionID() { return sessionID; }

    /**
     * Gets the value of compressionMethod.
     *
     * See also: compressionMethod.
     */
    public SSLCompressionMethod getCompressionMethod() { return compressionMethod; }

    /**
     * Gets the value of extendedMasterSecretUsed.
     *
     * See also: extendedMasterSecretUsed.
     */
    public boolean getExtendedMasterSecretUsed() { return extendedMasterSecretUsed; }

    /**
     * Gets the value of earlyDataAccepted.
     *
     * See also: earlyDataAccepted.
     */
    public boolean getEarlyDataAccepted() { return earlyDataAccepted; }

    /**
     * Gets the value of keaType.
     *
     * See also: keaType.
     */
    public SSLKEAType getKeaType() { return keaType; }

    /**
     * Gets the value of keaGroup.
     *
     * See also: keaGroup.
     */
    public SSLNamedGroup getKeaGroup() { return keaGroup; }

    /**
     * Gets the value of symCipher.
     *
     * See also: symCipher.
     */
    public SSLCipherAlgorithm getSymCipher() { return symCipher; }

    /**
     * Gets the value of macAlgorithm.
     *
     * See also: macAlgorithm.
     */
    public SSLMACAlgorithm getMacAlgorithm() { return macAlgorithm; }

    /**
     * Gets the value of authType.
     *
     * See also: authType.
     */
    public SSLAuthType getAuthType() { return authType; }

    /**
     * Gets the value of signatureScheme.
     *
     * See also: signatureScheme.
     */
    public SSLSignatureScheme getSignatureScheme() { return signatureScheme; }

    /**
     * Gets the value of originalKeaGroup; throws an exception when the
     * field isn't available from NSS.
     *
     * See also: originalKeaGroup.
     */
    public SSLNamedGroup getOriginalKeaGroup() throws ObjectNotFoundException {
        if (!haveNSS334) {
            String msg = "The version of NSS used to compile JSS doesn't ";
            msg += "support this field in SSLChannelInfo. Either backport ";
            msg += "this feature or upgrade to at least NSS v3.34. Check ";
            msg += "the value of HAVE_NSS_CHANNEL_INFO_ORIGINAL_KEA_GROUP ";
            msg += "when building JSS.";
            throw new ObjectNotFoundException(msg);
        }

        return originalKeaGroup;
    }

    /**
     * Gets the value of resumed; throws an exception when the field isn't
     * available from NSS.
     *
     * See also: resumed.
     */
    public boolean getResumed() throws ObjectNotFoundException {
        if (!haveNSS334) {
            String msg = "The version of NSS used to compile JSS doesn't ";
            msg += "support this field in SSLChannelInfo. Either backport ";
            msg += "this feature or upgrade to at least NSS v3.34. Check ";
            msg += "the value of HAVE_NSS_CHANNEL_INFO_ORIGINAL_KEA_GROUP ";
            msg += "when building JSS.";
            throw new ObjectNotFoundException(msg);
        }

        return resumed;
    }

    /**
     * Gets the value of peerDelegCred; throws an exception when the field
     * isn't available from NSS.
     *
     * See also: peerDelegCred.
     */
    public boolean getPeerDelegCred() throws ObjectNotFoundException {
        if (!haveNSS345) {
            String msg = "The version of NSS used to compile JSS doesn't ";
            msg += "support this field in SSLChannelInfo. Either backport ";
            msg += "this feature or upgrade to at least NSS v3.45. Check ";
            msg += "the value of HAVE_NSS_CHANNEL_INFO_PEER_DELEG_CRED ";
            msg += "when building JSS.";
            throw new ObjectNotFoundException(msg);
        }

        return peerDelegCred;
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
