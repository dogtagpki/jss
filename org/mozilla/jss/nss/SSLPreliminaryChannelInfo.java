package org.mozilla.jss.nss;

import java.lang.StringBuilder;

import org.mozilla.jss.ssl.*;

/**
 * Class representing the SSLPreliminaryChannelInfo struct from NSS's sslt.h.
 *
 * This class is a data class; it contains public fields rather than
 * getters/setters. It usually should be constructed via a call to
 * org.mozilla.jss.nss.SSL.GetPreliminaryChannelInfo(SSLFDProxy inst) rather
 * than directly constructing an instance.
 *
 * This class works regardless of handshake status; in particular, it will
 * succeed when called early in the handshake. If a given set of fields are
 * known, support will be indicated via the haveFIELD functions. If the value
 * of this field isn't yet known, the function will return false.
 *
 * Field names match that in the NSS equivalent struct. No fields have been
 * omitted.
 */
public class SSLPreliminaryChannelInfo {
    /**
     * Internal integer representing the fields with available data.
     */
    private long valuesSet;

    /**
     * Which protocol version is used by this SSL socket.
     */
    public SSLVersion protocolVersion;

    /**
     * Which cipher suite is used by this SSL socket.
     */
    public SSLCipher cipherSuite;

    /**
     * Whether or not early data can be sent.
     *
     * This field was added in NSS 3.29.
     *
     * NSS gives the following description about this field:
     *
     * |canSendEarlyData| is true when a 0-RTT is enabled. This can only be
     * true after sending the ClientHello and before the handshake completes.
     */
    public boolean canSendEarlyData;

    /**
     * The maximum amount of early data that can be sent.
     *
     * This field was added in NSS 3.31.
     *
     * NSS gives the following description of this field:
     *
     * The number of early data octets that a client is permitted to send on
     * this connection.  The value will be zero if the connection was not
     * resumed or early data is not permitted.  For a client, this value only
     * has meaning if |canSendEarlyData| is true.  For a server, this indicates
     * the value that was advertised in the session ticket that was used to
     * resume this session.
     */
    public long maxEarlyDataSize;

    /**
     * This field controls whether or not we have the zeroRttCipherSuite
     * field.
     *
     * When this field is true, zeroRttCipherSuite could be set with a value.
     * Otherwise, its value should be ignored. Check the corresponding field
     * function, have0RTTCipherSuite(), to see whether the handshake has
     * progressed far enough for this field to have a value.
     *
     * Note that the corresponding field is present when the version NSS used
     * to compile JSS and the runtime version of NSS match, and both have this
     * field.
     */
    public boolean haveNSS343;

    /**
     * Which cipher suite is in use for 0RTT TLS 1.3 connections.
     *
     * This field was added in NSS 3.43.
     *
     * NSS gives the following description of this field:
     *
     * This reports the cipher suite used for 0-RTT if it sent or accepted.  For
     * a client, this is set earlier than |cipherSuite|, and will match that
     * value if 0-RTT is accepted by the server.  The server only sets this
     * after accepting 0-RTT, so this will contain the same value.
     */
    public SSLCipher zeroRttCipherSuite;

    /**
     * This field controls whether or not we have the following three fields:
     *
     *  - peerDelegCred,
     *  - authKeyBits, and
     *  - signatureScheme.
     *
     * When this field is true, these fields could be set with a value.
     * Otherwise, their values should be ignored. Check the corresponding
     * field function, havePeerAuth(), to see whether the handshake has
     * progressed far enough for this field to have a value.
     *
     * Note that the corresponding fields are present when the version NSS used
     * to compile JSS and the runtime version of NSS match, and both have these
     * fields.
     */
    public boolean haveNSS348;

    /**
     * Whether or not the peer has offered a delegated field.
     *
     * This field was added in NSS 3.48.
     *
     * NSS gives the following description of these three fields:
     *
     * These fields contain information about the key that will be used in
     * the CertificateVerify message. If Delegated Credentials are being used,
     * this is the DC-contained SPKI, else the EE-cert SPKI. These fields are
     * valid only after the Certificate message is handled. This can be determined
     * by checking the valuesSet field against |ssl_preinfo_peer_auth|.
     */
    public boolean peerDelegCred;

    /**
     * How many bits are in the authentication key.
     *
     * This field was added in NSS 3.48.
     *
     * See also: peerDelegCred and SSLChannelInfo's authKeyBits field.
     */
    public int authKeyBits;

    /**
     * Signature scheme used.
     *
     * This field was added in NSS 3.48.
     *
     * See also: peerDelegCred and SSLChannelInfo's signatureScheme field.
     */
    public SSLSignatureScheme signatureScheme;

    /**
     * Constructor used by SSL.GetPreliminaryChannelInfo(...).
     *
     * This translates between ints and enum constants.
     */
    public SSLPreliminaryChannelInfo(long valuesSet, int protocolVersion,
        int cipherSuite, boolean canSendEarlyData, long maxEarlyDataSize,
        boolean haveNSS343, int zeroRttCipherSuite, boolean haveNSS348,
        boolean peerDelegCred, int authKeyBits, int signatureScheme)
    {
        this.valuesSet = valuesSet;

        if (haveProtocolVersion()) {
            try {
                this.protocolVersion = SSLVersion.valueOf(protocolVersion);
            } catch (IllegalArgumentException iae) {
                this.protocolVersion = null;
            }
        }

        if (haveCipherSuite()) {
            this.cipherSuite = SSLCipher.valueOf(cipherSuite);
        }

        this.canSendEarlyData = canSendEarlyData;
        this.maxEarlyDataSize = maxEarlyDataSize;

        this.haveNSS343 = haveNSS343;

        if (have0RTTCipherSuite()) {
            this.zeroRttCipherSuite = SSLCipher.valueOf(zeroRttCipherSuite);
        }

        this.haveNSS348 = haveNSS348;

        if (havePeerAuth()) {
            this.peerDelegCred = peerDelegCred;
            this.authKeyBits = authKeyBits;
            this.signatureScheme = SSLSignatureScheme.valueOf(signatureScheme);
        }
    }

    /**
     * Helper to check the valueSet bitmask for availability of the specified
     * field.
     */
    private boolean haveField(long mask) {
        return (valuesSet & mask) == mask;
    }

    /**
     * Check this to see whether the value of protocolVersion can be used.
     *
     * Returns true if the handshake has progressed far enough for the value
     * of the field to be determined.
     */
    public boolean haveProtocolVersion() {
        long ssl_preinfo_version = 1 << 0;
        return haveField(ssl_preinfo_version);
    }

    /**
     * Check this to see whether the value of cipherSuite can be used.
     *
     * Returns true if the handshake has progressed far enough for the value
     * of the field to be determined.
     */
    public boolean haveCipherSuite() {
        long ssl_preinfo_cipher_suite = 1 << 1;
        return haveField(ssl_preinfo_cipher_suite);
    }

    /**
     * Check this to see whether the value of zeroRttCipherSuite can be used.
     *
     * Returns true if the handshake has progressed far enough for the value
     * of the field to be determined.
     */
    public boolean have0RTTCipherSuite() {
        long ssl_preinfo_0rtt_cipher_suite = 1 << 2;
        return haveField(ssl_preinfo_0rtt_cipher_suite) && haveNSS343;
    }

    /**
     * Check this to see whether the value of the peerDelegCred, authKeyBits,
     * and signatureScheme fields can be used.
     *
     * Returns true if the handshake has progressed far enough for the value
     * of the fields to be determined.
     */
    public boolean havePeerAuth() {
        long ssl_preinfo_peer_auth = 1 << 3;
        return haveField(ssl_preinfo_peer_auth) && haveNSS348;
    }

    /**
     * Returns a string representation of the data in this data structure.
     */
    public String toString() {
        StringBuilder result = new StringBuilder("SSLPreliminaryChannelInfo:");

        if (haveProtocolVersion()) {
            result.append("\n- protocolVersion: " + protocolVersion);
        }

        if (haveCipherSuite()) {
            result.append("\n- cipherSuite: " + cipherSuite);
        }

        result.append("\n- canSendEarlyData: " + canSendEarlyData);
        result.append("\n- maxEarlyDataSize: " + maxEarlyDataSize);

        if (have0RTTCipherSuite()) {
            result.append("\n- zeroRttCipherSuite: " + zeroRttCipherSuite);
        }

        if (havePeerAuth()) {
            result.append("\n- peerDelegCred: " + peerDelegCred);
            result.append("\n- authKeyBits: " + authKeyBits);
            result.append("\n- signatureScheme: " + signatureScheme);
        }

        return result.toString();
    }
}
