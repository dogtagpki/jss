package org.mozilla.jss.nss;

/**
 * The fields in a SecurityStatusResult indicate whether a given SSL-enabled
 * PRFileDesc has completed its handshake and the resulting handshake-specific
 * information.
 *
 * These object is returned by org.mozilla.jss.nss.SSL.SecurityStatus(fd).
 */
public class SecurityStatusResult {
    /* Whether or not the handshake has completed successfully. */
    public int on;

    /* The current ciphersuite used. */
    public byte[] cipher;

    /* Size of the negotiated peer key. */
    public int keySize;

    /* Size of the session secret key. */
    public int secretKeySize;

    /* Issuer of the peer's certificate. */
    public byte[] issuer;

    /* Subject of the peer's certificate. */
    public byte[] subject;

    public SecurityStatusResult(int _on, byte[] _cipher, int _keySize,
        int _secretKeySize, byte[] _issuer, byte[] _subject)
    {
        this.on = _on;
        this.cipher = _cipher;
        this.keySize = _keySize;
        this.secretKeySize = _secretKeySize;
        this.issuer = _issuer;
        this.subject = _subject;
    }
}

