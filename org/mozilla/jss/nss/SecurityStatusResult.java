package org.mozilla.jss.nss;

public class SecurityStatusResult {
    public int on;
    public byte[] cipher;
    public int keySize;
    public int secretKeySize;
    public byte[] issuer;
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

