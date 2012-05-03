/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.crypto;

import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import java.util.Hashtable;
import java.security.NoSuchAlgorithmException;

/**
 * Algorithms that can be used for signing.
 */
public class SignatureAlgorithm extends Algorithm {

    private static Hashtable oidMap = new Hashtable();

    protected SignatureAlgorithm(int oidIndex, String name,
        SignatureAlgorithm signingAlg, DigestAlgorithm digestAlg,
        OBJECT_IDENTIFIER oid)
    {
        super(oidIndex, name, oid);
        if(signingAlg == null) {
            this.signingAlg = this;
        } else {
            this.signingAlg = signingAlg;
        }
        this.digestAlg = digestAlg;
        oidMap.put(oid, this);
    }

    /**
     * Looks up the signature algorithm with the given OID.
     * @exception NoSuchAlgorithmException If no algorithm is found with this
     *      OID.
     */
    public static SignatureAlgorithm fromOID(OBJECT_IDENTIFIER oid)
        throws NoSuchAlgorithmException
    {
        Object alg = oidMap.get(oid);  
        if( alg == null ) {
            throw new NoSuchAlgorithmException();
        }
        return (SignatureAlgorithm) alg;
    }

    /**
     * The raw encryption portion of the signature algorithm. For example, 
     * SignatureAlgorithm.RSASignatureWithMD2Digest.getSigningAlg ==
     * SignatureAlgorithm.RSASignature.
     */
    public Algorithm getSigningAlg() {
        return signingAlg;
    }
    public SignatureAlgorithm getRawAlg() {
        return signingAlg;
    }
    private SignatureAlgorithm signingAlg;

    /**
     * The digest portion of the signature algorithm.
     */
    public DigestAlgorithm getDigestAlg() throws NoSuchAlgorithmException {
        if( digestAlg == null ) {
            throw new NoSuchAlgorithmException();
        }
        return digestAlg;
    }
    private DigestAlgorithm digestAlg;

    //////////////////////////////////////////////////////////////////////
    // Signature Algorithms
    //////////////////////////////////////////////////////////////////////

    /**********************************************************************
     * Raw RSA signing. This algorithm does not do any hashing, it merely
     * encrypts its input, which should be a hash.
     */
    public static final SignatureAlgorithm
    RSASignature = new SignatureAlgorithm(SEC_OID_PKCS1_RSA_ENCRYPTION, "RSA",
            null, null, OBJECT_IDENTIFIER.PKCS1.subBranch(1)  );

    /**********************************************************************
     * Raw DSA signing. This algorithm does not do any hashing, it merely
     * operates on its input, which should be a hash.
     */
    public static final SignatureAlgorithm
    DSASignature = new SignatureAlgorithm(SEC_OID_ANSIX9_DSA_SIGNATURE, "DSA",
        null, null, ANSI_X9_ALGORITHM.subBranch(1) );

    /**********************************************************************
     * Raw EC signing. This algorithm does not do any hashing, it merely
     * operates on its input, which should be a hash.
     */
    public static final SignatureAlgorithm
    ECSignature = new SignatureAlgorithm(SEC_OID_ANSIX962_EC_PUBLIC_KEY, 
	"EC",
        null, null, ANSI_X962_OID.subBranch(2).subBranch(1) );

    //////////////////////////////////////////////////////////////////////
    public static final SignatureAlgorithm
    RSASignatureWithMD2Digest =
        new SignatureAlgorithm(SEC_OID_PKCS1_MD2_WITH_RSA_ENCRYPTION,
                "RSASignatureWithMD2Digest", RSASignature, DigestAlgorithm.MD2,
                OBJECT_IDENTIFIER.PKCS1.subBranch(2) );

    //////////////////////////////////////////////////////////////////////
    public static final SignatureAlgorithm
    RSASignatureWithMD5Digest =
        new SignatureAlgorithm(SEC_OID_PKCS1_MD5_WITH_RSA_ENCRYPTION,
                "RSASignatureWithMD5Digest", RSASignature, DigestAlgorithm.MD5,
                OBJECT_IDENTIFIER.PKCS1.subBranch(4) );

    //////////////////////////////////////////////////////////////////////
    public static final SignatureAlgorithm
    RSASignatureWithSHA1Digest =
        new SignatureAlgorithm(SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION,
            "RSASignatureWithSHA1Digest", RSASignature, DigestAlgorithm.SHA1,
            OBJECT_IDENTIFIER.PKCS1.subBranch(5) );

    //////////////////////////////////////////////////////////////////////
    public static final SignatureAlgorithm
    DSASignatureWithSHA1Digest =
        new SignatureAlgorithm(SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST,
            "DSASignatureWithSHA1Digest", DSASignature, DigestAlgorithm.SHA1,
            ANSI_X9_ALGORITHM.subBranch(3) );

    //////////////////////////////////////////////////////////////////////
    public static final SignatureAlgorithm
    ECSignatureWithSHA1Digest =
        new SignatureAlgorithm(SEC_OID_ANSIX962_ECDSA_SHA1_SIGNATURE,
            "ECSignatureWithSHA1Digest", ECSignature, DigestAlgorithm.SHA1,
            ANSI_X962_OID.subBranch(4).subBranch(1) );

    //////////////////////////////////////////////////////////////////////
    public static final SignatureAlgorithm
    ECSignatureWithSHA256Digest =
        new SignatureAlgorithm(SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE,
            "ECSignatureWithSHA256Digest", ECSignature, DigestAlgorithm.SHA256,
            ANSI_X962_OID.subBranch(4).subBranch(3).subBranch(2) );

    //////////////////////////////////////////////////////////////////////
    public static final SignatureAlgorithm
    ECSignatureWithSHA384Digest =
        new SignatureAlgorithm(SEC_OID_ANSIX962_ECDSA_SHA384_SIGNATURE,
            "ECSignatureWithSHA384Digest", ECSignature, DigestAlgorithm.SHA384,
            ANSI_X962_OID.subBranch(4).subBranch(3).subBranch(3) );

    //////////////////////////////////////////////////////////////////////
    public static final SignatureAlgorithm
    ECSignatureWithSHA512Digest =
        new SignatureAlgorithm(SEC_OID_ANSIX962_ECDSA_SHA512_SIGNATURE,
            "ECSignatureWithSHA512Digest", ECSignature, DigestAlgorithm.SHA512,
            ANSI_X962_OID.subBranch(4).subBranch(3).subBranch(4) );

    //////////////////////////////////////////////////////////////////////
    public static final SignatureAlgorithm
    RSASignatureWithSHA256Digest =
        new SignatureAlgorithm(SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION,
            "RSASignatureWithSHA256Digest", RSASignature, DigestAlgorithm.SHA256,
            OBJECT_IDENTIFIER.PKCS1.subBranch(11));

    //////////////////////////////////////////////////////////////////////
    public static final SignatureAlgorithm
    RSASignatureWithSHA384Digest =
        new SignatureAlgorithm(SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION,
            "RSASignatureWithSHA384Digest", RSASignature, DigestAlgorithm.SHA384,
            OBJECT_IDENTIFIER.PKCS1.subBranch(12));
    
    //////////////////////////////////////////////////////////////////////
    public static final SignatureAlgorithm
    RSASignatureWithSHA512Digest =
        new SignatureAlgorithm(SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION,
            "RSASignatureWithSHA512Digest", RSASignature, DigestAlgorithm.SHA512,
            OBJECT_IDENTIFIER.PKCS1.subBranch(13));

}
