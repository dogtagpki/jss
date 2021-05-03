/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.provider.java.security;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PSSParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.io.IOException;
import org.mozilla.jss.util.Assert;
import org.mozilla.jss.netscape.security.util.BigInt;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;

/**
 * A RSAPSSAlgorithmParameter implements the trandcoding between a
 * PSSAlgorithmSpec instance and the DER-encoded form.
 *
 * RSASSA-PSS-params ::= SEQUENCE {
 *  hashAlgorithm      [0] OAEP-PSSDigestAlgorithms  DEFAULT sha1,
 * maskGenAlgorithm   [1] PKCS1MGFAlgorithms  DEFAULT mgf1SHA1,
 * saltLength         [2] INTEGER  DEFAULT 20,
 *  trailerField       [3] INTEGER  DEFAULT 1
 * }
 *
 * where
 *
 *  OAEP-PSSDigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
 *    { OID id-sha1 PARAMETERS NULL   }|
 *    { OID id-sha224 PARAMETERS NULL   }|
 *    { OID id-sha256 PARAMETERS NULL }|
 *    { OID id-sha384 PARAMETERS NULL }|
 *    { OID id-sha512 PARAMETERS NULL },
 *    ...  -- Allows for future expansion --
 *  }
 *
 *  PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
 *    { OID id-mgf1 PARAMETERS OAEP-PSSDigestAlgorithms },
 *    ...  -- Allows for future expansion --
 *  }
 */
public class RSAPSSAlgorithmParameters extends AlgorithmParametersSpi {
    public final static AlgorithmId defaultHashAlg = new AlgorithmId(AlgorithmId.SHA_oid);
    public final static AlgorithmId defaultMaskGenFunc  = new AlgorithmId(AlgorithmId.MGF1_oid);
    public final static BigInt          defaultSaltLen = new BigInt(20);
    public final static BigInt          defaultTrailerField = new BigInt(1);

    private PSSParameterSpec spec = PSSParameterSpec.DEFAULT;
    private AlgorithmId hashAlg = defaultHashAlg;
    private AlgorithmId maskGenFunc = defaultMaskGenFunc;
    private BigInt saltLen = defaultSaltLen;
    private BigInt trailerField = defaultTrailerField;

    public RSAPSSAlgorithmParameters() {}

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {
        spec = (PSSParameterSpec) paramSpec;
        populateFromSpec();
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException  {
        if (paramSpec.isAssignableFrom(PSSParameterSpec.class)) {
            return paramSpec.cast(spec);
        }

        throw new InvalidParameterSpecException("Unknown parameter spec passed to PSS parameters object: " + paramSpec.getName());
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        decode(new DerInputStream(params), params);
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        // Assume Der for now.
        Assert.notReached("engineInit(byte[],String) not supported");
        throw new IOException("engineInit(byte[],String) not supported");
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        DerOutputStream out = new DerOutputStream();
        encode(out);
        return out.toByteArray();

    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        //Assume Der for now.
        Assert.notReached("engineGetEncoded(String format)) not supported");
        throw new IOException("engineGetEncoded(String format)) not supported");
    }

    @Override
    protected String engineToString() {
        String str = new String("Mozilla-JSS PSSAlgorithmParameters " +  getClass().getName() + " HashAlg: " + spec.getDigestAlgorithm() + " MaskGenAlg: " + spec.getMGFAlgorithm() );
        return str;
    }

    private void decode(DerInputStream in , byte[] encoded) throws IOException {
        if (in == null) {
            throw new IOException("Invalid input: got null DerInputStream");
        }

        // Sequence has 3 members, trailer field ignored
        DerValue seq[] = in.getSequence(3);
        if (seq.length < 3 || seq.length > 4) {
            throw new IOException("Invalid data! Expected a sequence with either 3 or 4 members; got " + seq.length);
        }

        if (seq[0].isContextSpecific((byte)0)) {
            seq[0] = seq[0].data.getDerValue();
        } else {
             throw new IOException("Invalid encoded data! Expecting OAEP-PSSDigestAlgorithms (hashAlgorithm).");
        }

        AlgorithmId algid = AlgorithmId.parse(seq[0]);

        String specAlgName = getSpecAlgName(algid.getName());

        String specMGF1Name = "";
        // Now the MFG1 parameter hash fun is the same as the main hash func.
        MGF1ParameterSpec specMFG1ParamSpec = new MGF1ParameterSpec(specAlgName);

        if (seq[1].isContextSpecific((byte)1)) {
            seq[1] = seq[1].data.getDerValue();
        } else {
            throw new IOException("Invalid encoded data! Expecting OAEP-PSSDigestAlgorithms (maskGenAlgorithm).");
        }

        DerInputStream mgf1Str = new DerInputStream(seq[1].toByteArray());
        DerValue[] seqMgf1 = mgf1Str.getSequence(2);

        ObjectIdentifier mgf1OID = seqMgf1[0].getOID();

        if (!mgf1OID.equals(AlgorithmId.MGF1_oid)) {
           throw new IOException("Invalid encoded data: expected MGF1 OID but got: " + mgf1OID.toString());
        } else {
           specMGF1Name = "MGF1";
        }

        if (seq[2].isContextSpecific((byte)2)) {
            seq[2]  = seq[2].data.getDerValue();
        } else {
            throw new IOException("Invalid encoded data! Expected INTEGER (saltLength).");
        }

        BigInt sLength = seq[2].getInteger();

        this.spec = new PSSParameterSpec(specAlgName, specMGF1Name, specMFG1ParamSpec,
                                         sLength.toInt(), 1 /* always default trailer */);

        populateFromSpec();
    }

    private void encode(DerOutputStream out) throws IOException {
        try (
            DerOutputStream tmp = new DerOutputStream();
            DerOutputStream mgf = new DerOutputStream();
            DerOutputStream seq1 = new DerOutputStream();
            DerOutputStream intStream = new DerOutputStream();
        ) {
            // Hash algorithm
            hashAlg.derEncodeWithContext(tmp,0);

            // Mask Gen Function Sequence
            mgf.putOID(maskGenFunc.getOID());

            // MGF hash alg is the same as the hash Alg at this point.
            hashAlg.encode(mgf);
            seq1.write(DerValue.tag_Sequence,mgf);
            tmp.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                                             true, (byte) 1), seq1);

            // Salt Length
            intStream.putInteger(saltLen);

            tmp.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 2),
                    intStream);

            // Ignore trailer field, it never changes over all sequence tags
            out.write(DerValue.tag_Sequence, tmp);

            byte[] data = out.toByteArray();
        }
    }

    private void populateFromSpec() {
        if (spec == null || hashAlg == null) {
            return;
        }

        String hashAlgName = spec.getDigestAlgorithm();
        String maskGenName = spec.getMGFAlgorithm();

        int saltLen = spec.getSaltLength();
        this.saltLen = new BigInt(saltLen);
        int trailer = spec.getTrailerField();

        // Create the hash alg and mask gen func objects
        if (hashAlgName.equals("SHA-256")) {
            hashAlg = new AlgorithmId(AlgorithmId.SHA256_oid);
        }  else if(hashAlgName.equals("SHA-512")) {
            hashAlg = new AlgorithmId(AlgorithmId.SHA512_oid);
        }  else if(hashAlgName.equals("SHA-384")) {
            hashAlg = new AlgorithmId(AlgorithmId.SHA384_oid);
        } else {
            // Default to SHA-1 per above ASN.1 encoding.
            hashAlg = new AlgorithmId(AlgorithmId.SHA_oid);
        }
    }

    private String getSpecAlgName(String algName) {
        if ("SHA256".equals(algName)) {
            return "SHA-256";
        } else if("SHA384".equals(algName)) {
            return "SHA-384";
        } else if("SHA512".equals(algName)) {
            return "SHA-512";
        } else {
            // Default to SHA-1 per above ASN.1 encoding.
            return "SHA-1";
        }
    }
}
