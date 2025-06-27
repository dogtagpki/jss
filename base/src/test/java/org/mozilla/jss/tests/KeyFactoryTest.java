/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.Policy;
import org.mozilla.jss.util.ECCurve;
import org.mozilla.jss.util.PasswordCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

abstract class TestValues {
    protected TestValues(String keyGenAlg, String sigAlg,
        Class<? extends KeySpec> privateKeySpecClass, Class<? extends KeySpec> publicKeySpecClass,
        String provider)
    {
        this.keyGenAlg = keyGenAlg;
        this.sigAlg = sigAlg;
        this.privateKeySpecClass = privateKeySpecClass;
        this.publicKeySpecClass = publicKeySpecClass;
        this.provider = provider;
    }

    public final String keyGenAlg;
    public final String sigAlg;
    public final Class<? extends KeySpec> privateKeySpecClass;
    public final Class<? extends KeySpec> publicKeySpecClass;
    public final String provider;
}

class RSATestValues extends TestValues {
    public RSATestValues() {
        super("RSA", "SHA512withRSA", RSAPrivateCrtKeySpec.class,
            RSAPublicKeySpec.class, "SunRsaSign");
    }

    public RSATestValues(String provider) {
        super("RSA", "SHA512withRSA", RSAPrivateCrtKeySpec.class,
            RSAPublicKeySpec.class, provider);
    }
}

class DSATestValues extends TestValues {
    public DSATestValues() {
        super("DSA", "SHA512withDSA", DSAPrivateKeySpec.class,
            DSAPublicKeySpec.class, "SUN");
    }

    public DSATestValues(String provider) {
        super("DSA", "SHA512withDSA", DSAPrivateKeySpec.class,
            DSAPublicKeySpec.class, provider);
    }
}

public class KeyFactoryTest {

    public static Logger logger = LoggerFactory.getLogger(KeyFactoryTest.class);

    public static void main(String argv[]) throws Throwable {
        if( argv.length < 2 ) {
	    System.out.println(
		"Usage: java org.mozilla.jss.tests.KeyFactoryTest " +
		 "<dbdir> <passwordFile>");
            System.exit(1);
        }
        CryptoToken tok = CryptoManager.getInstance().getInternalKeyStorageToken();
	PasswordCallback cb = new FilePasswordCallback(argv[1]);
        tok.login(cb);

/* This is just a huge amount of needless info for the tinderbox and nightly QA
*        Provider []provs = Security.getProviders();
*        for( int i=0; i < provs.length; ++i) {
*            System.out.println("======");
*            System.out.println(provs[i].getName());
*            provs[i].list(System.out);
*            System.out.println("======");
*        }
*/

        (new KeyFactoryTest()).doTest();
    }

    public void doTest() throws Throwable {
        RSATestValues rsa = new RSATestValues();
        boolean exception = false;

        // Generate RSA private key from spec
        genPrivKeyFromSpec(rsa);

        // translate RSA key
        genPubKeyFromSpec(rsa);

        getECPubKeyFromSpec();
    }

    void genPrivKeyFromSpec(TestValues vals) throws Throwable {

        // generate the key pair
        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance(vals.keyGenAlg, vals.provider);
        if (vals.keyGenAlg.equalsIgnoreCase("RSA")) {
            kpg.initialize(Policy.RSA_MINIMUM_KEY_SIZE);
        } else if (vals.keyGenAlg.equalsIgnoreCase("DSA")) {
            kpg.initialize(Policy.DSA_MINIMUM_KEY_SIZE);
        } else {
            throw new IllegalArgumentException("Unknown algorithm type: " + vals.keyGenAlg);
        }

        KeyPair pair = kpg.generateKeyPair();

        // get the private key spec
        KeyFactory sunFact = KeyFactory.getInstance(vals.keyGenAlg,
            vals.provider);
        KeySpec keySpec =
            sunFact.getKeySpec(pair.getPrivate(), vals.privateKeySpecClass);

        // import it into JSS
        KeyFactory jssFact = KeyFactory.getInstance(vals.keyGenAlg,
            "Mozilla-JSS");
        PrivateKey jssPrivk = jssFact.generatePrivate(keySpec);

        signVerify(vals.sigAlg, jssPrivk, "Mozilla-JSS",
            pair.getPublic(), vals.provider);

        System.out.println("Successfully generated a " + vals.keyGenAlg +
            " private key from a " + vals.privateKeySpecClass.getName());
    }

    public void signVerify(String sigAlg, PrivateKey privk, String signProv,
        PublicKey pubk, String verifyProv) throws Throwable
    {
        Signature signSig = Signature.getInstance(sigAlg, signProv);
        signSig.initSign(privk);
        String toBeSigned = "blah blah blah sign me";
        signSig.update(toBeSigned.getBytes("UTF-8"));
        byte[] signature = signSig.sign();

        Signature verSig = Signature.getInstance(sigAlg, verifyProv);
        verSig.initVerify(pubk);
        verSig.update(toBeSigned.getBytes("UTF-8"));
        if( ! verSig.verify(signature) ) {
            throw new Exception(
                "Private/public key mismatch: signing alg=" + sigAlg +
                ", signing provider=" + signProv + ", verifying provider = " +
                verifyProv);
        }
    }

    void genPubKeyFromSpec(TestValues vals) throws Throwable {
        // generate a key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(vals.keyGenAlg,
            vals.provider);
        if (vals.keyGenAlg.equalsIgnoreCase("RSA")) {
            kpg.initialize(Policy.RSA_MINIMUM_KEY_SIZE);
        } else if (vals.keyGenAlg.equalsIgnoreCase("DSA")) {
            kpg.initialize(Policy.DSA_MINIMUM_KEY_SIZE);
        } else {
            throw new IllegalArgumentException("Unknown algorithm type: " + vals.keyGenAlg);
        }
        KeyPair pair = kpg.generateKeyPair();

        // get the public key spec
        KeyFactory sunFact = KeyFactory.getInstance(vals.keyGenAlg,
            vals.provider);
        KeySpec keySpec =
            sunFact.getKeySpec(pair.getPublic(), vals.publicKeySpecClass);

        // import it into JSS
        KeyFactory jssFact = KeyFactory.getInstance(vals.keyGenAlg,
            "Mozilla-JSS");
        PublicKey jssPubk = jssFact.generatePublic(keySpec);

        signVerify(vals.sigAlg, pair.getPrivate(), vals.provider,
            jssPubk, "Mozilla-JSS");

        System.out.println("Successfully generated a " + vals.keyGenAlg +
            " public key from a " + vals.publicKeySpecClass.getName());
    }

    void getECPubKeyFromSpec() throws Throwable {

        String message = "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IklkZE5BWi1CMG5mT1ZBUnBJeklOdjkzUmNiQ2VmdnNwRkl1eWItenJlaEUiLCJ5IjoidXlvd3duRVFHM1VWZUk3NUtkSUpfbmVXTjVQZGNmXzNRZGFRX0x1Rl9zOCJ9LCJub25jZSI6Iktka0Q1NmxEYjBVMHhtbzJ4dEtvSUEiLCJ1cmwiOiJodHRwczovL3BraS5leGFtcGxlLmNvbTo4NDQzL2FjbWUvbmV3LWFjY291bnQifQ.eyJzdGF0dXMiOiIiLCJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZX0";
        String signature = "MEQCIP0ZKGeCvoVOwb3LsMssIFf0eslxZuRB/3eVshsHzULXAiBXnrXR5+9y6p4NtB/GBccv13KqzYuFJWu/ss1i6y27sg";

        String x = "IddNAZ+B0nfOVARpIzINv93RcbCefvspFIuyb+zrehE";
        String y = "uyowwnEQG3UVeI75KdIJ/neWN5Pdcf/3QdaQ/LuF/s8";

        Signature signer;
        PublicKey publicKey;

        signer = Signature.getInstance("SHA256withECDSA", "Mozilla-JSS");

        KeyFactory keyFactory = KeyFactory.getInstance("EC", "Mozilla-JSS");
        ECCurve curve = ECCurve.fromName("P-256");
        BigInteger biX = new BigInteger(1, Base64.getDecoder().decode(x));
        BigInteger biY = new BigInteger(1, Base64.getDecoder().decode(y));
        ECPoint ecPoint = new ECPoint(biX, biY);
        ECParameterSpec ecParameterSpec = new ECParameterSpec(curve.getEC(), ecPoint, curve.getOrder(), curve.getCofactor());
        ECPublicKeySpec ecKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
        publicKey = keyFactory.generatePublic(ecKeySpec);

        signer.initVerify(publicKey);
        signer.update(message.getBytes());

        if (!signer.verify(Base64.getDecoder().decode(signature))) {
            throw new Exception("Invalid JWS");
        }
    }
}
