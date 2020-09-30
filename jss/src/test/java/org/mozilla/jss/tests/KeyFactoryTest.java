/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
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
        super("RSA", "SHA1withRSA", RSAPrivateCrtKeySpec.class,
            RSAPublicKeySpec.class, "SunRsaSign");
    }

    public RSATestValues(String provider) {
        super("RSA", "SHA1withRSA", RSAPrivateCrtKeySpec.class,
            RSAPublicKeySpec.class, provider);
    }
}

class DSATestValues extends TestValues {
    public DSATestValues() {
        super("DSA", "SHA1withDSA", DSAPrivateKeySpec.class,
            DSAPublicKeySpec.class, "SUN");
    }

    public DSATestValues(String provider) {
        super("DSA", "SHA1withDSA", DSAPrivateKeySpec.class,
            DSAPublicKeySpec.class, provider);
    }
}

public class KeyFactoryTest {

    public static Logger logger = LoggerFactory.getLogger(KeyFactoryTest.class);

    public static void main(String argv[]) {
      try {

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

      } catch(Throwable e) {
            e.printStackTrace();
            System.exit(1);
      }
      System.exit(0);
    }

    public void doTest() throws Throwable {
        String javaVendor = System.getProperty("java.vendor");
        RSATestValues rsa = null;
        DSATestValues dsa = null;
        boolean exception = false;

        if ( javaVendor.equals("IBM Corporation") ) {
            rsa = new RSATestValues("IBMJCE");
            dsa = new DSATestValues("IBMJCE");
        } else {
            rsa = new RSATestValues();
            dsa = new DSATestValues();
        }

        // Generate RSA private key from spec
        try {
            genPrivKeyFromSpec(rsa);
        } catch (java.security.spec.InvalidKeySpecException ex) {
            logger.warn("InvalidKeySpecException caught " +
                   "genPrivKeyFromSpec(rsa): " + ex.getMessage(), ex);
            if ( javaVendor.equals("IBM Corporation") ) {
                System.out.println("Could not generated a RSA private key from " +
                    "a\njava.security.spec.RSAPrivateKeySpec. Not supported " +
                    "IBMJCE");
            } else {
                exception = true;
            }
        } catch (Exception ex) {
            logger.warn("Exception caught genPrivKeyFromSpec(rsa): " +
                ex.getMessage(), ex);
        }

        // Generate DSA private key from spec
        try {
            genPrivKeyFromSpec(dsa);
        } catch (java.security.spec.InvalidKeySpecException ex) {
            logger.warn("InvalidKeySpecException caught " +
                    "genPrivKeyFromSpec(dsa): " + ex.getMessage(), ex);
            exception = true;
        } catch (Exception ex) {
            logger.warn("Exception caught genPrivKeyFromSpec(dsa): " +
                ex.getMessage(), ex);
        }

        // translate RSA key
        try {
            genPubKeyFromSpec(rsa);
        } catch (Exception ex) {
            logger.warn("Exception caught genPubKeyFromSpec(rsa): " +
                ex.getMessage(), ex);
            exception = true;
        }

        // translate key
        try {
	    genPubKeyFromSpec(dsa);
        } catch (Exception ex) {
            logger.warn("Exception caught genPubKeyFromSpec(dsa): " +
                ex.getMessage(), ex);
            exception = true;
        }

        if (exception)
	    System.exit(1);
        else
	    System.exit(0);
    }

    void genPrivKeyFromSpec(TestValues vals) throws Throwable {

        // generate the key pair
        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance(vals.keyGenAlg, vals.provider);
        kpg.initialize(512);
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
        kpg.initialize(512);
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
}
