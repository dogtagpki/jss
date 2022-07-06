
package org.mozilla.jss.tests;


import java.security.Key;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.InitializationValues;

import org.mozilla.jss.crypto.CryptoToken;


public class HmacTest {

  private static final String INTERNAL_KEY_STORAGE_TOKEN =
    new InitializationValues("").getInternalKeyStorageTokenDescription().trim();

  private static final String NSS_DATABASE_DIR = "sql:data";
  private static final String PROVIDER = "Mozilla-JSS";


  public static void main(String[] args) throws Exception {

    String algorithm = "hmac-sha1";

       configureCrypto(args);

       Mac mac = Mac.getInstance(algorithm, PROVIDER);

       byte[] keyData = new byte[16];
       Key key = importHmacSha1Key(keyData);

       mac.init(key);

       doHMAC(mac,"Dogtag rules!");

       System.out.println("Done");
  }

  private static void configureCrypto(String[] args)
    throws Exception {

    CryptoManager cryptoManager = CryptoManager.getInstance();

    CryptoToken cryptoToken =
      cryptoManager.getTokenByName(INTERNAL_KEY_STORAGE_TOKEN);

    cryptoManager.setThreadToken(cryptoToken);
  }

  private static Key importHmacSha1Key(byte[] key)
    throws Exception {
    SecretKeyFactory factory = SecretKeyFactory.getInstance("HmacSHA1", "Mozilla-JSS");
    return factory.generateSecret(new SecretKeySpec(key, "HmacSHA1"));
  }

  private static synchronized Key getWrappingKey()
    throws Exception {

    final String keyGenAlgorithm = "AES";
    final int wrappingKeyLength = 256;

    KeyGenerator keyGen = KeyGenerator.getInstance(keyGenAlgorithm, PROVIDER);
    keyGen.init(wrappingKeyLength);
    return keyGen.generateKey();
  }

  public static void doHMAC(Mac mozillaHmac, String clearText)
            throws Exception {
        byte[] mozillaHmacOut;

        //Get the Mozilla HMAC
        mozillaHmacOut = mozillaHmac.doFinal(clearText.getBytes());

        if (mozillaHmacOut.length == mozillaHmac.getMacLength()) {
            System.out.println(PROVIDER + " supports " +
                    mozillaHmac.getAlgorithm() + "  and the output size is " + mozillaHmac.getMacLength());
        } else {
            throw new Exception("ERROR: hmac output size is " +
                    mozillaHmacOut.length + ", should be " +
                    mozillaHmac.getMacLength());
        }
    }


}
