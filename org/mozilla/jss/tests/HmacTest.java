
package org.mozilla.jss.tests;


import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.SymmetricKey;


public class HmacTest {

  private static final String INTERNAL_KEY_STORAGE_TOKEN =
    new CryptoManager.InitializationValues("").getInternalKeyStorageTokenDescription().trim();

  private static final String NSS_DATABASE_DIR = "sql:data";
  private static final String PROVIDER = "Mozilla-JSS";


  public static void main(String[] args)
   {

    String algorithm = "hmac-sha1";

    try {
       configureCrypto(args);

       Mac mac = Mac.getInstance(algorithm, PROVIDER);

       byte[] keyData = new byte[16];
       Key key = importHmacSha1Key(keyData);

       mac.init(key);

       doHMAC(mac,"Dogtag rules!");

       System.out.println("Done");

       System.exit(0);
    } catch (Exception e) {
        System.exit(1);
    }
  }

  private static void configureCrypto(String[] args)
    throws Exception {

    CryptoManager.InitializationValues initializationValues =
      new CryptoManager.InitializationValues(args[0]);

    CryptoManager.initialize(initializationValues);

    CryptoManager cryptoManager = CryptoManager.getInstance();

    CryptoToken cryptoToken =
      cryptoManager.getTokenByName(INTERNAL_KEY_STORAGE_TOKEN);

    cryptoManager.setThreadToken(cryptoToken);
  }

  private static Key importHmacSha1Key(byte[] key)
    throws Exception {

    final String WRAPPING_ALGORITHM = "AES/CBC/PKCS5Padding";

    Key wrappingKey = getWrappingKey();

    byte[] iv = new byte[16];
    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

    Cipher wrappingCipher = Cipher.getInstance(WRAPPING_ALGORITHM, PROVIDER);
    wrappingCipher.init(Cipher.ENCRYPT_MODE, wrappingKey, ivParameterSpec);

    byte[] wrappedKeyData = wrappingCipher.doFinal(key);

    Cipher unwrappingCipher = Cipher.getInstance(WRAPPING_ALGORITHM, PROVIDER);
    unwrappingCipher.init(Cipher.UNWRAP_MODE, wrappingKey, ivParameterSpec);

    return (SecretKey) unwrappingCipher.unwrap(wrappedKeyData,
                                               SymmetricKey.SHA1_HMAC.toString(),
                                               Cipher.SECRET_KEY);
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
