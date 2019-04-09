package org.mozilla.jss.provider.javax.crypto;

import java.security.*;
import javax.net.ssl.*;

import org.mozilla.jss.*;
import org.mozilla.jss.util.*;
import org.mozilla.jss.provider.java.security.*;

public class JSSKeyManagerFactory extends KeyManagerFactorySpi {
    protected void engineInit(KeyStore ks, char[] password) throws KeyStoreException {
        try {
            // At most, we can update the password callback if one doesn't exist.
            CryptoManager cm = CryptoManager.getInstance();

            if (cm.getPasswordCallback() == null && password != null) {
                PasswordCallback callback = new Password(password);
                cm.setPasswordCallback(callback);
            }
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    protected void engineInit(ManagerFactoryParameters spec) {
        // There is absolutely nothing we can do here, so exit without
        // initializing anything.
    }

    protected KeyManager[] engineGetKeyManagers() {
        KeyManager[] kms = new KeyManager[1];
        kms[0] = new JSSKeyManager();

        return kms;
    }
}
