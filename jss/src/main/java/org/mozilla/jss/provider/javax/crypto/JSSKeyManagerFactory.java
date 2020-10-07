package org.mozilla.jss.provider.javax.crypto;

import java.security.*;
import javax.net.ssl.*;

import org.mozilla.jss.*;
import org.mozilla.jss.util.*;
import org.mozilla.jss.provider.java.security.*;

public class JSSKeyManagerFactory extends KeyManagerFactorySpi {
    private KeyStore internalStorage;
    char[] password;

    protected void engineInit(KeyStore ks, char[] password) throws KeyStoreException {
        if (password != null) {
            engineInitCryptoManager(password);

            // We need to keep this password around and give it to the
            // JSSKeyManager instance; the KeyStore API requires a password
            // to open private keys, though JSS might not necessarily use
            // that.
            this.password = password;
        }

        if (ks != null) {
            engineInitKeyStore(ks);
        }
    }

    protected void engineInitCryptoManager(char[] password) throws KeyStoreException {
        try {
            // At most, we can update the password callback if one doesn't exist.
            CryptoManager cm = CryptoManager.getInstance();

            if (cm.getPasswordCallback() == null && password != null) {
                PasswordCallback callback = new Password(password);
                cm.setPasswordCallback(callback);
            }
        } catch (Exception e) {
            throw new KeyStoreException(e.getMessage(), e);
        }
    }

    protected void engineInitKeyStore(KeyStore ks) throws KeyStoreException {
        try {
            if (!ks.getProvider().getName().equals("Mozilla-JSS")) {
                String msg = "Unable to initialize JSSKeyManagerFactory ";
                msg += "with key store from non-JSS provider.";
                throw new KeyStoreException(msg);
            }

            internalStorage = ks;
        } catch (Exception e) {
            throw new KeyStoreException(e.getMessage(), e);
        }
    }

    protected void engineInit(ManagerFactoryParameters spec) {
        // There is nothing we can do here, so exit without initializing
        // anything. In the future, we can provide a method to return
        // multiple token-specific KeyManagers.
    }

    protected KeyManager[] engineGetKeyManagers() {
        KeyManager[] kms = new KeyManager[1];
        kms[0] = new JSSTokenKeyManager(internalStorage, password);

        return kms;
    }
}
