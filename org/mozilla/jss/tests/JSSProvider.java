package org.mozilla.jss.tests;

import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.net.ssl.*;

import org.mozilla.jss.*;
import org.mozilla.jss.pkcs11.*;

public class JSSProvider {
    public static String BASE_PACKAGE = "org.mozilla.jss.provider.";

    public static void shouldProvide(Provider p, String algo, String _type) {
        String item = (String) p.get(algo);
        assert(item != null);
        assert(item.startsWith(BASE_PACKAGE));
        assert(item.endsWith("." + _type));
    }

    public static void shouldNotProvide(Provider p, String algo) {
        assert(p.get(algo) == null);
    }

    public static void main(String[] args) throws Exception {
        // Before we initialize the CryptoManager, the JSS Provider shouldn't
        // exist.
        assert(Security.getProvider("Mozilla-JSS") == null);

        CryptoManager.initialize(args[0]);
        CryptoManager cm = CryptoManager.getInstance();
        cm.setPasswordCallback(new FilePasswordCallback(args[1]));

        // Validate that the CryptoManager registers us as the
        // default/first provider.
        Provider p = Security.getProviders()[0];
        assert(p.getName().equals("Mozilla-JSS"));
        assert(p instanceof org.mozilla.jss.JSSProvider);

        // Validate assumptions about how provider.get() works:
        //
        // Something which by no means should ever be implemented returns
        // null.
        shouldNotProvide(p, "Charlie's Chocolate Factory");

        // Validate that our provider implements certain interfaces we care
        // about. In particular, ensure they're overriden as part of our
        // org.mozilla.jss.provider package, and that the class name matches
        // what we expect our implementation to be.
        shouldProvide(p, "KeyManagerFactory.NssX509", "JSSKeyManagerFactory");

        // Validate that our provider is "default"; that is, when we get an
        // algorithm instance without explicitly providing the provider, we
        // end up with an instance from our provider.
        Mac m = Mac.getInstance("HmacSHA512");
        assert(m.getProvider().getName().equals(p.getName()));

        // Our KeyManagerFactory and TrustMangerFactory should return KeyManagers
        // and TrustManagers from our class namespace.
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("NssX509");
        assert(kmf.getKeyManagers().length > 0);
        for (KeyManager km : kmf.getKeyManagers()) {
            System.out.println("got KeyManager: " + km);
            assert(km instanceof org.mozilla.jss.provider.javax.crypto.JSSKeyManager);
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("NssX509");
        assert(tmf.getTrustManagers().length > 0);
        for (TrustManager tm : tmf.getTrustManagers()) {
            System.out.println("got TrustManager: " + tm);
            assert(tm instanceof org.mozilla.jss.provider.javax.crypto.JSSTrustManager);
        }

        // Our KeyStore should return instances or extensions of PK11Cert.
        KeyStore ks = KeyStore.getInstance("PKCS11");
        ks.load(null, null);
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            java.security.cert.Certificate cert = ks.getCertificate(alias);

            if (cert == null) {
                continue;
            }

            assert(cert instanceof org.mozilla.jss.pkcs11.PK11Cert);
        }
    }
}
