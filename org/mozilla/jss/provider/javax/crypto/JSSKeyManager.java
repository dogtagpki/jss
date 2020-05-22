package org.mozilla.jss.provider.javax.crypto;

import javax.net.ssl.X509KeyManager;

/**
 * All JSSKeyManagers are X509KeyManagers that return PK11Cert
 * instances.
 */
public interface JSSKeyManager extends X509KeyManager {
    public org.mozilla.jss.crypto.X509Certificate getCertificate(String alias);
}
