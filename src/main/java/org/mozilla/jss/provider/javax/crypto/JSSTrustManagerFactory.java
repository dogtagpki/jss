package org.mozilla.jss.provider.javax.crypto;

import java.security.*;
import javax.net.ssl.*;

public class JSSTrustManagerFactory extends TrustManagerFactorySpi {
    protected void engineInit(KeyStore ks) {
        // There is nothing we can do here.
    }

    protected void engineInit(ManagerFactoryParameters spec) {
        // There is nothing we can do here.
    }

    protected TrustManager[] engineGetTrustManagers() {
        TrustManager[] tms = new TrustManager[1];
        tms[0] = new JSSTrustManager();
        return tms;
    }
}
