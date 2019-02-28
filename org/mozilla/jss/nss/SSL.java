package org.mozilla.jss.nss;

/**
 * This class provides static access to raw NSS calls with the SSL prefix,
 * and handles the usage of NativeProxy objects.
 */

import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.pkcs11.PK11PrivKey;

public class SSL {
    public static native PRFDProxy ImportFD(PRFDProxy model, PRFDProxy fd);

    public static native int OptionSet(PRFDProxy fd, int option, int val);

    public static native int SetURL(PRFDProxy fd, String url);

    public static native SecurityStatusResult SecurityStatus(PRFDProxy fd);

    public static native int ResetHandshake(PRFDProxy fd, boolean asServer);

    public static native int ForceHandshake(PRFDProxy fd);

    public static native int ConfigSecureServer(PRFDProxy fd, PK11Cert cert,
        PK11PrivKey key, int kea);

    public static native int ConfigServerSessionIDCache(int maxCacheEntries,
        long timeout, long ssl3_timeout, String directory);
}
