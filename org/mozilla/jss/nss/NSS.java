package org.mozilla.jss.nss;

/**
 * This class provides static access to raw NSS calls with the NSS prefix,
 * and handles the usage of NativeProxy objects.
 */

public class NSS {
    public static native int Init(String directory);
}
