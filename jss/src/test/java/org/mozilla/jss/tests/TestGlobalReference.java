package org.mozilla.jss.tests;

import org.mozilla.jss.util.*;

public class TestGlobalReference {
    public static void main(String[] args) throws Exception {
        String arg = "Something";

        for (int i = 0; i < 100; i++) {
            GlobalRefProxy proxy = new GlobalRefProxy(arg);
            // This should free the global reference.
            proxy.close();
            // This call makes sure the NativeProxy was removed from the
            // reference tracker; otherwise, the JVM would crash due to a
            // double free.
            proxy.close();
            // This call makes sure clear behaves correctly after a call to
            // close was also made.
            proxy.clear();
        }

        for (int i = 1; i <= 4; i++) {
            // This attempts to provoke the GC into running, hopefully
            // executing GlobalRefProxy.finalize(...) on the above objects.
            // This will be another attempt to trigger a double free, but
            // we shouldn't crash.
            System.gc();
            Thread.sleep(i * 500);
        }

        // Since we didn't initialize JSS and we freed all our GlobalRefProxy
        // instances we created, we expect the registry to be empty.
        NativeProxy.assertRegistryEmpty();
    }
}
