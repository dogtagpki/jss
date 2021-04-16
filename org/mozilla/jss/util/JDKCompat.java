
package org.mozilla.jss.util;

import java.lang.reflect.Method;

import javax.net.ssl.SSLParameters;

public class JDKCompat {
    public static class SSLParametersHelper {
        public static String[] getApplicationProtocols(SSLParameters inst) {
            try {
                Method getter = inst.getClass().getMethod("getApplicationProtocols");
                Object result = getter.invoke(inst);
                return (String[]) result;
            } catch (NoSuchMethodException nsme) {
                return null;
            } catch (Throwable t) {
                throw new RuntimeException(t.getMessage(), t);
            }
        }
    }
}
