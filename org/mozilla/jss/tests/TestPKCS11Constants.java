package org.mozilla.jss.tests;

import java.lang.reflect.*;
import java.util.*;

public class TestPKCS11Constants {
    /**
     * This test compares the value of the PKCS11Constants that is maintained
     * by JSS against the values maintained by Sun in the equivalent methods.
     *
     * Note that this should only be run on JDK8, the last JDK to ship an
     * accessible set of PKCS11Constants
     */
    public static void main(String[] args) throws Exception {
        // Query the two classes to get references to their definitions.
        Class jss = Class.forName("org.mozilla.jss.pkcs11.PKCS11Constants");
        Class sun = Class.forName("sun.security.pkcs11.wrapper.PKCS11Constants");

        assert(!jss.equals(sun));

        // Get lists of all fields; lets us call the reflection seervices
        // once as they're likely slow.
        Field[] jss_fields = jss.getDeclaredFields();
        Field[] sun_fields = sun.getDeclaredFields();

        // To easily access the fields, build a HashMap of String->Field,
        // and maintain a set of all known field names.
        HashMap<String, Field> jss_map = new HashMap<String, Field>();
        HashMap<String, Field> sun_map = new HashMap<String, Field>();
        HashSet<String> keys = new HashSet<String>();

        for (Field field : jss_fields) {
            jss_map.put(field.getName(), field);
            keys.add(field.getName());
        }
        for (Field field : sun_fields) {
            sun_map.put(field.getName(), field);
            keys.add(field.getName());
        }

        // For pretty output, sort keys first...
        String[] keys_sorted = new String[keys.size()];
        keys_sorted = keys.toArray(keys_sorted);
        Arrays.sort(keys_sorted);

        for (String key : keys_sorted) {
            // If the field is present in both, validate that the value
            // is the same across JSS and Sun implementation. Otherwise,
            // output which implementation it is present in.
            if (jss_map.containsKey(key) && sun_map.containsKey(key)) {
                Field jss_field = jss_map.get(key);
                Field sun_field = sun_map.get(key);

                // Validate that types are correct before accessing...
                assert(jss_field.getType() == long.class);
                assert(sun_field.getType() == long.class);

                if (jss_field.getLong(null) != sun_field.getLong(null)) {
                    System.err.println("Symbol: " + key + " - NOT OK!!\n");
                    System.err.println("\tJSS: " + jss_field.getLong(null));
                    System.err.println("\tSun: " + sun_field.getLong(null));
                }

                assert(jss_field.getLong(null) == sun_field.getLong(null));
                System.out.println("Field: " + key + " - OK");
            } else if (jss_map.containsKey(key)) {
                System.err.println("Field: " + key + " - only JSS");
            } else if (sun_map.containsKey(key)) {
                System.err.println("Field: " + key + " - only Sun");
            }
        }
    }
}
