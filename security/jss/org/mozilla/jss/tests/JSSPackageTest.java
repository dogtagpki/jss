/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

public class JSSPackageTest {

    public static void main(String[] args) {
        try {
            Package pkg = Package.getPackage("org.mozilla.jss");
            if (pkg != null) {
                System.out.println("\n---------------------------------------------------------");
                System.out.println("Checking jss jar and library version");
                System.out.println("---------------------------------------------------------");
                System.out.println("              Introspecting jss jar file");
                System.out.println("Package name:\t" + pkg.getName());

                System.out.println("Spec title  :\t" + pkg.getSpecificationTitle());
                System.out.println("Spec vendor :\t" + pkg.getSpecificationVendor());
                System.out.println("Spec version:\t" + pkg.getSpecificationVersion());

                System.out.println("Impl title  :\t" + pkg.getImplementationTitle());
                System.out.println("Impl vendor :\t" + pkg.getImplementationVendor());
                System.out.println("Impl version:\t" + pkg.getImplementationVersion());
            }
            System.out.println("\n\tFetching version information " +
                               "from CryptoManager");
            System.out.println("\n\t" + org.mozilla.jss.CryptoManager.JAR_JSS_VERSION);
            System.out.println("\n\tSuggested NSS/NSPR version to use " +
                               "with this JSS:");
            System.out.println("\n\t" + org.mozilla.jss.CryptoManager.JAR_NSS_VERSION);
            System.out.println("\t" + org.mozilla.jss.CryptoManager.JAR_NSPR_VERSION);

            System.out.println("\n\tTo check the JNI version in libjss4.so:"); 
            System.out.println("\n\ttry: strings libjss4.so | grep -i header"); 
            System.out.println("\n\tor : ident libjss4.so");         
            System.exit(0);

        } catch (Exception e) {
            System.out.println("Exception caught : " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
