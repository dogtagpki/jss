
import java.security.Security;
import java.security.Provider;

import java.util.*;
import java.security.*;
import javax.crypto.*;
import java.security.Provider;
import java.security.Security;
import java.util.Enumeration;
import java.util.Properties;

import java.io.File;
import java.io.FileWriter;
import java.io.FileInputStream;
import java.io.IOException;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.InitializationValues;
import org.mozilla.jss.JSSProvider;
import org.mozilla.jss.util.Password;
import org.mozilla.jss.util.PasswordCallback;
import org.mozilla.jss.util.PasswordCallbackInfo;
import org.mozilla.jss.util.NullPasswordCallback;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * List the available capabilities for ciphers, key agreement, macs, message
 * digests, signatures and other objects for the Mozilla-JSS provider.
 *
 * The listing is done via two methods:
 * 1) A brief enumeration from example given at page that can no longer be found
 *    http://www.java2s.com/Code/Java/Security/ListAllProviderAndItsAlgorithms.html
 * 2) A verbose enumeration based on example 1 from Cryptography for Java by David Hook
 *
 * Initialization code is like the one in org.mozilla.jss.tests.HmacTest
 */
public class CapabilitiesList {

    // start Capabilities inner class

    /**
     * List the available capabilities for ciphers, key agreement, macs, message
     * digests, signatures and other objects for the Mozilla-JSS provider.
     *
     * The listing is done via two methods:
     * 1) A brief enumeration from example given at page that can no longer be found
     *    http://www.java2s.com/Code/Java/Security/ListAllProviderAndItsAlgorithms.html
     * 2) A verbose enumeration based on example 1 from Cryptography for Java by David Hook
     *
     * It incorporates code from org.mozilla.jss.tests.JSSProvider
     */
    static class Capabilities {

        public static Logger logger = LoggerFactory.getLogger(CapabilitiesList.class);
        public static String briefFileBase = "listings/brief/Capabilities4";
        public static String verboseFileBase = "listings/verbose/Capabilities4";

        /* Inner class to use existing system nss database
         */
        public static class UseSystemDB {
            /* Same location in the Linux distros we have tested
             */
            public static String NSS_DB_LOCATION = "/etc/pki/nssdb";
            private UseSystemDB() {}
            /* Only a static method */

           /* Method adapted from one used in the candlepin projects
            * https://github.com/candlepin/candlepin/pull/2370/files#diff-170cc2e1af322c9796d4d8fe20e32bb0R98
            * an approach that was suggested by Alexander Scheel
            */
            public static void addJSSProvider() throws Exception {
                logger.debug("Starting call to JSSProviderLoader.addProvider()...");
                InitializationValues ivs = new InitializationValues(NSS_DB_LOCATION);
                ivs.noCertDB = true;
                ivs.installJSSProvider = true;
                ivs.initializeJavaOnly = false;
                CryptoManager.initialize(ivs);
                CryptoManager cm = CryptoManager.getInstance();
            }
        }

        public Capabilities() {
        }

        /* List capabilites of the specified provider */
        public void listCapabilities(FileWriter fw, Provider p) throws Exception {

            String pName = p.getName();
            Set<Object> keySet = p.keySet();
            assert(keySet != null);
            Iterator it = keySet.iterator();
            assert(it != null);
            it = p.keySet().iterator();
            while (it.hasNext()) {
                String entry = (String)it.next();
                if (entry.startsWith("Alg.alias.")) {
                    entry = entry.substring("Alg.Alias.".length());
                }
                String factoryClass = entry.substring(0, entry.indexOf('.'));
                String name = entry.substring(factoryClass.length()+1);
                assert(name != null);
                fw.write(String.format("\t %s : %s", factoryClass, name));
                fw.write(System.lineSeparator());
            }
        }

        /* Determine whether Mozilla-JSS provider was registered */
        public boolean jssIsRegistered(Provider[] ps) throws Exception {
            Provider jssProvider = null;
            for (int i = 0; i < ps.length; i++) {
                Provider p = ps[i];
                if (p.getName().equals("Mozilla-JSS")) {
                    jssProvider = p;
                    break;
                }
            }
            assert(jssProvider != null);
            assert(jssProvider.getName().equals("Mozilla-JSS"));
            assert(jssProvider instanceof org.mozilla.jss.JSSProvider);
            return (jssProvider != null);
        }

        public void addJssProvider() throws Exception {
            try {
                UseSystemDB.addJSSProvider();
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Alternative method failed: keep going");
            }

            // Validate that CryptoManager registers jss as a provider.
            assert(jssIsRegistered(Security.getProviders()) == true);
        }

        public boolean createOutputDirs() throws Exception {

           try {
                /* Create hierarchy of directores for the results */

                File dir4Listings = new File(System.getProperty("user.dir").concat("/listings"));
                dir4Listings.mkdir();

                File dir4verboseListings = 
                    new File(System.getProperty("user.dir").concat("/listings/verbose"));
                    dir4verboseListings.mkdir();

                File dir4briefListings = 
                    new File(System.getProperty("user.dir").concat("/listings/brief"));
                dir4briefListings.mkdir();

                return true;

            } catch (Exception e) {
                logger.info("Exception caught in createOutputDirs: " + e.getMessage(), e);
                logger.info("Keep going");
                return false;
            }
        }

        /* List providers capabilities using the brief listing method which adds
         * results for each provider listed to the listings/brief directory
         */
        public void listBrief(Provider[] ps) throws Exception {
            try {
                for (int i = 0; i < ps.length; i++) {
                    String fileName = briefFileBase + ps[i].getName() + ".txt";
                    FileWriter fw = new FileWriter(new File(fileName));
                    for (Enumeration e = ps[i].keys(); e.hasMoreElements();) {
                        fw.write(String.format("\t %s", e.nextElement()));
                        fw.write(System.lineSeparator());
                    }
                    fw.close();
                    File resultsFile = new File(fileName);
                    assert(resultsFile.exists());
                }
            } catch (Exception e) {
                logger.info("Exception caught in listBrief: " + e.getMessage(), e);
                logger.info("Keep going");
            }
        }

        /* List providers capabilities using the verbose listing method which
         * adds results for each provider listed to the listings/verbose directory
         */
        public void listVerbose(Provider[] ps) throws Exception {
            try {
                for (int i = 0; i < ps.length; i++) {
                    String fileName = verboseFileBase + ps[i].getName() + ".txt";
                    FileWriter fw = new FileWriter(new File(fileName));
                    listCapabilities(fw, ps[i]);
                    fw.close();
                    File resultsFile = new File(fileName);
                    assert(resultsFile.exists());
                }
            } catch (Exception e) {
                logger.info("Exception caught in listVerbose: " + e.getMessage(), e);
                logger.info("Keep going");
            }
        }
    }

    public static void main(String[] args) {
        try {
            Capabilities lister = new Capabilities();
            if (!lister.createOutputDirs()) return;
            lister.addJssProvider();
            Provider ps[] = Security.getProviders();
            lister.listBrief(ps);
            lister.listVerbose(ps);
        } catch (Exception e) {
            Capabilities.logger.info("Exception caught in main: " + e.getMessage(), e);
        }
    }
}
