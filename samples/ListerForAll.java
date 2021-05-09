
import java.security.Security;
import java.security.Provider;
import org.slf4j.Logger;

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
public class ListerForAll {

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
