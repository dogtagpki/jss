package org.mozilla.jss;

import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.NullPointerException;
import java.security.Provider;
import java.util.Properties;

import org.mozilla.jss.util.Password;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The JSS Loader facilitates loading JSS via the Provider interface directly,
 * including from a static java.security configuration file.
 *
 * This replaces the previous CryptoManager.initialize(...) approach, allowing
 * better control over where the JSSProvider gets loaded. In order to use this
 * provider, the caller has to specify a configuration file (either via a
 * String path or its contents via an InputStream). This configuration file is
 * a java.util.Properties file. The following keys are understood:
 *
 *  - nss.config_dir -- the path to the NSS DB to initialize with
 *  - nss.cert_prefix -- the prefix for the certificate store
 *  - nss.key_prefix -- the prefix for the key store
 *  - nss.secmod_name -- the name of the secmod file
 *
 *  - nss.read_only -- whether to open the NSS DB read-only (default: false)
 *  - nss.java_only -- whether to initialize only the java portion of JSS,
 *                     and assume that NSS is already initialized (default:
 *                     false)
 *
 *  - nss.pkix_verify -- whether to use PKIX for verification (default: false)
 *  - nss.no_cert_db -- whether to open the certificate and key databases;
 *                      see InitializationValues for more info (default: false)
 *  - nss.no_mod_db -- whether to open the security module database; see
 *                     InitializationValues for more info (default: false)
 *  - nss.force_open -- whether to force initializations even if the database
 *                      cannot be opened; see InitializationValues for more
 *                      info (default: false)
 *  - nss.no_root_init -- whether to look for root certificate module and load
 *                        it; see InitializationValues for more info
 *                        (default: false)
 *  - nss.optimize_space -- whether to use smaller tables and caches; see
 *                          InitializationValues for more info (default: false)
 *  - nss.pk11_thread_safe -- whether to only load PKCS#11 modules that are
 *                            thread-safe; see InitializationValues for more
 *                            info (default: false)
 *  - nss.pk11_reload -- whether to ignore already initialized errors when
 *                       loading PKCS#11 modules; see InitializationValues for
 *                       more info (default: false)
 *  - nss.no_pk11_finalize -- whether to avoid calling C_Finalize on PKCS#11
 *                            modules; see InitializationValues for more info
 *                            (default: false)
 *  - nss.cooperate -- whether to cooperate with other parts of the program
 *                     already having initialized NSS (default: false)
 *
 *  - jss.experimental.sslengine -- whether to enable experimental SSLEngine
 *                                  support
 *
 *  - jss.fips -- whether to switch this NSS DB into FIPS mode; allowed values
 *                are ENABLED (to force FIPS mode), DISABLED (to force
 *                non-FIPS mode), or UNCHANGED (default, to infer the value
 *                from the NSS DB and/or the system)
 *
 *  - jss.ocsp.enabled -- whether or not to enable OCSP checking
 *  - jss.ocsp.responder.url -- URL of the OCSP responder to check
 *  - jss.ocsp.responder.cert_nickname -- nickname of the OCSP responder's
 *                                        certificate in the NSS DB
 *  - jss.ocsp.policy -- which JSS OCSP checking policy to use; allowed values
 *                       are NONE, NORMAL, and LEAF_AND_CHAIN; refer to
 *                       CryptoManager documentation for the difference
 *
 *  - jss.password -- static password to use to authenticate to tokens; if
 *                    this fails, the user will be prompted via the console
 */
public class JSSLoader {
    public static Logger logger = LoggerFactory.getLogger(JSSLoader.class);

    /**
     * Initialize JSS from the specified path to a configuration file.
     */
    public static CryptoManager init(String config_path) throws Exception {
        if (config_path == null) {
            String msg = "Please specify the path to the JSS configuration ";
            msg += "file in the java.security provider list.";
            throw new NullPointerException(msg);
        }

        try (FileInputStream fistream = new FileInputStream(config_path)) {
            return init(fistream);
        }
    }

    /**
     * Initialize JSS from an InputStream.
     */
    public static CryptoManager init(InputStream istream) throws Exception {
        if (CryptoManager.isInitialized()) {
            return CryptoManager.getInstance();
        }

        if (istream == null) {
            String msg = "Please specify the JSS configuration InputStream ";
            msg += "in order to properly install this provider.";
            throw new NullPointerException(msg);
        }

        Properties config = new Properties();
        config.load(istream);

        InitializationValues ivs = constructIV(config);
        parseFipsMode(config, ivs);
        parseReadOnly(config, ivs);

        parseOCSPSettings(config, ivs);
        parseProviderSettings(config, ivs);
        parseNSSSettings(config, ivs);

        // For more information about the interactions between JSSLoader and
        // CryptoManager, see docs/usage/cryptomanager.md in the source
        // distribution.
        CryptoManager.initialize(ivs);
        CryptoManager cm = CryptoManager.getInstance();

        parseOCSPPolicy(config, cm);
        parsePasswords(config, cm);

        parseExperimental(config);

        return cm;
    }

    /**
     * Constructs an InitializationValues from the specified properties files,
     * reading only the properties required to construct a new instance.
     *
     * These properties are:
     *  - nss.config_dir
     *  - nss.cert_prefix
     *  - nss.key_prefix
     *  - nss.secmod_name
     */
    private static InitializationValues constructIV(Properties config) {
        String configDir = config.getProperty("nss.config_dir", "/etc/pki/nssdb");
        String certPrefix = config.getProperty("nss.cert_prefix");
        String keyPrefix = config.getProperty("nss.key_prefix");
        String secmodName = config.getProperty("nss.secmod_name");

        if (certPrefix == null && keyPrefix == null && secmodName == null) {
            return new InitializationValues(configDir);
        }

        return new InitializationValues(configDir, certPrefix, keyPrefix, secmodName);
    }

    /**
     * Updates the specified InitializationValues with the FIPS-specific
     * properties.
     *
     * These properties are:
     *  - jss.fips
     */
    private static void parseFipsMode(Properties config, InitializationValues ivs) {
        String mode = config.getProperty("jss.fips", "unchanged");

        if (mode.equalsIgnoreCase("enabled")) {
            ivs.fipsMode = InitializationValues.FIPSMode.ENABLED;
        } else if (mode.equalsIgnoreCase("disabled")) {
            ivs.fipsMode = InitializationValues.FIPSMode.DISABLED;
        } else if (mode.equalsIgnoreCase("unchanged")) {
            ivs.fipsMode = InitializationValues.FIPSMode.UNCHANGED;
        } else {
            String msg = "Unknown value for jss.fips: " + mode + ". ";
            msg += "Expecting one of ENABLED, DISABLED, or UNCHANGED.";
            throw new RuntimeException(msg);
        }
    }

    /**
     * Update the specified InitializationValues with the value of the
     * nss.read_only property.
     */
    private static void parseReadOnly(Properties config, InitializationValues ivs) {
        Boolean value = parseBoolean(config, "nss.read_only");
        if (value != null) {
            ivs.readOnly = value;
        }
    }

    /**
     * Update the specified InitializationValues with the value of the OCSP
     * properties.
     *
     * These properties are:
     *  - jss.ocsp.enabled
     *  - jss.ocsp.responder.url
     *  - jss.ocsp.responder.cert_nickname
     */
    private static void parseOCSPSettings(Properties config, InitializationValues ivs) {
        Boolean enabled = parseBoolean(config, "jss.ocsp.enabled");
        if (enabled != null) {
            ivs.ocspCheckingEnabled = enabled;
        }

        String url = config.getProperty("jss.ocsp.responder.url");
        ivs.ocspResponderURL = url;

        String nickname = config.getProperty("jss.ocsp.responder.cert_nickname");
        ivs.ocspResponderCertNickname = nickname;
    }

    /**
     * Configure the specified InitializationValues with the correct
     * provider-related properties.
     */
    private static void parseProviderSettings(Properties config, InitializationValues ivs) {
        // We don't want to do any of this: if the user wanted to, they'd have
        // already specified this as part of the java.security configuration
        // file. Plus, we're installing ourselves as the Mozilla-JSS provider.
        ivs.installJSSProvider = false;
        ivs.removeSunProvider = false;
        ivs.installJSSProviderFirst = false;
    }

    /**
     * Configure the specified InitializationValues with the values of various
     * NSS-specific configuration values.
     *
     * These properties are:
     *  - nss.java_only
     *  - nss.pkix_verify
     *  - nss.no_cert_db
     *  - nss.no_mod_db
     *  - nss.force_open
     *  - nss.no_root_init
     *  - nss.optimize_space
     *  - nss.pk11_thread_safe
     *  - nss.pk11_reload
     *  - nss.no_pk11_finalize
     *  - nss.cooperate
     */
    private static void parseNSSSettings(Properties config, InitializationValues ivs) {
        Boolean initializeJavaOnly = parseBoolean(config, "nss.java_only");
        if (initializeJavaOnly != null) {
            ivs.initializeJavaOnly = initializeJavaOnly;
        }

        Boolean PKIXVerify = parseBoolean(config, "nss.pkix_verify");
        if (PKIXVerify!= null) {
            ivs.PKIXVerify= PKIXVerify;
        }

        Boolean noCertDB = parseBoolean(config, "nss.no_cert_db");
        if (noCertDB != null) {
            ivs.noCertDB = noCertDB;
        }

        Boolean noModDB = parseBoolean(config, "nss.no_mod_db");
        if (noModDB != null) {
            ivs.noModDB = noModDB;
        }

        Boolean forceOpen = parseBoolean(config, "nss.force_open");
        if (forceOpen != null) {
            ivs.forceOpen = forceOpen;
        }

        Boolean noRootInit = parseBoolean(config, "nss.no_root_init");
        if (noRootInit != null) {
            ivs.noRootInit = noRootInit;
        }

        Boolean optimizeSpace = parseBoolean(config, "nss.optimize_space");
        if (optimizeSpace != null) {
            ivs.optimizeSpace = optimizeSpace;
        }

        Boolean PK11ThreadSafe = parseBoolean(config, "nss.pk11_thread_safe");
        if (PK11ThreadSafe != null) {
            ivs.PK11ThreadSafe = PK11ThreadSafe;
        }

        Boolean PK11Reload = parseBoolean(config, "nss.pk11_reload");
        if (PK11Reload != null) {
            ivs.PK11Reload = PK11Reload;
        }

        Boolean noPK11Finalize = parseBoolean(config, "nss.no_pk11_finalize");
        if (noPK11Finalize != null) {
            ivs.noPK11Finalize = noPK11Finalize;
        }

        Boolean cooperate = parseBoolean(config, "nss.cooperate");
        if (cooperate != null) {
            ivs.cooperate = cooperate;
        }
    }

    /**
     * Once the CryptoManager has been initialized, update it with the value
     * of the remaining OCSP propertiy, jss.ocsp.policy.
     */
    private static void parseOCSPPolicy(Properties config, CryptoManager cm) {
        String policy = config.getProperty("jss.ocsp.policy", "NONE");

        if (policy.equalsIgnoreCase("none")) {
            cm.setOCSPPolicy(CryptoManager.OCSPPolicy.NONE);
        } else if (policy.equalsIgnoreCase("normal")) {
            cm.setOCSPPolicy(CryptoManager.OCSPPolicy.NORMAL);
        } else if (policy.equalsIgnoreCase("leaf_and_chain")) {
            cm.setOCSPPolicy(CryptoManager.OCSPPolicy.LEAF_AND_CHAIN);
        } else {
            String msg = "Unknown value for jss.ocsp.policy: " + policy + ".";
            msg += "Expecting one of NONE, NORMAL, or LEAF_AND_CHAIN.";
            throw new RuntimeException(msg);
        }
    }

    /**
     * Once the CryptoManager has been initialized, update it with the correct
     * PasswordCallback handler.
     *
     * Currently only understands a hard-coded password set via jss.password.
     */
    private static void parsePasswords(Properties config, CryptoManager cm) {
        String password = config.getProperty("jss.password");
        if (password != null && !password.isEmpty()) {
            Password pass_cb = new Password(password.toCharArray());
            cm.setPasswordCallback(pass_cb);
        }
    }

    /**
     * Check for exerpimental flags.
     */
    private static void parseExperimental(Properties config) {
        Boolean sslengine = parseBoolean(config, "jss.experimental.sslengine");
        if (sslengine != null) {
            JSSProvider.ENABLE_JSSENGINE = sslengine;
        }
    }

    /**
     * Helper function to parse a boolean value at the given key name.
     *
     * Returns true if the value is true or yes, false if the value is
     * false or no, and null if the value is empty or not present. Throws
     * an exception for a malformed value. Case insensitive.
     */
    private static Boolean parseBoolean(Properties config, String key_name) {
        String value = config.getProperty(key_name);
        if (value == null || value.isEmpty()) {
            return null;
        }

        if (value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes")) {
            return true;
        }

        if (value.equalsIgnoreCase("false") || value.equalsIgnoreCase("no")) {
            return false;
        }

        String msg = "Unknown value for boolean " + key_name + ": " + value;
        msg += ". Expecting true, false, or not specified.";
        throw new RuntimeException(msg);
    }
}
