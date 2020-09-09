/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss;

import java.security.Security;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Vector;

import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.crypto.Algorithm;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.InternalCertificate;
import org.mozilla.jss.crypto.NoSuchItemOnTokenException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.TokenSupplier;
import org.mozilla.jss.crypto.TokenSupplierManager;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.KeyType;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.pkcs11.PK11Module;
import org.mozilla.jss.pkcs11.PK11SecureRandom;
import org.mozilla.jss.pkcs11.PK11Token;
import org.mozilla.jss.provider.java.security.JSSMessageDigestSpi;
import org.mozilla.jss.util.Assert;
import org.mozilla.jss.util.InvalidNicknameException;
import org.mozilla.jss.util.NativeProxy;
import org.mozilla.jss.util.PasswordCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is the starting poing for the crypto package.
 * Use it to initialize the subsystem and to lookup certs, keys, and tokens.
 * Initialization is done with static methods, and must be done before
 * an instance can be created.  All other operations are done with instance
 * methods.
 * @version $Revision$ $Date$
 */
public final class CryptoManager implements TokenSupplier
{
    public static Logger logger = LoggerFactory.getLogger(CryptoManager.class);

    static {

        logger.debug("CryptoManager: loading JSS library");

        try {
            System.loadLibrary("jss4");
            logger.debug("CryptoManager: loaded JSS library from java.library.path");

        } catch (UnsatisfiedLinkError e) {

            try {
                System.load("/usr/lib64/jss/libjss4.so");
                logger.debug("CryptoManager: loaded JSS library from /usr/lib64/jss/libjss4.so");

            } catch (UnsatisfiedLinkError e1) {
                System.load("/usr/lib/jss/libjss4.so");
                logger.debug("CryptoManager: loaded JSS library from /usr/lib/jss/libjss4.so");
            }
        }
    }

    /**
     * note: this is obsolete in NSS
     * CertUsage options for validation
     */
    public final static class CertUsage {

        static private ArrayList<CertUsage> list = new ArrayList<>();

        private int usage;
        private String name;

        private CertUsage() {
        }

        private CertUsage(int usage, String name) {
            this.usage = usage;
            this.name =  name;
            list.add(this);

        }

        public int getUsage() {
            return usage;
        }

        static public Iterator<CertUsage> getCertUsages() {
            return list.iterator();

        }
        public String toString() {
            return name;
        }

        // certUsage, these must be kept in sync with nss/lib/certdb/certt.h
        public static final CertUsage SSLClient = new CertUsage(0, "SSLClient");
        public static final CertUsage SSLServer = new CertUsage(1, "SSLServer");
        public static final CertUsage SSLServerWithStepUp = new CertUsage(2, "SSLServerWithStepUp");
        public static final CertUsage SSLCA = new CertUsage(3, "SSLCA");
        public static final CertUsage EmailSigner = new CertUsage(4, "EmailSigner");
        public static final CertUsage EmailRecipient = new CertUsage(5, "EmailRecipient");
        public static final CertUsage ObjectSigner = new CertUsage(6, "ObjectSigner");
        public static final CertUsage UserCertImport = new CertUsage(7, "UserCertImport");
        public static final CertUsage VerifyCA = new CertUsage(8, "VerifyCA");
        public static final CertUsage ProtectedObjectSigner = new CertUsage(9, "ProtectedObjectSigner");
        public static final CertUsage StatusResponder = new CertUsage(10, "StatusResponder");
        public static final CertUsage AnyCA = new CertUsage(11, "AnyCA");
    }

    ////////////////////////////////////////////////////
    //  Module and Token Management
    ////////////////////////////////////////////////////

    /**
     * Retrieves the internal cryptographic services token. This is the
     * token built into NSS that performs bulk
     * cryptographic operations.
     * <p>In FIPS mode, the internal cryptographic services token is the
     * same as the internal key storage token.
     *
     * @return The internal cryptographic services token.
     */
    public synchronized CryptoToken getInternalCryptoToken() {
        return internalCryptoToken;
    }

    /**
     * Retrieves the internal key storage token.  This is the token
     * provided by NSS to store private keys.
     * The keys stored in this token are stored in an encrypted key database.
     * <p>In FIPS mode, the internal key storage token is the same as
     * the internal cryptographic services token.
     *
     * @return The internal key storage token.
     */
    public synchronized CryptoToken getInternalKeyStorageToken() {
        return internalKeyStorageToken;
    }

    /**
     * Looks up the CryptoToken with the given name.  Searches all
     * loaded cryptographic modules for the token.
     *
     * @param name The name of the token.
     * @return The token.
     * @exception org.mozilla.jss.NoSuchTokenException If no token
     *  is found with the given name.
     */
    public synchronized CryptoToken getTokenByName(String name)
        throws NoSuchTokenException
    {
        Enumeration<CryptoToken> tokens = getAllTokens();
        CryptoToken token;

        while(tokens.hasMoreElements()) {
            token = tokens.nextElement();
            try {
                if( name.equals(token.getName()) ) {
                    return token;
                }
            } catch( TokenException e ) {
                throw new RuntimeException(e);
            }
        }
        throw new NoSuchTokenException("No such token: " + name);
    }

    /**
     * Retrieves all tokens that support the given algorithm.
     *
     * @param alg Algorithm.
     * @return Enumeration of tokens.
     */
    public synchronized Enumeration<CryptoToken> getTokensSupportingAlgorithm(Algorithm alg)
    {
        Enumeration<CryptoToken> tokens = getAllTokens();
        Vector<CryptoToken> goodTokens = new Vector<>();
        CryptoToken tok;

        while(tokens.hasMoreElements()) {
            tok = tokens.nextElement();
            if( tok.doesAlgorithm(alg) ) {
                goodTokens.addElement(tok);
            }
        }
        return goodTokens.elements();
    }

    /**
     * Retrieves all tokens. This is an enumeration of all tokens on all
     * modules.
     *
     * @return All tokens accessible from JSS. Each item of the enumeration
     *      is a <code>CryptoToken</code>
     * @see org.mozilla.jss.crypto.CryptoToken
     */
    public synchronized Enumeration<CryptoToken> getAllTokens() {
        Enumeration<PK11Module> modules = getModules();
        Enumeration<CryptoToken> tokens;
        Vector<CryptoToken> allTokens = new Vector<>();

        while(modules.hasMoreElements()) {
            tokens = modules.nextElement().getTokens();
            while(tokens.hasMoreElements()) {
                allTokens.addElement( tokens.nextElement() );
            }
        }
        return allTokens.elements();
    }

    /**
     * Retrieves all tokens except those built into NSS.
     * This excludes the internal token and the internal
     * key storage token (which are one and the same in FIPS mode).
     *
     * @return All tokens accessible from JSS, except for the built-in
     *      internal tokens.
     */
    public synchronized Enumeration<CryptoToken> getExternalTokens() {
        Enumeration<PK11Module> modules = getModules();
        Enumeration<CryptoToken> tokens;
        PK11Token token;
        Vector<CryptoToken> allTokens = new Vector<>();

        while(modules.hasMoreElements()) {
            tokens = modules.nextElement().getTokens();
            while(tokens.hasMoreElements()) {
                token = (PK11Token) tokens.nextElement();
                if( ! token.isInternalCryptoToken() &&
                    ! token.isInternalKeyStorageToken() )
                {
                    allTokens.addElement( token );
                }
            }
        }
        return allTokens.elements();
    }

    /**
     * Retrieves all installed cryptographic modules.
     *
     * @return An enumeration of all installed PKCS #11 modules. Each
     *      item in the enumeration is a <code>PK11Module</code>.
     * @see org.mozilla.jss.pkcs11.PK11Module
     */
    public synchronized Enumeration<PK11Module> getModules() {
        return moduleVector.elements();
    }

    // Need to reload modules after adding new one
    //public native addModule(String name, String libraryName);

    /**
     * The list of modules. This should be initialized by the constructor
     * and updated whenever 1) a new module is added, 2) a module is deleted,
     * or 3) FIPS mode is switched.
     */
    private Vector<PK11Module> moduleVector;

    /**
     * Re-creates the Vector of modules that is stored by CryptoManager.
     * This entails going into native code to enumerate all modules,
     * wrap each one in a PK11Module, and storing the PK11Module in the vector.
     */
    private synchronized void reloadModules() {
        moduleVector = new Vector<>();
        putModulesInVector(moduleVector);

        // Get the internal tokens
        Enumeration<CryptoToken> tokens = getAllTokens();

        internalCryptoToken = null;
        internalKeyStorageToken = null;
        while(tokens.hasMoreElements()) {
            PK11Token token = (PK11Token) tokens.nextElement();
            if( token.isInternalCryptoToken() ) {
                assert(internalCryptoToken == null);
                internalCryptoToken = token;
            }
            if( token.isInternalKeyStorageToken() ) {
                assert(internalKeyStorageToken == null);
                internalKeyStorageToken = token;
            }
        }
        assert(internalKeyStorageToken != null);
        assert(internalCryptoToken != null);
    }

    /**
     * The internal cryptographic services token.
     */
    private CryptoToken internalCryptoToken;

    /**
     * The internal key storage token.
     */
    private CryptoToken internalKeyStorageToken;

    /**
     * Native code to traverse all PKCS #11 modules, wrap each one in
     * a PK11Module, and insert each PK11Module into the given vector.
     */
    private native void putModulesInVector(Vector<PK11Module> vector);


    ///////////////////////////////////////////////////////////////////////
    // Constructor and Accessors
    ///////////////////////////////////////////////////////////////////////

    /**
     * Constructor, for internal use only.
     */
    protected CryptoManager()  {
        TokenSupplierManager.setTokenSupplier(this);
        reloadModules();
    }

    public static boolean isInitialized() {
        synchronized (CryptoManager.class) {
            return instance != null;
        }
    }

    /**
     * Retrieve the single instance of CryptoManager.
     * This cannot be called before initialization.
     *
     * @see #initialize(InitializationValues)
     * @exception NotInitializedException If
     *      <code>initialize(InitializationValues</code> has not yet been
     *      called.
     * @return CryptoManager instance.
     */
    public static CryptoManager getInstance()
        throws NotInitializedException
    {
        synchronized (CryptoManager.class) {
            if (instance != null) {
                return instance;
            }
        }

        /* Java has lazy-loading Security providers; until a provider
         * is requested, it won't be loaded. This means we could've
         * initialized the CryptoManager via the JSSLoader but we won't
         * know about it until it is explicitly requested.
         *
         * This breaks tests looking to configure a file-based password
         * handler: if the very first call is to getInstance(...) instead
         * of a Provider call, we'd fail.
         *
         * Try to get the Mozilla-JSS provider by name before reporting
         * that we're not initialized.
         *
         * However, in order for the JSSProvider to load, we need to
         * release our lock on CryptoManager (and in particular, on
         * CryptoManager.instance).
         */
        java.security.Provider p = Security.getProvider("Mozilla-JSS");

        synchronized (CryptoManager.class) {
            // When instance is properly configured, use that.
            if (instance != null) {
                return instance;
            }

            // Otherwise, work around this by looking at what JSSProvider
            // created.
            if (p instanceof JSSProvider) {
                JSSProvider jssProvider = (JSSProvider) p;
                assert jssProvider.getCryptoManager() != null;

                if (instance == null) {
                    instance = jssProvider.getCryptoManager();
                }

                return instance;
            }
        }

        throw new NotInitializedException();
    }

    /**
     * The singleton instance, and a static initializer to create it.
     */
    private static CryptoManager instance=null;


    ///////////////////////////////////////////////////////////////////////
    // FIPS management
    ///////////////////////////////////////////////////////////////////////

    /**
     * Enables or disables FIPS-140-2 compliant mode. If this returns true,
     * you must reloadModules(). This should only be called once in a program,
     * at the beginning, because it invalidates tokens and modules.
     *
     * @param fips true to turn FIPS compliant mode on, false to turn it off.
     */
    private static native boolean enableFIPS(boolean fips)
        throws GeneralSecurityException;

    /**
     * Determines whether FIPS-140-2 compliance is active.
     *
     * @return true if the security library is in FIPS-140-2 compliant mode.
     */
    public synchronized native boolean FIPSEnabled();


    ///////////////////////////////////////////////////////////////////////
    // Password Callback management
    ///////////////////////////////////////////////////////////////////////

    /**
     * This function sets the global password callback.  It is
     * not thread-safe to change this.
     * <p>The callback may be NULL, in which case password callbacks will
     * fail gracefully.
     *
     * @param pwcb Password callback.
     */
    public synchronized void setPasswordCallback(PasswordCallback pwcb) {
        passwordCallback = pwcb;
        setNativePasswordCallback( pwcb );
    }
    private native void setNativePasswordCallback(PasswordCallback cb);

    /**
     * Returns the currently registered password callback.
     *
     * @return Password callback.
     */
    public synchronized PasswordCallback getPasswordCallback() {
        return passwordCallback;
    }

    private PasswordCallback passwordCallback;


    ////////////////////////////////////////////////////
    // Initialization
    ////////////////////////////////////////////////////

    /**
     * Initialize the security subsystem.  Opens the databases, loads all
     * PKCS #11 modules, initializes the internal random number generator.
     * The <code>initialize</code> methods that take arguments should be
     * called only once, otherwise they will throw
     * an exception. It is OK to call them after calling
     * <code>initialize()</code>.
     *
     * @param configDir The directory containing the security databases.
     * @exception org.mozilla.jss.KeyDatabaseException Unable to open
     *  the key database, or it was currupted.
     * @exception org.mozilla.jss.CertDatabaseException Unable
     *  to open the certificate database, or it was currupted.
     * @exception AlreadyInitializedException If the security subsystem is already initialized.
     * @exception GeneralSecurityException If other security error occurred.
     **/
    public static synchronized void initialize( String configDir )
        throws  KeyDatabaseException,
                CertDatabaseException,
                AlreadyInitializedException,
                GeneralSecurityException
    {
        initialize( new InitializationValues(configDir) );
    }

    /**
     * Initialize the security subsystem.  Opens the databases, loads all
     * PKCS #11 modules, initializes the internal random number generator.
     * The <code>initialize</code> methods that take arguments should be
     * called only once, otherwise they will throw
     * an exception. It is OK to call them after calling
     * <code>initialize()</code>.
     *
     * @param values The options with which to initialize CryptoManager.
     * @exception org.mozilla.jss.KeyDatabaseException Unable to open
     *  the key database, or it was corrupted.
     * @exception org.mozilla.jss.CertDatabaseException Unable
     *  to open the certificate database, or it was currupted.
     * @exception AlreadyInitializedException If security subsystem is already initialized.
     * @exception GeneralSecurityException If other security error occurred.
     **/
    public static synchronized void initialize( InitializationValues values )
        throws
        KeyDatabaseException,
        CertDatabaseException,
        AlreadyInitializedException,
        GeneralSecurityException
    {
        if(instance != null) {
            throw new AlreadyInitializedException();
        }

        if (values.ocspResponderURL != null) {
            if (values.ocspResponderCertNickname == null) {
                throw new GeneralSecurityException(
                    "Must set ocspResponderCertNickname");
            }
        }

        initializeAllNative2(values.configDir,
                            values.certPrefix,
                            values.keyPrefix,
                            values.secmodName,
                            values.readOnly,
                            values.getManufacturerID(),
                            values.getLibraryDescription(),
                            values.getInternalTokenDescription(),
                            values.getInternalKeyStorageTokenDescription(),
                            values.getInternalSlotDescription(),
                            values.getInternalKeyStorageSlotDescription(),
                            values.getFIPSSlotDescription(),
                            values.getFIPSKeyStorageSlotDescription(),
                            values.ocspCheckingEnabled,
                            values.ocspResponderURL,
                            values.ocspResponderCertNickname,
                            values.initializeJavaOnly,
                            values.PKIXVerify,
                            values.noCertDB,
                            values.noModDB,
                            values.forceOpen,
                            values.noRootInit,
                            values.optimizeSpace,
                            values.PK11ThreadSafe,
                            values.PK11Reload,
                            values.noPK11Finalize,
                            values.cooperate
                            );

        instance = new CryptoManager();
        instance.setPasswordCallback(values.passwordCallback);
        if( values.fipsMode != InitializationValues.FIPSMode.UNCHANGED) {
            if( enableFIPS(values.fipsMode ==
                    InitializationValues.FIPSMode.ENABLED) )
            {
                instance.reloadModules();
            }
        }

        // Force class load before we install the provider. Otherwise we get
        // an infinite loop as the Security manager tries to instantiate the
        // digest to verify its own JAR file.
        JSSMessageDigestSpi mds = new JSSMessageDigestSpi.SHA1();
        logger.debug("Loaded " + mds);

        // Force the KeyType class to load before we can install JSS as a
        // provider.  JSS's signature provider accesses KeyType.
        KeyType kt = KeyType.getKeyTypeFromAlgorithm(
            SignatureAlgorithm.RSASignatureWithSHA1Digest);
        logger.debug("Loaded " + kt);

        if( values.installJSSProvider ) {
            int insert_position = 1;
            if (!values.installJSSProviderFirst) {
                insert_position = java.security.Security.getProviders().length + 1;
            }

            int position = java.security.Security.insertProviderAt(new JSSProvider(true), insert_position);
            if (position < 0) {
                logger.warn("JSS provider is already installed");
            }
            // This returns -1 if the provider was already installed, in which
            // case it is not installed again.  Is this
            // an error? I don't think so, although it might be confusing
            // if the provider is not in the position they expected.
            // However, this will only happen if they are installing the
            // provider themselves, so presumably they know what they're
            // doing.
        }
        if( values.removeSunProvider ) {
            java.security.Security.removeProvider("SUN");
        }

        logger.info("JSS CryptoManager: successfully initialized from NSS database at " + values.configDir);
    }

    private static native void
    initializeAllNative2(String configDir,
                        String certPrefix,
                        String keyPrefix,
                        String secmodName,
                        boolean readOnly,
                        String manufacturerID,
                        String libraryDescription,
                        String internalTokenDescription,
                        String internalKeyStorageTokenDescription,
                        String internalSlotDescription,
                        String internalKeyStorageSlotDescription,
                        String fipsSlotDescription,
                        String fipsKeyStorageSlotDescription,
                        boolean ocspCheckingEnabled,
                        String ocspResponderURL,
                        String ocspResponderCertNickname,
                        boolean initializeJavaOnly,
                        boolean PKIXVerify,
                        boolean noCertDB,
                        boolean noModDB,
                        boolean forceOpen,
                        boolean noRootInit,
                        boolean optimizeSpace,
                        boolean PK11ThreadSafe,
                        boolean PK11Reload,
                        boolean noPK11Finalize,
                        boolean cooperate)
        throws KeyDatabaseException,
        CertDatabaseException,
        AlreadyInitializedException;

    /////////////////////////////////////////////////////////////
    // Cert Lookup
    /////////////////////////////////////////////////////////////
    /**
     * Retrieves all CA certificates in the trust database.  This
     * is a fairly expensive operation in that it involves traversing
     * the entire certificate database.
     * @return An array of all CA certificates stored permanently
     *      in the trust database.
     */
    public native X509Certificate[]
    getCACerts();

    /**
     * Retrieves all certificates in the trust database.  This
     * is a fairly expensive operation in that it involves traversing
     * the entire certificate database.
     * @return An array of all certificates stored permanently
     *      in the trust database.
     */
    public native X509Certificate[]
    getPermCerts();

    /**
     * Imports a chain of certificates.  The leaf certificate may be a
     *  a user certificate, that is, a certificate that belongs to the
     *  current user and whose private key is available for use.
     *  If the leaf certificate is a user certificate, it is stored
     *  on the token
     *  that contains the corresponding private key, and is assigned the
     *  given nickname.
     *
     * @param certPackage An encoded certificate or certificate chain.
     *      Acceptable
     *      encodings are binary PKCS #7 <i>SignedData</i> objects and
     *      DER-encoded certificates, which may or may not be wrapped
     *      in a Base-64 encoding package surrounded by
     *      "<code>-----BEGIN CERTIFICATE-----</code>" and
     *      "<code>-----END CERTIFICATE-----</code>".
     * @param nickname The nickname for the user certificate.  It must
     *      be unique. It is ignored if there is no user certificate.
     * @return The leaf certificate from the chain.
     * @exception CertificateEncodingException If the package encoding
     *      was not recognized.
     * @exception NicknameConflictException If the leaf certificate
     *      is a user certificate, and another certificate already has the
     *      given nickname.
     * @exception UserCertConflictException If the leaf certificate
     *      is a user certificate, but it has already been imported.
     * @exception NoSuchItemOnTokenException If the leaf certificate is
     *      a user certificate, but the matching private key cannot be found.
     * @exception TokenException If an error occurs importing a leaf
     *      certificate into a token.
     */
    public X509Certificate
    importCertPackage(byte[] certPackage, String nickname )
        throws CertificateEncodingException,
            NicknameConflictException,
            UserCertConflictException,
            NoSuchItemOnTokenException,
            TokenException
    {
        return importCertPackageNative(certPackage, nickname, false, false);
    }

    /**
     * Imports a chain of certificates.  The leaf of the chain is a CA
     * certificate AND a user certificate (this would only be called by
     * a CA installing its own certificate).
     *
     * @param certPackage An encoded certificate or certificate chain.
     *      Acceptable
     *      encodings are binary PKCS #7 <i>SignedData</i> objects and
     *      DER-encoded certificates, which may or may not be wrapped
     *      in a Base-64 encoding package surrounded by
     *      "<code>-----BEGIN CERTIFICATE-----</code>" and
     *      "<code>-----END CERTIFICATE-----</code>".
     * @param nickname The nickname for the user certificate.  It must
     *      be unique.
     * @return The leaf certificate from the chain.
     * @exception CertificateEncodingException If the package encoding
     *      was not recognized.
     * @exception NicknameConflictException If the leaf certificate
     *      another certificate already has the given nickname.
     * @exception UserCertConflictException If the leaf certificate
     *      has already been imported.
     * @exception NoSuchItemOnTokenException If the the private key matching
     *      the leaf certificate cannot be found.
     * @exception TokenException If an error occurs importing the leaf
     *      certificate into a token.
     */
    public X509Certificate
    importUserCACertPackage(byte[] certPackage, String nickname)
        throws CertificateEncodingException,
            NicknameConflictException,
            UserCertConflictException,
            NoSuchItemOnTokenException,
            TokenException
    {
        return importCertPackageNative(certPackage, nickname, false, true);
    }



    /**
     * Imports a chain of certificates, none of which is a user certificate.
     *
     * @param certPackage An encoded certificate or certificate chain.
     *      Acceptable
     *      encodings are binary PKCS #7 <i>SignedData</i> objects and
     *      DER-encoded certificates, which may or may not be wrapped
     *      in a Base-64 encoding package surrounded by
     *      "<code>-----BEGIN CERTIFICATE-----</code>" and
     *      "<code>-----END CERTIFICATE-----</code>".
     * @return The leaf certificate from the chain.
     * @exception CertificateEncodingException If the package encoding
     *      was not recognized.
     * @exception TokenException If an error occurs importing a leaf
     *      certificate into a token.
     */
    public X509Certificate
    importCACertPackage(byte[] certPackage)
        throws CertificateEncodingException,
            TokenException
    {
        try {
            return importCertPackageNative(certPackage, null, true, false);
        } catch(NicknameConflictException e) {
            logger.error("importing CA certs caused nickname conflict", e);
            throw new RuntimeException("Importing CA certs caused nickname conflict: " + e.getMessage(), e);
        } catch(UserCertConflictException e) {
            logger.error("importing CA certs caused user cert conflict", e);
            throw new RuntimeException("Importing CA certs caused user cert conflict: " + e.getMessage(), e);
        } catch(NoSuchItemOnTokenException e) {
            logger.error("importing CA certs caused NoSuchItemOnTokenException", e);
            throw new RuntimeException("Importing CA certs caused NoSuchItemOnToken"+
                "Exception: " + e.getMessage(), e);
        }
    }

    /**
     * Imports a single certificate into the permanent certificate
     * database.
     *
     * @param cert the certificate you want to add
     * @param nickname the nickname you want to refer to the certificate as
     *        (must not be null)
     * @return Certificate object.
     * @throws TokenException If an error occurred in the token.
     * @throws InvalidNicknameException If the nickname is invalid.
     */

    public InternalCertificate
        importCertToPerm(X509Certificate cert, String nickname)
        throws TokenException, InvalidNicknameException
    {
        if (nickname==null) {
            throw new InvalidNicknameException("Nickname must be non-null");
        }

        else {
            return importCertToPermNative(cert,nickname);
        }
    }

    /**
     * Imports a single DER-encoded certificate into the permanent or temporary
     * certificate database.
     */
    public X509Certificate importDERCert(byte[] cert, CertificateUsage usage,
                                         boolean permanent, String nickname) {
        return importDERCertNative(cert, usage.getEnumValue(), permanent, nickname);
    }

    private native X509Certificate importDERCertNative(byte[] cert, int usage, boolean permanent, String nickname);

    private native InternalCertificate
        importCertToPermNative(X509Certificate cert, String nickname)
        throws TokenException;

    /**
     * @param noUser true if we know that none of the certs are user certs.
     *      In this case, no attempt will be made to find a matching private
     *      key for the leaf certificate.
     */
    private native X509Certificate
    importCertPackageNative(byte[] certPackage, String nickname,
        boolean noUser, boolean leafIsCA)
        throws CertificateEncodingException,
            NicknameConflictException,
            UserCertConflictException,
            NoSuchItemOnTokenException,
            TokenException;

    /*============ CRL importing stuff ********************************/

    private static int TYPE_KRL = 0;
    private static int TYPE_CRL = 1;
    /**
     * Imports a CRL, and stores it into the cert7.db
     * Validate CRL then import it to the dbase.  If there is already a CRL with the
      * same CA in the dbase, it will be replaced if derCRL is more up to date.
     *
     * @param crl the DER-encoded CRL.
     * @param url the URL where this CRL can be retrieved from (for future updates).
     *    [ note that CRLs are not retrieved automatically ]. Can be null
     * @exception CRLImportException If the package encoding
     *      was not recognized.
     * @exception TokenException If an error occurred in the token.
     */
     public void
    importCRL(byte[] crl,String url)
        throws CRLImportException,
            TokenException
    {
        importCRLNative(crl,url,TYPE_CRL);
    }


    /**
     * Imports a CRL, and stores it into the cert7.db
     *
     * @param the DER-encoded CRL.
     */
    private native
    void importCRLNative(byte[] crl, String url, int rl_type)
        throws CRLImportException, TokenException;



    /*============ Cert Exporting stuff ********************************/


    /**
     * Exports one or more certificates into a PKCS #7 certificate container.
     * This is just a <i>SignedData</i> object whose <i>certificates</i>
     * field contains the given certificates but whose <i>content</i> field
     * is empty.
     *
     * @param certs One or more certificates that should be exported into
     *      the PKCS #7 object.  The leaf certificate should be the first
     *      in the chain.  The output of <code>buildCertificateChain</code>
     *      would be appropriate here.
     * @exception CertificateEncodingException If the array is empty,
     *        or an error occurred encoding the certificates.
     * @return A byte array containing a PKCS #7 <i>SignedData</i> object.
     * @see #buildCertificateChain
     */
    public native byte[]
    exportCertsToPKCS7(X509Certificate[] certs)
        throws CertificateEncodingException;

    /**
     * Looks up a certificate given its nickname.
     *
     * @param nickname The nickname of the certificate to look for.
     * @return The certificate matching this nickname, if one is found.
     * @exception ObjectNotFoundException If no certificate could be found
     *      with the given nickname.
     * @exception TokenException If an error occurs in the security library.
     */
    public org.mozilla.jss.crypto.X509Certificate
    findCertByNickname(String nickname)
        throws ObjectNotFoundException, TokenException
    {
        assert(nickname!=null);
        return findCertByNicknameNative(nickname);
    }

    /**
     * Returns all certificates with the given nickname.
     *
     * @param nickname The nickname of the certificate to look for.
     * @return The certificates matching this nickname. The array may be empty
     *      if no matching certs were found.
     * @exception TokenException If an error occurs in the security library.
     */
    public org.mozilla.jss.crypto.X509Certificate[]
    findCertsByNickname(String nickname)
        throws TokenException
    {
        assert(nickname!=null);
        return findCertsByNicknameNative(nickname);
    }

    /**
     * Looks up a certificate by issuer and serial number. The internal
     *      database and all PKCS #11 modules are searched.
     *
     * @param derIssuer The DER encoding of the certificate issuer name.
     *      The issuer name has ASN.1 type <i>Name</i>, which is defined in
     *      X.501.
     * @param serialNumber The certificate serial number.
     * @return Certificate object.
     * @exception ObjectNotFoundException If the certificate is not found
     *      in the internal certificate database or on any PKCS #11 token.
     * @exception TokenException If an error occurs in the security library.
     */
    public org.mozilla.jss.crypto.X509Certificate
    findCertByIssuerAndSerialNumber(byte[] derIssuer, INTEGER serialNumber)
        throws ObjectNotFoundException, TokenException
    {
      try {
        ANY sn = (ANY) ASN1Util.decode(ANY.getTemplate(),
                                 ASN1Util.encode(serialNumber) );
        return findCertByIssuerAndSerialNumberNative(derIssuer,
            sn.getContents() );
      } catch( InvalidBERException e ) {
        throw new RuntimeException("Invalid BER encoding of INTEGER: " + e.getMessage(), e);
      }
    }

    /**
     * @param serialNumber The contents octets of a DER-encoding of the
     *  certificate serial number.
     */
    private native org.mozilla.jss.crypto.X509Certificate
    findCertByIssuerAndSerialNumberNative(byte[] derIssuer, byte[] serialNumber)
        throws ObjectNotFoundException, TokenException;

    protected native org.mozilla.jss.crypto.X509Certificate
    findCertByNicknameNative(String nickname)
        throws ObjectNotFoundException, TokenException;

    protected native org.mozilla.jss.crypto.X509Certificate[]
    findCertsByNicknameNative(String nickname)
        throws TokenException;

    /////////////////////////////////////////////////////////////
    // build cert chains
    /////////////////////////////////////////////////////////////
    /**
     * Given a certificate, constructs its certificate chain. It may
     * or may not chain up to a trusted root.
     * @param leaf The certificate that is the starting point of the chain.
     * @return An array of certificates, starting at the leaf and ending
     *      with the highest certificate on the chain that was found.
     * @throws CertificateException If the certificate is not recognized
     *      by the underlying provider.
     * @throws TokenException If an error occurred in the token.
     */
    public org.mozilla.jss.crypto.X509Certificate[]
    buildCertificateChain(org.mozilla.jss.crypto.X509Certificate leaf)
        throws java.security.cert.CertificateException, TokenException
    {
        if( ! (leaf instanceof PK11Cert) ) {
            throw new CertificateException(
                        "Certificate is not a PKCS #11 certificate");
        }
        return buildCertificateChainNative((PK11Cert)leaf);
    }

    native org.mozilla.jss.crypto.X509Certificate[]
    buildCertificateChainNative(PK11Cert leaf)
        throws CertificateException, TokenException;


    /////////////////////////////////////////////////////////////
    // lookup private keys
    /////////////////////////////////////////////////////////////
    /**
     * Looks up the PrivateKey matching the given certificate.
     *
     * @param cert Certificate.
     * @return Private key.
     * @exception ObjectNotFoundException If no private key can be
     *      found matching the given certificate.
     * @exception TokenException If an error occurs in the security library.
     */
    public org.mozilla.jss.crypto.PrivateKey
    findPrivKeyByCert(org.mozilla.jss.crypto.X509Certificate cert)
        throws ObjectNotFoundException, TokenException
    {
        assert(cert!=null);
        if(! (cert instanceof org.mozilla.jss.pkcs11.PK11Cert)) {
            throw new ObjectNotFoundException("Non-pkcs11 cert passed to PK11Finder");
        }
        return findPrivKeyByCertNative(cert);
    }

    protected native org.mozilla.jss.crypto.PrivateKey
    findPrivKeyByCertNative(org.mozilla.jss.crypto.X509Certificate cert)
        throws ObjectNotFoundException, TokenException;

    /////////////////////////////////////////////////////////////
    // Provide Pseudo-Random Number Generation
    /////////////////////////////////////////////////////////////

    /**
     * Retrieves a FIPS-140-2 validated random number generator.
     *
     * @return A JSS SecureRandom implemented with FIPS-validated NSS.
     */
    public org.mozilla.jss.crypto.JSSSecureRandom
    createPseudoRandomNumberGenerator()
    {
        return new PK11SecureRandom();
    }

    /**
     * Retrieves a FIPS-140-2 validated random number generator.
     *
     * @return A JSS SecureRandom implemented with FIPS-validated NSS.
     */
    public org.mozilla.jss.crypto.JSSSecureRandom
    getSecureRNG() {
        return new PK11SecureRandom();
    }

    /********************************************************************/
    /* The VERSION Strings should be updated everytime a new release    */
    /* of JSS is generated. Note that this is done by changing          */
    /* cmake/JSSConfig.cmake.                                           */
    /********************************************************************/


    public native static int getJSSMajorVersion();
    public native static int getJSSMinorVersion();
    public native static int getJSSPatchVersion();
    private native static boolean getJSSDebug();

    public static final String
    JAR_JSS_VERSION     = "JSS_VERSION = JSS_" + getJSSMajorVersion() +
                          "_" + getJSSMinorVersion() +
                          "_" + getJSSPatchVersion();

    public static final boolean JSS_DEBUG = getJSSDebug();

    // Hashtable is synchronized.
    private Hashtable<Thread, CryptoToken> perThreadTokenTable = new Hashtable<>();

    /**
     * Sets the default token for the current thread. This token will
     * be used when JSS is called through the JCA interface, which has
     * no means of specifying which token to use.
     *
     * <p>If no token is set, the InternalKeyStorageToken will be used. Setting
     * this thread's token to <code>null</code> will also cause the
     * InternalKeyStorageToken to be used.
     *
     * @param token The token to use for crypto operations. Specifying
     * <code>null</code> will cause the InternalKeyStorageToken to be used.
     */
    public void setThreadToken(CryptoToken token) {
        if( token != null ) {
            perThreadTokenTable.put(Thread.currentThread(), token);
        } else {
            perThreadTokenTable.remove(Thread.currentThread());
        }
    }

    /**
     * Returns the default token for the current thread. This token will
     * be used when JSS is called through the JCA interface, which has
     * no means of specifying which token to use.
     *
     * <p>If no token is set, the InternalKeyStorageToken will be used. Setting
     * this thread's token to <code>null</code> will also cause the
     * InternalKeyStorageToken to be used.
     *
     * @return The default token for this thread. If it has not been specified,
     * it will be the InternalKeyStorageToken.
     */
    public CryptoToken getThreadToken() {
        CryptoToken tok =
            perThreadTokenTable.get(Thread.currentThread());
        if( tok == null ) {
            tok = getInternalKeyStorageToken();
        }
        return tok;
    }

    /////////////////////////////////////////////////////////////
    // isCertValid
    /////////////////////////////////////////////////////////////
    /**
     * Verify a certificate that exists in the given cert database,
     * check if is valid and that we trust the issuer. Verify time
     * against Now.
     * @param nickname The nickname of the certificate to verify.
     * @param checkSig verify the signature of the certificate
     * @return currCertificateUsage which contains current usage bit map as defined in CertificateUsage
     *
     * @exception InvalidNicknameException If the nickname is null
     * @exception ObjectNotFoundException If no certificate could be found
     *      with the given nickname.
     */
    public int isCertValid(String nickname, boolean checkSig)
        throws ObjectNotFoundException, InvalidNicknameException
    {
        if (nickname==null) {
            throw new InvalidNicknameException("Nickname must be non-null");
        }
        int currCertificateUsage = 0x0000; // initialize it to 0
        currCertificateUsage = verifyCertificateNowCUNative(nickname,
                checkSig);
        return currCertificateUsage;
    }

    private native int verifyCertificateNowCUNative(String nickname,
        boolean checkSig) throws ObjectNotFoundException;

    /////////////////////////////////////////////////////////////
    // isCertValid
    /////////////////////////////////////////////////////////////
    /**
     * Verify a certificate that exists in the given cert database,
     * check if is valid and that we trust the issuer. Verify time
     * against Now.
     * @param nickname The nickname of the certificate to verify.
     * @param checkSig verify the signature of the certificate
     * @param certificateUsage see certificateUsage defined to verify Certificate; to retrieve current certificate usage, call the isCertValid() above
     * @return true for success; false otherwise
     *
     * @exception InvalidNicknameException If the nickname is null
     * @exception ObjectNotFoundException If no certificate could be found
     *      with the given nickname.
     * @deprecated Use verifyCertificate() instead
     */
    @Deprecated
    public boolean isCertValid(String nickname, boolean checkSig,
            CertificateUsage certificateUsage)
        throws ObjectNotFoundException, InvalidNicknameException
    {
        if (nickname==null) {
            throw new InvalidNicknameException("Nickname must be non-null");
        }
        // 0 certificate usage will get current usage
        // should call isCertValid() call above that returns certificate usage
        if ((certificateUsage == null) ||
                (certificateUsage == CertificateUsage.CheckAllUsages)){
            int currCertificateUsage = 0x0000;
            currCertificateUsage = verifyCertificateNowCUNative(nickname,
                checkSig);

            if (currCertificateUsage == CertificateUsage.basicCertificateUsages){
                // cert is good for nothing
                return false;
            } else
                return true;
        } else {
            return verifyCertificateNowNative(nickname, checkSig,
              certificateUsage.getUsage());
        }
    }

    /**
     * Verify a certificate that exists in the given cert database,
     * check if it's valid and that we trust the issuer. Verify time
     * against now.
     * @param nickname nickname of the certificate to verify.
     * @param checkSig verify the signature of the certificate
     * @param certificateUsage see certificate usage defined to verify certificate
     *
     * @exception InvalidNicknameException If the nickname is null.
     * @exception ObjectNotFoundException If no certificate could be found
     *      with the given nickname.
     * @exception CertificateException If certificate is invalid.
     */
    public void verifyCertificate(String nickname,
            boolean checkSig,
            CertificateUsage certificateUsage)
                    throws ObjectNotFoundException, InvalidNicknameException, CertificateException {
        int usage = certificateUsage == null ? 0 : certificateUsage.getUsage();
        verifyCertificateNowNative2(nickname, checkSig, usage);
    }

    /**
     * Verify an X509Certificate by checking if it's valid and that we trust
     * the issuer. Verify time against now.
     * @param cert the certificate to verify
     * @param checkSig verify the signature of the certificate
     * @param certificateUsage see certificate usage defined to verify certificate
     *
     * @exception InvalidNicknameException If the nickname is null.
     * @exception ObjectNotFoundException If no certificate could be found
     *      with the given nickname.
     * @exception CertificateException If certificate is invalid.
     */
    public void verifyCertificate(X509Certificate cert, boolean checkSig,
            CertificateUsage certificateUsage) throws ObjectNotFoundException,
            InvalidNicknameException, CertificateException {
        int usage = certificateUsage == null ? 0 : certificateUsage.getUsage();
        verifyCertificateNowNative3(cert, checkSig, usage);
    }

    private native boolean verifyCertificateNowNative(String nickname,
        boolean checkSig, int certificateUsage) throws ObjectNotFoundException;

    private native void verifyCertificateNowNative2(
            String nickname,
            boolean checkSig,
            int certificateUsage)
       throws ObjectNotFoundException, InvalidNicknameException, CertificateException;

    private native void verifyCertificateNowNative3(
            X509Certificate cert,
            boolean checkSig,
            int certificateUsage)
        throws ObjectNotFoundException, InvalidNicknameException, CertificateException;

    /**
     * note: this method calls obsolete function in NSS
     *
     * Verify a certificate that exists in the given cert database,
     * check if is valid and that we trust the issuer. Verify time
     * against Now.
     * @param nickname The nickname of the certificate to verify.
     * @param checkSig verify the signature of the certificate
     * @param certUsage see exposed certUsage defines to verify Certificate
     * @return true for success; false otherwise
     *
     * @exception InvalidNicknameException If the nickname is null
     * @exception ObjectNotFoundException If no certificate could be found
     *      with the given nickname.
     */

    public boolean isCertValid(String nickname, boolean checkSig,
            CertUsage certUsage)
        throws ObjectNotFoundException, InvalidNicknameException
    {
        if (nickname==null) {
            throw new InvalidNicknameException("Nickname must be non-null");
        }
        return verifyCertNowNative(nickname, checkSig, certUsage.getUsage());
    }

    /*
     * Obsolete in NSS
     */
    private native boolean verifyCertNowNative(String nickname,
        boolean checkSig, int cUsage) throws ObjectNotFoundException;

    /////////////////////////////////////////////////////////////
    // isCertValid
    /////////////////////////////////////////////////////////////
    /**
     * Verify a certificate in memory. Check if
     * valid and that we trust the issuer. Verify time
     * against Now.
     * @param certPackage certificate in memory
     * @param checkSig verify the signature of the certificate
     * @param certUsage see exposed certUsage defines to verify Certificate
     * @return true for success; false otherwise
     *
     * @exception TokenException unable to insert temporary certificate
     *            into database.
     * @exception CertificateEncodingException If the package encoding
     *      was not recognized.
     */

    public boolean isCertValid(byte[] certPackage, boolean checkSig,
            CertUsage certUsage)
        throws TokenException, CertificateEncodingException
    {
        return verifyCertTempNative(certPackage , checkSig,
                                    certUsage.getUsage());
    }


    private native boolean verifyCertTempNative(byte[] certPackage,
        boolean checkSig, int cUsage)
        throws TokenException, CertificateEncodingException;

     ///////////////////////////////////////////////////////////////////////
    // OCSP management
    ///////////////////////////////////////////////////////////////////////

    /* OCSP Policy related */

    public enum OCSPPolicy {
        NONE,
        NORMAL,
        LEAF_AND_CHAIN;
    }

    private static OCSPPolicy ocspPolicy  = OCSPPolicy.NONE;

    /**
     * Gets the current ocsp Policy.
     * Currently we only support 2 modes  OCSP_LEAF_AND_CHAIN_POLICY.
     * And OCSP_NORMAL_POLICY, which is current processing , by default.
     * If we have AIA based OCSP enabled we will check all certs in the chain.
     * using PKIX cert verfication calls in the various cert auth callbacks we
     * have.
     * @return - The current ocsp policy in effect.
     */

    public static synchronized int getOCSPPolicy() {
        return ocspPolicy.ordinal();
    }

    /**
     * Gets the current OCSP Policy.
     *
     * @see getOCSPPolicy()
     *
     * @return - The current OCSP policy in effect.
     */
    public static synchronized OCSPPolicy getOCSPPolicyEnum() {
        return ocspPolicy;
    }

    /**
     * Sets the current ocsp Policy.
     * Currently we only support one mode OCSP_LEAF_AND_CHAIN_POLICY.
     * If we have AIA based OCSP enabled we will check all certs in the chain.
     * using PKIX cert verfication calls in the various cert auth callbacks we
     * have.
     * @param policy - Either cert and chain or normal default processing.
     *
     */
 
    public static synchronized void setOCSPPolicy(OCSPPolicy policy) {
        ocspPolicy = policy;
    }

    /**
     * Enables OCSP, note when you Initialize JSS for the first time, for
     * backwards compatibility, the initialize will enable OCSP if you
     * previously set values.ocspCheckingEnabled and
     * values.ocspResponderURL/values.ocspResponderCertNickname
     * configureOCSP will allow changing of the the OCSPResponder at runtime.
     * @param ocspCheckingEnabled true or false to enable/disable OCSP
     * @param ocspResponderURL - url of the OCSP responder
     * @param ocspResponderCertNickname - the nickname of the OCSP
     *        signer certificate or the CA certificate found in the cert DB
     * @throws GeneralSecurityException If a security error has occurred.
     */

    public void configureOCSP(
        boolean ocspCheckingEnabled,
        String ocspResponderURL,
        String ocspResponderCertNickname )
    throws GeneralSecurityException
    {
        /* set the ocsp policy */

        if(ocspCheckingEnabled && 
            ocspResponderURL == null && 
            ocspResponderCertNickname == null) {
            setOCSPPolicy(OCSPPolicy.LEAF_AND_CHAIN);
        } else {
            setOCSPPolicy(OCSPPolicy.NORMAL);
        }

        configureOCSPNative(ocspCheckingEnabled,
                                   ocspResponderURL,
                                    ocspResponderCertNickname );
    }

    private native void configureOCSPNative( boolean ocspCheckingEnabled,
                    String ocspResponderURL,
                    String ocspResponderCertNickname )
                    throws GeneralSecurityException;

    /**
     * change OCSP cache settings
     * @param ocsp_cache_size max cache entries
     * @param ocsp_min_cache_entry_duration minimum seconds to next fetch attempt
     * @param ocsp_max_cache_entry_duration maximum seconds to next fetch attempt
     * @throws GeneralSecurityException If a security error has occurred.
     */
    public void OCSPCacheSettings(
        int ocsp_cache_size,
        int ocsp_min_cache_entry_duration,
        int ocsp_max_cache_entry_duration)
    throws GeneralSecurityException
    {
        OCSPCacheSettingsNative(ocsp_cache_size,
                                   ocsp_min_cache_entry_duration,
                                   ocsp_max_cache_entry_duration);
    }

    private native void OCSPCacheSettingsNative(
        int ocsp_cache_size,
        int ocsp_min_cache_entry_duration,
        int ocsp_max_cache_entry_duration)
                    throws GeneralSecurityException;

    /**
     * set OCSP timeout value
     * @param ocsp_timeout OCSP timeout in seconds
     * @throws GeneralSecurityException If a security error has occurred.
     */
    public void setOCSPTimeout(
        int ocsp_timeout )
    throws GeneralSecurityException
    {
        setOCSPTimeoutNative( ocsp_timeout);
    }

    private native void setOCSPTimeoutNative(
        int ocsp_timeout )
                    throws GeneralSecurityException;

    /**
     * Shutdowns this CryptoManager instance and the associated NSS
     * initialization.
     */
    public synchronized void shutdown() throws Exception {
        try {
            NativeProxy.purgeAllInRegistry();
        } finally {
            shutdownNative();
            CryptoManager.instance = null;
        }
    }

    public native void shutdownNative();
}
