/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss;

import org.mozilla.jss.util.ConsolePasswordCallback;
import org.mozilla.jss.util.PasswordCallback;

/**
 * The various options that can be used to initialize CryptoManager.
 */
public final class InitializationValues {

    protected InitializationValues() {
        throw new RuntimeException("Default InitializationValues constructor");
    }

    /////////////////////////////////////////////////////////////
    // Constants
    /////////////////////////////////////////////////////////////
    /**
     * Token names must be this length exactly.
     */
    public final int TOKEN_LENGTH = 33;
    /**
     * Slot names must be this length exactly.
     */
    public final int SLOT_LENGTH = 65;
    /**
     * ManufacturerID must be this length exactly.
     */
    public final int MANUFACTURER_LENGTH = 33;
    /**
     * Library description must be this length exactly.
     */
    public final int LIBRARY_LENGTH = 33;

    /**
     * This class enumerates the possible modes for FIPS compliance.
     */
    public static final class FIPSMode {
        private FIPSMode() {}

        /**
         * Enable FIPS mode.
         */
        public static final InitializationValues.FIPSMode ENABLED = new FIPSMode();
        /**
         * Disable FIPS mode.
         */
        public static final InitializationValues.FIPSMode DISABLED = new FIPSMode();
        /**
         * Leave FIPS mode unchanged.  All servers except Admin
         * Server should use this, because only Admin Server should
         * be altering FIPS mode.
         */
        public static final InitializationValues.FIPSMode UNCHANGED = new FIPSMode();
            }

    public InitializationValues(String configDir) {
        this.configDir = configDir;
    }

    public InitializationValues(String configDir, String certPrefix,
        String keyPrefix, String secmodName)
    {
        this.configDir = configDir;
        this.certPrefix = certPrefix;
        this.keyPrefix = keyPrefix;
        this.secmodName = secmodName;
    }

    public String configDir = null;
    public String certPrefix = null;
    public String keyPrefix = null;
    public String secmodName = null;

    /**
     * The password callback to be used by JSS whenever a password
     * is needed. May be NULL, in which the library will immediately fail
     * to get a password if it tries to login automatically while
     * performing
     * a cryptographic operation.  It will still work if the token
     * has been manually logged in with <code>CryptoToken.login</code>.
     * <p>The default is a <code>ConsolePasswordCallback</code>.
     */
    public PasswordCallback passwordCallback =
        new ConsolePasswordCallback();

    /**
     * The FIPS mode of the security library.  Servers should
     * use <code>FIPSMode.UNCHANGED</code>, since only
     * Admin Server is supposed to alter this value.
     * <p>The default is <code>FIPSMode.UNCHANGED</code>.
     */
    public InitializationValues.FIPSMode fipsMode = FIPSMode.UNCHANGED;

    /**
     * To open the databases in read-only mode, set this flag to
     * <code>true</code>.  The default is <code>false</code>, meaning
     * the databases are opened in read-write mode.
     */
    public boolean readOnly = false;

    ////////////////////////////////////////////////////////////////////
    // Manufacturer ID
    ////////////////////////////////////////////////////////////////////
    /**
     * Returns the Manufacturer ID of the internal PKCS #11 module.
     * <p>The default is <code>"mozilla.org                     "</code>.
     *
     * @return Manufacturer ID.
     */
    public String getManufacturerID() { return manufacturerID; }

    /**
     * Sets the Manufacturer ID of the internal PKCS #11 module.
     * This value must be exactly <code>MANUFACTURER_LENGTH</code>
     * characters long.
     *
     * @param s Manufacturer ID.
     * @exception InvalidLengthException If <code>s.length()</code> is not
     *      exactly <code>MANUFACTURER_LENGTH</code>.
     */
    public void setManufacturerID(String s) throws InvalidLengthException {
        if( s.length() != MANUFACTURER_LENGTH ) {
            throw new InvalidLengthException();
        }
        manufacturerID = s;
    }
    private String manufacturerID =
        "mozilla.org                      ";

    ////////////////////////////////////////////////////////////////////
    // Library Description
    ////////////////////////////////////////////////////////////////////
    /**
     * Returns the description of the internal PKCS #11 module.
     * <p>The default is <code>"Internal Crypto Services         "</code>.
     *
     * @return Library description.
     */
    public String getLibraryDescription() { return libraryDescription; }

    /**
     * Sets the description of the internal PKCS #11 module.
     * This value must be exactly <code>LIBRARY_LENGTH</code>
     *  characters long.
     *
     * @param s Library description.
     * @exception InvalidLengthException If <code>s.length()</code> is
     *      not exactly <code>LIBRARY_LENGTH</code>.
     */
    public void setLibraryDescription(String s)
        throws InvalidLengthException
    {
        if( s.length() != LIBRARY_LENGTH ) {
            throw new InvalidLengthException();
        }
        libraryDescription = s;
    }
    private String libraryDescription =
        "Internal Crypto Services         ";

    ////////////////////////////////////////////////////////////////////
    // Internal Token Description
    ////////////////////////////////////////////////////////////////////
    /**
     * Returns the description of the internal PKCS #11 token.
     * <p>The default is <code>"Internal Crypto Services Token   "</code>.
     *
     * @return Description of internal PKCS #11 token.
     */
    public String getInternalTokenDescription() {
        return internalTokenDescription;
    }

    /**
     * Sets the description of the internal PKCS #11 token.
     * This value must be exactly <code>TOKEN_LENGTH</code> characters long.
     *
     * @param s Description of internal PKCS #11 token.
     * @exception InvalidLengthException If <code>s.length()</code> is
     *      not exactly <code>TOKEN_LENGTH</code>.
     */
    public void setInternalTokenDescription(String s)
        throws InvalidLengthException
    {
        if(s.length() != TOKEN_LENGTH) {
            throw new InvalidLengthException();
        }
        internalTokenDescription = s;
    }
    private String internalTokenDescription =
        "NSS Generic Crypto Services      ";

    ////////////////////////////////////////////////////////////////////
    // Internal Key Storage Token Description
    ////////////////////////////////////////////////////////////////////
    /**
     * Returns the description of the internal PKCS #11 key storage token.
     * <p>The default is <code>"Internal Key Storage Token       "</code>.
     *
     * @return Description of internal PKCS #11 key storage token.
     */
    public String getInternalKeyStorageTokenDescription() {
        return internalKeyStorageTokenDescription;
    }

    /**
     * Sets the description of the internal PKCS #11 key storage token.
     * This value must be exactly <code>TOKEN_LENGTH</code> characters long.
     *
     * @param s Description of internal PKCS #11 key storage token.
     * @exception InvalidLengthException If <code>s.length()</code> is
     *      not exactly <code>TOKEN_LENGTH</code>.
     */
    public void setInternalKeyStorageTokenDescription(String s)
        throws InvalidLengthException
    {
        if(s.length() != TOKEN_LENGTH) {
            throw new InvalidLengthException();
        }
        internalKeyStorageTokenDescription = s;
    }
    private String internalKeyStorageTokenDescription =
        "Internal Key Storage Token       ";

    ////////////////////////////////////////////////////////////////////
    // Internal Slot Description
    ////////////////////////////////////////////////////////////////////
    /**
     * Returns the description of the internal PKCS #11 slot.
     * <p>The default is <code>"NSS Internal Cryptographic Services                              "</code>.
     *
     * @return Description of internal PKCS #11 slot.
     */
    public String getInternalSlotDescription() {
        return internalSlotDescription;
    }

    /**
     * Sets the description of the internal PKCS #11 slot.
     * This value must be exactly <code>SLOT_LENGTH</code> characters
     * long.
     *
     * @param s Description of internal PKCS #11 slot.
     * @exception InvalidLengthException If <code>s.length()</code> is
     *      not exactly <code>SLOT_LENGTH</code>.
     */
    public void setInternalSlotDescription(String s)
        throws InvalidLengthException
    {
        if(s.length() != SLOT_LENGTH)  {
            throw new InvalidLengthException();
        }
        internalSlotDescription = s;
    }
    private String internalSlotDescription =
        "NSS Internal Cryptographic Services                              ";

    ////////////////////////////////////////////////////////////////////
    // Internal Key Storage Slot Description
    ////////////////////////////////////////////////////////////////////
    /**
     * Returns the description of the internal PKCS #11 key storage slot.
     * <p>The default is <code>"NSS Internal Private Key and Certificate Storage                 "</code>.
     *
     * @return Description of internal PKCS #11 key storage slot.
     */
    public String getInternalKeyStorageSlotDescription() {
        return internalKeyStorageSlotDescription;
    }

    /**
     * Sets the description of the internal PKCS #11 key storage slot.
     * This value must be exactly <code>SLOT_LENGTH</code> characters
     * long.
     *
     * @param s Description of internal PKCS #11 key storage slot.
     * @exception InvalidLengthException If <code>s.length()</code> is
     *      not exactly <code>SLOT_LENGTH</code>.
     */
    public void setInternalKeyStorageSlotDescription(String s)
        throws InvalidLengthException
    {
        if(s.length() != SLOT_LENGTH) {
            throw new InvalidLengthException();
        }
        internalKeyStorageSlotDescription = s;
    }
    private String internalKeyStorageSlotDescription =
        "NSS User Private Key and Certificate Services                    ";

    ////////////////////////////////////////////////////////////////////
    // FIPS Slot Description
    ////////////////////////////////////////////////////////////////////
    /**
     * Returns the description of the internal PKCS #11 FIPS slot.
     * <p>The default is
     * <code>"NSS FIPS 140-2 User Private Key Services"</code>.
     *
     * @return Description of internal PKCS #11 FIPS slot.
     */
    public String getFIPSSlotDescription() {
        return FIPSSlotDescription;
    }

    /**
     * Sets the description of the internal PKCS #11 FIPS slot.
     * This value must be exactly <code>SLOT_LENGTH</code> characters
     * long.
     *
     * @param s Description of internal PKCS #11 FIPS slot.
     * @exception InvalidLengthException If <code>s.length()</code> is
     *      not exactly <code>SLOT_LENGTH</code>.
     */
    public void setFIPSSlotDescription(String s)
        throws InvalidLengthException
    {
        if(s.length() != SLOT_LENGTH) {
            throw new InvalidLengthException();
        }
        FIPSSlotDescription = s;
    }
    private String FIPSSlotDescription =
        "NSS FIPS 140-2 User Private Key Services                         ";

    ////////////////////////////////////////////////////////////////////
    // FIPS Key Storage Slot Description
    ////////////////////////////////////////////////////////////////////
    /**
     * Returns the description of the internal PKCS #11 FIPS
     * Key Storage slot.
     * <p>The default is
     * <code>"NSS FIPS 140-2 User Private Key Services"</code>.
     *
     * @return Description of internal PKCS #11 FIPS key storage slot.
     */
    public String getFIPSKeyStorageSlotDescription() {
        return FIPSKeyStorageSlotDescription;
    }

    /**
     * Sets the description of the internal PKCS #11 FIPS Key Storage slot.
     * This value must be exactly <code>SLOT_LENGTH</code> characters
     * long.
     *
     * @param s Description of internal PKCS #11 FIPS key storage slot.
     * @exception InvalidLengthException If <code>s.length()</code> is
     *      not exactly <code>SLOT_LENGTH</code>.
     */
    public void setFIPSKeyStorageSlotDescription(String s)
        throws InvalidLengthException
    {
        if(s.length() != SLOT_LENGTH) {
            throw new InvalidLengthException();
        }
        FIPSKeyStorageSlotDescription = s;
    }
    private String FIPSKeyStorageSlotDescription =
        "NSS FIPS 140-2 User Private Key Services                         ";

    /**
     * To have NSS check the OCSP responder for when verifying
     * certificates, set this flags to true. It is false by
     * default.
     */
    public boolean ocspCheckingEnabled = false;

    /**
     * Specify the location and cert of the responder.
     * If OCSP checking is enabled *and* this variable is
     * set to some URL, all OCSP checking will be done via
     * this URL.
     *
     * If this variable is null, the OCSP responder URL will
     * be obtained from the AIA extension in the certificate
     * being queried.
     *
     * If this is set, you must also set ocspResponderCertNickname
     *
     */
    public String ocspResponderURL = null;

    /**
     * The nickname of the cert to trust (expected) to
     * sign the OCSP responses.
     * Only checked when the OCSPResponder value is set.
     */
    public String ocspResponderCertNickname = null;


    /**
     * Install the JSS crypto provider. Default is true.
     */
    public boolean installJSSProvider = true;

    /**
     * Remove the Sun crypto provider. Default is false.
     */
    public boolean removeSunProvider = false;

    /**
     * If <code>true</code>, none of the underlying NSS components will
     * be initialized. Only the Java portions of JSS will be
     * initialized. This should only be used if NSS has been initialized
     * elsewhere.
     *
     * <p>Specifically, the following components will <b>not</b> be
     *  configured by <code>CryptoManager.initialize</code> if this flag is set:
     * <ul>
     * <li>The NSS databases.
     * <li>OCSP checking.
     * <li>The NSS password callback.
     * <li>The internal PKCS #11 software token's identifier labels:
     *      slot, token, module, and manufacturer.
     * <li>The minimum PIN length for the software token.
     * <li>The frequency with which the user must login to the software
     *      token.
     * <li>The cipher strength policy (export/domestic).
     * </ul>
     *
     * <p>The default is <code>false</code>.
     */
    public boolean initializeJavaOnly = false;

    /**
     * Enable PKIX verify rather than the old cert library,
     * to verify certificates. Default is false.
     */
    public boolean PKIXVerify = false;

    /**
     * Don't open the cert DB and key DB's, just
     * initialize the volatile certdb. Default is false.
     */
    public boolean noCertDB = false;

    /**
     * Don't open the security module DB,
     * just initialize the PKCS #11 module.
     * Default is false.
     */
    public boolean noModDB = false;

    /**
     * Continue to force initializations even if the
     * databases cannot be opened.
     * Default is false.
     */
    public boolean forceOpen = false;

    /**
     * Don't try to look for the root certs module
     * automatically.
     * Default is false.
     */
    public boolean noRootInit = false;

    /**
     * Use smaller tables and caches.
     * Default is false.
     */
    public boolean optimizeSpace = false;

    /**
     * only load PKCS#11 modules that are
     * thread-safe, ie. that support locking - either OS
     * locking or NSS-provided locks . If a PKCS#11
     * module isn't thread-safe, don't serialize its
     * calls; just don't load it instead. This is necessary
     * if another piece of code is using the same PKCS#11
     * modules that NSS is accessing without going through
     * NSS, for example the Java SunPKCS11 provider.
     * Default is false.
     */
    public boolean PK11ThreadSafe = false;

    /**
     * Init PK11Reload to ignore the CKR_CRYPTOKI_ALREADY_INITIALIZED
     * error when loading PKCS#11 modules. This is necessary
     * if another piece of code is using the same PKCS#11
     * modules that NSS is accessing without going through
     * NSS, for example Java SunPKCS11 provider.
     * default is false.
     */
    public boolean PK11Reload = false;

    /**
     * never call C_Finalize on any
     * PKCS#11 module. This may be necessary in order to
     * ensure continuous operation and proper shutdown
     * sequence if another piece of code is using the same
     * PKCS#11 modules that NSS is accessing without going
     * through NSS, for example Java SunPKCS11 provider.
     * The following limitation applies when this is set :
     * SECMOD_WaitForAnyTokenEvent will not use
     * C_WaitForSlotEvent, in order to prevent the need for
     * C_Finalize. This call will be emulated instead.
     * Default is false.
     */
    public boolean noPK11Finalize = false;

    /**
     * Sets 4 recommended options for applications that
     * use both NSS and the Java SunPKCS11 provider.
     * Default is false.
     */
    public boolean cooperate = false;
}
