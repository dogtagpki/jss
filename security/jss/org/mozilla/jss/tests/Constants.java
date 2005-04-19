/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is Netscape Security Services for Java.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 2002
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

package org.mozilla.jss.tests;

import org.mozilla.jss.ssl.*;

/**
 * Holds immutable values for JSS Tests.
 *
 * @author  Sandeep.Konchady@Sun.COM
 * @version
 */
public class Constants {
    
    /** There is no need to create instances of this class */
    private Constants() {
    }
    
    /** Debug level for all tests */
    public static int debug_level = 0;
    
    /** Cipher supported by JSS */
    public static int jssCipherSuites[] = {
        SSLSocket.SSL3_RSA_WITH_NULL_MD5,
        SSLSocket.SSL3_RSA_WITH_NULL_SHA,
        SSLSocket.SSL3_RSA_EXPORT_WITH_RC4_40_MD5,
        SSLSocket.SSL3_RSA_WITH_RC4_128_MD5,
        SSLSocket.SSL3_RSA_WITH_RC4_128_SHA,
        SSLSocket.SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
        SSLSocket.SSL3_RSA_WITH_IDEA_CBC_SHA,
        SSLSocket.SSL3_RSA_EXPORT_WITH_DES40_CBC_SHA,
        SSLSocket.SSL3_RSA_WITH_DES_CBC_SHA,
        SSLSocket.SSL3_RSA_WITH_3DES_EDE_CBC_SHA,
        // DH and DHE Ciphers are client only.
        SSLSocket.SSL3_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
        SSLSocket.SSL3_DH_DSS_WITH_DES_CBC_SHA,
        SSLSocket.SSL3_DH_DSS_WITH_3DES_EDE_CBC_SHA,
        SSLSocket.SSL3_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
        SSLSocket.SSL3_DH_RSA_WITH_DES_CBC_SHA,
        SSLSocket.SSL3_DH_RSA_WITH_3DES_EDE_CBC_SHA,
        SSLSocket.SSL3_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
        SSLSocket.SSL3_DHE_DSS_WITH_DES_CBC_SHA,
        SSLSocket.SSL3_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        SSLSocket.SSL3_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
        SSLSocket.SSL3_DHE_RSA_WITH_DES_CBC_SHA,
        SSLSocket.SSL3_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
        SSLSocket.SSL3_DH_ANON_EXPORT_WITH_RC4_40_MD5,
        SSLSocket.SSL3_DH_ANON_WITH_RC4_128_MD5,
        SSLSocket.SSL3_DH_ANON_EXPORT_WITH_DES40_CBC_SHA,
        SSLSocket.SSL3_DH_ANON_WITH_DES_CBC_SHA,
        SSLSocket.SSL3_DH_ANON_WITH_3DES_EDE_CBC_SHA,
        // Don't bother with FORTEZZA Ciphers.
        SSLSocket.SSL3_FORTEZZA_DMS_WITH_NULL_SHA,
        SSLSocket.SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA,
        SSLSocket.SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA,
        SSLSocket.SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA,
        SSLSocket.SSL_RSA_FIPS_WITH_DES_CBC_SHA,
        // These are TLS Ciphers.
        SSLSocket.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
        SSLSocket.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
        // DH and DHE Ciphers are client only.
        SSLSocket.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
        SSLSocket.TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
        SSLSocket.TLS_DHE_DSS_WITH_RC4_128_SHA,
        SSLSocket.TLS_RSA_WITH_AES_128_CBC_SHA,
        SSLSocket.TLS_DH_DSS_WITH_AES_128_CBC_SHA,
        SSLSocket.TLS_DH_RSA_WITH_AES_128_CBC_SHA,
        SSLSocket.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        SSLSocket.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        SSLSocket.TLS_DH_ANON_WITH_AES_128_CBC_SHA,
        SSLSocket.TLS_RSA_WITH_AES_256_CBC_SHA,
        SSLSocket.TLS_DH_DSS_WITH_AES_256_CBC_SHA,
        SSLSocket.TLS_DH_RSA_WITH_AES_256_CBC_SHA,
        SSLSocket.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        SSLSocket.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        SSLSocket.TLS_DH_ANON_WITH_AES_256_CBC_SHA,
        0
    };
    
    /** String representation of JSS supported ciphers */
    public static String jssCipherNames[] = {
        "SSLSocket.SSL3_RSA_WITH_NULL_MD5",
        "SSLSocket.SSL3_RSA_WITH_NULL_SHA",
        "SSLSocket.SSL3_RSA_EXPORT_WITH_RC4_40_MD5",
        "SSLSocket.SSL3_RSA_WITH_RC4_128_MD5",
        "SSLSocket.SSL3_RSA_WITH_RC4_128_SHA",
        "SSLSocket.SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        "SSLSocket.SSL3_RSA_WITH_IDEA_CBC_SHA",
        "SSLSocket.SSL3_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "SSLSocket.SSL3_RSA_WITH_DES_CBC_SHA",
        "SSLSocket.SSL3_RSA_WITH_3DES_EDE_CBC_SHA",
        "SSLSocket.SSL3_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
        "SSLSocket.SSL3_DH_DSS_WITH_DES_CBC_SHA",
        "SSLSocket.SSL3_DH_DSS_WITH_3DES_EDE_CBC_SHA",
        "SSLSocket.SSL3_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "SSLSocket.SSL3_DH_RSA_WITH_DES_CBC_SHA",
        "SSLSocket.SSL3_DH_RSA_WITH_3DES_EDE_CBC_SHA",
        "SSLSocket.SSL3_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
        "SSLSocket.SSL3_DHE_DSS_WITH_DES_CBC_SHA",
        "SSLSocket.SSL3_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
        "SSLSocket.SSL3_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "SSLSocket.SSL3_DHE_RSA_WITH_DES_CBC_SHA",
        "SSLSocket.SSL3_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "SSLSocket.SSL3_DH_ANON_EXPORT_WITH_RC4_40_MD5",
        "SSLSocket.SSL3_DH_ANON_WITH_RC4_128_MD5",
        "SSLSocket.SSL3_DH_ANON_EXPORT_WITH_DES40_CBC_SHA",
        "SSLSocket.SSL3_DH_ANON_WITH_DES_CBC_SHA",
        "SSLSocket.SSL3_DH_ANON_WITH_3DES_EDE_CBC_SHA",
        "SSLSocket.SSL3_FORTEZZA_DMS_WITH_NULL_SHA",
        "SSLSocket.SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA",
        "SSLSocket.SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA",
        "SSLSocket.SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",
        "SSLSocket.SSL_RSA_FIPS_WITH_DES_CBC_SHA",
        "SSLSocket.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
        "SSLSocket.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
        "SSLSocket.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
        "SSLSocket.TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",
        "SSLSocket.TLS_DHE_DSS_WITH_RC4_128_SHA",
        "SSLSocket.TLS_RSA_WITH_AES_128_CBC_SHA",
        "SSLSocket.TLS_DH_DSS_WITH_AES_128_CBC_SHA",
        "SSLSocket.TLS_DH_RSA_WITH_AES_128_CBC_SHA",
        "SSLSocket.TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
        "SSLSocket.TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "SSLSocket.TLS_DH_ANON_WITH_AES_128_CBC_SHA",
        "SSLSocket.TLS_RSA_WITH_AES_256_CBC_SHA",
        "SSLSocket.TLS_DH_DSS_WITH_AES_256_CBC_SHA",
        "SSLSocket.TLS_DH_RSA_WITH_AES_256_CBC_SHA",
        "SSLSocket.TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
        "SSLSocket.TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        "SSLSocket.TLS_DH_ANON_WITH_AES_256_CBC_SHA"
    };
    
    /** Cipher supported by JSSE (JDK 1.5.x) */
    public static String [] sslciphersarray_jdk150 = {
        // These ciphers must always pass
        "SSL_RSA_WITH_RC4_128_MD5",
        "SSL_RSA_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "SSL_RSA_WITH_DES_CBC_SHA",
        "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
        "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
        "SSL_RSA_WITH_NULL_MD5",
        // These ciphers are not supported by JSSE
        "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
        "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
        "SSL_DHE_RSA_WITH_DES_CBC_SHA",
        "SSL_DHE_DSS_WITH_DES_CBC_SHA",
        "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
        "SSL_DH_anon_WITH_RC4_128_MD5",
        "TLS_DH_anon_WITH_AES_128_CBC_SHA",
        "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",
        "SSL_DH_anon_WITH_DES_CBC_SHA",
        "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",
        "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
        "TLS_KRB5_WITH_RC4_128_SHA",
        "TLS_KRB5_WITH_RC4_128_MD5",
        "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
        "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
        "TLS_KRB5_WITH_DES_CBC_SHA",
        "TLS_KRB5_WITH_DES_CBC_MD5",
        "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
        "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
        "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
        "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
        // This is needed here for successful transmission
        // of null to terminate the server program.
        "SSL_RSA_WITH_NULL_SHA"
    };
    
    /** Cipher supported by JSSE (JDK 1.4.x) */
    public static String [] sslciphersarray_jdk142 = {
        // These ciphers must always pass
        "SSL_RSA_WITH_RC4_128_MD5",
        "SSL_RSA_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "SSL_RSA_WITH_DES_CBC_SHA",
        "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
        "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
        "SSL_RSA_WITH_NULL_MD5",
        // These ciphers are not supported by JSSE
        "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
        "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
        "SSL_DHE_RSA_WITH_DES_CBC_SHA",
        "SSL_DHE_DSS_WITH_DES_CBC_SHA",
        "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
        "SSL_DH_anon_WITH_RC4_128_MD5",
        "TLS_DH_anon_WITH_AES_128_CBC_SHA",
        "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",
        "SSL_DH_anon_WITH_DES_CBC_SHA",
        "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",
        "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
        // This is needed here for successful transmission
        // of null to terminate the server program.
        "SSL_RSA_WITH_NULL_SHA"
    };
}
