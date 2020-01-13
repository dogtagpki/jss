package org.mozilla.jss.ssl.javax;

import javax.net.ssl.*;
import java.util.*;

import org.mozilla.jss.ssl.*;

/**
 * JSSParameters is an implementation of SSLParameters to interoperate
 * with NSS.
 *
 * In particular, we extend SSLParameters to provide cipher suites and
 * protocol versions as NSS constants. This aids with the JNI translation
 * layer. We also create a default set of SSLParameters which use a null
 * cipher suite list and null protocol version list to fall back on the
 * NSS default. On RHEL-like systems, this will default to CryptoPolicies.
 *
 * We also need to store the desired certificate alias; this contrasts to
 * the SNI functionality provided by SSLParameters in that it ties back
 * to a certificate in the NSS DB and works with client certificates. When
 * using the JSSEngine implementation of SSLEngine, only the alias will be
 * used to find the certificate.
 */
public class JSSParameters extends SSLParameters {
    private SSLCipher[] suites;
    private SSLVersionRange range;
    private String alias;
    private String hostname;

    public JSSParameters() {
        // Choose our default set of SSLParameters here; default to null
        // everywhere to rely on the default NSS policies.
        super(null, null);
    }

    public JSSParameters(SSLParameters downcast) {
        this();
        if (downcast == null) {
            return;
        }

        // Copy data from downcast
        setCipherSuites(downcast.getCipherSuites());
        setProtocols(downcast.getProtocols());
        setAlgorithmConstraints(downcast.getAlgorithmConstraints());
        setEndpointIdentificationAlgorithm(downcast.getEndpointIdentificationAlgorithm());
        setServerNames(downcast.getServerNames());
        setSNIMatchers(downcast.getSNIMatchers());
        setUseCipherSuitesOrder(downcast.getUseCipherSuitesOrder());

        if (downcast.getWantClientAuth()) {
            setWantClientAuth(downcast.getWantClientAuth());
        }
        if (downcast.getNeedClientAuth()) {
            setNeedClientAuth(downcast.getNeedClientAuth());
        }
    }

    public JSSParameters(String[] cipherSuites) {
        super(cipherSuites);
    }

    public JSSParameters(String[] cipherSuites, String[] protocols) {
        super(cipherSuites, protocols);
    }

    public void setCipherSuites(String[] cipherSuites) throws IllegalArgumentException {
        if (cipherSuites == null || cipherSuites.length == 0) {
            suites = null;
            return;
        }

        ArrayList<SSLCipher> converted = new ArrayList<SSLCipher>();
        for (String cipherSuite : cipherSuites) {
            try {
                converted.add(SSLCipher.valueOf(cipherSuite));
            } catch (Exception e) {
                throw new IllegalArgumentException("JSSParameters.setCipherSuites() - Unknown cipher suite (" + cipherSuite + "): " + e.getMessage(), e);
            }
        }

        suites = converted.toArray(new SSLCipher[0]);
    }

    public void setCipherSuites(SSLCipher[] cipherSuites) {
        if (cipherSuites == null || cipherSuites.length == 0) {
            suites = null;
            return;
        }

        // Perform a copy of cipherSuites in case it is modified later.
        suites = new SSLCipher[cipherSuites.length];
        for (int index = 0; index < cipherSuites.length; index++) {
            suites[index] = cipherSuites[index];
        }
    }

    public String[] getCipherSuites() {
        if (suites == null) {
            return null;
        }

        ArrayList<String> ciphers = new ArrayList<String>();
        for (SSLCipher suite : suites) {
            ciphers.add(suite.name());
        }

        return ciphers.toArray(new String[0]);
    }

    public SSLCipher[] getSSLCiphers() {
        return suites;
    }

    public void setProtocols(String[] protocols) throws IllegalArgumentException {
        if (protocols == null || protocols.length == 0) {
            range = null;
            return;
        }

        try {
            SSLVersion minProtocol = SSLVersion.findByAlias(protocols[0]);
            SSLVersion maxProtocol = minProtocol;

            for (String protocol : protocols) {
                SSLVersion version = SSLVersion.findByAlias(protocol);
                if (minProtocol.ordinal() > version.ordinal()) {
                    minProtocol = version;
                }

                if (maxProtocol.ordinal() < version.ordinal()) {
                    maxProtocol = version;
                }
            }

            range = new SSLVersionRange(minProtocol, maxProtocol);
        } catch (Exception e) {
            throw new IllegalArgumentException("JSSParameters.setProtocols() - unknown protocol: " + e.getMessage(), e);
        }
    }

    public void setProtocols(SSLVersion min, SSLVersion max) {
        range = new SSLVersionRange(min, max);
    }

    public void setProtocols(SSLVersionRange vrange) {
        range = vrange;
    }

    public String[] getProtocols() {
        if (range == null) {
            return null;
        }

        ArrayList<String> enabledProtocols = new ArrayList<String>();
        for (SSLVersion v: SSLVersion.values()) {
            if (range.getMinVersion().ordinal() <= v.ordinal() && v.ordinal() <= range.getMaxVersion().ordinal()) {
                // We've designated the second alias as the standard Java name
                // for the protocol. However if one isn't provided, fall back
                // to the first alias. It currently is the case that all
                // elements in SSLVersion have two aliases.

                if (v.aliases().length >= 2) {
                    enabledProtocols.add(v.aliases()[1]);
                } else {
                    enabledProtocols.add(v.aliases()[0]);
                }
            }
        }

        return enabledProtocols.toArray(new String[0]);
    }

    public SSLVersionRange getSSLVersionRange() {
        return range;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String cert_alias) {
        alias = cert_alias;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String server_hostname) {
        hostname = server_hostname;
    }
}
