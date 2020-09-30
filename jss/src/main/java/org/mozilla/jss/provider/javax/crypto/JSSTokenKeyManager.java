/* BEGIN COPYRIGHT BLOCK
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Copyright (C) 2017 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK */

package org.mozilla.jss.provider.javax.crypto;

import java.net.Socket;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

import javax.net.ssl.X509KeyManager;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.pkcs11.PK11Cert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JSSTokenKeyManager implements JSSKeyManager {

    final static Logger logger = LoggerFactory.getLogger(JSSTokenKeyManager.class);

    private KeyStore jks;
    private CryptoManager cm;
    private char[] password;

    public JSSTokenKeyManager(KeyStore jssKeyStore, char[] password) {
        jks = jssKeyStore;
        this.password = password;

        try {
            cm = CryptoManager.getInstance();
        } catch (NotInitializedException nie) {
            String msg = "CryptoManager reported as not initialized but have ";
            msg += "a working KeyStore instance! " + nie.getMessage();
            throw new RuntimeException(msg, nie);
        }
    }

    @Override
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        logger.debug("JSSKeyManager: chooseClientAlias() - not implemented");
        return null;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        logger.debug("JSSKeyManager: chooseServerAlias() - not implemented");
        return null;
    }

    public org.mozilla.jss.crypto.X509Certificate getCertificate(String alias) {
        try {
            if (jks == null) {
                return cm.findCertByNickname(alias);
            }

            return (org.mozilla.jss.crypto.X509Certificate) jks.getCertificate(alias);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        logger.debug("JSSKeyManager: getCertificateChain(" + alias + ")");

        try {
            org.mozilla.jss.crypto.X509Certificate cert = getCertificate(alias);
            org.mozilla.jss.crypto.X509Certificate[] chain = cm.buildCertificateChain(cert);

            logger.debug("JSSKeyManager: cert chain:");

            Collection<org.mozilla.jss.pkcs11.PK11Cert> list = new ArrayList<>();
            for (org.mozilla.jss.crypto.X509Certificate c : chain) {
                logger.debug("JSSKeyManager: - " + c.getSubjectDN());
                list.add((PK11Cert) c);
            }

            return list.toArray(new X509Certificate[list.size()]);
        } catch (Throwable e) {
            logger.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        logger.debug("JSSKeyManager: getClientAliases() - not implemented");
        return null;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {

        logger.debug("JSSKeyManager: getPrivateKey(" + alias + ")");

        try {
            if (jks == null) {
                try (PK11Cert cert = (PK11Cert) cm.findCertByNickname(alias)) {
                    PrivateKey key = cm.findPrivKeyByCert(cert);
                    return key;
                }
            }

            return (PrivateKey) jks.getKey(alias, password);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        logger.debug("JSSKeyManager: getServerAliases() - not implemented");
        return null;
    }
}
