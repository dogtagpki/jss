/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.provider.java.security;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.NoSuchItemOnTokenException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SecretKeyFacade;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenCertificate;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.TokenSupplierManager;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.pkcs11.PK11Token;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.pkcs11.TokenProxy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The JSS implementation of the JCA KeyStore SPI.
 *
 * <p>Implementation notes
 * <ol>
 * <li>deleteEntry will delete all entries with that label. If the entry is a
 * cert with a matching private key, it will also delete the private key.
 *
 * <li>getCertificate returns first cert with matching nickname. Returns it as
 * a PK11Cert, when possible.
 *
 * <li>getCreationDate is unsupported because NSS doesn't store that
 * information.
 *
 * <li>getKey first looks for a private/symmetric key with the given label.
 * It returns the first one it finds. If it doesn't find one, it looks for a
 * cert with the given nickname. If it finds one, it returns the private key
 * for that cert.
 *
 * <li>isCertificateEntry returns true if there is a cert with this nickname,
 * but it doesn't have a private key. isKeyEntry returns true if there is a key
 * with this nickname, or if there is a cert with this nickname and the cert
 * has an associated private key.
 *
 * <li>load updates the token in the keystore.
 *
 * <li>store is a no-op.
 *
 * <li>setCertificateEntry doesn't work.NSS doesn't have a way of storing a
 * certificate on a specific token unless it has an associated private key.
 * That rules out trusted certificate entries.
 *
 * <li>setKeyEntry not supported yet. Need to convert a temporary key
 * into a permanent key.
 * </ol>
 */
public class JSSKeyStoreSpi extends java.security.KeyStoreSpi {

    public static Logger logger = LoggerFactory.getLogger(JSSKeyStoreSpi.class);

    CryptoToken token;
    protected TokenProxy proxy;

    public JSSKeyStoreSpi() {

        logger.debug("JSSKeyStoreSpi: <init>()");

        CryptoToken token =
            TokenSupplierManager.getTokenSupplier().getThreadToken();
        PK11Token pk11tok = (PK11Token)token;
        proxy = pk11tok.getProxy();
    }

    String[] parseAlias(String alias) {

        String tokenName;
        String nickname;

        String[] parts = StringUtils.splitPreserveAllTokens(alias, ':');

        if (parts.length == 1) {
            tokenName = null;
            nickname = parts[0];

        } else if (parts.length == 2) {
            tokenName = StringUtils.defaultIfEmpty(parts[0], null);
            nickname = parts[1];

        } else {
            throw new RuntimeException("Invalid alias: " + alias);
        }

        logger.debug("JSSKeyStoreSpi: token: " + tokenName);
        logger.debug("JSSKeyStoreSpi: nickname: " + nickname);

        return new String[] { tokenName, nickname };
    }

    public Enumeration<String> engineAliases() {
        logger.debug("JSSKeyStoreSpi: engineAliases()");
        return Collections.enumeration(getAliases());
    }

    public Collection<String> getAliases() {

        logger.debug("JSSKeyStoreSpi: getAliases()");
        Set<String> aliases = new LinkedHashSet<>();

        try {
            List<CryptoToken> tokens = new ArrayList<>();
            CryptoManager cm = CryptoManager.getInstance();

            if (token == null) {
                logger.debug("JSSKeyStoreSpi: getting aliases from all tokens");

                Enumeration<CryptoToken> e = cm.getAllTokens();

                while (e.hasMoreElements()) {
                    CryptoToken t = e.nextElement();

                    if (t == cm.getInternalCryptoToken()) {
                        continue; // exclude crypto token
                    }

                    tokens.add(t);
                }

            } else {
                logger.debug("JSSKeyStoreSpi: getting aliases from keystore token");
                tokens.add(token);
            }

            for (CryptoToken token : tokens) {

                String tokenName;
                if (token == cm.getInternalKeyStorageToken()) {
                    tokenName = null;
                    logger.debug("JSSKeyStoreSpi: token: internal");

                } else {
                    tokenName = token.getName();
                    logger.debug("JSSKeyStoreSpi: token: " + tokenName);
                }

                CryptoStore store = token.getCryptoStore();

                logger.debug("JSSKeyStoreSpi: - certificates:");
                for (X509Certificate cert : store.getCertificates()) {
                    String nickname = cert.getNickname();
                    logger.debug("JSSKeyStoreSpi:   - " + nickname);
                    aliases.add(nickname);
                }

                logger.debug("JSSKeyStoreSpi: - private keys:");
                for (PrivateKey privateKey : store.getPrivateKeys()) {
                    // convert key ID into hexadecimal
                    String keyID = Utils.HexEncode(privateKey.getUniqueID());
                    String nickname;
                    if (tokenName == null) {
                        nickname = keyID;
                    } else {
                        nickname = tokenName + ":" + keyID;
                    }
                    logger.debug("JSSKeyStoreSpi:   - " + nickname);
                    aliases.add(nickname);
                }
            }

            return aliases;

        } catch (NotInitializedException e) {
            throw new RuntimeException(e);

        } catch (TokenException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean engineContainsAlias(String alias) {

        logger.debug("JSSKeyStoreSpi: engineContainsAlias(" + alias + ")");

        return getAliases().contains(alias);
    }

    public void engineDeleteEntry(String alias) throws KeyStoreException {

        try {
            CryptoManager manager = CryptoManager.getInstance();

            try {
                logger.debug("JSSKeyStoreSpi: searching for cert");
                X509Certificate cert = manager.findCertByNickname(alias);

                CryptoToken token;
                if (cert instanceof TokenCertificate) {
                    TokenCertificate tokenCert = (TokenCertificate) cert;
                    token = tokenCert.getOwningToken();

                } else {
                    token = manager.getInternalKeyStorageToken();
                }

                CryptoStore store = token.getCryptoStore();

                logger.debug("JSSKeyStoreSpi: deleting cert: " + alias);
                store.deleteCertOnly(cert);
                return;

            } catch (ObjectNotFoundException e) {
                logger.debug("JSSKeyStoreSpi: cert not found, searching for key");
            }

            String[] parts = parseAlias(alias);
            String tokenName = parts[0];
            String nickname = parts[1];

            CryptoToken token;
            if (tokenName == null) {
                token = manager.getInternalKeyStorageToken();
            } else {
                token = manager.getTokenByName(tokenName);
            }

            CryptoStore store = token.getCryptoStore();

            logger.debug("JSSKeyStoreSpi: searching for private key");

            for (PrivateKey privateKey : store.getPrivateKeys()) {

                // convert key ID into hexadecimal
                String keyID = Utils.HexEncode(privateKey.getUniqueID());
                logger.debug("JSSKeyStoreSpi: - " + keyID);

                if (!nickname.equals(keyID)) {
                    continue;
                }

                try {
                    logger.debug("JSSKeyStoreSpi: searching for public key: " + nickname);
                    PublicKey publicKey = store.findPublicKey(privateKey);

                    logger.debug("JSSKeyStoreSpi: deleting public key: " + nickname);
                    store.deletePublicKey(publicKey);

                } catch (ObjectNotFoundException e) {
                    logger.debug("JSSKeyStoreSpi: public key not found: " + nickname);
                }

                logger.debug("JSSKeyStoreSpi: deleting private key: " + nickname);
                store.deletePrivateKey(privateKey);

                return;
            }

            logger.debug("JSSKeyStoreSpi: entry not found: " + alias);
            throw new KeyStoreException("Entry not found: " + alias);

        } catch (NotInitializedException e) {
            throw new KeyStoreException(e);

        } catch (NoSuchTokenException e) {
            throw new KeyStoreException(e);

        } catch (TokenException e) {
            throw new KeyStoreException(e);

        } catch (NoSuchItemOnTokenException e) {
            throw new KeyStoreException(e);
        }
    }

    public Certificate engineGetCertificate(String alias) {

        logger.debug("JSSKeyStoreSpi: engineGetCertificate(" + alias + ")");

        try {
            CryptoManager cm = CryptoManager.getInstance();
            X509Certificate cert = cm.findCertByNickname(alias);

            logger.debug("JSSKeyStoreSpi: cert found: " + alias);

            if (cert instanceof PK11Cert) {
                return (PK11Cert) cert;
            }

            byte[] bytes = cert.getEncoded();
            InputStream is = new ByteArrayInputStream(bytes);

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return certFactory.generateCertificate(is);

        } catch (ObjectNotFoundException e) {
            logger.debug("JSSKeyStoreSpi: cert not found: " + alias);
            return null;

        } catch (NotInitializedException e) {
            throw new RuntimeException(e);

        } catch (TokenException e) {
            throw new RuntimeException(e);

        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);

        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public String engineGetCertificateAlias(Certificate cert) {

        logger.debug("JSSKeyStoreSpi: engineGetCertificateAlias()");

      try {
        if (cert instanceof PK11Cert) {
            PK11Cert _c = (PK11Cert) cert;
            return _c.getNickname();
        }

        return getCertNickname( cert.getEncoded() );
      } catch(CertificateEncodingException e) {
        return null;
      }
    }

    private native String getCertNickname(byte[] derCert);

    public Certificate[] engineGetCertificateChain(String alias) {

        logger.debug("JSSKeyStoreSpi: engineGetCertificateChain(" + alias + ")");

        try {
            logger.debug("JSSKeyStoreSpi: searching for leaf cert");

            CryptoManager cm = CryptoManager.getInstance();
            X509Certificate leaf = cm.findCertByNickname(alias);

            logger.debug("JSSKeyStoreSpi: building cert chain");

            X509Certificate[] certs = cm.buildCertificateChain(leaf);
            Certificate[] chain = new Certificate[certs.length];

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            for (int i = 0; i < certs.length; i++) {
                X509Certificate cert = certs[i];
                logger.debug("JSSKeyStoreSpi: - " + cert.getSubjectDN());

                if (cert instanceof PK11Cert) {
                    chain[i] = (PK11Cert) cert;
                    continue;
                }

                byte[] bytes = cert.getEncoded();
                InputStream is = new ByteArrayInputStream(bytes);
                chain[i] = certFactory.generateCertificate(is);
            }

            return chain;

        } catch (ObjectNotFoundException e) {
            logger.debug("leaf cert not found: " + alias);
            return null;

        } catch (NotInitializedException e) {
            throw new RuntimeException(e);

        } catch (TokenException e) {
            throw new RuntimeException(e);

        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    /*
     * Not supported.
     */
    public java.util.Date engineGetCreationDate(String alias) {

        logger.debug("JSSKeyStoreSpi: engineGetCreationDate(" + alias + ")");

        return null;
    }

    public Key engineGetKey(String alias, char[] password) {

        logger.debug("JSSKeyStoreSpi: engineGetKey(" + alias + ")");

        try {
            CryptoManager cm = CryptoManager.getInstance();

            logger.debug("JSSKeyStoreSpi: searching for cert");

            try {
                X509Certificate cert = cm.findCertByNickname(alias);
                logger.debug("JSSKeyStoreSpi: found cert: " + alias);

                PrivateKey privateKey = cm.findPrivKeyByCert(cert);
                logger.debug("JSSKeyStoreSpi: found private key: " + alias);

                return privateKey;

            } catch (ObjectNotFoundException e) {
                logger.debug("JSSKeyStoreSpi: cert/key not found, searching for key");
            }

            String[] parts = parseAlias(alias);
            String tokenName = parts[0];
            String nickname = parts[1];

            CryptoToken token;
            if (tokenName == null) {
                token = cm.getInternalKeyStorageToken();
            } else {
                token = cm.getTokenByName(tokenName);
            }

            CryptoStore store = token.getCryptoStore();

            logger.debug("JSSKeyStoreSpi: searching for private key");

            for (PrivateKey privateKey : store.getPrivateKeys()) {

                // convert key ID into hexadecimal
                String keyID = Utils.HexEncode(privateKey.getUniqueID());
                logger.debug("JSSKeyStoreSpi: - " + keyID);

                if (nickname.equals(keyID)) {
                    logger.debug("JSSKeyStoreSpi: found private key: " + nickname);
                    return privateKey;
                }
            }

            logger.debug("JSSKeyStoreSpi: searching for symmetric key");

            for (SymmetricKey symmetricKey : store.getSymmetricKeys()) {

                logger.debug("JSSKeyStoreSpi: - " + symmetricKey.getNickName());

                if (nickname.equals(symmetricKey.getNickName())) {
                    logger.debug("JSSKeyStoreSpi: found symmetric key: " + nickname);
                    return new SecretKeyFacade(symmetricKey);
                }
            }

            logger.debug("JSSKeyStoreSpi: key not found: " + nickname);
            return null;

        } catch (NoSuchTokenException e) {
            throw new RuntimeException(e);

        } catch (NotInitializedException e) {
            throw new RuntimeException(e);

        } catch (TokenException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Returns true if there is a cert with this nickname but there is no
     * key associated with the cert.
     */
    public boolean engineIsCertificateEntry(String alias) {

        logger.debug("JSSKeyStoreSpi: engineIsCertificateEntry(" + alias + ")");

        try {
            CryptoManager cm = CryptoManager.getInstance();
            cm.findCertByNickname(alias);

            logger.debug("JSSKeyStoreSpi: cert found: " + alias);
            return true;

        } catch (ObjectNotFoundException e) {
            logger.debug("JSSKeyStoreSpi: cert not found: " + alias);
            return false;

        } catch (NotInitializedException e) {
            throw new RuntimeException(e);

        } catch (TokenException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Returns true if there is a key with this alias, or if
     * there is a cert with this alias that has an associated key.
     */
    public boolean engineIsKeyEntry(String alias) {

        logger.debug("JSSKeyStoreSpi: engineIsKeyEntry(" + alias + ")");

        /* this is somewhat wasteful but we can speed it up later */
        return engineGetKey(alias, null) != null;
    }

    public void engineLoad(InputStream stream, char[] password)
        throws IOException
    {
        logger.debug("JSSKeyStoreSpi: engineLoad(stream, password)");
    }

    public void engineLoad(KeyStore.LoadStoreParameter param)
        throws IOException
    {
        logger.debug("JSSKeyStoreSpi: engineLoad(param)");

        if (!(param instanceof JSSLoadStoreParameter)) {
            throw new IOException("Invalid keystore parameter type: " + param.getClass().getName());
        }

        JSSLoadStoreParameter jssParam = (JSSLoadStoreParameter) param;
        token = jssParam.getToken();

        try {
            logger.debug("JSSKeyStoreSpi: token: " + token.getName());
        } catch (TokenException e) {
            throw new IOException(e);
        }
    }

    /**
     * NSS doesn't have a way of storing a certificate on a specific token
     * unless it has an associated private key.  That rules out
     * trusted certificate entries, so we can't supply this method currently.
     */
    public void engineSetCertificateEntry(String alias, Certificate cert)
            throws KeyStoreException
    {

        logger.debug("JSSKeyStoreSpi: engineSetCertificateEntry(" + alias + ")");

        throw new KeyStoreException(
            "Storing trusted certificate entries to a JSS KeyStore is not" +
            " supported.");
    }


    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain)
        throws KeyStoreException
    {

        logger.debug("JSSKeyStoreSpi: engineSetKeyEntry(" + alias + ", key, chain)");

        throw new KeyStoreException("Storing plaintext keys is not supported."+
            "Store the key as a handle instead.");
    }

    public void engineSetKeyEntry(String alias, Key key, char[] password,
        Certificate[] chain) throws KeyStoreException
    {

        logger.debug("JSSKeyStoreSpi: engineSetKeyEntry(" + alias + ", key, password, chain)");

        if( key instanceof SecretKeyFacade ) {
            SecretKeyFacade skf = (SecretKeyFacade)key;
            engineSetKeyEntryNative(alias, skf.key, password, chain);
        } else {
            engineSetKeyEntryNative(alias, key, password, chain);
        }
    }

    private native void engineSetKeyEntryNative(String alias, Object key,
        char[] password, Certificate[] chain) throws KeyStoreException;

    public int engineSize() {

        logger.debug("JSSKeyStoreSpi: engineSize()");

        return getAliases().size();
    }

    public void engineStore(OutputStream stream, char[] password)
            throws IOException
    {
        logger.debug("JSSKeyStoreSpi: engineStore()");
    }
}
