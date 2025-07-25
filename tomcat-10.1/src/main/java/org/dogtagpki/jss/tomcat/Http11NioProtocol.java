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
package org.dogtagpki.jss.tomcat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.coyote.http11.AbstractHttp11JsseProtocol;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.NioChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Http11NioProtocol extends AbstractHttp11JsseProtocol<NioChannel> {

    public static Logger logger = LoggerFactory.getLogger(Http11NioProtocol.class);
    private static final Log log = LogFactory.getLog(Http11NioProtocol.class);

    TomcatJSS tomcatjss = TomcatJSS.getInstance();

    public Http11NioProtocol() {
       super(new JSSNioEndpoint());
    }

    public String getCertdbDir() {
        return tomcatjss.getCertdbDir();
    }

    public void setCertdbDir(String certdbDir) {
        tomcatjss.setCertdbDir(certdbDir);
    }

    public String getPasswordClass() {
        return tomcatjss.getPasswordClass();
    }

    public void setPasswordClass(String passwordClass) {
        tomcatjss.setPasswordClass(passwordClass);
    }

    public String getPasswordFile() {
        return tomcatjss.getPasswordFile();
    }

    public void setPasswordFile(String passwordFile) {
        tomcatjss.setPasswordFile(passwordFile);
    }

    public String getServerCertNickFile() {
        return tomcatjss.getServerCertNickFile();
    }

    public void setServerCertNickFile(String serverCertNickFile) {
        tomcatjss.setServerCertNickFile(serverCertNickFile);
    }

    public boolean getEnableOCSP() {
        return tomcatjss.getEnableRevocationCheck();
    }

    public void setEnableOCSP(boolean enableOCSP) {
        tomcatjss.setEnableRevocationCheck(enableOCSP);
    }

    public boolean getEnableRevocationCheck() {
        return tomcatjss.getEnableRevocationCheck();
    }
    
    public void setEnableRevocationCheck(boolean enableRevocationCheck) {
        tomcatjss.setEnableRevocationCheck(enableRevocationCheck);
    }

    public String getOcspResponderURL() {
        return tomcatjss.getOcspResponderURL();
    }

    public void setOcspResponderURL(String ocspResponderURL) {
        tomcatjss.setOcspResponderURL(ocspResponderURL);
    }

    public String getOcspResponderCertNickname() {
        return tomcatjss.getOcspResponderCertNickname();
    }

    public void setOcspResponderCertNickname(String ocspResponderCertNickname) {
        tomcatjss.setOcspResponderCertNickname(ocspResponderCertNickname);
    }

    public int getOcspCacheSize() {
        return tomcatjss.getOcspCacheSize();
    }

    public void setOcspCacheSize(int ocspCacheSize) {
        tomcatjss.setOcspCacheSize(ocspCacheSize);
    }

    public int getOcspMinCacheEntryDuration() {
        return tomcatjss.getOcspMinCacheEntryDuration();
    }

    public void setOcspMinCacheEntryDuration(int ocspMinCacheEntryDuration) {
        tomcatjss.setOcspMinCacheEntryDuration(ocspMinCacheEntryDuration);
    }

    public int getOcspMaxCacheEntryDuration() {
        return tomcatjss.getOcspMaxCacheEntryDuration();
    }

    public void setOcspMaxCacheEntryDuration(int ocspMaxCacheEntryDuration) {
        tomcatjss.setOcspMaxCacheEntryDuration(ocspMaxCacheEntryDuration);
    }

    public int getOcspTimeout() {
        return tomcatjss.getOcspTimeout();
    }

    public void setOcspTimeout(int ocspTimeout) {
        tomcatjss.setOcspTimeout(ocspTimeout);
    }

/*    public void setKeystorePassFile(String keystorePassFile) {
        try {
            Path path = Paths.get(keystorePassFile);
            String password = new String(Files.readAllBytes(path)).trim();
            setKeystorePass(password);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void setTruststorePassFile(String truststorePassFile) {
        try {
            Path path = Paths.get(truststorePassFile);
            String password = new String(Files.readAllBytes(path)).trim();
            setTruststorePass(password);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
*/
    @Override
    protected Log getLog() {
        return log;
    }

    @Override
    protected String getNamePrefix() {
        if (isSSLEnabled()) {
            return "https-" + getSslImplementationShortName()+ "-jss-nio";
        }
        return "http-jss-nio";
    }

    // These methods are temporarly present to replicate the default behaviour provided by tomcat
    public void setSelectorTimeout(long timeout) {
        ((JSSNioEndpoint)getEndpoint()).setSelectorTimeout(timeout);
    }

    public long getSelectorTimeout() {
        return ((JSSNioEndpoint)getEndpoint()).getSelectorTimeout();
    }

    public void setPollerThreadPriority(int threadPriority) {
        ((JSSNioEndpoint)getEndpoint()).setPollerThreadPriority(threadPriority);
    }

    public int getPollerThreadPriority() {
      return ((JSSNioEndpoint)getEndpoint()).getPollerThreadPriority();
    }
}
