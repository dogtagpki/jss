package org.dogtagpki.jss.tomcat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Http11NioProtocol extends org.apache.coyote.http11.Http11NioProtocol {

    public static Logger logger = LoggerFactory.getLogger(Http11NioProtocol.class);

    TomcatJSS tomcatjss = TomcatJSS.getInstance();

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

    public boolean getEnabledOCSP() {
        return tomcatjss.getEnableOCSP();
    }

    public void setEnableOCSP(boolean enableOCSP) {
        tomcatjss.setEnableOCSP(enableOCSP);
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

    public void setKeystorePassFile(String keystorePassFile) {
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
}
