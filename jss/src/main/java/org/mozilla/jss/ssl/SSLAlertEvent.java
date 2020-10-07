/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

import java.util.EventObject;

import javax.net.ssl.SSLException;

import org.mozilla.jss.nss.SSLFDProxy;

public class SSLAlertEvent extends EventObject {

    private static final long serialVersionUID = 1L;

    int level;
    int description;

    SSLAlertLevel levelEnum;
    SSLAlertDescription descriptionEnum;

    public SSLAlertEvent(SSLSocket socket) {
        super(socket);
    }

    public SSLAlertEvent(SSLSocket socket, int level, int description) {
        super(socket);

        setLevel(level);
        setDescription(description);
    }

    public SSLAlertEvent(SSLSocket socket, SSLAlertLevel level, SSLAlertDescription description) {
        super(socket);

        setLevel(level);
        setDescription(description);
    }

    public SSLAlertEvent(SSLFDProxy proxy) {
        super(proxy);
    }

    public SSLAlertEvent(SSLFDProxy proxy, int level, int description) {
        super(proxy);

        setLevel(level);
        setDescription(description);
    }

    public SSLAlertEvent(SSLFDProxy proxy, SSLAlertLevel level, SSLAlertDescription description) {
        super(proxy);

        setLevel(level);
        setDescription(description);
    }

    public SSLSocket getSocket() {
        return (SSLSocket)getSource();
    }

    public SSLFDProxy getFileDesc() {
        return (SSLFDProxy)getSource();
    }

    public int getLevel() {
        return level;
    }

    public SSLAlertLevel getLevelEnum() {
        return levelEnum;
    }

    public void setLevel(int level) {
        this.level = level;
        this.levelEnum = SSLAlertLevel.valueOf(level);
    }

    public void setLevel(SSLAlertLevel level) {
        this.levelEnum = level;
        this.level = level.getID();
    }

    public int getDescription() {
        return description;
    }

    public SSLAlertDescription getDescriptionEnum() {
        return descriptionEnum;
    }

    public void setDescription(int description) {
        this.description = description;
        this.descriptionEnum = SSLAlertDescription.valueOf(description);
    }

    public void setDescription(SSLAlertDescription description) {
        this.descriptionEnum = description;
        this.description = description.getID();
    }

    public SSLException toException() {
        if (levelEnum == SSLAlertLevel.FATAL) {
            Class<? extends SSLException> exception_class = descriptionEnum.getExceptionClass();
            SSLException exception;

            try {
                exception = exception_class.getConstructor(String.class).newInstance(this.toString());
            } catch (Exception e) {
                // When we fail to construct an exception of type
                // exception_class, usually that means that we've gotten
                // a null exception_class. In which case, because this is
                // a fatal exception, throw it as a generic SSLException.
                exception = new SSLException(this.toString());
            }

            return exception;
        }

        return null;
    }

    public void throwException() throws SSLException {
        throw this.toException();
    }

    public String toString() {
        return this.levelEnum + ": " + this.descriptionEnum;
    }
}
