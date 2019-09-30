/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

import java.util.EventObject;

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

    public SSLSocket getSocket() {
        return (SSLSocket)getSource();
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
}
