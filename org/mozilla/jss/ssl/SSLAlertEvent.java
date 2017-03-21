/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

import java.util.EventObject;

public class SSLAlertEvent extends EventObject {

    private static final long serialVersionUID = 1L;

    int level;
    int description;

    public SSLAlertEvent(SSLSocket socket) {
        super(socket);
    }

    public SSLSocket getSocket() {
        return (SSLSocket)getSource();
    }

    public int getLevel() {
        return level;
    }

    public void setLevel(int level) {
        this.level = level;
    }

    public int getDescription() {
        return description;
    }

    public void setDescription(int description) {
        this.description = description;
    }
}
