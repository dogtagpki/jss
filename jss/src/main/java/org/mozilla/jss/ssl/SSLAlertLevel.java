/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

public enum SSLAlertLevel {

    // see lib/ssl/ssl3prot.h in NSS
    WARNING (1),
    FATAL   (2);

    private int id;

    private SSLAlertLevel(int id) {
        this.id = id;
    }

    public int getID() {
        return id;
    }

    public static SSLAlertLevel valueOf(int id) {
        for (SSLAlertLevel level : SSLAlertLevel.class.getEnumConstants()) {
            if (level.id == id) return level;
        }
        return null;
    }
}
