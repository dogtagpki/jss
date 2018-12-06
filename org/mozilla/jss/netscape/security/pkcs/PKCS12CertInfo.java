// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2016 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.mozilla.jss.netscape.security.pkcs;

import org.mozilla.jss.netscape.security.x509.X509CertImpl;

public class PKCS12CertInfo {

    private byte[] id;
    private X509CertImpl cert;
    private String friendlyName;
    private String trustFlags;
    private byte[] keyID;

    public PKCS12CertInfo() {
    }

    public byte[] getID() {
        return id;
    }

    public void setID(byte[] id) {
        this.id = id;
    }

    public X509CertImpl getCert() {
        return cert;
    }

    public void setCert(X509CertImpl cert) {
        this.cert = cert;
    }

    public String getFriendlyName() {
        return friendlyName;
    }

    public void setFriendlyName(String friendlyName) {
        this.friendlyName = friendlyName;
    }

    public String getTrustFlags() {
        return trustFlags;
    }

    public void setTrustFlags(String trustFlags) {
        this.trustFlags = trustFlags;
    }

    public byte[] getKeyID() {
        return keyID;
    }

    public void setKeyID(byte[] keyID) {
        this.keyID = keyID;
    }
}
