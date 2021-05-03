/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

public class CipherPolicy {

    public static final CipherPolicy DOMESTIC =
        new CipherPolicy(SocketBase.SSL_POLICY_DOMESTIC);

    public static final CipherPolicy EXPORT =
        new CipherPolicy(SocketBase.SSL_POLICY_EXPORT);

    public static final CipherPolicy FRANCE =
        new CipherPolicy(SocketBase.SSL_POLICY_FRANCE);

    private int _enum;

    private CipherPolicy(int _enum) { }

    int getEnum() { return _enum; }
}
