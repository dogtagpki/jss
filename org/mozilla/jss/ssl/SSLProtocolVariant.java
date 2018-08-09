/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

public class SSLProtocolVariant {

    public static final SSLProtocolVariant STREAM =
        new SSLProtocolVariant(SocketBase.SSL_Variant_Stream);

    public static final SSLProtocolVariant DATA_GRAM =
        new SSLProtocolVariant(SocketBase.SSL_Variant_Datagram);

    private int _enum;

    private SSLProtocolVariant(int val) { _enum = val; }

    int getEnum() { return _enum; }
}
