/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/*
 * SSLHandshakeCompletedEvent.java
 * 
 * 
 */

package org.mozilla.jss.ssl;

import java.net.*;
import java.util.*;

import org.mozilla.jss.ssl.javax.JSSEngine;

/*
 * right now, this only extends EventObject, but it will eventually
 * extend javax.net.ssl.HandshakeCompletedEvent
 */

/**
 * This class represents the event telling you a handshake
 * operation is complete.
 */
public class SSLHandshakeCompletedEvent extends EventObject {
    private static final long serialVersionUID = 1L;

    public SSLHandshakeCompletedEvent(SSLSocket socket) {
        super(socket);
    }

    public SSLHandshakeCompletedEvent(JSSEngine engine) {
        super(engine);
    }
    
    /**
     * Get security information about this socket, including
     * cert data; null if on a SSLEngine.
     */
    public SSLSecurityStatus getStatus() throws SocketException {
        if (getSocket() != null) {
            return getSocket().getStatus();
        }

        return null;
    }
    
    /**
     * Get socket on which the event occurred; null if on a SSLEngine.
     */
    public SSLSocket getSocket() {
        Object obj = getSource();
        if (obj != null && obj instanceof SSLSocket) {
            return (SSLSocket)getSource();
        }

        return null;
    }

    /**
     * Get engine on which the event occurred; null if on a SSLSocket.
     */
    public JSSEngine getEngine() {
        Object obj = getSource();
        if (obj != null  && obj instanceof JSSEngine) {
            return (JSSEngine)getSource();
        }

        return null;
    }
}
