/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/*
 * SSLHandshakeCompletedEvent.java
 * 
 * 
 */

package org.mozilla.jss.ssl;

import java.io.*;
import java.net.*;
import java.util.*;

/*
 * right now, this only extends EventObject, but it will eventually
 * extend javax.net.ssl.HandshakeCompletedEvent
 */

/**
 * This class represents the event telling you a handshake
 * operation is complete.
 */
public class SSLHandshakeCompletedEvent extends EventObject {
    public SSLHandshakeCompletedEvent(SSLSocket socket) {
	super(socket);
    }
    
    /**
     * get security information about this socket, including
     * cert data
     */
    public SSLSecurityStatus getStatus() throws SocketException {
	return getSocket().getStatus();
    }
    
    /**
     * get socket on which the event occured
     */
    public SSLSocket getSocket() {
	return (SSLSocket)getSource();
    }
}
