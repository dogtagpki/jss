/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/*
 * SSLHandshakeCompletedListener.java
 * 
 * 
 */

package org.mozilla.jss.ssl;

import java.io.*;
import java.net.*;
import java.util.*;

/**
 * This interface is used when you want to know that a security
 * handshake is complete.
 */
public interface SSLHandshakeCompletedListener extends EventListener {
    public void handshakeCompleted(SSLHandshakeCompletedEvent event);
}
