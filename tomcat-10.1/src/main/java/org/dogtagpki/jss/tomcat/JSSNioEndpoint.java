/* BEGIN COPYRIGHT BLOCK
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Copyright (C) 2017 Red Hat, Inc.
 * All rights reserved.
 *
 *
 *
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 *  Apache Tomcat
 *  Copyright 1999-2023 The Apache Software Foundation
 *
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License. *
 * END COPYRIGHT BLOCK */

package org.dogtagpki.jss.tomcat;


import java.nio.channels.SocketChannel;
import java.util.List;

import javax.net.ssl.SSLEngine;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.net.NioChannel;
import org.apache.tomcat.util.net.NioEndpoint;
import org.apache.tomcat.util.net.SocketBufferHandler;
import org.apache.tomcat.util.net.openssl.ciphers.Cipher;

public class JSSNioEndpoint extends NioEndpoint {

    private static final Log log = LogFactory.getLog(NioEndpoint.class);
    /**
     * Code in the following method is almost identical of that available in the base
     * class {@link org.apache.tomcat.util.net.NioEndpoint#setSocketOptions(SocketChannel) from tomcat
     * git repository for the version 9.0.78..
     * <p>
     * The only difference is the instantiation of the JSSSecureNioChannel class instead of the tomcat
     * provided SecureNioChannel class. This is needed because the channel class is hard-coded in the
     * base class method.
     *
     * @see org.apache.tomcat.util.net.NioEndpoint#setSocketOptions(SocketChannel socket)
     */

    @Override
    protected boolean setSocketOptions(SocketChannel socket) {
        NioSocketWrapper socketWrapper = null;
        try {
            // Allocate channel and wrapper
            NioChannel channel = null;
            if (getNioChannels() != null) {
                channel = getNioChannels().pop();
            }
            if (channel == null) {
                SocketBufferHandler bufhandler = new SocketBufferHandler(
                        socketProperties.getAppReadBufSize(),
                        socketProperties.getAppWriteBufSize(),
                        socketProperties.getDirectBuffer());
                if (isSSLEnabled()) {
// This is the change from the code in the base class
                    channel = new JSSSecureNioChannel(bufhandler, this);
// End of difference
                } else {
                    channel = new NioChannel(bufhandler);
                }
            }
            NioSocketWrapper newWrapper = new NioSocketWrapper(channel, this);
            channel.reset(socket, newWrapper);
            connections.put(socket, newWrapper);
            socketWrapper = newWrapper;

            // Set socket properties
            // Disable blocking, polling will be used
            socket.configureBlocking(false);
            if (getUnixDomainSocketPath() == null) {
                socketProperties.setProperties(socket.socket());
            }

            socketWrapper.setReadTimeout(getConnectionTimeout());
            socketWrapper.setWriteTimeout(getConnectionTimeout());
            socketWrapper.setKeepAliveLeft(JSSNioEndpoint.this.getMaxKeepAliveRequests());
            getPoller().register(socketWrapper);
            return true;
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            try {
                log.error(sm.getString("endpoint.socketOptionsError"), t);
            } catch (Throwable tt) {
                ExceptionUtils.handleThrowable(tt);
            }
            if (socketWrapper == null) {
                destroySocket(socket);
            }
        }
        // Tell to close the socket if needed
        return false;

    }
    @Override
    protected SSLEngine createSSLEngine(String arg0, List<Cipher> arg1, List<String> arg2) {
        return super.createSSLEngine(arg0, arg1, arg2);
    }

}
