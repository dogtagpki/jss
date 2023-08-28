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

import java.io.IOException;
import java.nio.channels.SelectionKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.buf.ByteBufferUtils;
import org.apache.tomcat.util.compat.JreCompat;
import org.apache.tomcat.util.net.NioEndpoint;
import org.apache.tomcat.util.net.SSLSupport;
import org.apache.tomcat.util.net.SSLUtil;
import org.apache.tomcat.util.net.SecureNioChannel;
import org.apache.tomcat.util.net.SocketBufferHandler;
import org.apache.tomcat.util.net.TLSClientHelloExtractor;
import org.apache.tomcat.util.net.TLSClientHelloExtractor.ExtractorResult;
import org.apache.tomcat.util.net.openssl.ciphers.Cipher;
import org.apache.tomcat.util.res.StringManager;
import org.mozilla.jss.ssl.javax.JSSSession;
/**
 * Implementation of a secure socket channel
 * <p>
 * Code in the following methods are almost identical of that available in the base
 * class {@link org.apache.tomcat.util.net.SecureNioChannel from tomcat git repository
 * for the version 9.0.78.
 * <p>
 * The only difference is the registration of local and remote IP in the SSL engine session.
 * These IPs are required for audit purpose but the tomcat implementation does not provide
 * such information to the engine, since they are not needed for Java SSL engine specification.
 * <p>
 * The SSL engine is created in the private method {@link JSSSecureNioChannel#processSNI()} so
 * the calling methods have been duplicated in order to work properly.
 *
 * @see org.apache.tomcat.util.net.SecureNioChannel
 */

public class JSSSecureNioChannel extends SecureNioChannel {

    private static final Log log = LogFactory.getLog(JSSSecureNioChannel.class);
    private static final StringManager sm = StringManager.getManager(JSSSecureNioChannel.class);

    private final JSSNioEndpoint endpoint;

    private final Map<String,List<String>> additionalTlsAttributes = new HashMap<>();

    public JSSSecureNioChannel(SocketBufferHandler bufHandler, NioEndpoint endpoint) {
        super(bufHandler, endpoint);
        this.endpoint = (JSSNioEndpoint) endpoint;
    }


    /**
     * Performs SSL handshake, non blocking, but performs NEED_TASK on the same
     * thread. Hence, you should never call this method using your Acceptor
     * thread, as you would slow down your system significantly. If the return
     * value from this method is positive, the selection key should be
     * registered interestOps given by the return value.
     *
     * @param read boolean - true if the underlying channel is readable
     * @param write boolean - true if the underlying channel is writable
     *
     * @return 0 if hand shake is complete, -1 if an error (other than an
     *         IOException) occurred, otherwise it returns a SelectionKey
     *         interestOps value
     *
     * @throws IOException If an I/O error occurs during the handshake or if the
     *                     handshake fails during wrapping or unwrapping
     */
    @Override
    public int handshake(boolean read, boolean write) throws IOException {
        if (handshakeComplete) {
            return 0; //we have done our initial handshake
        }

        if (!sniComplete) {
// This is the change from the code in the base class
            int sniResult = processJSSSNI();
// End of difference

            if (sniResult == 0) {
                sniComplete = true;
            } else {
                return sniResult;
            }
        }

        if (!flush(netOutBuffer)) {
            return SelectionKey.OP_WRITE; //we still have data to write
        }

        SSLEngineResult handshake = null;

        while (!handshakeComplete) {
            switch (handshakeStatus) {
                case NOT_HANDSHAKING:
                    //should never happen
                    throw new IOException(sm.getString("channel.nio.ssl.notHandshaking"));
                case FINISHED:
                    if (endpoint.hasNegotiableProtocols()) {
                        if (sslEngine instanceof SSLUtil.ProtocolInfo) {
                            socketWrapper.setNegotiatedProtocol(
                                    ((SSLUtil.ProtocolInfo) sslEngine).getNegotiatedProtocol());
                        } else if (JreCompat.isAlpnSupported()) {
                            socketWrapper.setNegotiatedProtocol(
                                    JreCompat.getInstance().getApplicationProtocol(sslEngine));
                        }
                    }
                    //we are complete if we have delivered the last package
                    handshakeComplete = !netOutBuffer.hasRemaining();
                    //return 0 if we are complete, otherwise we still have data to write
                    return handshakeComplete ? 0 : SelectionKey.OP_WRITE;
                case NEED_WRAP:
                    //perform the wrap function
                    try {
                        handshake = handshakeWrap(write);
                    } catch (SSLException e) {
                        handshake = handshakeWrap(write);
                        throw e;
                    }
                    if (handshake.getStatus() == Status.OK) {
                        if (handshakeStatus == HandshakeStatus.NEED_TASK) {
                            handshakeStatus = tasks();
                        }
                    } else if (handshake.getStatus() == Status.CLOSED) {
                        flush(netOutBuffer);
                        return -1;
                    } else {
                        //wrap should always work with our buffers
                        throw new IOException(sm.getString("channel.nio.ssl.unexpectedStatusDuringWrap", handshake.getStatus()));
                    }
                    if (handshakeStatus != HandshakeStatus.NEED_UNWRAP || (!flush(netOutBuffer))) {
                        //should actually return OP_READ if we have NEED_UNWRAP
                        return SelectionKey.OP_WRITE;
                    }
                    //fall down to NEED_UNWRAP on the same call, will result in a
                    //BUFFER_UNDERFLOW if it needs data
                //$FALL-THROUGH$
                case NEED_UNWRAP:
                    //perform the unwrap function
                    handshake = handshakeUnwrap(read);
                    if (handshake.getStatus() == Status.OK) {
                        if (handshakeStatus == HandshakeStatus.NEED_TASK) {
                            handshakeStatus = tasks();
                        }
                    } else if ( handshake.getStatus() == Status.BUFFER_UNDERFLOW ){
                        //read more data, reregister for OP_READ
                        return SelectionKey.OP_READ;
                    } else {
                        throw new IOException(sm.getString("channel.nio.ssl.unexpectedStatusDuringWrap", handshake.getStatus()));
                    }
                    break;
                case NEED_TASK:
                    handshakeStatus = tasks();
                    break;
                default:
                    throw new IllegalStateException(sm.getString("channel.nio.ssl.invalidStatus", handshakeStatus));
            }
        }
        // Handshake is complete if this point is reached
        return 0;
    }


    /*
     * Peeks at the initial network bytes to determine if the SNI extension is
     * present and, if it is, what host name has been requested. Based on the
     * provided host name, configure the SSLEngine for this connection.
     *
     * @return 0 if SNI processing is complete, -1 if an error (other than an
     *         IOException) occurred, otherwise it returns a SelectionKey
     *         interestOps value
     *
     * @throws IOException If an I/O error occurs during the SNI processing
     */
// This is the change from the code in the base class
    private int processJSSSNI() throws IOException {
//End of difference
        // Read some data into the network input buffer so we can peek at it.
        int bytesRead = sc.read(netInBuffer);
        if (bytesRead == -1) {
            // Reached end of stream before SNI could be processed.
            return -1;
        }
        TLSClientHelloExtractor extractor = new TLSClientHelloExtractor(netInBuffer);

        while (extractor.getResult() == ExtractorResult.UNDERFLOW &&
                netInBuffer.capacity() < endpoint.getSniParseLimit()) {
            // extractor needed more data to process but netInBuffer was full so
            // expand the buffer and read some more data.
            int newLimit = Math.min(netInBuffer.capacity() * 2, endpoint.getSniParseLimit());
            log.info(sm.getString("channel.nio.ssl.expandNetInBuffer",
                    Integer.toString(newLimit)));

            netInBuffer = ByteBufferUtils.expand(netInBuffer, newLimit);
            sc.read(netInBuffer);
            extractor = new TLSClientHelloExtractor(netInBuffer);
        }

        String hostName = null;
        List<Cipher> clientRequestedCiphers = null;
        List<String> clientRequestedApplicationProtocols = null;
        switch (extractor.getResult()) {
        case COMPLETE:
            hostName = extractor.getSNIValue();
            clientRequestedApplicationProtocols =
                    extractor.getClientRequestedApplicationProtocols();
            //$FALL-THROUGH$ to set the client requested ciphers
        case NOT_PRESENT:
            clientRequestedCiphers = extractor.getClientRequestedCiphers();
            break;
        case NEED_READ:
            return SelectionKey.OP_READ;
        case UNDERFLOW:
            // Unable to buffer enough data to read SNI extension data
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("channel.nio.ssl.sniDefault"));
            }
            hostName = endpoint.getDefaultSSLHostConfigName();
            clientRequestedCiphers = Collections.emptyList();
            break;
        case NON_SECURE:
            netOutBuffer.clear();
            netOutBuffer.put(TLSClientHelloExtractor.USE_TLS_RESPONSE);
            netOutBuffer.flip();
            flushOutbound();
            throw new IOException(sm.getString("channel.nio.ssl.foundHttp"));
        }

        if (log.isDebugEnabled()) {
            log.debug(sm.getString("channel.nio.ssl.sniHostName", sc, hostName));
        }

        sslEngine = endpoint.createSSLEngine(hostName, clientRequestedCiphers,
                clientRequestedApplicationProtocols);

// This is the change from the code in the base class
        JSSSession jsession = (JSSSession) sslEngine.getSession();
        jsession.setLocalAddr(socketWrapper.getLocalAddr());
        jsession.setRemoteAddr(socketWrapper.getRemoteAddr());
// End of difference
        // Populate additional TLS attributes obtained from the handshake that
        // aren't available from the session
        additionalTlsAttributes.put(SSLSupport.REQUESTED_PROTOCOL_VERSIONS_KEY,
                extractor.getClientRequestedProtocols());
        additionalTlsAttributes.put(SSLSupport.REQUESTED_CIPHERS_KEY,
                extractor.getClientRequestedCipherNames());

        // Ensure the application buffers (which have to be created earlier) are
        // big enough.
        getBufHandler().expand(sslEngine.getSession().getApplicationBufferSize());
        if (netOutBuffer.capacity() < sslEngine.getSession().getApplicationBufferSize()) {
            // Info for now as we may need to increase DEFAULT_NET_BUFFER_SIZE
            log.info(sm.getString("channel.nio.ssl.expandNetOutBuffer",
                    Integer.toString(sslEngine.getSession().getApplicationBufferSize())));
        }
        netInBuffer = ByteBufferUtils.expand(netInBuffer, sslEngine.getSession().getPacketBufferSize());
        netOutBuffer = ByteBufferUtils.expand(netOutBuffer, sslEngine.getSession().getPacketBufferSize());

        // Set limit and position to expected values
        netOutBuffer.position(0);
        netOutBuffer.limit(0);

        // Initiate handshake
        sslEngine.beginHandshake();
        handshakeStatus = sslEngine.getHandshakeStatus();

        return 0;
    }



    @Override
    public SSLSupport getSSLSupport() {
        if (sslEngine != null) {
            SSLSession session = sslEngine.getSession();
            return endpoint.getSslImplementation().getSSLSupport(session, additionalTlsAttributes);
        }
        return null;
    }

}
