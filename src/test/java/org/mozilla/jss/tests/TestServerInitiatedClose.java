/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import java.nio.ByteBuffer;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngineResult;

import org.mozilla.jss.ssl.javax.JSSEngine;

/** Tests server-initiated close without receiving the peer's close_notify. */
public class TestServerInitiatedClose {
    public static void main(String[] args) throws Exception {
        // Arguments: NSS database, password file, client alias, server alias.
        TestSSLEngine.initialize(args);
        SSLContext context = SSLContext.getInstance("TLS", "Mozilla-JSS");
        context.init(TestSSLEngine.getKMs(), TestSSLEngine.getTMs(), null);
        int retained = 0;
        int completed = 0;

        for (String protocol : new String[] {"TLSv1.2", "TLSv1.3"}) {
            String cipher = protocol.equals("TLSv1.2")
                    ? "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
                    : "TLS_AES_128_GCM_SHA256";
            for (int i = 0; i < 25; i++) {
                JSSEngine client = (JSSEngine) context.createSSLEngine();
                JSSEngine server = (JSSEngine) context.createSSLEngine();
                try {
                    client.setSSLParameters(TestSSLEngine.createParameters(args[2]));
                    server.setSSLParameters(TestSSLEngine.createParameters(args[3]));
                    client.setUseClientMode(true);
                    server.setUseClientMode(false);
                    TestSSLEngine.configureSSLEngine(client, protocol, cipher);
                    TestSSLEngine.configureSSLEngine(server, protocol, cipher);
                    TestSSLEngine.testHandshake(client, server, false);
                    TestSSLEngine.testPostHandshakeTransfer(client, server);

                    ByteBuffer wire = ByteBuffer.allocate(65536);
                    server.closeOutbound();
                    SSLEngineResult result = server.wrap(ByteBuffer.allocate(0), wire);
                    if (result.getStatus() != SSLEngineResult.Status.CLOSED) {
                        throw new AssertionError("Expected CLOSED: " + result);
                    }
                    // Inspect before explicit cleanup. Tomcat may never call
                    // closeInbound after sending the server's close_notify.
                    if (!server.isInboundDone() || !server.isOutboundDone()
                            || server.getSSLFDProxy() != null) {
                        retained++;
                    }
                    completed++;
                } finally {
                    // Bound resource use even when testing an unfixed build.
                    server.cleanup();
                    client.cleanup();
                }
            }
        }
        System.out.println("Server close: completed=" + completed + " retained=" + retained);
        if (retained != 0) {
            throw new AssertionError("Server resources retained after outbound close: " + retained);
        }
    }
}
