/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

import java.io.IOException;

class SSLOutputStream extends java.io.OutputStream {

    SSLOutputStream(SSLSocket sock) {
        this.sock = sock;
    }

    public void write(int b) throws IOException {
        write( new byte[] {(byte)b}, 0, 1 );
    }

    public void write(byte[] b) throws IOException {
        write( b, 0, b.length);
    }

    public void write(byte[] b, int off, int len) throws IOException {
        sock.write(b, off, len);
    }       

    public void close() throws IOException {
        sock.close();
    }

    private SSLSocket sock;
}
