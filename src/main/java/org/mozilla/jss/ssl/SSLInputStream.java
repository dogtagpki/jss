/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

import java.io.IOException;

class SSLInputStream extends java.io.InputStream {

    SSLInputStream(SSLSocket sock) {
        this.sock = sock;
    }

    @Override
    public int available() throws IOException {
        return sock.socketAvailable();
    }

    @Override
    public void close() throws IOException {
        sock.close();
    }

    @Override
    public int read() throws IOException {
        byte[] b = new byte[1];
        int nread = read(b, 0, 1);
        if( nread == -1 ) {
            return nread;
        } else {
            return ((int) b[0]) & (0xff);
        }
    }

    @Override
    public int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        return sock.read(b, off, len);
    }

    @Override
    public long skip(long n) throws IOException {
        long numSkipped = 0;

        int size = (int) (n < 2048 ? n : 2048);
        byte[] trash = new byte[size];
        while( n > 0) {
            size = (int) (n < 2048 ? n : 2048);
            int nread = read(trash, 0, size);
            if( nread <= 0 ) {
                break;
            }
            numSkipped += nread;
            n -= nread;
        }
        return numSkipped;
    }

    private SSLSocket sock;
}
