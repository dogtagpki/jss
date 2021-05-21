/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.asn1;

import java.io.IOException;
import java.io.InputStream;

/**
 * This class keeps track of the number of bytes that have been read from
 * a stream. It will be incremented by the number of bytes read or skipped.
 * If the stream is marked and then reset, the number of bytes read will
 * be reset as well.
 */
class CountingStream extends InputStream {

    private int count=0;
    private int markpos;
    private InputStream source;

    private static final boolean DEBUG = false;

    public CountingStream(InputStream source) {
        this.source = source;
    }

    @Override
    public int available() throws IOException {
        return source.available();
    }

    @Override
    public void mark(int readlimit) {
        source.mark(readlimit);
        markpos = count;
        if(DEBUG) {
            System.out.println("Marked at position "+markpos);
        }
    }

    @Override
    public boolean markSupported() {
        return source.markSupported();
    }

    @Override
    public int read() throws IOException {
        int n = source.read();
        if( n != -1 ) {
            count++;
            if(DEBUG) {
                System.out.println("read() 1 byte, count="+count);
            }
        }
        return n;
    }

    @Override
    public int read(byte[] buffer) throws IOException {
        int n = source.read(buffer);
        if( n != -1 ) {
            count += n;
        }
        if(DEBUG) {
            System.out.println("read([]) "+n+" bytes, count="+count);
        }
        return n;
    }

    @Override
    public int read(byte[] buffer, int offset, int count) throws IOException {
        int n = source.read(buffer, offset, count);
        if( n != -1 ) {
            this.count += n;
        }
        if(DEBUG) {
            System.out.println("read(...) "+n+" bytes, count="+this.count);
        }
        return n;
    }

    @Override
    public void reset() throws IOException {
        source.reset();
        if(DEBUG) {
            System.out.println("reset from "+count+" to "+markpos);
        }
        count = markpos;
    }

    @Override
    public long skip(long count) throws IOException {
        this.count += count;
        if(DEBUG) {
            System.out.println("skipped "+count+", now at "+this.count);
        }
        return source.skip(count);
    }

    public int getNumRead() {
        return count;
    }

    public void resetNumRead() {
        count = 0;
        markpos = 0;
        if(DEBUG) {
            System.out.println("resetting count to 0");
        }
    }
}
