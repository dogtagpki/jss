/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;


/**
 * A subclass of java.net.SocketException that contains an error code
 * from the native (NSS/NSPR) code. These error codes are defined in the
 * class <code>org.mozilla.jss.util.NativeErrcodes</code>.
 * @see org.mozilla.jss.util.NativeErrcodes
 */
public class SSLSocketException extends java.net.SocketException {

    private static final long serialVersionUID = 1L;
    private int errcode = -1;

    public SSLSocketException() {
        super();
    }

    public SSLSocketException(String msg) {
        super(msg);
    }

    public SSLSocketException(String msg, int errcode) {
        super(msg);
        this.errcode = errcode;
    }

    /**
     * Returns an error code, as defined in class
     * <code>org.mozilla.jss.util.NativeErrcodes</code>.
     * @see org.mozilla.jss.util.NativeErrcodes
     */
    public int getErrcode() {
        return errcode;
    }
}
