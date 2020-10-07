package org.mozilla.jss.crypto;

import org.mozilla.jss.util.NativeEnclosure;


/**
 * A KBKDF Data Parameter is a structure of type CK_PRF_DATA_PARAM, with
 * three members: a type, a pointer to its data, and the size of the data
 * field.
 */
public abstract class KBKDFDataParameter extends NativeEnclosure {
    public long type;

    public KBKDFDataParameter(long type) {
        this.type = type;
    }
}
