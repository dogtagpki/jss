package org.mozilla.jss.nss;

import java.lang.StringBuilder;
import java.util.Arrays;

import org.mozilla.jss.ssl.SSLNextProtoState;

/**
 * The fields in the NextProtoResult indicate whether a given SSL-enabled
 * PRFileDesc has negotiated a next protocol (via ALPN) and if so, what it
 * is.
 *
 * These object is returned by org.mozilla.jss.nss.SSL.GetNextProto(fd).
 * This is a native method; note that updating the constructor will require
 * modifying util/java_ids.h and nss/SSL.c
 */
public class NextProtoResult {
    public SSLNextProtoState state;
    public byte[] protocol;

    public NextProtoResult(int state_value, byte[] protocol) {
        state = SSLNextProtoState.valueOf(state_value);
        this.protocol = protocol;
    }

    public String getProtocol() {
        if (protocol == null) {
            return null;
        }

        return new String(protocol);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("State: " + state + "\n");
        sb.append("Protocol: " + getProtocol() + " ");
        sb.append(Arrays.toString(protocol) + "\n");
        return sb.toString();
    }
}
