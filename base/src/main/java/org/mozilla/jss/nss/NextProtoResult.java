package org.mozilla.jss.nss;
import java.nio.charset.StandardCharsets;
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
    private final String decodedProtocol;

    public NextProtoResult(int state_value, byte[] protocol) {
        state = SSLNextProtoState.valueOf(state_value);
        this.protocol = protocol;
        this.decodedProtocol = (protocol == null) ? null : new String(protocol, StandardCharsets.UTF_8);
    }

    public String getProtocol() {
        return decodedProtocol;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("State: " + state + "\n");
        sb.append("Protocol: " + getProtocol() + " ");
        sb.append(Arrays.toString(protocol) + "\n");
        return sb.toString();
    }
}
