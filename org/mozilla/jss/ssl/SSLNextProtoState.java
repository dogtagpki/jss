package org.mozilla.jss.ssl;

public enum SSLNextProtoState {
    SSL_NEXT_PROTO_NO_SUPPORT (0),
    SSL_NEXT_PROTO_NEGOTIATED (1),
    SSL_NEXT_PROTO_NO_OVERLAP (2),
    SSL_NEXT_PROTO_SELECTED (3),
    SSL_NEXT_PROTO_EARLY_VALUE (4);

    private int value;

    private SSLNextProtoState(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static SSLNextProtoState valueOf(int value) {
        for (SSLNextProtoState type : SSLNextProtoState.values()) {
            if (type.value == value) {
                return type;
            }
        }

        return null;
    }
}
