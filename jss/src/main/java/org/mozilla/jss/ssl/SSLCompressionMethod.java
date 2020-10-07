package org.mozilla.jss.ssl;

public enum SSLCompressionMethod {
    NULL (0),
    DEFLATE (1);

    private int value;

    private SSLCompressionMethod(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static SSLCompressionMethod valueOf(int value) {
        for (SSLCompressionMethod method : SSLCompressionMethod.values()) {
            if (method.value == value) {
                return method;
            }
        }

        return null;
    }
}
