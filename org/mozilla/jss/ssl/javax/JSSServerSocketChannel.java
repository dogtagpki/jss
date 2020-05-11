package org.mozilla.jss.ssl.javax;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.security.*;
import java.util.*;

import javax.net.ssl.*;

public class JSSServerSocketChannel extends ServerSocketChannel {
    private JSSServerSocket sslSocket;
    private ServerSocketChannel parent;
    private ServerSocket parentSocket;
    private JSSEngine engine;

    public JSSServerSocketChannel(JSSServerSocket sslSocket, ServerSocketChannel parent, JSSEngine engine) throws IOException {
        super(null);

        this.sslSocket = sslSocket;
        this.parent = parent;
        this.parentSocket = parent.socket();
        this.engine = engine;

        // Copy blocking mode from the parent channel.
        configureBlocking(parent.isBlocking());
    }

    public JSSServerSocketChannel(JSSServerSocket sslSocket, ServerSocket parentSocket, JSSEngine engine) throws IOException {
        super(null);

        this.sslSocket = sslSocket;
        this.parentSocket = parentSocket;
        this.engine = engine;

        // When there is no parent channel, the channel must be in
        // blocking mode.
        configureBlocking(false);
    }

    public JSSSocketChannel accept() throws IOException {
        if (parent == null) {
            String msg = "Unable to accept() on a JSSServerSocketChannel ";
            msg += "which wraps a blocking ServerSocket lacking a channel.";
            throw new IOException(msg);
        }

        SocketChannel acceptedChannel = parent.accept();
        if (acceptedChannel == null) {
            return null;
        }

        Socket acceptedSocket = acceptedChannel.socket();
        JSSSocket sslAcceptedSocket = sslSocket.acceptSocket(acceptedSocket);
        return sslAcceptedSocket.getChannel();
    }

    public JSSServerSocketChannel bind(SocketAddress local, int backlog) throws IOException {
        if (parent == null) {
            parentSocket.bind(local, backlog);
            return this;
        }

        parent.bind(local, backlog);
        return this;
    }

    public <T> T getOption(SocketOption<T> name) throws IOException {
        if (parent == null) {
            return null;
        }

        return parent.getOption(name);
    }

    public Set<SocketOption<?>> supportedOptions() {
        if (parent == null) {
            return null;
        }

        return parent.supportedOptions();
    }

    public <T> JSSServerSocketChannel setOption(SocketOption<T> name, T value) throws IOException {
        if (parent != null) {
            parent.setOption(name, value);
        }

        return this;
    }

    public JSSServerSocket socket() {
        return sslSocket;
    }

    public SocketAddress getLocalAddress() throws IOException {
        if (parent == null) {
            return parentSocket.getLocalSocketAddress();
        }

        return parent.getLocalAddress();
    }

    public void implCloseSelectableChannel() throws IOException {
        engine.cleanup();
        engine = null;

        if (parent == null) {
            parentSocket.close();
            return;
        }

        parent.close();
    }

    public void implConfigureBlocking(boolean block) throws IOException {
        if (parent == null) {
            return;
        }

        parent.configureBlocking(block);
    }
}
