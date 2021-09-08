package org.mozilla.jss.tests;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.nss.*;

public class TestJByteBuffer {
    public static void TestCapacity() {
        ByteBuffer buffer = ByteBuffer.allocate(10);
        assert buffer.position() == 0;
        assert buffer.limit() == 10;

        ByteBufferProxy proxy = JByteBuffer.Create(false);

        JByteBuffer.SetBuffer(proxy, buffer);
        assert JByteBuffer.Capacity(proxy) == 10;
        JByteBuffer.ClearBuffer(proxy);

        buffer.put((byte) '1');
        assert buffer.position() == 1;
        assert buffer.limit() == 10;

        JByteBuffer.SetBuffer(proxy, buffer);
        assert JByteBuffer.Capacity(proxy) == 9;
        JByteBuffer.ClearBuffer(proxy);

        byte[] array = new byte[20];
        buffer = ByteBuffer.wrap(array, 5, 10);

        assert buffer.position() == 5;
        assert buffer.limit() == 15;
        assert buffer.remaining() == 10;

        JByteBuffer.SetBuffer(proxy, buffer);
        assert JByteBuffer.Capacity(proxy) == 10;
        JByteBuffer.ClearBuffer(proxy);

        buffer.put((byte) '1');
        assert buffer.position() == 6;
        assert buffer.limit() == 15;
        assert buffer.remaining() == 9;

        JByteBuffer.SetBuffer(proxy, buffer);
        assert JByteBuffer.Capacity(proxy) == 9;
        JByteBuffer.ClearBuffer(proxy);
    }

    public static void TestWriting() {
        ByteBuffer buffer = ByteBuffer.allocate(10);
        assert buffer.position() == 0;
        assert buffer.limit() == 10;

        ByteBufferProxy read_proxy = JByteBuffer.Create(false);
        ByteBufferProxy write_proxy = JByteBuffer.Create(true);

        PRFDProxy fd = PR.NewByteBufferPRFD(read_proxy, write_proxy, null);

        JByteBuffer.SetBuffer(write_proxy, buffer);
        assert JByteBuffer.Capacity(write_proxy) == 10;
        byte[] data = new byte[1];
        data[0] = (byte) 1;
        assert PR.Write(fd, data) == 1;
        assert JByteBuffer.Capacity(write_proxy) == 9;
        JByteBuffer.ClearBuffer(write_proxy);
        assert buffer.position() == 1;
        buffer.position(0);
        assert buffer.get() == (byte) 1;
    }

    public static void TestFlipping() {
        ByteBuffer buffer = ByteBuffer.allocate(10);
        assert buffer.position() == 0;
        assert buffer.limit() == 10;

        ByteBufferProxy read_proxy = JByteBuffer.Create(false);
        ByteBufferProxy write_proxy = JByteBuffer.Create(true);

        PRFDProxy fd = PR.NewByteBufferPRFD(read_proxy, write_proxy, null);

        JByteBuffer.SetBuffer(write_proxy, buffer);
        assert JByteBuffer.Capacity(write_proxy) == 10;

        byte[] data = new byte[] {
            (byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5,
            (byte) 6, (byte) 7, (byte) 8, (byte) 9, (byte) 10
        };
        assert PR.Write(fd, data) == 10;

        assert JByteBuffer.Capacity(write_proxy) == 0;
        JByteBuffer.ClearBuffer(write_proxy);
        assert JByteBuffer.Capacity(write_proxy) == 0;

        buffer.flip();

        assert buffer.position() == 0;
        assert buffer.limit() == 10;
        assert buffer.remaining() == 10;

        JByteBuffer.SetBuffer(read_proxy, buffer);
        assert JByteBuffer.Capacity(read_proxy) == 10;

        byte[] other_data = PR.Read(fd, 10);
        assert other_data != null;
        assert other_data.length == data.length;
        assert Arrays.equals(data, other_data);

        assert JByteBuffer.Capacity(read_proxy) == 0;
        JByteBuffer.ClearBuffer(read_proxy);
        assert JByteBuffer.Capacity(read_proxy) == 0;
    }

    public static void main(String[] args) throws Exception {
        CryptoManager.getInstance();

        System.out.println("TestCapacity()...");
        TestCapacity();

        System.out.println("TestWriting()...");
        TestWriting();

        System.out.println("TestFlipping()...");
        TestFlipping();
    }
}
