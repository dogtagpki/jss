package org.mozilla.jss.tests;

import org.mozilla.jss.nss.Buffer;
import org.mozilla.jss.nss.BufferProxy;

public class TestBuffer {
    public static void TestCreateFree() {
        BufferProxy buf = Buffer.Create(100);
        assert(buf != null);
        Buffer.Free(buf);
    }

    public static void TestReadWrite() {
        BufferProxy buf = Buffer.Create(10);
        byte[] data = { 0x01, 0x00, 0x02, 0x03 };
        assert(buf != null);

        assert(Buffer.Write(buf, data) == 4);

        byte[] out_data = Buffer.Read(buf, 4);
        assert(out_data.length == 4);
        assert(out_data[0] == data[0]);
        assert(out_data[1] == data[1]);
        assert(out_data[2] == data[2]);
        assert(out_data[3] == data[3]);

        Buffer.Free(buf);
    }

    public static void TestCapacities() {
        BufferProxy buf = Buffer.Create(6);
        byte[] data = {0x00, 0x01, 0x02};

        assert(buf != null);
        assert(Buffer.Capacity(buf) == 6);
        assert(Buffer.ReadCapacity(buf) == 0);
        assert(Buffer.WriteCapacity(buf) == 6);
        assert(!Buffer.CanRead(buf));
        assert(Buffer.CanWrite(buf));

        assert(Buffer.Write(buf, data) == data.length);
        assert(Buffer.CanRead(buf));
        assert(Buffer.CanWrite(buf));
        assert(Buffer.ReadCapacity(buf) == 3);
        assert(Buffer.WriteCapacity(buf) == 3);

        assert(Buffer.Write(buf, data) == data.length);
        assert(Buffer.CanRead(buf));
        assert(!Buffer.CanWrite(buf));
        assert(Buffer.ReadCapacity(buf) == 6);
        assert(Buffer.WriteCapacity(buf) == 0);

        Buffer.Free(buf);
    }

    public static void TestPutGet() {
        BufferProxy buf = Buffer.Create(2);
        assert(buf != null);

        assert(Buffer.Put(buf, (byte) 0x00) == 0x00);
        assert(Buffer.Get(buf) == 0x00);
        assert(Buffer.Get(buf) == -1);

        assert(Buffer.Put(buf, (byte) 0x01) == 0x01);
        assert(Buffer.Put(buf, (byte) 0x02) == 0x02);
        assert(Buffer.Put(buf, (byte) 0x03) == -1);
        assert(Buffer.Get(buf) == 0x01);
        assert(Buffer.Get(buf) == 0x02);
        assert(Buffer.Get(buf) == -1);

        Buffer.Free(buf);
    }

    public static void main(String[] args) {
        System.loadLibrary("jss4");

        System.out.println("Calling TestCreateFree()...");
        TestCreateFree();

        System.out.println("Calling TestReadWrite()...");
        TestReadWrite();

        System.out.println("Calling TestCapacities()...");
        TestCapacities();

        System.out.println("Calling TestPutGet()...");
        TestPutGet();
    }
}
