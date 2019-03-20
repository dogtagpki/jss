package org.mozilla.jss.tests;

import org.mozilla.jss.nss.Buffer;
import org.mozilla.jss.nss.BufferProxy;
import org.mozilla.jss.nss.PR;
import org.mozilla.jss.nss.PRFDProxy;

public class TestBufferPRFD {
    public static void TestCreateClose() {
        byte[] info = {0x01, 0x02, 0x03, 0x04};
        BufferProxy left_read = Buffer.Create(10);
        BufferProxy right_read = Buffer.Create(10);

        assert(left_read != null);
        assert(right_read != null);

        PRFDProxy left = PR.NewBufferPRFD(left_read, right_read, info);
        PRFDProxy right = PR.NewBufferPRFD(right_read, left_read, info);

        assert(left != null);
        assert(right != null);

        System.err.println(PR.Write(left, info));
        assert(PR.Send(left, info, 0, 0) == 4);
        assert(PR.Send(left, info, 0, 0) == 4);
        assert(PR.Send(left, info, 0, 0) == 2);

        byte[] result = PR.Recv(right, 10, 0, 0);
        assert(result.length == 10);

        for (int i = 0; i < 10; i++) {
            assert(result[i] == info[i % info.length]);
        }

        assert(PR.Close(left) == 0);
        assert(PR.Close(right) == 0);

        Buffer.Free(left_read);
        Buffer.Free(right_read);
    }

    public static void main(String[] args) {
        System.loadLibrary("jss4");

        System.out.println("Calling TestCreateClose()...");
        TestCreateClose();
    }
}
