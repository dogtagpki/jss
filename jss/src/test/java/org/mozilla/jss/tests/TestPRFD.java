package org.mozilla.jss.tests;

import org.mozilla.jss.nss.PR;
import org.mozilla.jss.nss.PRErrors;
import org.mozilla.jss.nss.PRFDProxy;

public class TestPRFD {
    public static void TestPROpenNoCreate() {
        String name = "path_which_should_not_exist_on_any_reasonable_system";
        PRFDProxy fd = PR.Open(name, 0x02, 00644);
        assert(fd == null);
    }

    public static void TestPROpenClose() {
        PRFDProxy fd = PR.Open("results/prfd_open_close", 0x04 | 0x08, 00644);
        assert(fd != null);

        assert(PR.Close(fd) == PR.SUCCESS);
    }

    public static void TestPROpenWriteClose() {
        PRFDProxy fd = PR.Open("results/prfd_open_write_close", 0x04 | 0x08, 00644);
        assert(fd != null);

        byte[] data = {0x2a, 0x20, 0x2a, 0x20};
        assert(PR.Write(fd, data) == 4);

        assert(PR.Close(fd) == PR.SUCCESS);
    }

    public static void TestPRRead() {
        byte[] data = {0x2a, 0x20, 0x2a, 0x20};

        PRFDProxy fd = PR.Open("results/prfd_open_write_close", 0x04, 00644);
        assert(fd != null);

        byte[] read_data = PR.Read(fd, 10);
        assert(read_data != null);
        assert(read_data.length == data.length);

        for (int i = 0; i < data.length; i++) {
            assert(read_data[i] == data[i]);
        }

        assert(PR.Close(fd) == PR.SUCCESS);
    }

    public static void TestPREmptyRead() {
        PRFDProxy fd = PR.Open("results/prfd_open_close", 0x04, 00644);
        assert(fd != null);

        byte[] read_data = PR.Read(fd, 10);
        assert(read_data == null || read_data.length == 0);

        assert(PR.Close(fd) == PR.SUCCESS);
    }

    public static void TestNewTCPSocket() {
        PRFDProxy fd = PR.NewTCPSocket();
        assert(fd != null);
    }

    public static void TestShutdown() {
        PRFDProxy fd = PR.NewTCPSocket();
        assert(fd != null);

        PR.Shutdown(fd, PR.SHUTDOWN_RCV);
        PR.Shutdown(fd, PR.SHUTDOWN_SEND);
        PR.Shutdown(fd, PR.SHUTDOWN_BOTH);

        assert(PR.Close(fd) == PR.SUCCESS);
    }

    public static void TestConstants() {
        // Test to ensure constants present
        System.out.println("PR.SHUTDOWN_RCV: " + PR.SHUTDOWN_RCV);
        System.out.println("PR.SHUTDOWN_SEND: " + PR.SHUTDOWN_SEND);
        System.out.println("PR.SHUTDOWN_BOTH: " + PR.SHUTDOWN_BOTH);

        assert(PR.ErrorToName(PRErrors.WOULD_BLOCK_ERROR).equals("PR_WOULD_BLOCK_ERROR"));
    }

    public static void main(String[] args) {
        System.loadLibrary("jss4");

        System.out.println("Calling TestPROpenNoCreate()...");
        TestPROpenNoCreate();

        System.out.println("Calling TestPROpenClose()...");
        TestPROpenClose();

        System.out.println("Calling TestPROpenWriteClose()...");
        TestPROpenWriteClose();

        System.out.println("Calling TestPRRead()...");
        TestPRRead();

        System.out.println("Calling TestPREmptyRead()...");
        TestPREmptyRead();

        System.out.println("Calling TestNewTCPSocket()...");
        TestNewTCPSocket();

        System.out.println("Calling TestShutdown()...");
        TestShutdown();

        System.out.println("Calling TestConstants()...");
        TestConstants();
    }
}
