package org.mozilla.jss.tests;

import org.mozilla.jss.nss.NSS;

public class TestRawNSS {
    public static void TestNSSInitInvalid() {
        String name = "path_which_should_not_exist_on_any_reasonable_system";
        int ret = NSS.Init(name);
        assert(ret != 0);
    }

    public static void TestNSSInitValid(String database) {
        int ret = NSS.Init(database);
        assert(ret == 0);
    }

    public static void main(String[] args) {
        System.loadLibrary("jss4");

        if (args.length != 1) {
            System.out.println("Usage: TestRawNSS /path/to/nssdb");
            System.exit(1);
        }

        System.out.println("Calling TestNSSInitInvalid()...");
        TestNSSInitInvalid();

        System.out.println("Calling TestNSSInitValid()...");
        TestNSSInitValid(args[0]);
    }
}
