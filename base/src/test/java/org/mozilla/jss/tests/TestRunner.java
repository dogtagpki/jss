/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.tests;

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;

import java.io.FileNotFoundException;
import java.io.PrintWriter;

import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.junit.platform.launcher.listeners.TestExecutionSummary;

public class TestRunner {

    SummaryGeneratingListener listener = new SummaryGeneratingListener();
    public void test(String className) throws FileNotFoundException {
        LauncherDiscoveryRequest request = LauncherDiscoveryRequestBuilder.request()
                .selectors(selectClass(className))
                .build();
              Launcher launcher = LauncherFactory.create();
              launcher.registerTestExecutionListeners(listener);
              launcher.execute(request);
    }
    public static void main(String[] args)  throws FileNotFoundException {
        TestRunner runner = new TestRunner();
        runner.test(args[0]);

        TestExecutionSummary summary = runner.listener.getSummary();
        summary.printTo(new PrintWriter(System.out));
        summary.printFailuresTo(new PrintWriter(System.out));

        if(summary.getTotalFailureCount() > 0)
            System.exit(1);
    }
}
