package org.mozilla.jss.ssl.javax;

import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.nss.PR;
import org.mozilla.jss.nss.PRFDProxy;
import org.mozilla.jss.nss.SSL;
import org.mozilla.jss.nss.SSLFDProxy;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.pkcs11.PK11PrivKey;
import org.mozilla.jss.tests.FilePasswordCallback;
import org.mozilla.jss.util.GlobalRefProxy;

/** Native regression test; run by CTest with an NSS database and two certificates. */
public class TestJSSEngineServerTemplate {

    private static final int CACHE_LIMIT = 2;
    private static final int TIMEOUT_SECONDS = 10;
    private static CryptoManager manager;

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    /** Resolve fresh certificate and key proxies to catch identity-based cache misses. */
    private static SSLFDProxy template(String... aliases) throws Exception {
        return template(new HashMap<>(), false, aliases);
    }

    private static SSLFDProxy template(
            HashMap<PK11Cert, PK11PrivKey> keys, boolean useProductionLookup, String... aliases)
            throws Exception {
        List<PK11Cert> certs = new ArrayList<>();
        try {
            for (String alias : aliases) {
                PK11Cert cert = (PK11Cert) manager.findCertByNickname(alias);
                PK11PrivKey key = (PK11PrivKey) manager.findPrivKeyByCert(cert);
                certs.add(cert);
                keys.put(cert, key);
            }
            return useProductionLookup
                    ? JSSEngine.getServerTemplate(certs, keys)
                    : JSSEngine.getServerTemplate(certs, keys, CACHE_LIMIT);
        } finally {
            for (PK11PrivKey key : keys.values()) {
                // Match JSSEngineReferenceImpl.initServer()'s key workaround.
                key.setTemporary(false);
                key.close();
            }
        }
    }

    private static void importTemplate(SSLFDProxy model) throws Exception {
        try (PRFDProxy raw = PR.NewTCPSocket()) {
            check(raw != null, "Unable to create socket: " + PR.GetError());
            try (SSLFDProxy connection = SSL.ImportFD(model, raw)) {
                SSL.OptionGet(connection, SSL.REQUEST_CERTIFICATE);
            }
        }
    }

    private static void testSuccessfulInitialization(String alias) throws Exception {
        try (PK11Cert cert = (PK11Cert) manager.findCertByNickname(alias);
             PK11PrivKey key = (PK11PrivKey) manager.findPrivKeyByCert(cert);
             PRFDProxy raw = PR.NewTCPSocket()) {
            key.setTemporary(false);
            check(raw != null, "Unable to create socket: " + PR.GetError());
            try (SSLFDProxy model = SSL.ImportFD(null, raw);
                 GlobalRefProxy reference = model.globalRef) {
                SSLFDProxy configured = JSSEngine.configureServerTemplate(model, List.of(cert), Map.of(cert, key));
                check(configured == model, "Initialization returned a different model");
                check(!model.isNull(), "Successful initialization closed the model");
                check(model.globalRef == null, "Template retained its JNI self-reference");
                check(reference.isNull(), "Template detached its JNI reference without closing it");
                importTemplate(model);
            }
        }
    }

    private static void testFailedInitialization(String alias, Throwable failure) throws Exception {
        try (PK11Cert cert = (PK11Cert) manager.findCertByNickname(alias)) {
            var keys = new HashMap<PK11Cert, PK11PrivKey>() {
                @Override
                public PK11PrivKey get(Object ignored) {
                    if (failure instanceof Error) {
                        throw (Error) failure;
                    }
                    throw (RuntimeException) failure;
                }
            };
            try (PRFDProxy raw = PR.NewTCPSocket()) {
                check(raw != null, "Unable to create socket: " + PR.GetError());
                try (SSLFDProxy model = SSL.ImportFD(null, raw);
                     GlobalRefProxy reference = model.globalRef) {
                    try {
                        JSSEngine.configureServerTemplate(model, List.of(cert), keys);
                        throw new AssertionError("Expected template initialization to fail");
                    } catch (Throwable actual) {
                        check(actual == failure, "Cleanup replaced the original failure");
                    }
                    // Check before try-with-resources performs its own cleanup.
                    check(model.isNull(), "Failed template was not closed");
                    check(model.globalRef == null, "Failed template retained its JNI reference");
                    check(reference.isNull(), "Failed template did not close its JNI reference");
                }
            }
        }
    }

    private static void testReuse(String alias) throws Exception {
        JSSEngine.serverTemplates.clear();
        SSLFDProxy model = template(alias);
        check(model.globalRef == null, "A cached template must not retain a JNI self-reference");
        for (int i = 0; i < 3; i++) {
            check(template(alias) == model, "Fresh certificate or private-key proxies caused a cache miss");
        }
        check(JSSEngine.serverTemplates.size() == 1, "Repeated connections grew the cache");
        importTemplate(model);
    }

    private static void testFailedLookup(String alias) throws Exception {
        JSSEngine.serverTemplates.clear();
        try (PK11Cert cert = (PK11Cert) manager.findCertByNickname(alias)) {
            try {
                JSSEngine.getServerTemplate(List.of(cert), Map.of());
                throw new AssertionError("Expected a missing private key to fail initialization");
            } catch (IllegalArgumentException expected) {
                check(JSSEngine.serverTemplates.isEmpty(), "Failed lookup cached an incomplete template");
            }
            SSLFDProxy model = template(alias);
            check(template(alias) == model, "Failed lookup prevented a later valid template from being cached");
            importTemplate(model);
        }
    }

    private static void testCacheKeySnapshot(String first, String second) throws Exception {
        JSSEngine.serverTemplates.clear();
        try (PK11Cert firstCert = (PK11Cert) manager.findCertByNickname(first);
             PK11Cert secondCert = (PK11Cert) manager.findCertByNickname(second);
             PK11PrivKey firstKey = (PK11PrivKey) manager.findPrivKeyByCert(firstCert);
             PK11PrivKey secondKey = (PK11PrivKey) manager.findPrivKeyByCert(secondCert)) {
            firstKey.setTemporary(false);
            secondKey.setTemporary(false);
            Map<PK11Cert, PK11PrivKey> keys = Map.of(firstCert, firstKey, secondCert, secondKey);
            List<PK11Cert> certs = new ArrayList<>(List.of(firstCert));
            try {
                // Exercise the production entry point as well as the smaller test limit.
                SSLFDProxy single = JSSEngine.getServerTemplate(certs, keys);
                certs.add(secondCert);
                check(template(first) == single, "Changing the caller's list damaged the cached key");
                SSLFDProxy combined = JSSEngine.getServerTemplate(certs, keys);
                check(combined != single, "Different certificate configurations shared a template");
                certs.clear();
                check(template(first) == single, "Clearing the caller's list damaged the single-certificate key");
                check(template(first, second) == combined, "Clearing the caller's list damaged the multi-certificate key");
                check(JSSEngine.serverTemplates.size() == 2, "Changing the caller's list grew the cache");
            } finally {
                // Remove keys before closing the certificate proxies they contain.
                JSSEngine.serverTemplates.clear();
            }
        }
    }

    private static void testOverflowAndCertificateOrder(String first, String second) throws Exception {
        JSSEngine.serverTemplates.clear();
        SSLFDProxy held = template(first);
        SSLFDProxy secondTemplate = template(second);
        check(JSSEngine.serverTemplates.size() == CACHE_LIMIT, "Cache cleared before exceeding its limit");

        // A third configuration resets the cache and retains its template.
        SSLFDProxy ordered = template(first, second);
        check(JSSEngine.serverTemplates.size() == 1, "Expected only the current template after the reset");
        check(template(first, second) == ordered, "Reset forced the current template to be recreated");
        check(!JSSEngine.serverTemplates.containsValue(held), "Cache retained the first template");
        check(!JSSEngine.serverTemplates.containsValue(secondTemplate), "Cache retained the second template");

        // Retain both certificate orders together so a reset cannot mask a bad key.
        SSLFDProxy reversed = template(second, first);
        check(reversed != ordered, "Reversed certificate order reused the same template");
        check(template(first, second) == ordered, "Ordered certificates were not cached");
        check(template(second, first) == reversed, "Reversed certificates were not cached");
        check(JSSEngine.serverTemplates.size() == CACHE_LIMIT, "Unexpected cache size after resetting");

        // Clearing must not close a model that a caller has yet to import.
        check(!held.isNull(), "Clearing closed a template still held by a caller");
        importTemplate(held);
        importTemplate(secondTemplate);
        importTemplate(ordered);
        importTemplate(reversed);
    }

    private static void testCacheHitDuringCreation(String first, String second) throws Exception {
        JSSEngine.serverTemplates.clear();
        // Use the production entry point to catch synchronization in its wrapper too.
        SSLFDProxy cached = template(new HashMap<>(), true, first);
        var creating = new CountDownLatch(1);
        var finishCreation = new CountDownLatch(1);
        var keys = new HashMap<PK11Cert, PK11PrivKey>() {
            @Override
            public PK11PrivKey get(Object cert) {
                creating.countDown();
                try {
                    // The test releases this latch in finally, even if the hit times out.
                    finishCreation.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException("Template creation interrupted", e);
                }
                return super.get(cert);
            }
        };
        var miss = new FutureTask<SSLFDProxy>(() -> template(keys, true, second));
        var hit = new FutureTask<SSLFDProxy>(() -> template(new HashMap<>(), true, first));
        Thread creator = new Thread(miss, "template-creating");
        Thread reader = new Thread(hit, "template-cached-reader");
        try {
            creator.start();
            check(creating.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "Miss did not reach template initialization");
            reader.start();
            try {
                check(hit.get(TIMEOUT_SECONDS, TimeUnit.SECONDS) == cached, "Cache hit returned a different model");
            } catch (TimeoutException e) {
                throw new AssertionError("Cache hit waited for unrelated template creation", e);
            }
            finishCreation.countDown();
            SSLFDProxy created = miss.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            check(template(new HashMap<>(), true, second) == created, "Miss did not retain its template");
            importTemplate(cached);
            importTemplate(created);
        } finally {
            finishCreation.countDown();
            miss.cancel(true);
            hit.cancel(true);
            creator.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
            reader.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
        }
    }

    /** Wait until a lookup is blocked on the cache's miss coordination lock. */
    private static void awaitCacheLock(Thread worker) throws Exception {
        var threads = ManagementFactory.getThreadMXBean();
        int cacheLock = System.identityHashCode(JSSEngine.serverTemplates);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(TIMEOUT_SECONDS);
        while (System.nanoTime() < deadline) {
            var info = threads.getThreadInfo(worker.getId());
            if (info != null && info.getThreadState() == Thread.State.BLOCKED
                    && info.getLockInfo() != null
                    && info.getLockInfo().getIdentityHashCode() == cacheLock) {
                return;
            }
            check(worker.isAlive(), "Lookup exited before reaching the cache lock");
            Thread.sleep(10);
        }
        throw new AssertionError("Lookup did not reach the cache lock");
    }

    private static void testConcurrentOverflow(String first, String second) throws Exception {
        JSSEngine.serverTemplates.clear();
        template(first);
        template(second);

        var ordered = new FutureTask<SSLFDProxy>(() -> template(first, second));
        var reversed = new FutureTask<SSLFDProxy>(() -> template(second, first));
        Thread firstWorker = new Thread(ordered, "template-overflow-ordered");
        Thread secondWorker = new Thread(reversed, "template-overflow-reversed");
        try {
            synchronized (JSSEngine.serverTemplates) {
                firstWorker.start();
                secondWorker.start();
                // Both misses must reach the lock before either can reset the
                // full cache. Inserting before this lock loses the second entry.
                awaitCacheLock(firstWorker);
                awaitCacheLock(secondWorker);
            }

            SSLFDProxy firstModel = ordered.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            SSLFDProxy secondModel = reversed.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            check(JSSEngine.serverTemplates.size() == CACHE_LIMIT, "Concurrent overflow lost a new template");
            check(template(first, second) == firstModel, "Ordered template was recreated after concurrent overflow");
            check(template(second, first) == secondModel, "Reversed template was recreated after concurrent overflow");
            importTemplate(firstModel);
            importTemplate(secondModel);
        } finally {
            ordered.cancel(true);
            reversed.cancel(true);
            firstWorker.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
            secondWorker.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
        }
    }

    private static void testConcurrentImports(String first, String second) throws Exception {
        JSSEngine.serverTemplates.clear();
        String[][] choices = {{first}, {second}, {first, second}, {second, first}};
        var executor = Executors.newFixedThreadPool(8);
        try {
            List<Callable<Void>> jobs = new ArrayList<>();
            // Exercise imports while other lookups may clear the shared cache.
            for (int i = 0; i < 64; i++) {
                String[] aliases = choices[i % choices.length];
                jobs.add(() -> {
                    importTemplate(template(aliases));
                    return null;
                });
            }
            for (var result : executor.invokeAll(jobs, 30, TimeUnit.SECONDS)) {
                check(!result.isCancelled(), "Concurrent template imports timed out");
                result.get();
            }
        } finally {
            executor.shutdownNow();
        }
        check(JSSEngine.serverTemplates.size() <= CACHE_LIMIT, "Concurrent lookups exceeded cache capacity");
    }

    public static void main(String[] args) throws Exception {
        // args: database, password file, first certificate, second certificate
        CryptoManager.initialize(args[0]);
        manager = CryptoManager.getInstance();
        manager.setPasswordCallback(new FilePasswordCallback(args[1]));

        try {
            testSuccessfulInitialization(args[2]);
            testFailedInitialization(args[2], new AssertionError("Injected initialization error"));
            testFailedInitialization(args[2], new IllegalArgumentException("Injected initialization exception"));
            testReuse(args[2]);
            testFailedLookup(args[2]);
            testCacheKeySnapshot(args[2], args[3]);
            testOverflowAndCertificateOrder(args[2], args[3]);
            testCacheHitDuringCreation(args[2], args[3]);
            testConcurrentOverflow(args[2], args[3]);
            testConcurrentImports(args[2], args[3]);
        } finally {
            JSSEngine.serverTemplates.clear();
        }
        System.out.println("Server template reuse, key snapshots, concurrent hits, overflow, and native cleanup passed");
    }
}
