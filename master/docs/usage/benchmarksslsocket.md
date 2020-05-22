# Usage

This benchmark is a server-side SSLSocket benchmark for use with clients
which measure performance. This benchmark does not, itself, make any
performance measurements. For instance:

```bash
$ ./run_test.sh org.mozilla.jss.tests.BenchmarkSSLSocket JSS.legacy Server_RSA 8443 1024 &
$ siege -c 100 -b -t 5m https://localhost:8443
$ kill %1
```

There are three supported SSLSocket implementations:

 1. `org.mozilla.jss.ssl.SSLSocket`, JSS's legacy implementation
    name: `JSS.legacy`
 2. `org.mozilla.jss.ssl.javax.JSSSocket`, JSS's new javax implementation
    name: `JSS.SSLSocket`
 3. `sun.security`'s `SSLSocketImpl` from the current JDK.
    name: `SunJSSE.SSLSocket`

It is suggested to disable all logging (for instance, via:
`truncate -s 0 tools/logging.properties`) in order have reproducible
results.

This class takes four arguments when invoked:

 1. The name of the implementation to benchmark, see above.
 2. An alias of the certificate or path to a PKCS#12 file. Only SunJSSE
    accepts a PKCS#12 as path -- the two JSS based SSLSocket
    implementations will utilize a nickname instead.
 3. The port to listen on.
 4. The size of the HTTP message to fake.

Note that, when utilizing a JSS provider, JSS must be loaded via a
java.security. When utilizing SunJSSE, for best results, do not load
JSS via java.security.

It is suggested to use `run_test.sh` from the `build/` directory for
executing this utility.

# Past Performance

## `JSSEngineReferenceImpl`


These are the results from siege [0] as run via:

```bash
 $ siege -c 100 -b -t 5m https://localhost:8443
```

with the benchmarker set to send a faked 1024-byte message:

```bash
 $ ./run_test.sh org.mozilla.jss.tests.BenchmarkSSLSocket JSS.legacy Server_RSA 8443 1024
```

The server certificate is 4096-bits. The selection of cipher suite and
protocol is left at their defaults. This is on a Lenovo Thinkpad P50
with an `Intel(R) Core(TM) i7-6820HQ CPU @ 2.70GHz` processor and 32GB of RAM.
Each request gets spun off and handled by a new thread.


Using the legacy `org.mozilla.jss.ssl.SSLSocket` (old NSS-based socket)
memory stays stable and under ~1-2% of total memory:

```json
{
        "transactions":                        98588,
        "availability":                        100.00,
        "elapsed_time":                        299.43,
        "data_transferred":                    96.28,
        "response_time":                       0.30,
        "transaction_rate":                    329.25,
        "throughput":                          0.32,
        "concurrency":                         99.80,
        "successful_transactions":             98588,
        "failed_transactions":                 0,
        "longest_transaction":                 29.94,
        "shortest_transaction":                0.04
}
```


Using `javax.net.ssl.SSLSocket` provided by SunJSSE (but with JSS crypto
and potentially random) and stays under 1-2% of total memory:

```json
{
        "transactions":                        2417,
        "availability":                        100.00,
        "elapsed_time":                        299.36,
        "data_transferred":                    2.36,
        "response_time":                       12.12,
        "transaction_rate":                    8.07,
        "throughput":                          0.01,
        "concurrency":                         97.82,
        "successful_transactions":             2417,
        "failed_transactions":                 0,
        "longest_transaction":                 21.27,
        "shortest_transaction":                1.63
}
```

**Note** that the above option was removed from the benchmark utility as it
was significantly slower.


Using `javax.net.ssl.SSLSocket` provided by SunJSSE (without JSS crypto,
via exporting to PKCS12 file) and stays under 8% of total memory:

```json
{
        "transactions":                        93168,
        "availability":                        100.00,
        "elapsed_time":                        299.92,
        "data_transferred":                    90.98,
        "response_time":                       0.32,
        "transaction_rate":                    310.64,
        "throughput":                          0.30,
        "concurrency":                         99.51,
        "successful_transactions":             93168,
        "failed_transactions":                 2,
        "longest_transaction":                 15.81,
        "shortest_transaction":                0.02
}
```


And `javax.net.ssl.SSLSocket` provided by Mozilla-JSS, backed by our slow
JSSEngine (proposed for 8.3) -- memory grows to ~35% of total, which suggests
there's also at least one memory leak still...

```json
{
        "transactions":                        87768,
        "availability":                        100.00,
        "elapsed_time":                        299.08,
        "data_transferred":                    85.71,
        "response_time":                       0.34,
        "transaction_rate":                    293.46,
        "throughput":                          0.29,
        "concurrency":                         99.60,
        "successful_transactions":             87768,
        "failed_transactions":                 1,
        "longest_transaction":                 16.05,
        "shortest_transaction":                0.08
}
```


Prior to jss-pr#553 (commit 1bd646a45613d16f18f28c641381f680ba1df319), the
performance of Mozilla-JSS's `SSLSocket` was similar to
`javax.net.ssl.SSLSoket` using `Mozilla-JSS` for primitives:

```json
{
        "transactions":                        1551,
        "availability":                        85.98,
        "elapsed_time":                        299.53,
        "data_transferred":                    1.51,
        "response_time":                       13.02,
        "transaction_rate":                    5.18,
        "throughput":                          0.01,
        "concurrency":                         67.42,
        "successful_transactions":             1551,
        "failed_transactions":                 253,
        "longest_transaction":                 78.01,
        "shortest_transaction":                0.50
}
```


And for comparison, `nginx-1.18.0-1.fc32.x86_64`, using the same cert from
above (admittedly, it uses OpenSSL and an `epoll` framework) and same `siege`
output:

```json
{
        "transactions":                        214725,
        "availability":                        100.00,
        "elapsed_time":                        299.05,
        "data_transferred":                    209.90,
        "response_time":                       0.14,
        "transaction_rate":                    718.02,
        "throughput":                          0.70,
        "concurrency":                         99.40,
        "successful_transactions":             214725,
        "failed_transactions":                 0,
        "longest_transaction":                 0.37,
        "shortest_transaction":                0.07
}
```
