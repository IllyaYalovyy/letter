string fixture (string name) {
    return Path.build_filename (Environment.get_variable ("TEST_TLS_CERT_DIR"), name);
}

Bytes fixture_bytes (string name) throws Error {
    uint8[] bytes;
    FileUtils.get_data (fixture (name), out bytes);
    return new Bytes (bytes);
}

void expect (bool condition, string reason) {
    if (!condition)
        error ("%s", reason);
}

bool verifies (Mail.TlsImageFetcher fetcher, TlsCertificate leaf, Bytes issuer, string host) {
    var loop = new MainLoop ();
    var valid = false;
    fetcher.verifies.begin (leaf, issuer, host, 443, null, (obj, result) => {
        valid = fetcher.verifies.end (result);
        loop.quit ();
    });
    loop.run ();
    return valid;
}

void test_download_limits () {
    var loop = new MainLoop ();
    var cancellable = new Cancellable ();
    Mail.TlsImageFetcher.read_limited.begin (new MemoryInputStream.from_bytes (new Bytes ("1234".data)), 4, cancellable, (obj, result) => {
        try {
            expect (Mail.TlsImageFetcher.read_limited.end (result).get_size () == 4, "exact download limit is allowed");
        } catch (Error e) {
            error ("bounded read failed: %s", e.message);
        }
        loop.quit ();
    });
    loop.run ();
    Mail.TlsImageFetcher.read_limited.begin (new MemoryInputStream.from_bytes (new Bytes ("12345".data)), 4, cancellable, (obj, result) => {
        try {
            Mail.TlsImageFetcher.read_limited.end (result);
            error ("oversized download was accepted");
        } catch (Error e) {
            expect (e is IOError.NO_SPACE, "oversized download is rejected");
        }
        loop.quit ();
    });
    loop.run ();
    cancellable.cancel ();
    Mail.TlsImageFetcher.read_limited.begin (new MemoryInputStream.from_bytes (new Bytes ("1234".data)), 4, cancellable, (obj, result) => {
        try {
            Mail.TlsImageFetcher.read_limited.end (result);
            error ("cancelled download was accepted");
        } catch (Error e) {
            expect (e is IOError.CANCELLED, "download cancellation is honored");
        }
        loop.quit ();
    });
    loop.run ();
}

void test_proxy_is_not_bypassed () {
    var fetcher = new Mail.TlsImageFetcher (null, new SimpleProxyResolver ("http://127.0.0.1:9", null));
    var loop = new MainLoop ();
    fetcher.fetch_issuer.begin ("http://issuer.example.test/intermediate.der", new Cancellable (), (obj, result) => {
        try {
            fetcher.fetch_issuer.end (result);
            error ("certificate download bypassed the proxy");
        } catch (Error e) {
            expect (e is IOError.NOT_SUPPORTED, "proxy refusal occurs before DNS or network access");
        }
        loop.quit ();
    });
    loop.run ();
}

void test_fetch_requires_https () {
    var fetcher = new Mail.TlsImageFetcher ();
    var loop = new MainLoop ();
    foreach (var url in new string[] { "http://127.0.0.1:9/image.png", "file:///etc/passwd", "https://user:password@127.0.0.1:9/image.png" }) {
        fetcher.fetch.begin (url, new Cancellable (), 1024, (obj, result) => {
            try {
                string mime;
                fetcher.fetch.end (result, out mime);
                error ("unsafe image URL was accepted");
            } catch (Error e) {
                expect (e is IOError.INVALID_ARGUMENT, "unsafe image URL is rejected before network access");
            }
            loop.quit ();
        });
        loop.run ();
    }
    var cancelled = new Cancellable ();
    cancelled.cancel ();
    fetcher.fetch.begin ("https://127.0.0.1:9/image.png", cancelled, 1024, (obj, result) => {
        try {
            string mime;
            fetcher.fetch.end (result, out mime);
            error ("cancelled image fetch was accepted");
        } catch (Error e) {
            expect (e is IOError.CANCELLED, "image fetch cancellation is honored");
        }
        loop.quit ();
    });
    loop.run ();
}

void main () {
    test_download_limits ();
    test_proxy_is_not_bypassed ();
    test_fetch_requires_https ();
    try {
        var database = TlsFileDatabase.@new (fixture ("root.pem"));
        var fetcher = new Mail.TlsImageFetcher (database);
        var leaf = new TlsCertificate.from_file (fixture ("leaf.pem"));
        var issuer = fixture_bytes ("issuer.pem");
        var missing = database.verify_chain (
            leaf, TlsDatabase.PURPOSE_AUTHENTICATE_SERVER,
            new NetworkAddress ("images.example.test", 443), null, TlsDatabaseVerifyFlags.NONE, null
        );
        expect ((missing & TlsCertificateFlags.UNKNOWN_CA) != 0, "missing intermediate is rejected");
        expect (verifies (fetcher, leaf, issuer, "images.example.test"), "PEM intermediate completes a trusted chain");
        expect (verifies (fetcher, leaf, fixture_bytes ("issuer.der"), "images.example.test"), "DER intermediate completes a trusted chain");
        expect (!verifies (fetcher, leaf, issuer, "wrong.example.test"), "wrong hostname is rejected");
        expect (!verifies (fetcher, new TlsCertificate.from_file (fixture ("expired.pem")), issuer, "images.example.test"), "expired certificate is rejected");
        expect (!verifies (fetcher, leaf, fixture_bytes ("untrusted.pem"), "images.example.test"), "unrelated issuer is rejected");
        expect (!verifies (fetcher, leaf, fixture_bytes ("constrained.pem"), "images.example.test"), "issuer name constraints are enforced");
        expect (!verifies (fetcher, new TlsCertificate.from_file (fixture ("client-only.pem")), issuer, "images.example.test"), "client-only certificate is rejected");
        expect (!verifies (fetcher, leaf, fixture_bytes ("issuer-client-only.pem"), "images.example.test"), "client-only issuer is rejected");
        expect (!verifies (fetcher, new TlsCertificate.from_file (fixture ("wrong-usage.pem")), issuer, "images.example.test"), "invalid server key usage is rejected");
        expect (!verifies (fetcher, leaf, fixture_bytes ("not-ca.pem"), "images.example.test"), "issuer must be a CA");
        var untrusted = new Mail.TlsImageFetcher (TlsFileDatabase.@new (fixture ("untrusted.pem")));
        expect (!verifies (untrusted, leaf, issuer, "images.example.test"), "intermediate does not become a trust anchor");
        expect (!verifies (fetcher, leaf, new Bytes ("invalid".data), "images.example.test"), "malformed issuer is rejected");
        expect (!verifies (fetcher, leaf, new Bytes (new uint8[65537]), "images.example.test"), "oversized issuer is rejected");
        expect (Mail.TlsImageFetcher.issuer_uri (leaf) == "http://issuer.example.test/intermediate.der", "AIA caIssuers URL is extracted");
        expect (Mail.TlsImageFetcher.issuer_uri (new TlsCertificate.from_file (fixture ("root.pem"))) == null, "missing AIA is handled");
        foreach (var address in new string[] {
            "0.0.0.0", "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254",
            "100.64.0.1", "198.18.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "224.0.0.1",
            "::", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "2001:db8::1", "2002:7f00:1::", "2001::7f00:1", "2001:2::1",
        })
            expect (!Mail.TlsImageFetcher.public_address (new InetAddress.from_string (address)), "private issuer address is rejected: " + address);
        foreach (var address in new string[] { "8.8.8.8", "2001:4860:4860::8888" })
            expect (Mail.TlsImageFetcher.public_address (new InetAddress.from_string (address)), "public issuer address is allowed");
        foreach (var uri in new string[] {
            "file:///etc/passwd", "ftp://issuer.example.test/x", "http://127.0.0.1/x",
            "https://issuer.example.test:8443/x", "http://user:password@issuer.example.test/x", "http://issuer.example.test/x#fragment",
        }) {
            var rejected = false;
            try {
                Mail.TlsImageFetcher.parse_issuer_uri (uri);
            } catch (Error e) {
                rejected = true;
            }
            expect (rejected, "invalid issuer URL is rejected");
        }
    } catch (Error e) {
        error ("TLS image fetcher test failed: %s", e.message);
    }
}
