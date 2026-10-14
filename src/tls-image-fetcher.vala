public class Mail.TlsImageFetcher : Object {
    internal const size_t MAX_ISSUER_BYTES = 64 * 1024;
    private const size_t MAX_IMAGE_BYTES = 8 * 1024 * 1024;
    private Soup.Session session;
    private ProxyResolver proxy_resolver;
    private HashTable<string, Bytes> issuers = new HashTable<string, Bytes> (str_hash, str_equal);
    private TlsDatabase? database;

    public TlsImageFetcher (TlsDatabase? database = null, ProxyResolver? proxy_resolver = null) {
        this.database = database ?? TlsBackend.get_default ().get_default_database ();
        this.proxy_resolver = proxy_resolver ?? ProxyResolver.get_default ();
        this.session = (Soup.Session) Object.new (
            typeof (Soup.Session), "timeout", 15,
            "tls-database", this.database, "proxy-resolver", this.proxy_resolver
        );
    }

    [CCode (cname = "letter_tls_issuer_uri", cheader_filename = "tls-issuer.h")]
    internal static extern string? issuer_uri (TlsCertificate certificate);

    [CCode (cname = "letter_tls_server_usage", cheader_filename = "tls-issuer.h")]
    private static extern bool server_usage (TlsCertificate certificate);

    internal static TlsCertificate complete_chain (TlsCertificate certificate, Bytes issuer) throws Error {
        if (issuer.get_size () == 0 || issuer.get_size () > MAX_ISSUER_BYTES)
            throw new IOError.INVALID_DATA ("Invalid issuer certificate size");
        unowned uint8[] data = issuer.get_data ();
        var pem = data.length >= 27 && ((string) data).has_prefix ("-----BEGIN CERTIFICATE-----")
            ? "%.*s".printf (data.length, (string) data)
            : "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n".printf (Base64.encode (data));
        return new TlsCertificate.from_pem (certificate.certificate_pem + "\n" + pem, -1);
    }

    internal async bool verifies (TlsCertificate certificate, Bytes issuer, string host, int port = 443, Cancellable? cancellable = null) {
        if (this.database == null)
            return false;
        try {
            var chain = complete_chain (certificate, issuer);
            if (!server_usage (chain))
                return false;
            return (yield this.database.verify_chain_async (
                chain,
                TlsDatabase.PURPOSE_AUTHENTICATE_SERVER,
                new NetworkAddress (host, (uint16) port),
                null, TlsDatabaseVerifyFlags.NONE, cancellable
            )) == 0;
        } catch (Error e) {
            return false;
        }
    }

    internal static bool public_address (InetAddress address) {
        if (address.is_any || address.is_loopback || address.is_link_local || address.is_multicast)
            return false;
        unowned uint8[] bytes = address.to_bytes ();
        if (address.family == SocketFamily.IPV6) {
            if (bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0
                && bytes[4] == 0 && bytes[5] == 0 && bytes[6] == 0 && bytes[7] == 0
                && bytes[8] == 0 && bytes[9] == 0 && bytes[10] == 0xff && bytes[11] == 0xff)
                return public_address (new InetAddress.from_bytes (bytes[12:16], SocketFamily.IPV4));
            return (bytes[0] & 0xe0) == 0x20
                && !(bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] < 2)
                && !(bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8)
                && !(bytes[0] == 0x20 && bytes[1] == 0x02);
        }
        return bytes[0] != 0 && bytes[0] != 10 && bytes[0] != 127 && bytes[0] < 224
            && !(bytes[0] == 169 && bytes[1] == 254)
            && !(bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            && !(bytes[0] == 192 && bytes[1] == 168)
            && !(bytes[0] == 192 && bytes[1] == 0 && (bytes[2] == 0 || bytes[2] == 2))
            && !(bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100)
            && !(bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113)
            && !(bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127)
            && !(bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19));
    }

    internal static Uri parse_issuer_uri (string url) throws Error {
        var uri = Uri.parse (url, UriFlags.NONE);
        var scheme = uri.get_scheme ();
        var host = uri.get_host ();
        if ((scheme != "http" && scheme != "https") || host == null
            || uri.get_userinfo () != null || uri.get_fragment () != null
            || (uri.get_port () != -1 && uri.get_port () != (scheme == "https" ? 443 : 80)))
            throw new IOError.INVALID_ARGUMENT ("Invalid issuer URL");
        var address = new InetAddress.from_string (host);
        if (address != null && !public_address (address))
            throw new IOError.PERMISSION_DENIED ("Issuer URL targets a private address");
        return uri;
    }

    internal async Bytes fetch_issuer (string url, Cancellable cancellable) throws Error {
        var uri = parse_issuer_uri (url);
        var proxies = yield this.proxy_resolver.lookup_async (url, cancellable);
        if (proxies.length == 0 || proxies[0] != "direct://")
            throw new IOError.NOT_SUPPORTED ("Certificate recovery is unavailable through a proxy");
        var addresses = yield Resolver.get_default ().lookup_by_name_async (uri.get_host (), cancellable);
        InetAddress? target = null;
        foreach (var address in addresses) {
            if (!public_address (address))
                throw new IOError.PERMISSION_DENIED ("Issuer host resolves to a private address");
            if (target == null)
                target = address;
        }
        if (target == null)
            throw new IOError.NOT_FOUND ("Issuer host has no address");
        var issuer_session = (Soup.Session) Object.new (
            typeof (Soup.Session), "timeout", 15,
            "remote-connectable", new InetSocketAddress (target, (uint16) (uri.get_scheme () == "https" ? 443 : 80)),
            "proxy-resolver", new SimpleProxyResolver (null, null)
        );
        var message = new Soup.Message.from_uri ("GET", uri);
        message.set_flags (Soup.MessageFlags.NO_REDIRECT);
        var stream = yield issuer_session.send_async (message, Priority.LOW, cancellable);
        try {
            if (message.status_code != Soup.Status.OK)
                throw new IOError.FAILED ("Issuer download failed");
            return yield read_limited (stream, MAX_ISSUER_BYTES, cancellable);
        } finally {
            close_stream (stream);
        }
    }

    internal static async Bytes read_limited (InputStream stream, size_t limit, Cancellable cancellable) throws Error {
        var bytes = new ByteArray ();
        uint8[] buffer = new uint8[16384];
        ssize_t count;
        while ((count = yield stream.read_async (buffer, Priority.LOW, cancellable)) > 0) {
            if (bytes.len + count > limit)
                throw new IOError.NO_SPACE ("Image or issuer exceeds size limit");
            bytes.append (buffer[:count]);
        }
        return ByteArray.free_to_bytes ((owned) bytes);
    }

    private static void close_stream (InputStream stream) {
        stream.close_async.begin (Priority.LOW, null, (obj, result) => {
            try {
                stream.close_async.end (result);
            } catch (Error e) {
            }
        });
    }

    private async InputStream send_image (Uri uri, Cancellable cancellable, out Soup.Message response) throws Error {
        response = new Soup.Message.from_uri ("GET", uri);
        TlsCertificate? verified = null;
        for (int attempt = 0; attempt < 2; attempt++) {
            var message = attempt == 0 ? response : new Soup.Message.from_uri ("GET", uri);
            message.set_flags (Soup.MessageFlags.NO_REDIRECT);
            TlsCertificate? missing = null;
            message.accept_certificate.connect ((certificate, errors) => {
                if (errors != TlsCertificateFlags.UNKNOWN_CA)
                    return false;
                if (verified != null && certificate.is_same (verified))
                    return true;
                missing = certificate;
                return false;
            });
            try {
                var stream = yield this.session.send_async (message, Priority.LOW, cancellable);
                response = message;
                return stream;
            } catch (Error e) {
                if (missing == null || attempt != 0)
                    throw e;
                var source = issuer_uri (missing);
                if (source == null)
                    throw e;
                var issuer = this.issuers.get (source);
                if (issuer == null)
                    issuer = yield fetch_issuer (source, cancellable);
                if (!(yield verifies (missing, issuer, uri.get_host (), uri.get_port () > 0 ? uri.get_port () : 443, cancellable)))
                    throw new IOError.PERMISSION_DENIED ("Recovered certificate chain is not trusted");
                if (this.issuers.size () >= 32)
                    this.issuers.remove_all ();
                this.issuers.set (source, issuer);
                verified = missing;
            }
        }
        throw new IOError.PERMISSION_DENIED ("Image certificate changed during recovery");
    }

    public async Bytes fetch (string url, Cancellable cancellable, size_t limit, out string mime_type) throws Error {
        mime_type = "";
        if (this.database == null)
            throw new IOError.NOT_SUPPORTED ("Image recovery requires a TLS trust database");
        var uri = Uri.parse (url, UriFlags.NONE);
        for (int redirect = 0; redirect < 4; redirect++) {
            if (uri.get_scheme () != "https" || uri.get_host () == null || uri.get_userinfo () != null)
                throw new IOError.INVALID_ARGUMENT ("Image recovery requires HTTPS");
            Soup.Message message;
            var stream = yield send_image (uri, cancellable, out message);
            try {
                if (message.status_code >= 300 && message.status_code < 400) {
                    var location = message.response_headers.get_one ("Location");
                    if (location == null)
                        throw new IOError.INVALID_DATA ("Image redirect has no location");
                    uri = Uri.parse_relative (uri, location, UriFlags.NONE);
                    continue;
                }
                if (message.status_code != Soup.Status.OK)
                    throw new IOError.FAILED ("Image download failed");
                mime_type = (message.response_headers.get_one ("Content-Type") ?? "").split (";")[0].strip ().down ();
                if (!mime_type.has_prefix ("image/"))
                    throw new IOError.INVALID_DATA ("Image response has an invalid content type");
                return yield read_limited (stream, size_t.min (limit, MAX_IMAGE_BYTES), cancellable);
            } finally {
                close_stream (stream);
            }
        }
        throw new IOError.FAILED ("Too many image redirects");
    }
}
