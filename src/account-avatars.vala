/* Profile pictures for the accounts rail (Google + Microsoft 365). */
public class Mail.AccountAvatars : Object {
    private const string GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo";
    private const string MICROSOFT_PHOTO_URL = "https://graph.microsoft.com/v1.0/me/photos/48x48/$value";
    private const int PICTURE_SIZE = 64;

    private Soup.Session session = new Soup.Session ();
    private HashTable<string, Gdk.Texture> pictures = new HashTable<string, Gdk.Texture> (str_hash, str_equal);

    /* The account's picture, or null when it has none or it cannot be fetched. */
    public async Gdk.Texture? load (Goa.Client goa, Account account) {
        var id = account.goa_id;
        if (id == null)
            return null;
        var cached = this.pictures.get (id);
        if (cached != null)
            return cached;

        var oauth = goa.lookup_by_id (id)?.get_oauth2_based ();
        if (oauth == null)
            return null;
        try {
            string token;
            int expires_in;
            yield oauth.call_get_access_token (null, out token, out expires_in);
            Gdk.Texture? picture = null;
            switch (account.kind) {
                case AccountKind.GOOGLE:
                    picture = yield load_google (token);
                    break;
                case AccountKind.MICROSOFT:
                    picture = yield load_microsoft (token);
                    break;
                default:
                    break;
            }
            if (picture != null)
                this.pictures.set (id, picture);
            return picture;
        } catch (Error e) {
            debug ("No account picture for %s: %s", id, e.message);
            return null;
        }
    }

    /* The picture link from a Google userinfo reply, asking for size pixels. */
    public static string? picture_url (Bytes userinfo, int size) {
        if (userinfo.get_size () == 0)
            return null;
        var parser = new Json.Parser ();
        try {
            unowned uint8[] data = userinfo.get_data ();
            parser.load_from_data ((string) data, data.length);
        } catch (Error e) {
            return null;
        }
        var root = parser.get_root ();
        if (root == null || root.get_node_type () != Json.NodeType.OBJECT)
            return null;

        string? picture = root.get_object ().get_string_member_with_default ("picture", "");
        if (picture == null || !picture.has_prefix ("https://"))
            return null;
        var link = picture.split_set ("?#")[0];
        var options = link.last_index_of_char ('=');
        if (options > link.last_index_of_char ('/'))
            link = link.substring (0, options);
        return "%s=s%d-c".printf (link, size);
    }

    private async Gdk.Texture? load_google (string token) throws Error {
        var url = picture_url (yield fetch (GOOGLE_USERINFO_URL, token), PICTURE_SIZE);
        if (url == null)
            return null;
        return Gdk.Texture.from_bytes (yield fetch (url, null));
    }

    private async Gdk.Texture? load_microsoft (string token) throws Error {
        try {
            return Gdk.Texture.from_bytes (yield fetch (MICROSOFT_PHOTO_URL, token));
        } catch (Error e) {
            /* 404 when the account has no photo — initials stay. */
            debug ("No Microsoft photo: %s", e.message);
            return null;
        }
    }

    private async Bytes fetch (string url, string? token) throws Error {
        var message = new Soup.Message ("GET", url);
        if (token != null)
            message.request_headers.append ("Authorization", "Bearer " + token);
        var body = yield this.session.send_and_read_async (message, Priority.DEFAULT, null);
        if (message.status_code != Soup.Status.OK)
            throw new IOError.FAILED ("HTTP %u", message.status_code);
        return body;
    }
}
