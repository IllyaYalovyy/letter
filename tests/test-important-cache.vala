void main () {
    var google = Mail.AccountKind.GOOGLE;
    var important = folder ("Important", "[Gmail]/Important").kind;
    var italiani = folder ("Importanti", "[Gmail]/Importanti").kind;
    var inbox = folder ("Inbox", "INBOX").kind;
    var archive = folder ("Archive", "Archive").kind;
    var starred = folder ("Starred", "[Gmail]/Starred").kind;
    expect (important == Mail.FolderKind.IMPORTANT, "Gmail Important kind");
    expect (italiani == Mail.FolderKind.IMPORTANT, "Gmail Importanti kind");
    expect (archive == Mail.FolderKind.ARCHIVE, "Archive kind");

    expect (
        Mail.HeaderListPolicy.trust_gmail_important_refresh (google, important, true),
        "finished Gmail Important is trusted"
    );
    expect (
        Mail.HeaderListPolicy.trust_gmail_important_refresh (google, italiani, true),
        "finished Gmail Importanti is trusted"
    );
    expect (
        !Mail.HeaderListPolicy.trust_gmail_important_refresh (google, important, false),
        "unfinished Gmail Important is not trusted"
    );
    expect (
        !Mail.HeaderListPolicy.trust_gmail_important_refresh (google, inbox, true),
        "Gmail Inbox is not trusted"
    );
    expect (
        !Mail.HeaderListPolicy.trust_gmail_important_refresh (google, archive, true),
        "Gmail Archive is not trusted"
    );
    expect (
        !Mail.HeaderListPolicy.trust_gmail_important_refresh (google, starred, true),
        "Gmail Starred is not trusted"
    );
    foreach (var kind in new Mail.AccountKind[] {
        Mail.AccountKind.MICROSOFT,
        Mail.AccountKind.EXCHANGE,
        Mail.AccountKind.IMAP,
        Mail.AccountKind.LOCAL,
        Mail.AccountKind.OTHER,
    }) {
        expect (
            !Mail.HeaderListPolicy.trust_gmail_important_refresh (kind, important, true),
            "non-Gmail Important is not trusted"
        );
    }

    /* Drop of 100 or less never reaches the shrink decision. */
    expect (
        !(7700 + Mail.HeaderListPolicy.SHRINK_SLOP < 7773),
        "small Important drop stays outside the shrink guard"
    );
    expect (
        3 + Mail.HeaderListPolicy.SHRINK_SLOP < 7773,
        "large Important drop is catastrophic"
    );

    string reason;
    /* camel_uids_before ≈ previous → finished walk may shrink. */
    const uint CAUGHT_UP = 7773;
    const uint CAMEL_BEHIND = 26;

    expect (
        !Mail.HeaderListPolicy.keep_prior_on_shrink (
            google, important, 7773, 3, true, true, true, CAUGHT_UP, out reason
        ) && reason == "complete Important",
        "finished Gmail Important replaces a large list when Camel is caught up"
    );
    expect (
        Mail.HeaderListPolicy.keep_prior_on_shrink (
            google, important, 7773, 3, true, false, false, CAUGHT_UP, out reason
        ) && reason == "incomplete refresh",
        "interrupted Gmail Important keeps the list"
    );
    expect (
        Mail.HeaderListPolicy.keep_prior_on_shrink (
            google, important, 7773, 3, true, true, false, CAUGHT_UP, out reason
        ) && reason == "large-folder refuse shrink",
        "skipped Gmail Important refresh keeps the list"
    );
    expect (
        Mail.HeaderListPolicy.keep_prior_on_shrink (
            google, important, 7773, 3, false, true, false, CAUGHT_UP, out reason
        ) && reason == "large-folder local refuse shrink",
        "local Important summary keeps the list"
    );
    expect (
        !Mail.HeaderListPolicy.keep_prior_on_shrink (
            Mail.AccountKind.MICROSOFT, important, 7773, 3, true, true, true, CAUGHT_UP, out reason
        ) && reason == "complete server list",
        "finished Microsoft Important trusts the server list when Camel is caught up"
    );
    expect (
        !Mail.HeaderListPolicy.keep_prior_on_shrink (
            google, archive, 7773, 3, true, true, true, CAUGHT_UP, out reason
        ) && reason == "complete server list",
        "finished Archive trusts a large server shrink when Camel is caught up"
    );
    expect (
        !Mail.HeaderListPolicy.keep_prior_on_shrink (
            google, inbox, 7773, 3, true, true, true, CAUGHT_UP, out reason
        ) && reason == "complete server list",
        "finished Inbox trusts a large server shrink when Camel is caught up"
    );
    expect (
        !Mail.HeaderListPolicy.keep_prior_on_shrink (
            google, archive, 7773, 0, true, true, true, CAUGHT_UP, out reason
        ) && reason == "complete empty",
        "a finished empty Archive is accepted when Camel is caught up"
    );
    expect (
        Mail.HeaderListPolicy.keep_prior_on_shrink (
            google, archive, 229, 28, true, true, true, CAMEL_BEHIND, out reason
        ) && reason == "finished but Camel behind",
        "finished walk with Camel still tiny keeps Letter’s Conoscenza-sized list"
    );
    expect (
        Mail.HeaderListPolicy.keep_prior_on_shrink (
            google, archive, 7773, 0, true, true, true, CAMEL_BEHIND, out reason
        ) && reason == "finished but Camel behind",
        "finished empty with Camel behind does not wipe a large Letter index"
    );
    expect (
        !Mail.HeaderListPolicy.keep_prior_on_shrink (
            google, important, 200, 40, true, true, true, 200, out reason
        ) && reason == "complete Important",
        "a finished small Gmail Important list still replaces when Camel is caught up"
    );
    expect (
        !Mail.HeaderListPolicy.keep_prior_on_shrink (
            google, inbox, 200, 40, true, true, true, 200, out reason
        ) && reason == "complete server list",
        "a finished small Inbox shrink trusts the server when Camel is caught up"
    );
    expect (
        Mail.HeaderListPolicy.keep_prior_on_shrink (
            google, inbox, 200, 40, true, true, true, 0, out reason
        ) && reason == "finished but Camel behind",
        "a finished small Inbox shrink with empty Camel keeps Letter’s list"
    );
    expect (
        !Mail.HeaderListPolicy.keep_prior_on_shrink (
            google, inbox, 200, 40, true, true, false, 0, out reason
        ) && reason == "small-folder trust shrink",
        "a small Inbox shrink without a server walk is still trusted"
    );

    expect (
        Mail.HeaderListPolicy.ram_cache_refuses_shrink (7773, 3, 7773, 500, 500, false),
        "RAM keeps a large shrink"
    );
    expect (
        !Mail.HeaderListPolicy.ram_cache_refuses_shrink (7773, 3, 7773, 500, 500, true),
        "RAM accepts a trusted shrink"
    );
    expect (
        !Mail.HeaderListPolicy.ram_cache_refuses_shrink (7773, 7500, 7773, 500, 500, false),
        "RAM allows a shrink inside the gap"
    );
    expect (
        Mail.HeaderListPolicy.ram_cache_refuses_shrink (7773, 7000, 0, 500, 500, false),
        "RAM keeps a shrink when the high-water is unknown"
    );
    expect (
        !Mail.HeaderListPolicy.ram_cache_refuses_shrink (100, 1, 100, 500, 500, false),
        "RAM does not guard a small list"
    );

    expect (
        Mail.HeaderListPolicy.disk_cache_refuses_shrink (7773, 3, false),
        "disk keeps a large shrink"
    );
    expect (
        !Mail.HeaderListPolicy.disk_cache_refuses_shrink (7773, 3, true),
        "disk accepts a trusted shrink"
    );
    expect (
        !Mail.HeaderListPolicy.disk_cache_refuses_shrink (7773, 0, false),
        "disk still accepts an explicit empty list"
    );
    expect (
        !Mail.HeaderListPolicy.disk_cache_refuses_shrink (7773, 7500, false),
        "disk allows a shrink inside the gap"
    );

    var three = messages (3);
    var retired = new HashTable<string, uint8> (str_hash, str_equal);
    retired.set ("1", 1);
    var dropped = Mail.HeaderListPolicy.without_retired (three, retired);
    expect (dropped != three, "retired drop returns a new array");
    expect (dropped.length == 2, "retired drop removes matching uids");
    expect (dropped[0].uid == "0" && dropped[1].uid == "2", "retired drop keeps the others");
    var empty = new HashTable<string, uint8> (str_hash, str_equal);
    expect (
        Mail.HeaderListPolicy.without_retired (three, empty) == three,
        "empty retired table returns the same array"
    );
}

GenericArray<Mail.Message> messages (uint n) {
    var list = new GenericArray<Mail.Message> ();
    for (uint i = 0; i < n; i++) {
        list.add (new Mail.Message () {
            uid = i.to_string (),
            subject = "s",
        });
    }
    return list;
}

Mail.Folder folder (string name, string full_name) {
    return new Mail.Folder () {
        name = name,
        full_name = full_name,
    };
}

void expect (bool cond, string message) {
    if (!cond)
        error ("%s", message);
}
