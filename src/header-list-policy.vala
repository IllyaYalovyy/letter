/* When a header list may shrink.
 *
 * Incomplete / skipped / local-only walks must not wipe a longer Letter
 * index (Archive tip, budget cancel, REFRESH_INFO_SKIP).
 *
 * A *finished* server refresh may be authoritative (Empty Trash, another
 * PC, phone) — but only when Camel’s UID summary was already roughly in
 * line with Letter *before* that walk. On Camel/Graph, a tip that times
 * out leaves a tiny local summary; the next “until-done” can return in
 * under a second, mark the refresh finished, and still only know about
 * those few UIDs. Trusting that as “server list” wiped Conoscenza
 * (229 → 28) on a slow hotspot. Own-engine sync without Camel does not
 * have this trap; here Camel must be caught up first.
 *
 * Gmail Important keeps an explicit reason string for logs/tests; the same
 * finished + Camel-caught-up rule applies to every other folder.
 *
 * LARGE and SHRINK_SLOP match MailSession HEADER_LIST_LARGE /
 * INCOMPLETE_REFRESH_SHRINK_MAX. DISK_GAP matches Window disk refuse. */
public class Mail.HeaderListPolicy {
    public const uint LARGE = 500;
    public const uint SHRINK_SLOP = 100;
    public const uint DISK_GAP = 500;

    public static bool trust_gmail_important_refresh (
        AccountKind account_kind,
        FolderKind folder_kind,
        bool server_refresh_finished
    ) {
        return server_refresh_finished
            && account_kind == AccountKind.GOOGLE
            && folder_kind == FolderKind.IMPORTANT;
    }

    /* Camel already held roughly as many UIDs as Letter before this walk.
     * Applies to every catastrophic shrink (not only LARGE folders): Conoscenza
     * sat at ~200 Letter headers with Camel still on ~26. */
    public static bool camel_summary_caught_up (uint previous_length, uint camel_uids_before) {
        return camel_uids_before + SHRINK_SLOP >= previous_length;
    }

    /* Called only when incoming + SHRINK_SLOP < previous.
     * Returns true → keep Letter’s prior list. */
    public static bool keep_prior_on_shrink (
        AccountKind account_kind,
        FolderKind folder_kind,
        uint previous_length,
        uint incoming_length,
        bool refresh,
        bool refresh_completed,
        bool server_refresh_finished,
        uint camel_uids_before,
        out string reason
    ) {
        if (refresh && !refresh_completed) {
            reason = "incomplete refresh";
            return true;
        }

        var camel_ok = camel_summary_caught_up (previous_length, camel_uids_before);

        if (incoming_length == 0 && refresh && server_refresh_finished) {
            if (!camel_ok) {
                reason = "finished but Camel behind";
                return true;
            }
            reason = "complete empty";
            return false;
        }
        if (trust_gmail_important_refresh (account_kind, folder_kind, server_refresh_finished)) {
            if (!camel_ok) {
                reason = "finished but Camel behind";
                return true;
            }
            reason = "complete Important";
            return false;
        }
        /* Finished server walk with Camel already caught up: trust the shorter
         * list — other clients win. */
        if (refresh && server_refresh_finished) {
            if (!camel_ok) {
                reason = "finished but Camel behind";
                return true;
            }
            reason = "complete server list";
            return false;
        }
        if (previous_length >= LARGE) {
            if (!refresh) {
                reason = "large-folder local refuse shrink";
                return true;
            }
            /* refresh_completed but no server walk (SKIP / pending flags). */
            reason = "large-folder refuse shrink";
            return true;
        }
        reason = "small-folder trust shrink";
        return false;
    }

    public static bool ram_cache_refuses_shrink (
        uint previous_length,
        uint incoming_length,
        uint high_water,
        uint large_list,
        uint gap,
        bool accept_server_shrink
    ) {
        if (accept_server_shrink)
            return false;
        if (previous_length < large_list)
            return false;
        if (incoming_length + gap >= previous_length)
            return false;
        if (high_water > 0 && incoming_length + gap >= high_water)
            return false;
        return true;
    }

    /* Same array when nothing is retired, so an unchanged folder stays unchanged. */
    public static GenericArray<Message> without_retired (
        GenericArray<Message> messages,
        HashTable<string, uint8> retired
    ) {
        if (retired.size () == 0)
            return messages;

        var any = false;
        for (uint i = 0; i < messages.length; i++) {
            var uid = messages[i].uid;
            if (uid != null && uid.length > 0 && retired.contains (uid)) {
                any = true;
                break;
            }
        }
        if (!any)
            return messages;

        var kept = new GenericArray<Message> ();
        for (uint i = 0; i < messages.length; i++) {
            var uid = messages[i].uid;
            if (uid != null && uid.length > 0 && retired.contains (uid))
                continue;
            kept.add (messages[i]);
        }
        return kept;
    }

    public static bool disk_cache_refuses_shrink (
        uint disk_n,
        uint write_n,
        bool accept_shrink
    ) {
        if (accept_shrink)
            return false;
        return disk_n > 0 && write_n > 0 && write_n + DISK_GAP < disk_n;
    }
}
