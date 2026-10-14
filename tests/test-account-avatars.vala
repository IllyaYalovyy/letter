string? picture_url (string userinfo) {
    return Mail.AccountAvatars.picture_url (new Bytes (userinfo.data), 64);
}

void test_disabled_by_default () {
    assert (!new Settings (Config.APP_ID).get_boolean ("account-avatars"));
}

void test_replaces_google_size () {
    assert (picture_url ("{\"picture\": \"https://lh3.googleusercontent.com/a/ACg8oc=s96-c\"}")
        == "https://lh3.googleusercontent.com/a/ACg8oc=s64-c");
}

void test_replaces_any_google_options () {
    assert (picture_url ("{\"picture\": \"https://lh3.googleusercontent.com/a/ACg8oc=s96-c-k-no\"}")
        == "https://lh3.googleusercontent.com/a/ACg8oc=s64-c");
    assert (picture_url ("{\"picture\": \"https://lh3.googleusercontent.com/a/ACg8oc=w400-h300\"}")
        == "https://lh3.googleusercontent.com/a/ACg8oc=s64-c");
}

void test_drops_query_and_fragment () {
    assert (picture_url ("{\"picture\": \"https://lh3.googleusercontent.com/-x/AAI/photo.jpg?sz=50\"}")
        == "https://lh3.googleusercontent.com/-x/AAI/photo.jpg=s64-c");
    assert (picture_url ("{\"picture\": \"https://lh3.googleusercontent.com/a/ACg8oc=s96-c?sz=1024#top\"}")
        == "https://lh3.googleusercontent.com/a/ACg8oc=s64-c");
}

void test_keeps_equals_sign_in_path () {
    assert (picture_url ("{\"picture\": \"https://lh3.googleusercontent.com/a=b/photo.jpg\"}")
        == "https://lh3.googleusercontent.com/a=b/photo.jpg=s64-c");
}

void test_adds_size () {
    assert (picture_url ("{\"picture\": \"https://lh3.googleusercontent.com/a-/photo.jpg\"}")
        == "https://lh3.googleusercontent.com/a-/photo.jpg=s64-c");
}

void test_no_picture () {
    assert (picture_url ("{\"email\": \"me@example.com\"}") == null);
    assert (picture_url ("{\"picture\": \"\"}") == null);
    assert (picture_url ("{\"picture\": 42}") == null);
}

void test_insecure_picture () {
    assert (picture_url ("{\"picture\": \"http://lh3.googleusercontent.com/a/x\"}") == null);
    assert (picture_url ("{\"picture\": \"file:///etc/passwd\"}") == null);
}

void test_not_userinfo () {
    assert (picture_url ("") == null);
    assert (picture_url ("not json") == null);
    assert (picture_url ("[\"https://lh3.googleusercontent.com/a/x\"]") == null);
}

void main (string[] args) {
    Test.init (ref args);
    Test.add_func ("/account-avatars/disabled-by-default", test_disabled_by_default);
    Test.add_func ("/account-avatars/replaces-google-size", test_replaces_google_size);
    Test.add_func ("/account-avatars/replaces-any-google-options", test_replaces_any_google_options);
    Test.add_func ("/account-avatars/drops-query-and-fragment", test_drops_query_and_fragment);
    Test.add_func ("/account-avatars/keeps-equals-sign-in-path", test_keeps_equals_sign_in_path);
    Test.add_func ("/account-avatars/adds-size", test_adds_size);
    Test.add_func ("/account-avatars/no-picture", test_no_picture);
    Test.add_func ("/account-avatars/insecure-picture", test_insecure_picture);
    Test.add_func ("/account-avatars/not-userinfo", test_not_userinfo);
    Test.run ();
}
