#pragma once

#include <gio/gio.h>

char *letter_tls_issuer_uri (GTlsCertificate *certificate);
gboolean letter_tls_server_usage (GTlsCertificate *certificate);
