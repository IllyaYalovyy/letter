#include "tls-issuer.h"
#include <gnutls/x509.h>
#include <string.h>

static gboolean
parse_certificate (GTlsCertificate *certificate, gnutls_x509_crt_t *parsed)
{
    g_autofree char *pem = NULL;

    g_object_get (certificate, "certificate-pem", &pem, NULL);
    if (pem == NULL || gnutls_x509_crt_init (parsed) < 0)
        return FALSE;

    gnutls_datum_t input = { (unsigned char *) pem, strlen (pem) };
    if (gnutls_x509_crt_import (*parsed, &input, GNUTLS_X509_FMT_PEM) < 0) {
        gnutls_x509_crt_deinit (*parsed);
        return FALSE;
    }
    return TRUE;
}

gboolean
letter_tls_server_usage (GTlsCertificate *certificate)
{
    for (GTlsCertificate *item = certificate; item != NULL;
         item = g_tls_certificate_get_issuer (item)) {
        gnutls_x509_crt_t parsed;
        if (!parse_certificate (item, &parsed))
            return FALSE;
        gboolean valid = gnutls_x509_crt_check_key_purpose (parsed, GNUTLS_KP_TLS_WWW_SERVER, 0);
        unsigned int usage;
        int result = gnutls_x509_crt_get_key_usage (parsed, &usage, NULL);
        if (result == 0) {
            unsigned int required = item == certificate
                ? GNUTLS_KEY_DIGITAL_SIGNATURE
                : GNUTLS_KEY_KEY_CERT_SIGN;
            valid = valid && (usage & required) != 0;
        } else if (result != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
            valid = FALSE;
        }
        gnutls_x509_crt_deinit (parsed);
        if (!valid)
            return FALSE;
    }
    return TRUE;
}

char *
letter_tls_issuer_uri (GTlsCertificate *certificate)
{
    gnutls_x509_crt_t parsed;
    char *uri = NULL;

    if (!parse_certificate (certificate, &parsed))
        return NULL;

    for (unsigned int i = 0; i < 16; i++) {
        gnutls_datum_t value = { 0 };
        if (gnutls_x509_crt_get_authority_info_access (
                parsed, i, GNUTLS_IA_CAISSUERS_URI, &value, NULL) >= 0
            && value.size > 0 && value.size <= 4096
            && memchr (value.data, '\0', value.size) == NULL)
            uri = g_strndup ((char *) value.data, value.size);
        gnutls_free (value.data);
        if (uri != NULL)
            break;
    }
    gnutls_x509_crt_deinit (parsed);
    return uri;
}
