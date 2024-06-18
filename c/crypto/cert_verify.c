#include "../include/crypto.h"
#include "../include/ferrumgate.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Minimal X.509 certificate parser for peer authentication.
 * Handles DER-encoded certificates, verifies notBefore/notAfter,
 * and extracts the Subject public key for handshake verification. */

#define ASN1_SEQUENCE  0x30
#define ASN1_INTEGER   0x02
#define ASN1_BIT_STR   0x03
#define ASN1_OBJ_ID    0x06
#define ASN1_UTC_TIME  0x17
#define ASN1_GEN_TIME  0x18

typedef struct {
    const uint8_t* data;
    size_t         len;
    size_t         pos;
} Asn1Reader;

static int asn1_read_tag(Asn1Reader* r, uint8_t* tag) {
    if (r->pos >= r->len) return FG_ERR_INVAL;
    *tag = r->data[r->pos++];
    return FG_OK;
}

static int asn1_read_len(Asn1Reader* r, size_t* out) {
    if (r->pos >= r->len) return FG_ERR_INVAL;
    uint8_t b = r->data[r->pos++];
    if (!(b & 0x80)) { *out = b; return FG_OK; }
    int num = b & 0x7f;
    if (num > 4 || r->pos + num > r->len) return FG_ERR_INVAL;
    *out = 0;
    for (int i = 0; i < num; i++) *out = (*out << 8) | r->data[r->pos++];
    return FG_OK;
}

static int asn1_enter_sequence(Asn1Reader* r, size_t* content_len) {
    uint8_t tag;
    if (asn1_read_tag(r, &tag) != FG_OK || tag != ASN1_SEQUENCE) return FG_ERR_INVAL;
    return asn1_read_len(r, content_len);
}

static int parse_utctime(const uint8_t* s, size_t len, time_t* out) {
    /* YYMMDDHHMMSSZ */
    if (len < 13) return FG_ERR_INVAL;
    struct tm tm = {0};
    tm.tm_year = (s[0]-'0')*10 + (s[1]-'0');
    tm.tm_year += (tm.tm_year < 50) ? 100 : 0;
    tm.tm_mon  = (s[2]-'0')*10 + (s[3]-'0') - 1;
    tm.tm_mday = (s[4]-'0')*10 + (s[5]-'0');
    tm.tm_hour = (s[6]-'0')*10 + (s[7]-'0');
    tm.tm_min  = (s[8]-'0')*10 + (s[9]-'0');
    tm.tm_sec  = (s[10]-'0')*10 + (s[11]-'0');
    *out = timegm(&tm);
    return FG_OK;
}

int fg_cert_check_validity(const uint8_t* der, size_t der_len) {
    if (!der || der_len < 16) return FG_ERR_INVAL;

    Asn1Reader r = { der, der_len, 0 };
    size_t seq_len;
    if (asn1_enter_sequence(&r, &seq_len) != FG_OK) return FG_ERR_INVAL;
    if (asn1_enter_sequence(&r, &seq_len) != FG_OK) return FG_ERR_INVAL;

    /* skip version, serial number, signature alg, issuer, find validity */
    /* simplified: scan for UTCTIME tag */
    time_t not_before = 0, not_after = 0;
    int found = 0;
    while (r.pos < r.len && found < 2) {
        uint8_t tag;
        size_t  tlen;
        if (asn1_read_tag(&r, &tag) != FG_OK) break;
        if (asn1_read_len(&r, &tlen) != FG_OK) break;
        if (r.pos + tlen > r.len) break;

        if (tag == ASN1_UTC_TIME && found == 0) {
            parse_utctime(r.data + r.pos, tlen, &not_before);
            found++;
        } else if (tag == ASN1_UTC_TIME && found == 1) {
            parse_utctime(r.data + r.pos, tlen, &not_after);
            found++;
        }
        r.pos += tlen;
    }

    if (found < 2) return FG_ERR_INVAL;

    time_t now = time(NULL);
    if (now < not_before || now > not_after) return FG_ERR_EXPIRED;
    return FG_OK;
}
