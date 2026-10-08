/* libc time + ctype. */
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <bits/ml_sys.h>

long __ml_ret(long r);

int clock_gettime(clockid_t id, struct timespec *ts) {
    return (int)__ml_ret(__ML_SYS2(LX_SYS_clock_gettime, id, ts));
}

int clock_getres(clockid_t id, struct timespec *ts) {
    return (int)__ml_ret(__ML_SYS2(LX_SYS_clock_getres, id, ts));
}

int gettimeofday(struct timeval *tv, void *tz) {
    return (int)__ml_ret(__ML_SYS2(LX_SYS_gettimeofday, tv, tz));
}

time_t time(time_t *t) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return (time_t)-1;
    if (t) *t = ts.tv_sec;
    return ts.tv_sec;
}

/* Days-from-civil (Howard Hinnant): epoch days for y/m/d. */
static long ml_days(long y, int m, int d) {
    y -= m <= 2;
    {
        long era = (y >= 0 ? y : y - 399) / 400;
        unsigned yoe = (unsigned)(y - era * 400);
        unsigned doy =
            (153u * (unsigned)(m + (m > 2 ? -3 : 9)) + 2u) / 5u +
            (unsigned)(d - 1);
        unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
        return era * 146097 + (long)doe - 719468;
    }
}

static struct tm ml_tm_buf;

static struct tm *ml_break(time_t t) {
    long days = t / 86400;
    long rem = t % 86400;
    long y, weekday;
    int m, d, i;
    static const int mdays[12] = {31, 28, 31, 30, 31, 30,
                                  31, 31, 30, 31, 30, 31};
    if (rem < 0) {
        rem += 86400;
        days--;
    }
    /* civil-from-days */
    {
        long z = days + 719468;
        long era = (z >= 0 ? z : z - 146096) / 146097;
        unsigned doe = (unsigned)(z - era * 146097);
        unsigned yoe =
            (doe - doe / 1460u + doe / 36524u - doe / 146096u) / 365u;
        y = (long)yoe + era * 400;
        {
            unsigned doy = doe - (365u * yoe + yoe / 4u - yoe / 100u);
            unsigned mp = (5u * doy + 2u) / 153u;
            d = (int)(doy - (153u * mp + 2u) / 5u + 1u);
            m = (int)(mp + (mp < 10 ? 3 : -9));
            y += (m <= 2);
        }
    }
    weekday = (days % 7 + 7 + 4) % 7; /* 1970-01-01 was Thursday */
    ml_tm_buf.tm_sec = (int)(rem % 60);
    ml_tm_buf.tm_min = (int)((rem / 60) % 60);
    ml_tm_buf.tm_hour = (int)(rem / 3600);
    ml_tm_buf.tm_mday = d;
    ml_tm_buf.tm_mon = m - 1;
    ml_tm_buf.tm_year = (int)(y - 1900);
    ml_tm_buf.tm_wday = (int)weekday;
    {
        int yday = 0, leap = ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0);
        for (i = 0; i < m - 1; i++) yday += mdays[i];
        if (leap && m > 2) yday++;
        ml_tm_buf.tm_yday = yday + d - 1;
    }
    ml_tm_buf.tm_isdst = 0;
    (void)ml_days;
    return &ml_tm_buf;
}

struct tm *gmtime(const time_t *t) {
    if (!t) return 0;
    return ml_break(*t);
}

struct tm *localtime(const time_t *t) {
    /* No timezone database: UTC (documented). */
    return gmtime(t);
}

int nanosleep(const struct timespec *req, struct timespec *rem) {
    long r;
    if (!req || req->tv_sec < 0 || req->tv_nsec < 0 ||
        req->tv_nsec >= 1000000000L) {
        errno = EINVAL;
        return -1;
    }
    /* Real tick sleep in the kernel (single ecall, yield-safe). */
    r = __ml_call6(LX_SYS_nanosleep, (long)req, (long)rem, 0, 0, 0, 0);
    return (int)__ml_ret(r);
}

/* ---- calendar extras (all UTC: localtime == gmtime, documented) ---- */

static int ml_is_leap(long y) {
    return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
}

static struct tm *ml_break_r(time_t t, struct tm *tm) {
    long days = t / 86400;
    long rem = t % 86400;
    long y, weekday;
    int m, d, i;
    static const int mdays[12] = {31, 28, 31, 30, 31, 30,
                                  31, 31, 30, 31, 30, 31};
    if (rem < 0) {
        rem += 86400;
        days--;
    }
    {
        long z = days + 719468;
        long era = (z >= 0 ? z : z - 146096) / 146097;
        unsigned doe = (unsigned)(z - era * 146097);
        unsigned yoe =
            (doe - doe / 1460u + doe / 36524u - doe / 146096u) / 365u;
        y = (long)yoe + era * 400;
        {
            unsigned doy = doe - (365u * yoe + yoe / 4u - yoe / 100u);
            unsigned mp = (5u * doy + 2u) / 153u;
            d = (int)(doy - (153u * mp + 2u) / 5u + 1u);
            m = (int)(mp + (mp < 10 ? 3 : -9));
            y += (m <= 2);
        }
    }
    weekday = (days % 7 + 7 + 4) % 7;
    tm->tm_sec = (int)(rem % 60);
    tm->tm_min = (int)((rem / 60) % 60);
    tm->tm_hour = (int)(rem / 3600);
    tm->tm_mday = d;
    tm->tm_mon = m - 1;
    tm->tm_year = (int)(y - 1900);
    tm->tm_wday = (int)weekday;
    {
        int yday = 0, leap = ml_is_leap(y);
        for (i = 0; i < m - 1; i++) yday += mdays[i];
        if (leap && m > 2) yday++;
        tm->tm_yday = yday + d - 1;
    }
    tm->tm_isdst = 0;
    return tm;
}

struct tm *gmtime_r(const time_t *t, struct tm *tm) {
    if (!t || !tm) return 0;
    return ml_break_r(*t, tm);
}

struct tm *localtime_r(const time_t *t, struct tm *tm) {
    return gmtime_r(t, tm); /* UTC: no zone database (documented) */
}

time_t timegm(struct tm *tm) {
    long y;
    int m;
    long days;
    long long secs;
    if (!tm) return (time_t)-1;
    y = (long)tm->tm_year + 1900;
    m = tm->tm_mon + 1;
    /* Normalization is inherent: days-from-civil + clock fields fold
     * out-of-range inputs (mktime contract). tm_yday/tm_wday ignored. */
    days = ml_days(y, m, tm->tm_mday);
    secs = (long long)days * 86400ll + (long long)tm->tm_hour * 3600ll +
           (long long)tm->tm_min * 60ll + (long long)tm->tm_sec;
    return (time_t)secs;
}

time_t mktime(struct tm *tm) {
    time_t t;
    if (!tm) return (time_t)-1;
    t = timegm(tm);
    /* Normalize the caller's fields (mktime contract): re-break. */
    ml_break_r(t, tm);
    return t;
}

double difftime(time_t a, time_t b) { return (double)a - (double)b; }

char *asctime_r(const struct tm *tm, char *buf) {
    static const char wday[7][4] = {"Sun", "Mon", "Tue", "Wed",
                                    "Thu", "Fri", "Sat"};
    static const char mon[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    int wd, mo, i = 0;
    char *p;
    if (!tm || !buf) return 0;
    wd = (tm->tm_wday < 0 || tm->tm_wday > 6) ? 0 : tm->tm_wday;
    mo = (tm->tm_mon < 0 || tm->tm_mon > 11) ? 0 : tm->tm_mon;
    p = buf;
    for (i = 0; i < 3; i++) *p++ = wday[wd][i];
    *p++ = ' ';
    for (i = 0; i < 3; i++) *p++ = mon[mo][i];
    *p++ = ' ';
    *p++ = (char)('0' + tm->tm_mday / 10);
    *p++ = (char)('0' + tm->tm_mday % 10);
    *p++ = ' ';
    *p++ = (char)('0' + tm->tm_hour / 10);
    *p++ = (char)('0' + tm->tm_hour % 10);
    *p++ = ':';
    *p++ = (char)('0' + tm->tm_min / 10);
    *p++ = (char)('0' + tm->tm_min % 10);
    *p++ = ':';
    *p++ = (char)('0' + tm->tm_sec / 10);
    *p++ = (char)('0' + tm->tm_sec % 10);
    *p++ = ' ';
    {
        /* Year, at least 4 digits (wider for far futures/past). */
        long y = (long)tm->tm_year + 1900;
        char yb[24];
        int yl = 0, k;
        unsigned long ay;
        if (y < 0) {
            *p++ = '-';
            ay = (unsigned long)(-y);
        } else {
            ay = (unsigned long)y;
        }
        do {
            yb[yl++] = (char)('0' + ay % 10);
            ay /= 10;
        } while (ay > 0);
        while (yl < 4) yb[yl++] = '0';
        for (k = yl - 1; k >= 0; k--) *p++ = yb[k];
    }
    *p++ = '\n';
    *p = '\0';
    return buf;
}

char *asctime(const struct tm *tm) {
    static char ml_asc_buf[64];
    return asctime_r(tm, ml_asc_buf);
}

char *ctime_r(const time_t *t, char *buf) {
    struct tm tm;
    if (!t || !buf) return 0;
    return asctime_r(localtime_r(t, &tm), buf);
}

char *ctime(const time_t *t) {
    static char ml_ct_buf[64];
    return ctime_r(t, ml_ct_buf);
}

int timespec_get(struct timespec *ts, int base) {
    if (!ts || base != TIME_UTC) return 0;
    if (clock_gettime(CLOCK_REALTIME, ts) != 0) return 0;
    return TIME_UTC;
}

int clock_nanosleep(clockid_t id, int flags, const struct timespec *req,
                    struct timespec *rem) {
    long r;
    if (!req || req->tv_nsec < 0 || req->tv_nsec >= 1000000000L) {
        errno = EINVAL;
        return EINVAL;
    }
    if (id != CLOCK_REALTIME && id != CLOCK_MONOTONIC &&
        id != CLOCK_PROCESS_CPUTIME_ID) {
        errno = EINVAL;
        return EINVAL;
    }
    r = __ml_call6(LX_SYS_clock_nanosleep, (long)id, (long)flags,
                   (long)req, (long)rem, 0, 0);
    if (r < 0 && r >= -4095) {
        errno = (int)-r;
        return (int)-r;
    }
    return 0;
}

/* ---- strftime (UTC; %Z -> "UTC", %z -> "+0000") ---- */

static size_t ml_sf_emit(char *s, size_t n, size_t pos, const char *t,
                         size_t tl) {
    size_t i;
    for (i = 0; i < tl; i++) {
        if (pos < n) s[pos] = t[i];
        pos++;
    }
    return pos;
}

static size_t ml_sf_num(char *s, size_t n, size_t pos, long v, int width) {
    char b[24];
    int i = 0, neg = 0;
    unsigned long u;
    if (v < 0) {
        neg = 1;
        u = (unsigned long)(-v);
    } else {
        u = (unsigned long)v;
    }
    do {
        b[i++] = (char)('0' + u % 10);
        u /= 10;
    } while (u > 0);
    while (i < width) b[i++] = '0';
    if (neg) b[i++] = '-';
    while (i > 0) {
        i--;
        if (pos < n) s[pos] = b[i];
        pos++;
    }
    return pos;
}

/* ISO-8601 week/year for %V/%G/%g (pure civil math). */
static void ml_iso_week(const struct tm *tm, long *iso_y, int *iso_w) {
    /* Monday-based weekday (Mon=0), ordinal day, then week calc. */
    long y = (long)tm->tm_year + 1900;
    int dow = (tm->tm_wday + 6) % 7;
    int doy = tm->tm_yday + 1;
    int w = (doy - dow + 9) / 7; /* candidate week */
    int dec31dow;
    int weeks;
    /* Weekday of Dec 31 this year. */
    {
        long jan1 = ml_days(y, 1, 1);
        int jan1dow = (int)((jan1 % 7 + 7 + 4) % 7); /* Sun=0 */
        int jan1m = (jan1dow + 6) % 7;               /* Mon=0 */
        int ylen = ml_is_leap(y) ? 366 : 365;
        dec31dow = (jan1m + ylen - 1) % 7;
        /* Years starting Thursday (or Wed in leap) have 53 weeks. */
        weeks = (jan1m == 3 || (ml_is_leap(y) && jan1m == 2)) ? 53 : 52;
        (void)dec31dow;
    }
    if (w < 1) {
        long py = y - 1;
        long pjan1 = ml_days(py, 1, 1);
        int pjan1m = (int)(((pjan1 % 7 + 7 + 4) % 7 + 6) % 7);
        *iso_y = py;
        *iso_w = (pjan1m == 3 || (ml_is_leap(py) && pjan1m == 2)) ? 53 : 52;
        return;
    }
    if (w > weeks) {
        *iso_y = y + 1;
        *iso_w = 1;
        return;
    }
    *iso_y = y;
    *iso_w = w;
}

size_t strftime(char *s, size_t n, const char *fmt, const struct tm *tm) {
    static const char *wd_full[7] = {"Sunday",   "Monday", "Tuesday",
                                     "Wednesday", "Thursday", "Friday",
                                     "Saturday"};
    static const char *wd_ab[7] = {"Sun", "Mon", "Tue", "Wed",
                                   "Thu", "Fri", "Sat"};
    static const char *mo_full[12] = {
        "January", "February", "March",     "April",   "May",      "June",
        "July",    "August",   "September", "October", "November", "December"};
    static const char *mo_ab[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    size_t pos = 0;
    int wd, mo;
    if (!s || !fmt || !tm) return 0;
    wd = (tm->tm_wday < 0 || tm->tm_wday > 6) ? 0 : tm->tm_wday;
    mo = (tm->tm_mon < 0 || tm->tm_mon > 11) ? 0 : tm->tm_mon;
    while (*fmt) {
        char tmp[32];
        if (*fmt != '%') {
            if (pos < n) s[pos] = *fmt;
            pos++;
            fmt++;
            continue;
        }
        fmt++;
        switch (*fmt) {
        case 'a':
            pos = ml_sf_emit(s, n, pos, wd_ab[wd], 3);
            break;
        case 'A':
            pos = ml_sf_emit(s, n, pos, wd_full[wd], strlen(wd_full[wd]));
            break;
        case 'b':
        case 'h':
            pos = ml_sf_emit(s, n, pos, mo_ab[mo], 3);
            break;
        case 'B':
            pos = ml_sf_emit(s, n, pos, mo_full[mo], strlen(mo_full[mo]));
            break;
        case 'c':
            pos = ml_sf_emit(s, n, pos, wd_ab[wd], 3);
            pos = ml_sf_emit(s, n, pos, " ", 1);
            pos = ml_sf_emit(s, n, pos, mo_ab[mo], 3);
            pos = ml_sf_emit(s, n, pos, " ", 1);
            pos = ml_sf_num(s, n, pos, tm->tm_mday, 2);
            pos = ml_sf_emit(s, n, pos, " ", 1);
            pos = ml_sf_num(s, n, pos, tm->tm_hour, 2);
            pos = ml_sf_emit(s, n, pos, ":", 1);
            pos = ml_sf_num(s, n, pos, tm->tm_min, 2);
            pos = ml_sf_emit(s, n, pos, ":", 1);
            pos = ml_sf_num(s, n, pos, tm->tm_sec, 2);
            pos = ml_sf_emit(s, n, pos, " ", 1);
            pos = ml_sf_num(s, n, pos, (long)tm->tm_year + 1900, 4);
            break;
        case 'C':
            pos = ml_sf_num(s, n, pos,
                            ((long)tm->tm_year + 1900) / 100, 2);
            break;
        case 'd':
            pos = ml_sf_num(s, n, pos, tm->tm_mday, 2);
            break;
        case 'D':
            pos = ml_sf_num(s, n, pos, tm->tm_mon + 1, 2);
            pos = ml_sf_emit(s, n, pos, "/", 1);
            pos = ml_sf_num(s, n, pos, tm->tm_mday, 2);
            pos = ml_sf_emit(s, n, pos, "/", 1);
            pos = ml_sf_num(s, n, pos,
                            ((long)tm->tm_year + 1900) % 100, 2);
            break;
        case 'e':
            tmp[0] = (char)('0' + tm->tm_mday / 10);
            tmp[1] = (char)('0' + tm->tm_mday % 10);
            if (tmp[0] == '0') tmp[0] = ' ';
            pos = ml_sf_emit(s, n, pos, tmp, 2);
            break;
        case 'F':
            pos = ml_sf_num(s, n, pos, (long)tm->tm_year + 1900, 4);
            pos = ml_sf_emit(s, n, pos, "-", 1);
            pos = ml_sf_num(s, n, pos, tm->tm_mon + 1, 2);
            pos = ml_sf_emit(s, n, pos, "-", 1);
            pos = ml_sf_num(s, n, pos, tm->tm_mday, 2);
            break;
        case 'G': {
            long iy;
            int iw;
            ml_iso_week(tm, &iy, &iw);
            pos = ml_sf_num(s, n, pos, iy, 4);
            break;
        }
        case 'g': {
            long iy;
            int iw;
            ml_iso_week(tm, &iy, &iw);
            pos = ml_sf_num(s, n, pos, iy % 100, 2);
            break;
        }
        case 'H':
            pos = ml_sf_num(s, n, pos, tm->tm_hour, 2);
            break;
        case 'I': {
            int h = tm->tm_hour % 12;
            pos = ml_sf_num(s, n, pos, h == 0 ? 12 : h, 2);
            break;
        }
        case 'j':
            pos = ml_sf_num(s, n, pos, tm->tm_yday + 1, 3);
            break;
        case 'k':
            tmp[0] = (char)('0' + tm->tm_hour / 10);
            tmp[1] = (char)('0' + tm->tm_hour % 10);
            if (tmp[0] == '0') tmp[0] = ' ';
            pos = ml_sf_emit(s, n, pos, tmp, 2);
            break;
        case 'l': {
            int h = tm->tm_hour % 12;
            if (h == 0) h = 12;
            tmp[0] = (char)('0' + h / 10);
            tmp[1] = (char)('0' + h % 10);
            if (tmp[0] == '0') tmp[0] = ' ';
            pos = ml_sf_emit(s, n, pos, tmp, 2);
            break;
        }
        case 'm':
            pos = ml_sf_num(s, n, pos, tm->tm_mon + 1, 2);
            break;
        case 'M':
            pos = ml_sf_num(s, n, pos, tm->tm_min, 2);
            break;
        case 'n':
            pos = ml_sf_emit(s, n, pos, "\n", 1);
            break;
        case 'p':
            pos = ml_sf_emit(s, n, pos, tm->tm_hour < 12 ? "AM" : "PM",
                             2);
            break;
        case 'r': {
            int h = tm->tm_hour % 12;
            if (h == 0) h = 12;
            pos = ml_sf_num(s, n, pos, h, 2);
            pos = ml_sf_emit(s, n, pos, ":", 1);
            pos = ml_sf_num(s, n, pos, tm->tm_min, 2);
            pos = ml_sf_emit(s, n, pos, ":", 1);
            pos = ml_sf_num(s, n, pos, tm->tm_sec, 2);
            pos = ml_sf_emit(s, n, pos, tm->tm_hour < 12 ? " AM" : " PM",
                             3);
            break;
        }
        case 'R':
            pos = ml_sf_num(s, n, pos, tm->tm_hour, 2);
            pos = ml_sf_emit(s, n, pos, ":", 1);
            pos = ml_sf_num(s, n, pos, tm->tm_min, 2);
            break;
        case 'S':
            pos = ml_sf_num(s, n, pos, tm->tm_sec, 2);
            break;
        case 's': {
            /* Seconds since the epoch (UTC, like timegm). */
            struct tm cp = *tm;
            time_t t = timegm(&cp);
            char b[24];
            int i = 0, k;
            unsigned long long u =
                t < 0 ? (unsigned long long)(-(long long)t)
                      : (unsigned long long)t;
            if (t < 0) pos = ml_sf_emit(s, n, pos, "-", 1);
            do {
                b[i++] = (char)('0' + u % 10);
                u /= 10;
            } while (u > 0);
            for (k = i - 1; k >= 0; k--) {
                if (pos < n) s[pos] = b[k];
                pos++;
            }
            break;
        }
        case 'T':
            pos = ml_sf_num(s, n, pos, tm->tm_hour, 2);
            pos = ml_sf_emit(s, n, pos, ":", 1);
            pos = ml_sf_num(s, n, pos, tm->tm_min, 2);
            pos = ml_sf_emit(s, n, pos, ":", 1);
            pos = ml_sf_num(s, n, pos, tm->tm_sec, 2);
            break;
        case 't':
            pos = ml_sf_emit(s, n, pos, "\t", 1);
            break;
        case 'u':
            pos = ml_sf_num(s, n, pos, wd == 0 ? 7 : wd, 0);
            break;
        case 'U': {
            /* Week number, Sunday-first (days before first Sunday are
             * week 0). */
            int jan1w = (wd - tm->tm_yday % 7 + 700) % 7;
            int w = (tm->tm_yday + 7 - ((7 - jan1w) % 7)) / 7;
            pos = ml_sf_num(s, n, pos, w, 2);
            break;
        }
        case 'V': {
            long iy;
            int iw;
            ml_iso_week(tm, &iy, &iw);
            pos = ml_sf_num(s, n, pos, iw, 2);
            break;
        }
        case 'w':
            pos = ml_sf_num(s, n, pos, wd, 0);
            break;
        case 'W': {
            /* Week number, Monday-first. */
            int jan1w = (wd - tm->tm_yday % 7 + 700) % 7;
            int jan1m = (jan1w + 6) % 7;
            int w = (tm->tm_yday + 7 - ((7 - jan1m) % 7)) / 7;
            pos = ml_sf_num(s, n, pos, w, 2);
            break;
        }
        case 'x':
            pos = ml_sf_num(s, n, pos, tm->tm_mon + 1, 2);
            pos = ml_sf_emit(s, n, pos, "/", 1);
            pos = ml_sf_num(s, n, pos, tm->tm_mday, 2);
            pos = ml_sf_emit(s, n, pos, "/", 1);
            pos = ml_sf_num(s, n, pos,
                            ((long)tm->tm_year + 1900) % 100, 2);
            break;
        case 'X':
            pos = ml_sf_num(s, n, pos, tm->tm_hour, 2);
            pos = ml_sf_emit(s, n, pos, ":", 1);
            pos = ml_sf_num(s, n, pos, tm->tm_min, 2);
            pos = ml_sf_emit(s, n, pos, ":", 1);
            pos = ml_sf_num(s, n, pos, tm->tm_sec, 2);
            break;
        case 'y':
            pos = ml_sf_num(s, n, pos,
                            ((long)tm->tm_year + 1900) % 100, 2);
            break;
        case 'Y':
            pos = ml_sf_num(s, n, pos, (long)tm->tm_year + 1900, 4);
            break;
        case 'z':
            pos = ml_sf_emit(s, n, pos, "+0000", 5);
            break;
        case 'Z':
            pos = ml_sf_emit(s, n, pos, "UTC", 3);
            break;
        case '%':
            pos = ml_sf_emit(s, n, pos, "%", 1);
            break;
        default:
            /* Unknown: echo literally (same rule as printf). */
            pos = ml_sf_emit(s, n, pos, "%", 1);
            if (*fmt) {
                if (pos < n) s[pos] = *fmt;
                pos++;
            }
            break;
        }
        if (*fmt) fmt++;
        (void)tmp;
    }
    if (n == 0) return 0;
    if (pos >= n) {
        s[n - 1] = '\0';
        return 0; /* truncated: C returns 0 when nothing fits */
    }
    s[pos] = '\0';
    return pos;
}

/* ---- strptime: inverse of the above for the sane subset ---- */

static int ml_sp_num(const char **sp, int lo, int hi, int *out) {
    const char *p = *sp;
    int v = 0, nd = 0;
    while (*p >= '0' && *p <= '9' && nd < 4) {
        v = v * 10 + (*p - '0');
        p++;
        nd++;
    }
    if (nd == 0 || v < lo || v > hi) return -1;
    *out = v;
    *sp = p;
    return 0;
}

static int ml_sp_word(const char **sp, const char *const *names, int n,
                      int *out) {
    int i;
    for (i = 0; i < n; i++) {
        size_t l = strlen(names[i]);
        size_t k;
        for (k = 0; k < l; k++) {
            char a = (*sp)[k], b = names[i][k];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) break;
        }
        if (k == l) {
            *out = i;
            *sp += l;
            return 0;
        }
    }
    return -1;
}

char *strptime(const char *s, const char *fmt, struct tm *tm) {
    static const char *const wd_full[7] = {
        "Sunday", "Monday", "Tuesday",  "Wednesday",
        "Thursday", "Friday", "Saturday"};
    static const char *const wd_ab[7] = {"Sun", "Mon", "Tue", "Wed",
                                         "Thu", "Fri", "Sat"};
    static const char *const mo_full[12] = {
        "January", "February", "March",     "April",   "May",      "June",
        "July",    "August",   "September", "October", "November", "December"};
    static const char *const mo_ab[12] = {"Jan", "Feb", "Mar", "Apr",
                                          "May", "Jun", "Jul", "Aug",
                                          "Sep", "Oct", "Nov", "Dec"};
    const char *p = s;
    int v, pm = -1;
    if (!s || !fmt || !tm) return 0;
    while (*fmt) {
        if (*fmt == ' ' || *fmt == '\t' || *fmt == '\n') {
            while (*p == ' ' || *p == '\t' || *p == '\n') p++;
            fmt++;
            continue;
        }
        if (*fmt != '%') {
            if (*p != *fmt) return 0;
            p++;
            fmt++;
            continue;
        }
        fmt++;
        switch (*fmt) {
        case 'a':
            if (ml_sp_word(&p, wd_ab, 7, &v) != 0) return 0;
            tm->tm_wday = v;
            break;
        case 'A':
            if (ml_sp_word(&p, wd_full, 7, &v) != 0) return 0;
            tm->tm_wday = v;
            break;
        case 'b':
        case 'h':
            if (ml_sp_word(&p, mo_ab, 12, &v) != 0) return 0;
            tm->tm_mon = v;
            break;
        case 'B':
            if (ml_sp_word(&p, mo_full, 12, &v) != 0) return 0;
            tm->tm_mon = v;
            break;
        case 'c':
            /* "%a %b %e %H:%M:%S %Y" shape. */
            if (ml_sp_word(&p, wd_ab, 7, &v) != 0) return 0;
            tm->tm_wday = v;
            while (*p == ' ') p++;
            if (ml_sp_word(&p, mo_ab, 12, &v) != 0) return 0;
            tm->tm_mon = v;
            while (*p == ' ') p++;
            if (ml_sp_num(&p, 1, 31, &v) != 0) return 0;
            tm->tm_mday = v;
            while (*p == ' ') p++;
            if (ml_sp_num(&p, 0, 23, &v) != 0) return 0;
            tm->tm_hour = v;
            if (*p++ != ':') return 0;
            if (ml_sp_num(&p, 0, 59, &v) != 0) return 0;
            tm->tm_min = v;
            if (*p++ != ':') return 0;
            if (ml_sp_num(&p, 0, 60, &v) != 0) return 0;
            tm->tm_sec = v;
            while (*p == ' ') p++;
            if (ml_sp_num(&p, 0, 9999, &v) != 0) return 0;
            tm->tm_year = v - 1900;
            break;
        case 'd':
        case 'e':
            if (*p == ' ') p++;
            if (ml_sp_num(&p, 1, 31, &v) != 0) return 0;
            tm->tm_mday = v;
            break;
        case 'D': /* %m/%d/%y */
            if (ml_sp_num(&p, 1, 12, &v) != 0) return 0;
            tm->tm_mon = v - 1;
            if (*p++ != '/') return 0;
            if (ml_sp_num(&p, 1, 31, &v) != 0) return 0;
            tm->tm_mday = v;
            if (*p++ != '/') return 0;
            if (ml_sp_num(&p, 0, 99, &v) != 0) return 0;
            tm->tm_year = (v < 69 ? 2000 + v : 1900 + v) - 1900;
            break;
        case 'F': /* %Y-%m-%d */
            if (ml_sp_num(&p, 0, 9999, &v) != 0) return 0;
            tm->tm_year = v - 1900;
            if (*p++ != '-') return 0;
            if (ml_sp_num(&p, 1, 12, &v) != 0) return 0;
            tm->tm_mon = v - 1;
            if (*p++ != '-') return 0;
            if (ml_sp_num(&p, 1, 31, &v) != 0) return 0;
            tm->tm_mday = v;
            break;
        case 'H':
        case 'k':
            if (*p == ' ') p++;
            if (ml_sp_num(&p, 0, 23, &v) != 0) return 0;
            tm->tm_hour = v;
            break;
        case 'I':
        case 'l':
            if (*p == ' ') p++;
            if (ml_sp_num(&p, 1, 12, &v) != 0) return 0;
            tm->tm_hour = v % 12;
            if (pm == 1) tm->tm_hour += 12;
            else if (pm == -1) tm->tm_hour = v % 12; /* fixed by %p */
            break;
        case 'j':
            if (ml_sp_num(&p, 1, 366, &v) != 0) return 0;
            tm->tm_yday = v - 1;
            break;
        case 'm':
            if (ml_sp_num(&p, 1, 12, &v) != 0) return 0;
            tm->tm_mon = v - 1;
            break;
        case 'M':
            if (ml_sp_num(&p, 0, 59, &v) != 0) return 0;
            tm->tm_min = v;
            break;
        case 'p':
            if ((*p == 'A' || *p == 'a') && (p[1] == 'M' || p[1] == 'm')) {
                pm = 0;
                p += 2;
            } else if ((*p == 'P' || *p == 'p') &&
                       (p[1] == 'M' || p[1] == 'm')) {
                pm = 1;
                p += 2;
            } else {
                return 0;
            }
            if (tm->tm_hour < 12 && pm == 1) tm->tm_hour += 12;
            break;
        case 'R': /* %H:%M */
            if (ml_sp_num(&p, 0, 23, &v) != 0) return 0;
            tm->tm_hour = v;
            if (*p++ != ':') return 0;
            if (ml_sp_num(&p, 0, 59, &v) != 0) return 0;
            tm->tm_min = v;
            break;
        case 'S':
            if (ml_sp_num(&p, 0, 60, &v) != 0) return 0;
            tm->tm_sec = v;
            break;
        case 's': {
            long long t = 0;
            int neg = 0;
            if (*p == '-') {
                neg = 1;
                p++;
            }
            if (*p < '0' || *p > '9') return 0;
            while (*p >= '0' && *p <= '9') {
                t = t * 10 + (*p - '0');
                p++;
            }
            {
                time_t tt = (time_t)(neg ? -t : t);
                ml_break_r(tt, tm);
            }
            break;
        }
        case 'T': /* %H:%M:%S */
            if (ml_sp_num(&p, 0, 23, &v) != 0) return 0;
            tm->tm_hour = v;
            if (*p++ != ':') return 0;
            if (ml_sp_num(&p, 0, 59, &v) != 0) return 0;
            tm->tm_min = v;
            if (*p++ != ':') return 0;
            if (ml_sp_num(&p, 0, 60, &v) != 0) return 0;
            tm->tm_sec = v;
            break;
        case 'u':
            if (ml_sp_num(&p, 1, 7, &v) != 0) return 0;
            tm->tm_wday = v % 7;
            break;
        case 'w':
            if (ml_sp_num(&p, 0, 6, &v) != 0) return 0;
            tm->tm_wday = v;
            break;
        case 'y':
            if (ml_sp_num(&p, 0, 99, &v) != 0) return 0;
            tm->tm_year = (v < 69 ? 2000 + v : 1900 + v) - 1900;
            break;
        case 'Y':
            if (ml_sp_num(&p, 0, 9999, &v) != 0) return 0;
            tm->tm_year = v - 1900;
            break;
        case 'z':
            /* Numeric zone: accept, convert to UTC shift. */
            if (*p == '+' || *p == '-') {
                int zh = 0, zm = 0, k;
                char sgn = *p++;
                for (k = 0; k < 2 && *p >= '0' && *p <= '9'; k++)
                    zh = zh * 10 + (*p++ - '0');
                if (k != 2) return 0;
                if (*p == ':') p++;
                for (k = 0; k < 2 && *p >= '0' && *p <= '9'; k++)
                    zm = zm * 10 + (*p++ - '0');
                (void)zh;
                (void)zm;
                (void)sgn;
            } else if (*p == 'Z' || *p == 'z') {
                p++;
            } else {
                return 0;
            }
            break;
        case 'Z':
            while ((*p >= 'A' && *p <= 'Z') ||
                   (*p >= 'a' && *p <= 'z') || *p == '_' || *p == '/' ||
                   (*p >= '0' && *p <= '9') || *p == '+' || *p == '-')
                p++;
            break;
        case '%':
            if (*p++ != '%') return 0;
            break;
        default:
            return 0; /* unsupported directive: hard fail (honest) */
        }
        if (*fmt) fmt++;
    }
    return (char *)p;
}

/* ---- interval timers: deadlines checked at yield boundaries ---- */

static long long ml_itimer_deadline[3] = {-1, -1, -1};
static long long ml_itimer_interval[3] = {0, 0, 0};

static long long ml_now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* Raised from sched_yield (see unistd.c): fires expired timers. */
void __ml_itimer_check(void) {
    long long now = ml_now_ns();
    int i;
    if (now < 0) return;
    for (i = 0; i < 3; i++) {
        if (ml_itimer_deadline[i] < 0) continue;
        if (now < ml_itimer_deadline[i]) continue;
        if (i == 0) raise(14); /* SIGALRM */
        else if (i == 1) raise(26); /* SIGVTALRM */
        else raise(27); /* SIGPROF */
        if (ml_itimer_interval[i] > 0)
            ml_itimer_deadline[i] = now + ml_itimer_interval[i];
        else ml_itimer_deadline[i] = -1;
    }
}

int setitimer(int which, const void *newv, void *oldv) {
    const struct itimerval *n = newv;
    struct itimerval *o = oldv;
    long long now;
    if (which < 0 || which > 2) {
        errno = EINVAL;
        return -1;
    }
    now = ml_now_ns();
    if (now < 0) return -1;
    if (o) {
        long long left = ml_itimer_deadline[which] - now;
        if (ml_itimer_deadline[which] < 0) left = 0;
        if (left < 0) left = 0;
        o->it_value.tv_sec = left / 1000000000LL;
        o->it_value.tv_usec = (left % 1000000000LL) / 1000;
        o->it_interval.tv_sec = ml_itimer_interval[which] / 1000000000LL;
        o->it_interval.tv_usec =
            (ml_itimer_interval[which] % 1000000000LL) / 1000;
    }
    if (n) {
        long long v =
            n->it_value.tv_sec * 1000000000LL + n->it_value.tv_usec * 1000LL;
        long long iv = n->it_interval.tv_sec * 1000000000LL +
                       n->it_interval.tv_usec * 1000LL;
        if (n->it_value.tv_sec < 0 || n->it_value.tv_usec < 0 ||
            n->it_value.tv_usec >= 1000000 ||
            n->it_interval.tv_sec < 0 || n->it_interval.tv_usec < 0 ||
            n->it_interval.tv_usec >= 1000000) {
            errno = EINVAL;
            return -1;
        }
        ml_itimer_interval[which] = iv;
        ml_itimer_deadline[which] = v <= 0 ? -1 : now + v;
    }
    return 0;
}

int getitimer(int which, void *cur) {
    return setitimer(which, 0, cur);
}

unsigned ualarm(unsigned us, unsigned interval) {
    struct itimerval n, o;
    n.it_value.tv_sec = (long)(us / 1000000u);
    n.it_value.tv_usec = (long)(us % 1000000u);
    n.it_interval.tv_sec = (long)(interval / 1000000u);
    n.it_interval.tv_usec = (long)(interval % 1000000u);
    if (setitimer(0, &n, &o) != 0) return 0;
    return (unsigned)(o.it_value.tv_sec * 1000000L + o.it_value.tv_usec);
}

/* ---- getdate: DATEMSK template list over strptime ---- */

#include <stdlib.h>

struct tm *getdate(const char *s) {
    static struct tm tm;
    const char *mask;
    FILE *fp;
    char line[256];
    if (!s) {
        errno = EINVAL;
        return 0;
    }
    mask = getenv("DATEMSK");
    if (!mask || !*mask) {
        errno = EINVAL; /* getdate_err = 1 */
        return 0;
    }
    fp = fopen(mask, "r");
    if (!fp) return 0;
    while (fgets(line, sizeof(line), fp)) {
        char *nl;
        struct tm cand;
        memset(&cand, 0, sizeof(cand));
        nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (!line[0] || line[0] == '#') continue;
        if (strptime(s, line, &cand)) {
            fclose(fp);
            tm = cand;
            return &tm;
        }
    }
    fclose(fp);
    errno = EINVAL; /* getdate_err = 7/8 (no match) */
    return 0;
}

int getdate_err = 0;
