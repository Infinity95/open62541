/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. 
 *
 *    Copyright 2016-2017 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2017 (c) Thomas Stalder, Blue Time Concept SA
 */

#ifdef UA_ARCHITECTURE_POSIX

#include <open62541/types.h>

#include <time.h>
#include <sys/time.h>

#if defined(__APPLE__) || defined(__MACH__)
# include <mach/clock.h>
# include <mach/mach.h>
#endif

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
/* To avoid zero timestamp value in header, the testingClock
 * is assigned with non-zero timestamp to pass unit tests */
static UA_DateTime testingClock = 0x5C8F735D;

void UA_sleep_ms(unsigned long ms) {
    testingClock += ms * UA_DATETIME_MSEC;
}

UA_DateTime UA_DateTime_now(void) {
    return testingClock;
}

UA_DateTime UA_DateTime_nowMonotonic(void) {
    return testingClock;
}

UA_DateTime UA_DateTime_localTimeUtcOffset(void) {
    return 0;
}

#else
UA_DateTime UA_DateTime_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * UA_DATETIME_SEC) + (tv.tv_usec * UA_DATETIME_USEC) + UA_DATETIME_UNIX_EPOCH;
}

/* Credit to https://stackoverflow.com/questions/13804095/get-the-time-zone-gmt-offset-in-c */
UA_Int64 UA_DateTime_localTimeUtcOffset(void) {
    time_t gmt, rawtime = time(NULL);
    struct tm *ptm;
    struct tm gbuf;
    ptm = gmtime_r(&rawtime, &gbuf);
    // Request that mktime() looksup dst in timezone database
    ptm->tm_isdst = -1;
    gmt = mktime(ptm);
    return (UA_Int64) (difftime(rawtime, gmt) * UA_DATETIME_SEC);
}

UA_DateTime UA_DateTime_nowMonotonic(void) {
#if defined(__APPLE__) || defined(__MACH__)
    /* OS X does not have clock_gettime, use clock_get_time */
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    return (mts.tv_sec * UA_DATETIME_SEC) + (mts.tv_nsec / 100);
#elif !defined(CLOCK_MONOTONIC_RAW)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * UA_DATETIME_SEC) + (ts.tv_nsec / 100);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (ts.tv_sec * UA_DATETIME_SEC) + (ts.tv_nsec / 100);
#endif
}

#endif // FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

#endif /* UA_ARCHITECTURE_POSIX */
