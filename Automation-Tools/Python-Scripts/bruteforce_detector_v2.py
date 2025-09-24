#!/usr/bin/env python3
# bruteforce_detector_v2.py
# Usage: python3 bruteforce_detector_v2.py auth.log 5 300
#  - threshold: number of attempts
#  - window: seconds window to consider (if timestamps parseable)
# If timestamps can't be parsed reliably, falls back to counting occurrences per IP.

import sys, re, collections, datetime

if len(sys.argv) < 4:
    print("Usage: python3 bruteforce_detector_v2.py <logfile> <threshold> <window_seconds>")
    sys.exit(1)

logfile, thresh, window = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])

# Patterns for failure-like messages (extend if needed)
failure_patterns = [
    r'Failed password', 
    r'authentication failure',
    r'Invalid user',
    r'Failed login',
    r'failed login',
    r'authentication failure for',
    r'error: PAM: Authentication failure'
]
failure_regex = re.compile("|".join(failure_patterns), re.IGNORECASE)

# Regex to pull IPv4 addresses
ip_regex = re.compile(r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3})')

# Try to parse classic syslog timestamp: "Sep 23 12:34:56"
syslog_ts_re = re.compile(r'^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')

events = []  # (ip, datetime) for lines we can timestamp
counts = collections.Counter()  # fallback counting if timestamps fail

with open(logfile, errors='ignore') as f:
    for line in f:
        if not failure_regex.search(line):
            continue
        ipm = ip_regex.search(line)
        if not ipm:
            continue
        ip = ipm.group('ip')
        counts[ip] += 1

        # try to parse syslog style timestamp
        m = syslog_ts_re.match(line.strip())
        if m:
            ts = m.group('ts') + f" {datetime.datetime.now().year}"
            try:
                dt = datetime.datetime.strptime(ts, "%b %d %H:%M:%S %Y")
                events.append((ip, dt))
            except Exception:
                pass
        else:
            # try ISO-like timestamp
            iso_re = re.compile(r'(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')
            im = iso_re.search(line)
            if im:
                try:
                    dt = datetime.datetime.strptime(im.group('iso'), "%Y-%m-%dT%H:%M:%S")
                    events.append((ip, dt))
                except Exception:
                    pass

# If we got timestamped events, do sliding-window detection per IP
if events:
    events.sort(key=lambda x: (x[0], x[1]))
    byip = collections.defaultdict(list)
    for ip, dt in events:
        byip[ip].append(dt)

    alerts = []
    for ip, times in byip.items():
        i = 0
        for j in range(len(times)):
            while (times[j] - times[i]).total_seconds() > window:
                i += 1
            if (j - i + 1) >= thresh:
                alerts.append((ip, times[i], times[j], j - i + 1))
                break

    if alerts:
        for ip, start, end, count in alerts:
            print(f"ALERT: {ip} | attempts={count} | window={start} -> {end}")
    else:
        print("No sliding-window brute-force patterns found. Showing top counts as fallback:")
        for ip, c in counts.most_common(10):
            print(f"{c:4d} attempts - {ip}")
else:
    print("No parseable timestamps found. Falling back to simple counts:")
    for ip, c in counts.most_common(20):
        status = "SUSPICIOUS" if c >= thresh else ""
        print(f"{c:4d} attempts - {ip} {status}")
