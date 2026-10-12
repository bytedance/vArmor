#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Bounded incremental collection; invoked by advisor.py, no third-party packages."""
import collections
import concurrent.futures
import contextlib
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import re
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import uuid


BLOCK = 65536
MAX_LINE = 1024 * 1024
LIST_FILES = '''command -v stat >/dev/null && command -v dd >/dev/null || exit 1
for f in "$1"/violations*.log; do
  [ -f "$f" ] || continue
  printf '%s\\t' "$f"
  stat -c '%d:%i %s' "$f" || exit 1
done'''
READ_BYTES = 'dd if="$1" bs=65536 skip="$2" count="$3" 2>/dev/null | head -c "$4" | tail -c "$5"'
READ_BATCH = '''command -v stat >/dev/null && command -v dd >/dev/null && command -v head >/dev/null || exit 1
directory="$1"; initialize="$2"; budget="$3"; shift 3
for f in "$directory"/violations*.log; do
  [ -f "$f" ] || continue
  info=$(stat -c '%d:%i %s' "$f") || exit 1
  identity=${info% *}; size=${info##* }; offset=0
  for checkpoint in "$@"; do
    [ "${checkpoint%:*}" = "$identity" ] && offset=${checkpoint##*:}
  done
  [ "$initialize" = 1 ] && offset="$size"
  [ "$offset" -gt "$size" ] && offset=0
  wanted=$((size-offset))
  [ "$wanted" -gt "$budget" ] && wanted="$budget"
  [ "$initialize" = 1 ] && wanted=0
  start=$((offset>64 ? offset-64 : 0))
  length=$((offset-start+wanted)); within=$((start%65536)); blocks=$(((within+length+65535)/65536))
  printf '%s\\t%s\\t%s\\t%s\\t%s\\n' "$f" "$identity" "$size" "$start" "$length"
  if [ "$length" -gt 0 ]; then
    dd if="$f" bs=65536 skip=$((start/65536)) count="$blocks" 2>/dev/null | head -c $((within+length)) | tail -c "$length"
  fi
  budget=$((budget-wanted))
done'''

# Reserve framing and 64-byte fingerprints for every retained file. The outer
# head is an additional transport bound, including unexpected file growth.
READ_CAPPED_BATCH = READ_BATCH.replace('shift 3\n', '''shift 3
count=0
for f in "$directory"/violations*.log; do [ ! -f "$f" ] || count=$((count+1)); done
budget=$((budget-count*576))
[ "$budget" -ge 0 ] || exit 3
''')


class ResourceLimit(RuntimeError):
    """The collector must wait or report incomplete evidence, never raise its cap."""


class ResourceBudget:
    """Rolling audit-exec stdout quota, including framing, overlap and retries.

    API/watch/TLS protocol bytes and CPU are not measurable by this helper.
    A workflow has one collector lease; its ledger survives phase changes.
    Reservations survive crashes conservatively for one round plus one minute.
    """
    def __init__(self, limit, ledger=None, api=None, round_seconds=30, clock=time.time):
        self.limit, self.ledger, self.api = int(limit), ledger, api
        self.clock, self.round_seconds = clock, round_seconds
        self.lock = threading.Condition()
        old = api['load'](ledger) if ledger and ledger.exists() else {}
        self.charges = old.get('charges', [])
        self.total = old.get('totalBytes', 0)
        self.limited = old.get('limitedAttempts', 0)
        self.active = set()
        self.peak = old.get('peakConcurrentReads', 0)

    def _save(self):
        if self.ledger:
            self.api['write'](self.ledger, self.snapshot_unlocked())

    def _prune(self):
        self.charges = [c for c in self.charges if c['id'] in self.active or c['at'] > self.clock() - 60]

    def reserve(self, requested, deadline):
        with self.lock:
            while True:
                self._prune()
                available = self.limit - sum(c['bytes'] for c in self.charges)
                if available >= 4096:
                    amount = min(int(requested), available)
                    key = uuid.uuid4().hex
                    self.charges.append({'id': key, 'bytes': amount, 'at': self.clock() + self.round_seconds})
                    self.active.add(key)
                    self.peak = max(self.peak, len(self.active))
                    self._save()
                    return key, amount
                if not self.active or time.monotonic() >= deadline:
                    self.limited += 1
                    self._save()
                    raise ResourceLimit('Audit transfer quota reached; keep the agreed limit and report backlog')
                self.lock.wait(timeout=min(0.2, max(0, deadline - time.monotonic())))

    def finish(self, key, actual=None):
        with self.lock:
            charge = next(c for c in self.charges if c['id'] == key)
            if actual is not None:
                if not 0 <= actual <= charge['bytes']:
                    raise ResourceLimit('Audit response exceeded reserved transport bytes')
                charge['bytes'] = actual
            charge['at'] = self.clock()
            self.total += charge['bytes']
            self.active.remove(key)
            self._save()
            self.lock.notify_all()

    def snapshot_unlocked(self):
        self._prune()
        return {'limitBytesPerMinute': self.limit, 'windowBytes': sum(c['bytes'] for c in self.charges),
                'totalBytes': self.total, 'limitedAttempts': self.limited,
                'peakConcurrentReads': self.peak, 'charges': self.charges,
                'scope': 'audit exec stdout; excludes Kubernetes/watch/transport overhead and CPU',
                'storageRoots': getattr(self, 'storage_roots', [])}

    def snapshot(self):
        with self.lock:
            return self.snapshot_unlocked()


def schema(con):
    con.execute('''CREATE TABLE IF NOT EXISTS cursors (
        source TEXT, identity TEXT, value TEXT NOT NULL, PRIMARY KEY(source, identity))''')
    con.execute('''CREATE TABLE IF NOT EXISTS gaps (
        id TEXT PRIMARY KEY, value TEXT NOT NULL)''')


def issue(con, source, kind, severity, **detail):
    """One durable issue per condition, without storing raw audit text."""
    value = {'source': source, 'kind': kind, 'severity': severity, **detail}
    key = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
    value['detectedAt'] = dt.datetime.now(dt.timezone.utc).isoformat()
    con.execute('INSERT OR IGNORE INTO gaps VALUES (?,?)', (key, json.dumps(value)))


def health(con):
    schema(con)
    gaps = [json.loads(r[0]) for r in con.execute('SELECT value FROM gaps ORDER BY rowid')]
    counts = collections.Counter(g['severity'] for g in gaps)
    pending = con.execute('SELECT count(*) FROM pending_pods').fetchone()[0]
    return {'status': 'confirmed-gap' if counts['confirmed'] else
            'suspected-gap' if counts['suspected'] else 'identity-incomplete' if pending else 'no-detected-gap',
            'unresolvedPodEvents': pending,
            'issues': gaps, 'scope': 'log-source; target event loss/count may be unknown',
            'upstreamLossDetection': 'unavailable: file continuity cannot detect events dropped before file writing'}


def resolve_pending(con, state, api):
    stats = collections.Counter()
    for key, raw in con.execute('SELECT id,record FROM pending_pods').fetchall():
        uid = json.loads(raw).get('podUID')
        if uid in state.get('baselinePodUIDs', []) or uid in state['podUIDs']:
            stats.update(api['ingest'](con, state, [('pending', raw)], identities=[key]))
            con.execute('DELETE FROM pending_pods WHERE id=?', (key,))
    return dict(stats)


def register_pod(state, pod):
    """Persist immutable identities, including Pods deleted before the next file scan."""
    meta, spec = pod.get('metadata', {}), pod.get('spec', {})
    uid = meta.get('uid')
    if state.get('purpose') == 'verification' and uid not in state.get('verifiedPodUIDs', []):
        return
    if not uid or meta.get('annotations', {}).get('pod.networkproxy.security.beta.varmor.org') != 'localhost/' + state['profile']:
        return
    if state.get('purpose') != 'verification' and meta.get('creationTimestamp') and state.get('observationEpoch'):
        created = dt.datetime.fromisoformat(meta['creationTimestamp'].replace('Z', '+00:00'))
        if created.timestamp() < state['startedAt']:
            state['baselinePodUIDs'] = sorted(set(state.get('baselinePodUIDs', [])) | {uid})
            return
    if not any(c['name'] == 'varmor-network-proxy' for c in spec.get('containers', [])):
        return
    if uid in state.get('baselinePodUIDs', []):
        return
    state['podUIDs'] = sorted(set(state.get('podUIDs', [])) | {uid})
    regular = any(v.get('hostPath') for v in spec.get('volumes', [])
                  if v.get('name') == 'varmor-network-proxy-audit-als')
    state.setdefault('podHistory', {})[uid] = {
        'name': meta['name'], 'node': spec.get('nodeName'), 'regular': regular,
        'createdAt': meta.get('creationTimestamp'),
        'proxyRestartCount': next((c.get('restartCount', 0) for c in
            pod.get('status', {}).get('containerStatuses', []) if c['name'] == 'varmor-network-proxy'), 0)}


class PodWatch:
    """Watch from LIST resourceVersion; never silently accept a broken discovery stream."""
    def __init__(self, context, namespace, resource_version, deadline):
        self.context, self.namespace, self.rv = context, namespace, resource_version
        self.deadline = deadline
        self.events = queue.Queue(maxsize=10000)
        self.done = threading.Event()
        self.process = None
        self.overflow = False
        self.thread = threading.Thread(target=self.run, daemon=True)

    def put(self, event):
        try:
            self.events.put_nowait(event)
        except queue.Full:
            self.overflow = True

    def start(self):
        self.thread.start()

    def run(self):
        # The main loop also LISTs every discovery interval, for recovery and status.
        # A closed watch is reported; LIST cannot recover already deleted short-lived Pods.
        decoder = json.JSONDecoder()
        while not self.done.is_set() and time.monotonic() < self.deadline:
            argv = ['kubectl', '--context', self.context, '--request-timeout=0', 'get', 'pods',
                    '-n', self.namespace, '--watch-only', '--output-watch-events', '-o', 'json']
            if self.rv:
                argv += ['--resource-version', self.rv]
            try:
                with tempfile_stderr() as err:
                    self.process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=err)
                    buffer = b''
                    while not self.done.is_set():
                        chunk = self.process.stdout.read1(65536)
                        if not chunk:
                            break
                        buffer += chunk
                        if len(buffer) > 8 * MAX_LINE:
                            raise ValueError('Pod watch object exceeds buffer limit')
                        while buffer.strip():
                            try:
                                text = buffer.decode('utf-8')
                                value, end = decoder.raw_decode(text.lstrip())
                            except (ValueError, UnicodeDecodeError):
                                break
                            consumed = len(text) - len(text.lstrip()) + end
                            buffer = text[consumed:].encode('utf-8')
                            if value.get('type') == 'ERROR':
                                self.put(('error', 'Pod watch server error; discovery continuity is uncertain'))
                                self.rv = None
                            else:
                                obj = value.get('object', {})
                                self.rv = obj.get('metadata', {}).get('resourceVersion', self.rv)
                                self.put(('pod', obj))
                    code = self.process.wait()
                    if not self.done.is_set() and (code or buffer.strip()):
                        self.put(('error', 'Pod watch disconnected; short-lived Pod discovery may be incomplete'))
            except (OSError, ValueError) as exc:
                self.put(('error', str(exc)))
            finally:
                if self.process and self.process.poll() is None:
                    self.process.terminate()
                    self.process.wait()
                if self.process and self.process.stdout:
                    self.process.stdout.close()
            self.done.wait(1)

    def drain(self):
        result = []
        if self.overflow:
            result.append(('error', 'Pod watch queue overflowed'))
            self.overflow = False
        while True:
            try:
                result.append(self.events.get_nowait())
            except queue.Empty:
                return result

    def close(self):
        self.done.set()
        if self.process and self.process.poll() is None:
            self.process.terminate()
        self.thread.join(timeout=3)


@contextlib.contextmanager
def tempfile_stderr():
    # Keep kubectl diagnostics off stdout and never accumulate them in memory.
    with open(os.devnull, 'wb') as stream:
        yield stream


def parse_manifest(raw, directory):
    files = {}
    for line in raw.splitlines():
        path, info = line.split('\t', 1)
        identity, size = info.split()
        if not re.fullmatch(re.escape(directory) + r'/violations[^/\x00-\x1f]*\.log', path) or \
           not re.fullmatch(r'\d+:\d+', identity) or not size.isdigit():
            raise ValueError('Invalid audit file metadata')
        if identity not in files or path.endswith('/violations.log'):
            files[identity] = {'path': path, 'size': int(size)}
    return files


def endpoints(api, state, args):
    """Warm all Agent nodes before handoff; retain nodes after target deletion/migration."""
    output = []
    if args.source in ('auto', 'agent'):
        argv = ['get', 'pods', '-n', args.agent_namespace]
        if args.agent_selector:
            argv += ['-l', args.agent_selector]
        agents = json.loads(api['kube'](state['context'], *argv, '-o', 'json'))['items']
        selected = collections.defaultdict(list)
        for p in agents:
            if p['metadata'].get('deletionTimestamp') or not p['spec'].get('nodeName'):
                continue
            for c in p['spec']['containers']:
                detected = any(t in ('--agent', '-agent', '--agent=true', '-agent=true')
                               for t in c.get('command', []) + c.get('args', []))
                if (not args.agent_container and detected) or (args.agent_container == c['name'] and
                                                               (args.agent_selector or detected)):
                    selected[p['spec']['nodeName']].append((p, c['name']))
        for node, choices in sorted(selected.items()):
            if len(choices) != 1:
                raise RuntimeError('Ambiguous vArmor Agent on node ' + node)
            p, container = choices[0]
            output.append({'id': 'node/' + node, 'directory': '/var/log/varmor',
                'prefix': ['exec', '-n', args.agent_namespace, p['metadata']['name'], '-c', container]})
        required = {v['node'] for v in state.get('podHistory', {}).values() if v['regular'] and v['node']}
        if required:
            output = [e for e in output if e['id'][5:] in required]
        for node in required - set(selected):
            output.append({'id': 'node/' + node, 'unavailable': 'No Agent endpoint on historical target node'})
        if args.source == 'agent' and not output:
            raise RuntimeError('No vArmor Agent endpoints; set namespace/selector/container or choose sidecar')
    if args.source in ('auto', 'sidecar'):
        for uid, p in sorted(state.get('podHistory', {}).items()):
            if args.source == 'auto' and p['regular']:
                continue
            output.append({'id': 'pod/' + uid, 'directory': '/var/log/varmor',
                'podUID': uid, 'podName': p['name'],
                'prefix': ['exec', '-n', state['namespace'], p['name'], '-c', 'varmor-network-proxy']})
    return output


class Reader:
    def __init__(self, api, state):
        self.api, self.state = api, state
        self.cache = {}
        self.resource_budget = None
        self.max_concurrent = 5
        self.read_started = {}

    def transfer(self, endpoint, script, argv, requested):
        if self.resource_budget is None:
            return self.api['kube'](self.state['context'], *endpoint['prefix'], '--', 'sh', '-c',
                                    script, *argv, binary=True)
        end = self.api['kube'].__globals__['KUBE_DEADLINE'] or time.monotonic() + 30
        key, cap = self.resource_budget.reserve(requested, end)
        try:
            wrapper = 'script="$1"; cap="$2"; shift 2; sh -c "$script" "$@" | head -c "$cap"'
            raw = self.api['kube'](self.state['context'], *endpoint['prefix'], '--', 'sh', '-c',
                wrapper, 'bounded-audit', script, str(cap), *argv, binary=True)
        except BaseException:
            self.resource_budget.finish(key)  # Unknown partial transfer consumes its reservation.
            raise
        self.resource_budget.finish(key, len(raw))
        return raw

    def prepare(self, endpoint, cursors, budget, initialize):
        if endpoint.get('unavailable'):
            raise RuntimeError(endpoint['unavailable'])
        if any(not re.fullmatch(r'\d+:\d+', identity) or type(cur.get('offset')) is not int or
               not 0 <= cur['offset'] < 2**63 for identity, cur in cursors.items()):
            raise ValueError('Invalid persisted audit checkpoint')
        if endpoint.get('podUID'):
            actual = self.api['get'](self.state['context'], 'pods', self.state['namespace'], endpoint['podName'])
            if actual['metadata']['uid'] != endpoint['podUID']:
                raise RuntimeError('Sidecar Pod name was reused with a different UID; old logs are unavailable')
        checkpoints = [identity + ':' + str(cur['offset']) for identity, cur in cursors.items()]
        self.read_started[endpoint['id']] = self.api.get('now', lambda: dt.datetime.now(dt.timezone.utc).isoformat())()
        if self.resource_budget:
            # The shell must use the actual reservation, not the larger requested grant.
            script = 'cap="$1"; shift; ' + READ_CAPPED_BATCH.replace('budget="$3"', 'budget="$cap"') + '\nprintf "__COMPLETE__\\n"'
            end = self.api['kube'].__globals__['KUBE_DEADLINE'] or time.monotonic() + 30
            key, cap = self.resource_budget.reserve(max(4096, budget + 4096), end)
            try:
                wrapper = 'script="$1"; cap="$2"; shift 2; sh -c "$script" audit-batch "$cap" "$@" | head -c "$cap"'
                raw = self.api['kube'](self.state['context'], *endpoint['prefix'], '--', 'sh', '-c', wrapper,
                    'bounded-audit', script, str(cap), endpoint['directory'], '1' if initialize else '0',
                    str(cap), *checkpoints, binary=True)
            except BaseException:
                self.resource_budget.finish(key)
                raise
            self.resource_budget.finish(key, len(raw))
            if not raw.endswith(b'__COMPLETE__\n'):
                raise ResourceLimit('Audit batch cannot fit the byte quota; do not treat a partial file list as complete')
            raw = raw[:-len(b'__COMPLETE__\n')]
        else:
            raw = self.api['kube'](self.state['context'], *endpoint['prefix'], '--', 'sh', '-c', READ_BATCH,
                'audit-batch', endpoint['directory'], '1' if initialize else '0', str(budget), *checkpoints, binary=True)
        files, chunks = {}, {}
        new_bytes = 0
        while raw:
            header, raw = raw.split(b'\n', 1)
            path, identity, size, start, length = header.decode('utf-8').split('\t')
            parsed = parse_manifest(path + '\t' + identity + ' ' + size, endpoint['directory'])
            start, length = int(start), int(length)
            if min(start, length) < 0 or length > len(raw):
                raise ValueError('Incomplete audit batch; file may have changed during read')
            if identity not in files or path.endswith('/violations.log'):
                files.update(parsed)
            chunks[path] = (start, raw[:length])
            old_offset = min(cursors.get(identity, {}).get('offset', 0), int(size))
            new_bytes += max(0, start + length - max(start, old_offset))
            raw = raw[length:]
        self.cache[endpoint['id']] = (files, chunks)
        return new_bytes

    def manifest(self, endpoint):
        if endpoint['id'] in self.cache:
            return self.cache[endpoint['id']][0]
        if endpoint.get('unavailable'):
            raise RuntimeError(endpoint['unavailable'])
        if endpoint.get('podUID'):
            actual = self.api['get'](self.state['context'], 'pods', self.state['namespace'], endpoint['podName'])
            if actual['metadata']['uid'] != endpoint['podUID']:
                raise RuntimeError('Sidecar Pod name was reused with a different UID; old logs are unavailable')
        raw = self.api['kube'](self.state['context'], *endpoint['prefix'], '--', 'sh', '-c',
                               LIST_FILES, 'audit-files', endpoint['directory'])
        return parse_manifest(raw, endpoint['directory'])

    def read(self, endpoint, path, offset, length):
        if length <= 0:
            return b''
        if endpoint['id'] in self.cache:
            start, raw = self.cache[endpoint['id']][1].get(path, (0, b''))
            if start <= offset and offset + length <= start + len(raw):
                return raw[offset - start:offset - start + length]
        block, within = divmod(offset, BLOCK)
        count = (within + length + BLOCK - 1) // BLOCK
        raw = self.transfer(endpoint, READ_BYTES,
            ['audit-bytes', path, str(block), str(count), str(within + length), str(length)], length)
        return raw[:length]


def prefetch(con, reader, targets, budget, initialize=False):
    """Independent exec reads run concurrently; SQLite commits remain on the main thread."""
    if not hasattr(reader, 'prepare'):
        return {}, {e['id']: budget for e in targets}  # In-memory test adapter.
    grants = {e['id']: 0 for e in targets}
    if targets and not initialize:
        grants[targets[0]['id']] = min(budget, 2 * MAX_LINE)
        remainder = budget - grants[targets[0]['id']]
        for endpoint in targets[1:]:
            grants[endpoint['id']] = remainder // max(1, len(targets) - 1)
    checkpoints = {e['id']: {r[0]: json.loads(r[1]) for r in con.execute(
        'SELECT identity,value FROM cursors WHERE source=?', (e['id'],))} for e in targets}
    errors = {}
    reader.cache.clear()
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(reader.max_concurrent, max(1, len(targets)))) as pool:
        work = {pool.submit(reader.prepare, e, checkpoints[e['id']], grants[e['id']], initialize): e['id'] for e in targets}
        for future, source in work.items():
            try:
                available = future.result()
                if available is not None:
                    grants[source] = min(grants[source], available)
            except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
                errors[source] = exc
    return errors, grants


def save_cursor(con, source, identity, value):
    con.execute('INSERT OR REPLACE INTO cursors VALUES (?,?,?)', (source, identity, json.dumps(value)))


@contextlib.contextmanager
def session_lock(api, root):
    deadline = api['kube'].__globals__['KUBE_DEADLINE']
    deadline = deadline if deadline is not None else time.monotonic() + 30
    while True:
        lock = api['locked'](root)
        try:
            lock.__enter__()
            break
        except RuntimeError as exc:
            if 'busy' not in str(exc):
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError('Session remained busy until the observation deadline') from exc
            time.sleep(0.1)
    try:
        yield
    finally:
        lock.__exit__(None, None, None)


def local_analysis(api, args, final=False):
    end = time.monotonic() + (30 if final else 0)
    while True:
        try:
            api['analyze'](args)
            return True
        except RuntimeError as exc:
            if 'busy' not in str(exc):
                raise
            if time.monotonic() >= end:
                return False
            time.sleep(0.1)


def scan(con, state, reader, endpoint, budget, initialize=False):
    """Commit event insertions and file offsets together; re-read incomplete tails."""
    source = endpoint['id']
    files = reader.manifest(endpoint)
    cursors = {r[0]: json.loads(r[1]) for r in con.execute('SELECT identity,value FROM cursors WHERE source=?', (source,))}
    stats = collections.Counter()
    for identity, cur in cursors.items():
        if identity not in files and not cur.get('missing'):
            unread = max(0, cur['lastSize'] - cur['offset'])
            if unread:
                issue(con, source, 'unread-file-disappeared', 'confirmed', identity=identity,
                      path=cur['path'], knownUnreadBytes=unread, lastSeen=cur.get('lastSeen'))
            elif cur['path'].endswith('/violations.log'):
                issue(con, source, 'active-file-disappeared', 'suspected', identity=identity,
                      lastSeen=cur.get('lastSeen'))
            cur['missing'] = True
            save_cursor(con, source, identity, cur)
    # Retained files first; ongoing writes are drained afterward.
    ordered = sorted(files.items(), key=lambda item: (item[1]['path'].endswith('/violations.log'), item[1]['path']))
    for identity, entry in ordered:
        cur = cursors.get(identity, {'offset': 0, 'generation': uuid.uuid4().hex, 'lastSize': 0})
        path, size = entry['path'], entry['size']
        old_offset = cur['offset']
        if initialize:
            tail = reader.read(endpoint, path, max(0, size - 64), min(size, 64))
            if len(tail) != min(size, 64):
                raise RuntimeError('Audit file changed during collector initialization; retry before handoff')
            cur.update(offset=size, discardPrefix=bool(tail and not tail.endswith(b'\n')),
                       anchor=hashlib.sha256(tail).hexdigest())
        else:
            changed = size < old_offset
            verified_anchor = None
            if old_offset and not changed and cur.get('anchor'):
                anchor = reader.read(endpoint, path, max(0, old_offset - 64), min(old_offset, 64))
                changed = hashlib.sha256(anchor).hexdigest() != cur['anchor']
                verified_anchor = anchor
            if changed or cur.get('missing'):
                issue(con, source, 'file-reset', 'suspected', identity=identity, offset=old_offset,
                      previousSize=cur['lastSize'], size=size)
                cur = {'offset': 0, 'generation': uuid.uuid4().hex, 'lastSize': 0}
            while cur['offset'] < size and budget > 0:
                length = min(size - cur['offset'], MAX_LINE + 1, budget)
                raw = reader.read(endpoint, path, cur['offset'], length)
                budget -= len(raw)
                stats['bytesRead'] += len(raw)
                if len(raw) != length:
                    issue(con, source, 'short-read', 'suspected', identity=identity,
                          offset=cur['offset'], expectedBytes=length, readBytes=len(raw))
                end = raw.rfind(b'\n') + 1
                if not end:
                    if len(raw) > MAX_LINE:
                        issue(con, source, 'oversized-line', 'confirmed', identity=identity,
                              offset=cur['offset'], discardedBytes=len(raw))
                        cur['offset'] += len(raw)
                        cur['discardPrefix'] = True
                        continue
                    break
                complete = raw[:end]
                offset = cur['offset']
                if cur.get('discardPrefix'):
                    first = complete.index(b'\n') + 1
                    complete = complete[first:]
                    offset += first
                    cur['discardPrefix'] = False
                identities = []
                for line in complete.split(b'\n')[:-1]:
                    identities.append('file:' + source + ':' + identity + ':' + cur['generation'] + ':' + str(offset))
                    offset += len(line) + 1
                if complete:
                    try:
                        text = complete.decode('utf-8')
                    except UnicodeDecodeError:
                        # Each invalid line is accounted for; never persist its raw contents.
                        text = complete.decode('utf-8', errors='replace')
                        issue(con, source, 'invalid-encoding', 'suspected', identity=identity, offset=cur['offset'])
                    stats.update(reader.api['ingest'](con, state, [(source, text)], identities=identities))
                cur['offset'] += end
                if len(raw) != length:
                    break
            if cur['offset']:
                anchor = verified_anchor if not changed and cur['offset'] == old_offset and verified_anchor is not None else \
                    reader.read(endpoint, path, max(0, cur['offset'] - 64), min(cur['offset'], 64))
                cur['anchor'] = hashlib.sha256(anchor).hexdigest()
        cur.update(path=path, lastSize=size, lastSeen=dt.datetime.now(dt.timezone.utc).isoformat(), missing=False)
        save_cursor(con, source, identity, cur)
        stats['backlogBytes'] += max(0, size - cur['offset'])
    return dict(stats), budget


def deadline(args):
    current = dt.datetime.now(dt.timezone.utc)
    try:
        until = dt.datetime.fromisoformat(args.until.replace('Z', '+00:00')) if args.until else \
                current + dt.timedelta(seconds=args.duration if args.duration is not None else 3600)
    except OverflowError as exc:
        raise ValueError('Observation deadline is outside the supported date range') from exc
    if until.tzinfo is None or until <= current:
        raise ValueError('Observation deadline must be in the future with an explicit timezone')
    duration = (until - current).total_seconds()
    if duration < 1 or not math.isfinite(duration):
        raise ValueError('Observation must have a finite future deadline at least 1 second away')
    return until


def plan(args, existing=None):
    if existing:
        return existing  # Recovery uses the latest acknowledged deadline, never new CLI defaults.
    until = deadline(args)
    if not 1 <= args.interval <= 300 or not 1 <= args.discovery_interval <= 30 or \
       args.analysis_interval < 1 or not math.isfinite(args.analysis_interval):
        raise ValueError('Invalid collection/discovery/analysis interval')
    if args.max_session_mb < 1 or args.max_read_mb < 2:
        raise ValueError('Session limit must be >=1 MiB and per-round read budget >=2 MiB')
    minimum = getattr(args, 'min_interval', None)
    minimum = min(5, args.interval) if minimum is None else minimum
    rate = getattr(args, 'max_transfer_mb_per_minute', 16)
    concurrency = getattr(args, 'max_concurrent_reads', 2)
    round_seconds = getattr(args, 'max_round_seconds', 30)
    if not 1 <= minimum <= args.interval or not math.isfinite(rate) or not 0.01 <= rate <= 1024 or \
       not 1 <= concurrency <= 8 or not 1 <= round_seconds <= 120 or args.max_read_mb > 64:
        raise ValueError('Invalid resource limits: min interval, rolling audit byte quota, concurrency or round deadline')
    return {'until': until.isoformat(), 'intervalSeconds': args.interval,
            'discoveryIntervalSeconds': args.discovery_interval, 'analysisIntervalSeconds': args.analysis_interval,
            'maxSessionMiB': args.max_session_mb, 'maxReadMiB': args.max_read_mb,
            'minIntervalSeconds': minimum, 'maxTransferMiBPerMinute': rate,
            'maxConcurrentReads': concurrency, 'maxRoundSeconds': round_seconds,
            'source': args.source, 'agentNamespace': args.agent_namespace,
            'agentSelector': args.agent_selector, 'agentContainer': args.agent_container}


@contextlib.contextmanager
def control_lock(api, root):
    lease = root / '.control.lock'
    lease.mkdir(exist_ok=True)
    with session_lock(api, lease):
        yield


def pending_deadline(api, root, progress):
    path = root / 'deadline-request.json'
    if not path.exists():
        return None
    request = api['load'](path)
    if progress.get('lastDeadlineChange', {}).get('requestId') == request['requestId']:
        return None
    return request


def acknowledge_deadline(progress, request, status, api, **detail):
    result = {**request, 'status': status, 'acknowledgedAt': api['now'](), **detail}
    progress.setdefault('deadlineChanges', []).append(result)
    progress['lastDeadlineChange'] = result


def apply_deadline_request(api, root, progress, watch):
    """Only the collector changes the effective plan, at a safe round boundary."""
    with control_lock(api, root):
        request = pending_deadline(api, root, progress)
        if not request:
            return False
        current = dt.datetime.now(dt.timezone.utc)
        until = dt.datetime.fromisoformat(request['until'])
        if time.monotonic() >= api['kube'].__globals__['KUBE_DEADLINE']:
            acknowledge_deadline(progress, request, 'rejected', api, reason='Original deadline already reached')
        elif request['expectedRevision'] != progress.get('planRevision', 0):
            acknowledge_deadline(progress, request, 'rejected', api, reason='Observation plan changed; inspect current status')
        else:
            previous = progress['plan']['until']
            # A shortened deadline may have passed while a bounded round was finishing.
            # Accept it and stop without starting another Kubernetes operation.
            effective = time.monotonic() + max(0, (until - current).total_seconds())
            api['kube'].__globals__['KUBE_DEADLINE'] = effective
            watch.deadline = effective
            progress['plan']['until'] = until.isoformat()
            progress['planRevision'] = progress.get('planRevision', 0) + 1
            acknowledge_deadline(progress, request, 'applied', api, previousUntil=previous)
        api['write'](root / 'collector.json', progress)
        return progress['lastDeadlineChange']['status'] == 'applied'


def reschedule(args, api):
    """Submit a user-requested change; stdout is a receipt, not an acknowledgement."""
    root = Path(args.session)
    until = deadline(args)
    with control_lock(api, root):
        progress = api['load'](root / 'collector.json')
        if progress.get('phase') not in ('ready', 'observing'):
            raise ValueError('Only a running, ready observation can be rescheduled; ended sessions need a new session')
        if (root / 'stop-request.json').exists():
            raise ValueError('Observation is stopping; create a new session if further observation is needed')
        if dt.datetime.fromisoformat(progress['plan']['until']) <= dt.datetime.now(dt.timezone.utc):
            raise ValueError('Observation deadline already reached; create a new session')
        lease = root / '.collector.lock'
        lease.mkdir(exist_ok=True)
        try:
            with api['locked'](lease):
                pass
        except RuntimeError as exc:
            if 'Session is busy' not in str(exc):
                raise
        else:
            raise ValueError('Collector is not running; resume before the agreed deadline or create a new session')
        if pending_deadline(api, root, progress):
            raise ValueError('A deadline change is pending; check its acknowledgement before submitting another')
        request = {'requestId': str(uuid.uuid4()), 'requestedAt': api['now'](), 'until': until.isoformat(),
                   'expectedRevision': progress.get('planRevision', 0), 'requestedReason': args.reason}
        api['write'](root / 'deadline-request.json', request)
    print(json.dumps({'status': 'deadline-change-requested', **request,
                      'note': 'Check collector.json lastDeadlineChange for applied/rejected acknowledgement'}, ensure_ascii=False))
    return 0


def monitor(args, api):
    root = Path(args.session)
    if not (root / 'session.json').is_file():
        raise ValueError('Session does not exist; prepare observe first')
    lease = root / '.collector.lock'
    lease.mkdir(exist_ok=True)
    state = api['load'](root / 'session.json')
    workflow = Path(state.get('observationSession', str(root)))
    workflow_lease = workflow / '.workflow-collector.lock'
    workflow_lease.mkdir(exist_ok=True)
    with api['locked'](workflow_lease), api['locked'](lease):
        return run_monitor(args, api)


def run_monitor(args, api):
    root = Path(args.session)
    stop_event = threading.Event()
    watch = None
    previous_signals = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        previous_signals[sig] = signal.signal(sig, lambda *unused: stop_event.set())
    reason, error = 'deadline', None
    ready = False
    try:
        state = api['load'](root / 'session.json')
        verification_mode = state.get('purpose') == 'verification'
        previous = api['load'](root / 'collector.json') if (root / 'collector.json').exists() else {}
        ready = bool(previous.get('readyAt'))
        if previous.get('phase') == 'stopped':
            raise ValueError('This observation ended; create a new session instead of extending its deadline')
        planned = plan(args, previous.get('plan'))
        if verification_mode and not previous:
            for key, value in state.get('resourcePlan', {}).items():
                if key != 'until':
                    planned[key] = value
        # Restore all settings on resume, as well as the fixed deadline.
        for field, key in [('source', 'source'), ('agent_namespace', 'agentNamespace'),
                           ('agent_selector', 'agentSelector'), ('agent_container', 'agentContainer')]:
            setattr(args, field, planned[key])
        remaining = (dt.datetime.fromisoformat(planned['until']) - dt.datetime.now(dt.timezone.utc)).total_seconds()
        api['kube'].__globals__['KUBE_DEADLINE'] = time.monotonic() + max(0, remaining)
        progress = {**previous, 'phase': 'initializing', 'plan': planned, 'processId': os.getpid(),
                    'startedAt': previous.get('startedAt', api['now']())}
        with control_lock(api, root):
            if previous:
                request = pending_deadline(api, root, progress)
                if request:
                    acknowledge_deadline(progress, request, 'rejected', api,
                                         reason='Collector restarted before acknowledging this request; submit again after readiness')
            api['write'](root / 'collector.json', progress)
        if remaining <= 0:
            reason = 'deadline'
            return 0
        if state.get('collectionMode') not in (None, 'live-incremental'):
            raise ValueError('Snapshot/offline evidence cannot share an incremental session; create a new session')
        if state.get('historicalSince') is not None:
            raise ValueError('Historical --since sessions use snapshot/offline analysis; use a fresh session for new Pod observation')
        with contextlib.closing(api['database'](root)) as con:
            schema(con)
            if not previous and con.execute('SELECT count(*) FROM events').fetchone()[0]:
                raise ValueError('Start incremental observation in a fresh session')
            con.commit()
        bootstrap_deadline = api['kube'].__globals__['KUBE_DEADLINE']
        api['kube'].__globals__['KUBE_DEADLINE'] = min(bootstrap_deadline,
            time.monotonic() + planned.get('maxRoundSeconds', 30))
        with session_lock(api, root):
            pods, policy = api['live_inventory'](state, api['load'](root / 'observe.yaml'), allow_empty=True)
            if policy.get('status', {}).get('ready') is not True:
                raise RuntimeError('Observation policy is not Ready; do not hand off workload creation')
            listed = api['get'](state['context'], 'pods', state['namespace'])
            if api['kube'](state['context'], 'auth', 'can-i', 'watch', 'pods', '-n', state['namespace']).strip() != 'yes':
                raise RuntimeError('Pod watch permission is required for short-lived Pod discovery')
            watch = PodWatch(state['context'], state['namespace'], listed.get('metadata', {}).get('resourceVersion'),
                             bootstrap_deadline)
            watch.start()
            if not previous.get('readyAt') and not verification_mode:
                baseline = {p['metadata']['uid'] for p in listed['items']}
                state['baselinePodUIDs'] = sorted(baseline)
                state['podUIDs'] = []
                state['podHistory'] = {}
            reader = Reader(api, state)
            workflow = Path(state.get('observationSession', str(root)))
            ledger = workflow / 'resource-usage.json'
            reader.resource_budget = ResourceBudget(int(planned.get('maxTransferMiBPerMinute', 16) * 1024 * 1024),
                ledger, api, planned.get('maxRoundSeconds', 30))
            reader.max_concurrent = planned.get('maxConcurrentReads', 2)
            roots = (api['load'](ledger).get('storageRoots', []) if ledger.exists() else [])
            reader.resource_budget.storage_roots = sorted(set(roots + [str(root.resolve()), str(workflow.resolve())]))
            targets = endpoints(api, state, args)
            with contextlib.closing(api['database'](root)) as con, con:
                schema(con)
                if not previous.get('readyAt'):
                    errors, _ = prefetch(con, reader, targets, 0, initialize=True)
                    for endpoint in targets:
                        if endpoint['id'] in errors:
                            raise errors[endpoint['id']]
                        scan(con, state, reader, endpoint, 0, initialize=True)
                    # Include Pods born during preflight, before the handoff epoch.
                    listed_after = api['get'](state['context'], 'pods', state['namespace'])['items']
                    if not verification_mode:
                        baseline.update(p['metadata']['uid'] for p in listed_after)
                    for kind, value in watch.drain():
                        if kind == 'pod' and value.get('metadata', {}).get('uid') and not verification_mode:
                            baseline.add(value['metadata']['uid'])
                        elif kind == 'error':
                            raise RuntimeError(value)
                    if not verification_mode:
                        state['baselinePodUIDs'] = sorted(baseline)
                    state['startedAt'] = int(dt.datetime.now(dt.timezone.utc).timestamp())
                    state['observationEpoch'] = api['now']()
                else:
                    issue(con, 'collector', 'collector-restarted', 'suspected',
                          lastSuccessfulCollection=previous.get('lastSuccessfulCollection'))
            state['collectionMode'] = 'live-incremental'
            api['kube'].__globals__['KUBE_DEADLINE'] = bootstrap_deadline
            api['write'](root / 'session.json', state)
            progress.update(phase='ready', readyAt=previous.get('readyAt', state.get('observationEpoch')),
                            baselinePodCount=len(state['baselinePodUIDs']),
                            readinessScope='Pod discovery and available Agent files; new sidecar sources are verified after injection')
            api['write'](root / 'collector.json', progress)
            ready = True
            print(json.dumps({'status': 'collector-ready', **progress}, ensure_ascii=False), flush=True)
        next_scan = next_discovery = next_analysis = time.monotonic()
        last_event_count = -1
        while True:
            if stop_event.is_set() or (root / 'stop-request.json').exists():
                reason = 'user-stop'
                break
            if apply_deadline_request(api, root, progress, watch):
                # Refresh the report even when there are no new audit events.
                last_event_count, next_analysis = -1, time.monotonic()
            if time.monotonic() >= api['kube'].__globals__['KUBE_DEADLINE']:
                break
            usage = sum(p.stat().st_size for folder in reader.resource_budget.storage_roots
                        for p in Path(folder).rglob('*') if p.is_file())
            if usage >= planned['maxSessionMiB'] * 1024 * 1024:
                reason = 'storage-limit'
                break
            tick = time.monotonic()
            if tick >= next_discovery or tick >= next_scan:
                with session_lock(api, root):
                    state = api['load'](root / 'session.json')
                    reader.state = state
                    with contextlib.closing(api['database'](root)) as con, con:
                        for kind, value in watch.drain():
                            if kind == 'pod':
                                register_pod(state, value)
                            else:
                                issue(con, 'pod-discovery', 'watch-interrupted', 'suspected', message=value)
                        original_deadline = api['kube'].__globals__['KUBE_DEADLINE']
                        api['kube'].__globals__['KUBE_DEADLINE'] = min(original_deadline,
                            time.monotonic() + planned.get('maxRoundSeconds', 30))
                        if tick >= next_discovery:
                            try:
                                pods, policy = api['live_inventory'](state, api['load'](root / 'observe.yaml'), allow_empty=True)
                                if verification_mode and state['pinnedPolicy'] != {'uid': policy['metadata']['uid'],
                                    'generation': policy['metadata'].get('generation'),
                                    'specHash': api['refinement_module']().fingerprint(policy['spec'])}:
                                    raise RuntimeError('Live policy differs from pinned enforcement generation')
                            except RuntimeError as exc:
                                # Policy identity/config changes are not recoverable in this session.
                                if any(token in str(exc) for token in ('Policy was recreated', 'Live policy differs', 'automatic workload')):
                                    raise
                                issue(con, 'pod-discovery', 'inventory-failed', 'suspected', message=str(exc))
                                pods = []
                            for pod in pods:
                                register_pod(state, pod)
                            next_discovery = tick + planned['discoveryIntervalSeconds']
                        resolved = resolve_pending(con, state, api)
                        if tick >= next_scan:
                            stats = collections.Counter(resolved)
                            attempted, successful = [], []
                            budget = int(planned['maxReadMiB'] * 1024 * 1024)
                            try:
                                targets = endpoints(api, state, args)
                            except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
                                issue(con, 'source-discovery', 'endpoints-failed', 'suspected', message=str(exc))
                                targets = []
                            # Rotate the first source, so sustained traffic cannot starve other nodes.
                            turn = progress.get('rounds', 0) % max(1, len(targets))
                            targets = targets[turn:] + targets[:turn]
                            errors, grants = prefetch(con, reader, targets, budget)
                            for endpoint in targets:
                                attempted.append(endpoint['id'])
                                try:
                                    con.execute('SAVEPOINT source_scan')
                                    if endpoint['id'] in errors:
                                        raise errors[endpoint['id']]
                                    result, unused = scan(con, state, reader, endpoint, grants[endpoint['id']])
                                    con.execute('RELEASE source_scan')
                                    stats.update(result)
                                    successful.append(endpoint['id'])
                                except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
                                    con.execute('ROLLBACK TO source_scan')
                                    con.execute('RELEASE source_scan')
                                    if isinstance(exc, ResourceLimit):
                                        stats['resourceLimitedSources'] += 1
                                        grants[endpoint['id']] = 0
                                    else:
                                        stats['readFailures'] += 1
                                        issue(con, endpoint['id'], 'source-read-failed', 'suspected', message=str(exc))
                            stats = {**stats, 'backlogBytes': stats['backlogBytes']}
                            stats.update(at=api['now'](), offline=False, incremental=True, sources=attempted,
                                         successfulSources=successful, policyUID=state['policyUID'])
                            stats['totalEvents'] = con.execute('SELECT count(*) FROM events').fetchone()[0]
                            stats['unresolvedPodEvents'] = con.execute('SELECT count(*) FROM pending_pods').fetchone()[0]
                            con.execute('INSERT INTO rounds(time,summary) VALUES (?,?)', (stats['at'], json.dumps(stats)))
                            api['write'](root / 'last-collection.json', dict(stats))
                            progress.update(phase='observing', rounds=progress.get('rounds', 0) + 1,
                                            lastAttemptAt=stats['at'], backlogBytes=stats['backlogBytes'],
                                            roundDurationSeconds=round(time.monotonic() - tick, 3),
                                            totalEvents=stats['totalEvents'], eligiblePodCount=len(state['podUIDs']))
                            progress['resources'] = reader.resource_budget.snapshot()
                            progress.setdefault('sourceCapturedAt', {}).update({source: reader.read_started[source]
                                for source in successful if source in getattr(reader, 'read_started', {})})
                            progress['resourcePressure'] = bool(stats.get('resourceLimitedSources') or stats['backlogBytes'])
                            if successful:
                                progress['lastSuccessfulCollection'] = stats['at']
                            progress['collectionHealth'] = health(con)
                            # Drain backlog promptly; regular polling stays independent of analysis.
                            delay = planned.get('minIntervalSeconds', min(5, planned['intervalSeconds'])) \
                                if stats['backlogBytes'] or stats.get('resourceLimitedSources') else planned['intervalSeconds']
                            progress['nextScanDelaySeconds'] = delay
                            next_scan = time.monotonic() + delay
                        elif resolved:
                            resolved.update(at=api['now'](), offline=False, incremental=True,
                                            sources=[], identityResolution=True)
                            con.execute('INSERT INTO rounds(time,summary) VALUES (?,?)', (resolved['at'], json.dumps(resolved)))
                        api['kube'].__globals__['KUBE_DEADLINE'] = original_deadline
                        progress['totalEvents'] = con.execute('SELECT count(*) FROM events').fetchone()[0]
                    api['write'](root / 'session.json', state)
                    progress['lastHeartbeatAt'] = api['now']()
                    api['write'](root / 'collector.json', progress)
            if tick >= next_analysis:
                count = (progress.get('totalEvents', 0), progress.get('resourcePressure', False),
                         progress.get('collectionHealth', {}).get('status'))
                if count != last_event_count:
                    if local_analysis(api, args):
                        last_event_count = count
                next_analysis = time.monotonic() + planned['analysisIntervalSeconds']
            stop_event.wait(min(0.5, max(0, api['kube'].__globals__['KUBE_DEADLINE'] - time.monotonic())))
    except (TimeoutError, subprocess.TimeoutExpired):
        # The active API deadline may be a shorter per-round bound. Only the
        # overall phase deadline can justify reporting a normal timed stop.
        phase_deadline = locals().get('original_deadline', locals().get('bootstrap_deadline',
            api['kube'].__globals__['KUBE_DEADLINE']))
        if phase_deadline is None or time.monotonic() < phase_deadline:
            reason, error = 'failure', 'Collection timed out before the observation deadline'
    except (RuntimeError, ValueError, TypeError, OSError, KeyError, sqlite3.Error) as exc:
        reason, error = 'failure', str(exc)
    finally:
        if watch:
            watch.close()
        api['kube'].__globals__['KUBE_DEADLINE'] = None
        for sig, handler in previous_signals.items():
            signal.signal(sig, handler)
        # Do not overwrite another process's progress when the collector lease was busy.
        if 'progress' in locals():
            with control_lock(api, root):
                request = pending_deadline(api, root, progress)
                if request:
                    acknowledge_deadline(progress, request, 'rejected', api, reason='Observation stopped: ' + reason)
                progress.update(phase='stopped', stopReason=reason, stoppedAt=api['now'](), error=error)
                if 'reader' in locals() and reader.resource_budget:
                    progress['resources'] = reader.resource_budget.snapshot()
                api['write'](root / 'collector.json', progress)
            with session_lock(api, root), contextlib.closing(api['database'](root)) as con, con:
                schema(con)
                if watch:
                    state = api['load'](root / 'session.json')
                    for kind, value in watch.drain():
                        if kind == 'pod':
                            register_pod(state, value)
                        else:
                            issue(con, 'pod-discovery', 'watch-interrupted', 'suspected', message=value)
                    resolved = resolve_pending(con, state, api)
                    if resolved:
                        resolved.update(at=api['now'](), offline=False, incremental=True,
                                        sources=[], identityResolution=True)
                        con.execute('INSERT INTO rounds(time,summary) VALUES (?,?)', (resolved['at'], json.dumps(resolved)))
                    api['write'](root / 'session.json', state)
                if reason not in ('deadline', 'user-stop'):
                    issue(con, 'collector', 'observation-stopped', 'suspected', reason=reason, message=error)
                backlog = con.execute('SELECT value FROM cursors').fetchall()
                remaining_bytes = sum(max(0, (v := json.loads(r[0]))['lastSize'] - v['offset']) for r in backlog if not json.loads(r[0]).get('missing'))
                progress['backlogBytes'] = remaining_bytes
                if remaining_bytes:
                    issue(con, 'collector', 'unread-at-stop', 'suspected', knownBacklogBytes=remaining_bytes)
                progress['collectionHealth'] = health(con)
                progress['elapsedSeconds'] = max(0, (dt.datetime.fromisoformat(progress['stoppedAt']) -
                                                      dt.datetime.fromisoformat(progress['startedAt'])).total_seconds())
                progress['observedSeconds'] = max(0, (dt.datetime.fromisoformat(progress['stoppedAt']) -
                    dt.datetime.fromisoformat(progress['readyAt'])).total_seconds()) if progress.get('readyAt') else 0
                api['write'](root / 'collector.json', progress)
            if ready:
                if not local_analysis(api, args, final=True):
                    progress['finalAnalysisPending'] = True
                    api['write'](root / 'collector.json', progress)
            print(json.dumps({'status': 'observation-ended', **progress}, ensure_ascii=False), flush=True)
        elif error:
            print(json.dumps({'status': 'observation-not-started', 'error': error}), file=sys.stderr)
    return 2 if error else 0


def stop(args, api):
    root = Path(args.session)
    with control_lock(api, root):
        progress = api['load'](root / 'collector.json')
        if progress.get('phase') == 'stopped':
            print(json.dumps({'status': 'already-stopped', 'stopReason': progress.get('stopReason')}))
            return 0
        api['write'](root / 'stop-request.json', {'requestedAt': api['now']()})
    print(json.dumps({'status': 'stop-requested', 'note': 'Stopping collection does not change the deployed policy'}))
    return 0
