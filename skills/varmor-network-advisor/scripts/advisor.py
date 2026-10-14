#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""NetworkProxy observation and allowlist drafts. Python 3.9+, kubectl; no pip dependencies."""
import argparse
import collections
import copy
import contextlib
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import uuid
import time
import importlib.util


# Set only by bounded collection. Every Kubernetes subprocess shares its deadline.
KUBE_DEADLINE = None
KUBE_WALL_DEADLINE = None


# Report prose follows the user's conversation; API values and audit evidence
# retain their original spelling. English is the fallback for older sessions.
ZH_REPORT_TEXT = {
    '# NetworkProxy allowlist recommendations': '# NetworkProxy 白名单建议',
    'Events: {events}; rules: {rules}; replay coverage: {covered}/{events}; collection rounds with new healthy data: {rounds}.':
        '事件数：{events}；规则数：{rules}；回放覆盖：{covered}/{events}；获得新健康数据的采集轮次：{rounds}。',
    'Evidence source: {source}; stable data rounds: {stable}; event span: {span} seconds.':
        '证据来源：{source}；稳定数据轮次：{stable}；事件时间跨度：{span} 秒。',
    'Collection continuity: {status}; excluded baseline Pod events: {excluded}. No detected gap does not guarantee complete logs.':
        '采集连续性：{status}；排除的基线 Pod 事件：{excluded}。未发现缺口不代表日志完整。',
    'The candidate defaults to deny and requires business review and real traffic validation before deployment.':
        '候选策略默认拒绝；上线前必须完成业务审核和真实流量验证。',
    'Insufficient data or no acceptable rules: candidate.yaml was not generated. Collect additional evidence or review exclusions; do not enable enforcement with an empty allowlist.':
        '数据不足或没有可接纳规则，未生成 candidate.yaml。请补充证据或审核排除项，不要使用空白名单开启拦截。',
    '## Changes this round and next steps': '## 本轮变化与下一步',
    'Compared with the previous draft: {added} permissions added and {removed} removed.':
        '与上一版草稿相比：新增 {added} 项权限，删除 {removed} 项权限。',
    'Initial permission baseline established; later analysis will list added and removed permissions.':
        '已建立首次权限基线，后续分析将列出新增和删除的权限。',
    '1. Confirm that the destinations below are necessary for normal business. Unreviewed TCP is not automatically allowed.':
        '1. 确认下列目标是否为正常业务所必需。未经审核的 TCP 不会自动放行。',
    '2. Specify the desired depth for dynamic paths. HTTPS without MITM supports SNI/port restrictions only.':
        '2. 指定动态路径的匹配深度。未启用 MITM 的 HTTPS 只能限制 SNI 和端口。',
    '3. Reuse injected Pods for rule-only tests. For additional startup observation, users create new instances after checking that collection is still ready; after observation ends, start a new session. Final startup acceptance uses a separate enforcement collection window. Review retries, low-frequency tasks and different replicas; reanalyzing old logs does not increase stability.':
        '3. 仅测试规则变化时，复用已注入的 Pod。补充启动观察时，先确认采集仍就绪，再由用户创建新实例。观察结束后，需要另开会话。最终启动验收使用独立的拦截采集窗口。请审核重试、低频任务和不同副本的覆盖。重新分析旧日志不会增加稳定性证据。',
    '4. After review, run allowed/denied traffic tests and keep observe.yaml as network-rule rollback material.':
        '4. 审核后执行允许和拒绝流量测试，保留 observe.yaml 作为网络规则回退材料。',
    '## Actual permissions': '## 实际授权',
    '| Destination | Port | Path | Method | Granularity and impact |': '| 目标 | 端口 | 路径 | 方法 | 授权粒度与影响 |',
    'All paths': '所有路径', 'All methods': '所有方法',
    'Requests visible through MITM': '经 MITM 解密后可见的请求',
    'Plaintext HTTP and MITM-decrypted HTTPS share these host/port/method/path rules; not HTTPS-only':
        '明文 HTTP 和 MITM 解密后的 HTTPS 共用这些主机、端口、方法和路径规则；并非仅允许 HTTPS',
    'Plaintext HTTP; approved HTTP deny constraints block matching TLS passthrough in this candidate':
        '明文 HTTP；本候选已批准的 HTTP 拒绝约束会阻断对应 TLS 透传',
    'Plaintext HTTP; TLS passthrough is subject to explicit deny constraints; inspect their host/port scope':
        '明文 HTTP；TLS 透传受显式拒绝约束影响，请核对其主机和端口范围',
    'Plaintext HTTP; HTTPS passthrough checks SNI/port only, without path or method restrictions':
        '明文 HTTP；HTTPS 透传仅检查 SNI 和端口，不限制路径或方法',
    '; all HTTP requests to the same domain/port are also allowed': '；同域名和端口的所有 HTTP 请求也会被允许',
    '; the base grant matches all HTTP paths and methods; explicit denies still apply':
        '；基础放行规则匹配所有 HTTP 路径和方法，显式拒绝仍然生效',
    'Entire IP/port allowed, including HTTP/TLS': '放行整个 IP 和端口，包括 HTTP/TLS',
    '## Observed behavior not covered': '## 未覆盖的已观测行为',
    '| Destination | Method | Path | Action | Uncovered events |': '| 目标 | 方法 | 路径 | 动作 | 未覆盖事件数 |',
    '## Review required': '## 待审核信息', '## Coverage limitations': '## 覆盖限制',
    'Observed activity is not evidence of business legitimacy.': '观测到访问不代表它属于合法业务。',
    'Empty collection rounds do not prove convergence; offline replay is not Envoy verification.':
        '空采集轮次不代表已收敛，离线回放不能替代 Envoy 实际验证。',
    'TCP only; DNS/UDP, QUIC, loopback and traffic bypassing redirection are not covered.':
        '仅覆盖 TCP；不覆盖 DNS/UDP、QUIC、回环及绕过重定向的流量。',
    'Review startup, scheduled jobs, retry/failover and multi-replica coverage before enforcement.':
        '开启拦截前，请审核启动、定时任务、重试和故障切换及多副本的覆盖情况。',
    'Paths remain sensitive after query removal; keep session files private.':
        '移除查询字符串后，路径仍可能包含敏感信息，请妥善保管会话文件。',
    'A host/port HTTP allow rule can authorize passthrough TLS by SNI unless explicit denies block it; HTTPS path/method limits require MITM.':
        'HTTP 域名和端口放行规则可能按 SNI 放行透传 TLS，除非被显式拒绝阻断；限制 HTTPS 路径和方法需要 MITM。',
    'HTTP rules do not select a URL scheme: MITM does not remove matching plaintext HTTP permissions, and explicit denies take precedence over grants.':
        'HTTP 规则不按 URL 协议区分权限：MITM 不会移除对应的明文 HTTP 权限；显式拒绝优先于放行。',
    'Snapshot dedupe cannot distinguish identical entries across log rotation without an event ID.':
        '没有事件 ID 时，快照去重无法区分轮转日志中的相同记录。',
    'No detected collection gap is not a guarantee of complete logs; upstream loss may be invisible.':
        '未发现采集缺口不保证日志完整；写入日志前的上游丢失可能无法感知。',
    'See analysis.json for the full behavior inventory and rule coverage. validation.yaml retains observation configuration.':
        '完整行为清单和规则覆盖详见 analysis.json，validation.yaml 保留观察配置。',
    'no-detected-gap': '未发现采集缺口（no-detected-gap）',
    'confirmed-gap': '已确认采集缺口（confirmed-gap）',
    'suspected-gap': '疑似采集缺口（suspected-gap）',
    'identity-incomplete': '身份信息不完整（identity-incomplete）',
    'not-assessed': '未评估连续性（not-assessed）',
    'Current draft: candidate.yaml. It is not automatically deployed.': '当前草稿：candidate.yaml；不会自动部署。',
    '## Required business connections': '## 必要业务连接',
    '| Destination | Origin | Observed | Approval | Verification |': '| 目标 | 来源 | 已观测 | 授权 | 验证 |',
    'user-declared': '用户业务声明', 'audit': '审计证据',
    'approved': '已批准完整 IP/端口', 'pending': '待批准', 'yes': '是', 'no': '否',
    'Required connections awaiting approval: {count}. The draft does not yet include them.':
        '尚有 {count} 项必要连接待授权；草稿尚未包含这些连接。',
    '## TCP decisions still needed': '## 待决定的 TCP 访问',
    '| Destination | Why it needs review |': '| 目标 | 待审核原因 |',
    'No pending TCP approvals.': '没有待批准的 TCP 访问。',
    'TCP/IP authorization requires review': '需要确认是否允许整个 IP 和端口',
    'Required business connection awaits whole IP/port approval': '必要业务连接，需要确认整个 IP 和端口的授权范围',
    'Approved destination has no usable raw TCP evidence; collect evidence or explicitly declare the requirement':
        '已批准的目标尚无可用原始 TCP 证据；需补充证据或明确记录业务声明',
    'Domain-wide review options affect every matching path and port: {domains}. Prefer scoped request decisions.':
        '整域名审核选项会影响该域名的所有匹配路径和端口：{domains}。建议按具体接口审核。',
    'Review the extra paths and methods opened by generalization; users need not choose numeric path depths.':
        '审核路径放宽后额外允许的接口和方法；用户不需要选择数字路径深度。',
    'Detailed collection state, exclusions and review data remain in analysis.json.':
        '完整采集状态、排除项与审核数据保存在 analysis.json。',
}


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def report_language(args, state, root):
    """Apply the user's report preference under the caller's session lock."""
    language = getattr(args, 'language', None) or state.get('reportLanguage', 'en')
    if language not in ('en', 'zh-CN'):
        raise ValueError('Report language must be en or zh-CN')
    if state.get('reportLanguage') != language:
        state['reportLanguage'] = language
        write(Path(root) / 'session.json', state)
    return language


_YAML_MODULE = None


def yaml_module():
    global _YAML_MODULE
    if _YAML_MODULE is None:
        spec = importlib.util.spec_from_file_location('varmor_policy_yaml', Path(__file__).with_name('yamlio.py'))
        _YAML_MODULE = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_YAML_MODULE)
    return _YAML_MODULE


def write(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            if path.suffix in ('.yaml', '.yml'):
                f.write(yaml_module().dumps(obj))
            else:
                json.dump(obj, f, ensure_ascii=False, indent=2)
                f.write('\n')
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load(path):
    path = Path(path)
    return yaml_module().loads(path.read_text()) if path.suffix in ('.yaml', '.yml') else json.loads(path.read_text())


def kube_command_summary(args):
    """Describe the operation without remote scripts, patch bodies or credentials."""
    head = list(args[:args.index('--')]) if '--' in args else list(args)
    verb = head[0] if head and head[0] in ('get', 'exec', 'auth', 'wait', 'apply', 'create', 'delete', 'rollout') else 'operation'
    summary = ['kubectl', verb]
    if verb == 'get' and len(head) > 1 and re.fullmatch(r'[A-Za-z0-9.,/-]+', head[1]):
        summary.append(head[1])
    if verb == 'auth':
        summary.append('can-i')
    for flag in ('-n', '--namespace', '-c', '--container'):
        if flag in head and head.index(flag) + 1 < len(head):
            value = head[head.index(flag) + 1]
            summary.extend([flag, value if re.fullmatch(r'[A-Za-z0-9_.-]{1,253}', value) else '[omitted]'])
    if verb == 'exec':
        summary.extend(['--', '[remote command omitted]'])
    return summary


class KubeTimeoutError(subprocess.TimeoutExpired):
    def __init__(self, diagnostic):
        self.diagnostic = diagnostic
        super().__init__(diagnostic['command'], diagnostic['timeoutSeconds'])

    def __str__(self):
        return 'Kubernetes operation timed out: ' + ' '.join(self.cmd) + ' (timeout=' + str(self.timeout) + 's)'


class KubeDeadlineError(TimeoutError):
    def __init__(self, diagnostic):
        self.diagnostic = diagnostic
        super().__init__('Kubernetes deadline reached before dispatch: ' + ' '.join(diagnostic['command']))


def kube(context, *args, data=None, binary=False):
    # argv only: audited hosts/paths never become shell commands.
    remaining = KUBE_DEADLINE - time.monotonic() if KUBE_DEADLINE is not None else 100
    if KUBE_WALL_DEADLINE is not None:
        remaining = min(remaining, KUBE_WALL_DEADLINE - time.time())
    timeout = max(0, min(20 if KUBE_DEADLINE is not None else 100, remaining))
    diagnostic = {'command': kube_command_summary(args), 'timeoutSeconds': timeout,
                  'deadlineRemainingSeconds': round(max(0, remaining), 3),
                  'deadlineBounded': KUBE_DEADLINE is not None}
    if remaining <= 0:
        raise KubeDeadlineError({**diagnostic, 'exceptionType': 'TimeoutError', 'kind': 'deadline-before-dispatch'})
    try:
        result = subprocess.run(['kubectl', '--context', context, '--request-timeout=20s', *args],
                                input=data, text=not binary, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise KubeTimeoutError({**diagnostic, 'exceptionType': 'TimeoutExpired', 'kind': 'subprocess-timeout'}) from None
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors='replace').strip() if binary else result.stderr.strip())
    return result.stdout


def get(context, resource, namespace=None, name=None):
    args = ['get', resource]
    if namespace:
        args += ['-n', namespace]
    if name:
        args += [name]
    return json.loads(kube(context, *args, '-o', 'json'))


def database(root):
    con = sqlite3.connect(str(Path(root) / 'events.sqlite'), timeout=30)
    con.execute('CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, record TEXT NOT NULL)')
    con.execute('CREATE TABLE IF NOT EXISTS rounds (id INTEGER PRIMARY KEY, time TEXT, summary TEXT)')
    con.execute('CREATE TABLE IF NOT EXISTS pending_pods (id TEXT PRIMARY KEY, record TEXT NOT NULL)')
    return con


@contextlib.contextmanager
def locked(root):
    # Lock the inode without unlinking it; OS releases ownership on process exit/crash.
    p = Path(root) / '.lock'
    fd = os.open(p, os.O_RDWR | os.O_CREAT, 0o600)
    acquired = False
    try:
        if os.name == 'nt':
            import msvcrt
            if os.fstat(fd).st_size == 0:
                os.write(fd, b'0')
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeError('Session is busy; retry after the active operation finishes') from exc
        else:
            import fcntl
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError('Session is busy; retry after the active operation finishes') from exc
        acquired = True
        yield
    finally:
        if acquired and os.name == 'nt':
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        os.close(fd)


def network_rules(policy):
    if policy.get('mode') == 'EnhanceProtect':
        return policy.setdefault('enhanceProtect', {}).setdefault('networkProxyRawRules', {})
    if policy.get('mode') == 'DefenseInDepth':
        return policy.setdefault('defenseInDepth', {}).setdefault('networkProxy', {})
    raise ValueError('Network observation requires EnhanceProtect or DefenseInDepth; existing mode is preserved')


def mitm_applies(domain, domains):
    for configured in domains:
        if configured.startswith('*.'):
            suffix = host(configured[2:])
            if domain.endswith('.' + suffix):
                return True
        elif domain == host(configured):
            return True
    return False


def safe_text(value):
    return isinstance(value, str) and not any(ord(c) < 32 or c in '\\"\x7f\x85\u2028\u2029' for c in value)


def host(value):
    """Return a literal host, excluding its authority port. Never infer DNS from an IP."""
    if not safe_text(value) or not value or value != value.strip():
        raise ValueError('invalid host')
    if value.startswith('['):
        m = re.fullmatch(r'\[([^\]]+)\](?::([0-9]+))?', value)
        if not m:
            raise ValueError('invalid IPv6 authority')
        return str(ipaddress.IPv6Address(m.group(1)))
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    value = re.sub(r':[0-9]+$', '', value).lower()
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value) or '..' in value:
        raise ValueError('invalid DNS host')
    if any(not x or len(x) > 63 or x.startswith('-') or x.endswith('-') for x in value.split('.')):
        raise ValueError('invalid DNS label')
    return value


def destination(value):
    if not isinstance(value, str):
        raise ValueError('missing destination')
    if value.startswith('['):
        m = re.fullmatch(r'\[([^\]]+)\]:([0-9]+)', value)
        if not m:
            raise ValueError('invalid destination')
        ip, port = m.groups()
    else:
        ip, port = value.rsplit(':', 1)
    ip, port = str(ipaddress.ip_address(ip)), int(port)
    if not 1 <= port <= 65535:
        raise ValueError('invalid port')
    return ip, port


def http_host(authority, port):
    domain = host(authority)
    explicit = re.search(r'\]:([0-9]+)$', authority) if authority.startswith('[') else \
               (re.search(r':([0-9]+)$', authority) if authority.count(':') == 1 else None)
    if explicit and int(explicit.group(1)) != port:
        raise ValueError('authority port differs from original destination')
    if not explicit and port not in (80, 443):
        raise ValueError('non-default destination requires explicit authority port')
    return domain


def path_match(value, options):
    # ALS is Envoy's already-normalized path. Do not URL-decode it a second time.
    value = value.split('?', 1)[0]
    if not safe_text(value) or not value.startswith('/'):
        raise ValueError('invalid path')
    if options.get('path', 'exact') == 'exact':
        return {'exact': value}
    depth = options['depth']
    segments = [s for s in value.split('/') if s]
    # Do not turn a shallow path into a broad prefix, or /api into /apix.
    if len(segments) <= depth:
        return {'exact': value}
    return {'prefix': '/' + '/'.join(segments[:depth]) + '/'}


def options_check(config):
    if not isinstance(config, dict) or not isinstance(config.get('default', {}), dict) or \
       not isinstance(config.get('domains', {}), dict) or not isinstance(config.get('approvedTcp', []), list):
        raise ValueError('review must contain default/domain objects and an approvedTcp list')
    if set(config) - {'default', 'domains', 'requests', 'declaredTcp', 'approvedTcp', 'excludedHosts', 'excludedTcp'}:
        raise ValueError('unknown review configuration keys')
    for raw in [config.get('default', {}), *config.get('domains', {}).values()]:
        if not isinstance(raw, dict):
            raise ValueError('each domain review must be an object')
        opt = {**config.get('default', {}), **raw}
        if set(opt) - {'path', 'depth', 'methods', 'includeErrors'}:
            raise ValueError('unknown domain options')
        if opt.get('path', 'exact') not in ('exact', 'prefix', 'host'):
            raise ValueError('path must be exact, prefix or host')
        if opt.get('path') == 'prefix' and (type(opt.get('depth')) is not int or opt['depth'] < 1):
            raise ValueError('prefix requires positive depth')
        for field in ('methods', 'includeErrors'):
            if field in opt and type(opt[field]) is not bool:
                raise ValueError(field + ' must be boolean')
    for domain in config.get('domains', {}):
        if host(domain) != domain:
            raise ValueError('review domain must be canonical literal host')
    for address in config.get('approvedTcp', []):
        destination(address)
    for key in ('excludedHosts', 'excludedTcp'):
        if not isinstance(config.get(key, []), list):
            raise ValueError(key + ' must be a list')
    for domain in config.get('excludedHosts', []):
        if host(domain) != domain:
            raise ValueError('excludedHosts requires canonical literal hosts')
    for address in config.get('excludedTcp', []):
        destination(address)
    requests = config.get('requests', [])
    if not isinstance(requests, list):
        raise ValueError('requests must be a list of scoped HTTP review decisions')
    for decision in requests:
        if not isinstance(decision, dict) or set(decision) - {'host', 'port', 'method', 'paths', 'pathPrefix',
                'path', 'depth', 'methods', 'includeErrors'}:
            raise ValueError('invalid scoped HTTP review keys')
        if host(decision.get('host')) != decision['host'] or type(decision.get('port')) is not int or not 1 <= decision['port'] <= 65535:
            raise ValueError('scoped review requires canonical host and literal port')
        if not isinstance(decision.get('method'), str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", decision['method']):
            raise ValueError('scoped review requires an exact HTTP method')
        if ('paths' in decision) == ('pathPrefix' in decision):
            raise ValueError('scoped review requires either paths or pathPrefix')
        paths = decision.get('paths', [decision.get('pathPrefix')])
        if not isinstance(paths, list) or not paths or any(not safe_text(p) or not p.startswith('/') or '?' in p for p in paths):
            raise ValueError('scoped review paths must be normalized, query-free paths')
        prefix = decision.get('pathPrefix')
        if prefix is not None and not prefix.endswith('/'):
            raise ValueError('pathPrefix must end with / to keep a path-segment boundary')
        opt = {k: decision[k] for k in ('path', 'depth', 'methods', 'includeErrors') if k in decision}
        effective = {**config.get('default', {}), **opt}
        options_check({'default': effective})
        if prefix and effective.get('path') == 'prefix' and effective['depth'] < len([p for p in prefix.split('/') if p]):
            raise ValueError('prefix depth would authorize an ancestor of the scoped path family')
    declared = config.get('declaredTcp', [])
    if not isinstance(declared, list):
        raise ValueError('declaredTcp must be a list of explicit business requirements')
    seen = set()
    for item in declared:
        if not isinstance(item, dict) or set(item) != {'destination', 'reason', 'approved'}:
            raise ValueError('declaredTcp requires destination, reason and explicit approved boolean')
        endpoint = destination(item['destination'])
        if endpoint in seen or not safe_text(item['reason']) or not item['reason'].strip() or type(item['approved']) is not bool:
            raise ValueError('duplicate or invalid declared TCP requirement')
        if item['approved'] and endpoint in {destination(x) for x in config.get('excludedTcp', [])}:
            raise ValueError('a declared TCP destination cannot be approved and excluded')
        if not item['approved'] and endpoint in {destination(x) for x in config.get('approvedTcp', [])}:
            raise ValueError('conflicting declared and observed TCP approval decisions')
        seen.add(endpoint)


def request_options(config, domain, port, method, path):
    """Scope a business decision to one host/port/method/path family."""
    selected = [r for r in config.get('requests', []) if r['host'] == domain and r['port'] == port and
                r['method'] == method and (path in r.get('paths', []) or
                ('pathPrefix' in r and path.startswith(r['pathPrefix'])))]
    if len(selected) > 1:
        raise RuntimeError('overlapping scoped HTTP decisions; resolve the ambiguity before analysis')
    # Scoped decisions replace legacy domain-wide options, while retaining explicit defaults.
    base = {**config.get('default', {})}
    override = selected[0] if selected else config.get('domains', {}).get(domain, {})
    base.update({k: override[k] for k in ('path', 'depth', 'methods', 'includeErrors') if k in override})
    return base


def declared_tcp_status(records, config):
    observed = set()
    for rec in records:
        ev = rec['event']
        if rec.get('action') != 'AUDIT' or ev.get('layer') != 'L4' or ev.get('sni') or ev.get('reason') not in (None, '', '-'):
            continue
        try:
            observed.add(destination(ev.get('dstAddress')))
        except (ValueError, TypeError, AttributeError):
            continue
    return [{**item, 'origin': 'user-declared', 'observed': destination(item['destination']) in observed,
             'verification': 'not-assessed'} for item in config.get('declaredTcp', [])]


def observe(args):
    root = Path(args.session).resolve()
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise ValueError('session directory must be new or empty; existing files will not be overwritten')
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', args.name) or len(args.name) > 63:
        raise ValueError('invalid policy name')
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', args.namespace) or len(args.namespace) > 63:
        raise ValueError('invalid namespace')
    if len(f'varmor-{args.namespace}-{args.name}') > 63:
        raise ValueError('namespace and policy name are too long together: varmor-NAMESPACE-POLICY must fit 63 characters')
    target = {'kind': args.kind, 'name': args.workload}
    if args.selector:
        labels = dict(pair.split('=', 1) for pair in args.selector.split(','))
        for key, value in labels.items():
            label_name = key.rsplit('/', 1)[-1]
            valid = r'[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?'
            if not re.fullmatch(valid, label_name) or (value and not re.fullmatch(valid, value)):
                raise ValueError('invalid selector label key/value')
            if '/' in key:
                prefix = key.rsplit('/', 1)[0]
                if '/' in prefix or host(prefix) != prefix or len(prefix) > 253:
                    raise ValueError('invalid selector label prefix')
        target = {'kind': args.kind, 'selector': {'matchLabels': labels}}
    if not args.workload and not args.selector and not args.base_policy:
        raise ValueError('specify --workload or --selector')
    if args.since is not None and args.since < 0:
        raise ValueError('--since must be nonnegative Unix seconds')
    domains = None
    if args.mitm_domain or args.clear_mitm:
        domains = []
        for domain in args.mitm_domain:
            try:
                canonical = str(ipaddress.ip_address(domain))
            except ValueError:
                if ':' in domain or '[' in domain:
                    raise ValueError('--mitm-domain takes a literal domain/IP without a port')
                canonical = host(domain)
            domains.append(canonical)
        domains = sorted(set(domains))
    egress = {'defaultAction': 'allow'}
    if args.observe in ('http', 'both'):
        egress['httpRules'] = [{'qualifiers': ['audit'], 'match': {'hosts': ['*']},
                               'description': 'Observe HTTP and TLS SNI without blocking'}]
    if args.observe in ('tcp', 'both'):
        # The translator skips L4 rules without IP/CIDR/port predicates.
        # A full destination-port range works for both IPv4 and IPv6.
        egress['rules'] = [{'qualifiers': ['audit'], 'ports': [{'port': 1, 'endPort': 65535}],
                            'description': 'Observe all redirected TCP ports'}]
    policy = {'enforcer': 'NetworkProxy', 'mode': 'EnhanceProtect',
              'enhanceProtect': {'networkProxyRawRules': {'egress': egress}}}
    if domains:
        policy['networkProxyConfig'] = {'mitm': {'domains': domains}}
    manifest = {'apiVersion': 'crd.varmor.org/v1beta1', 'kind': 'VarmorPolicy',
                'metadata': {'name': args.name, 'namespace': args.namespace},
                'spec': {'target': target, 'updateExistingWorkloads': False, 'policy': policy}}
    base = load(args.base_policy) if args.base_policy else None
    if args.base_policy and (not isinstance(base, dict) or not base):
        raise ValueError('--base-policy requires a VarmorPolicy JSON object')
    if base:
        if base.get('kind') != 'VarmorPolicy' or base.get('apiVersion') != manifest['apiVersion']:
            raise ValueError('--base-policy must be a VarmorPolicy JSON export from kubectl get -o json')
        if base['metadata']['name'] != args.name or base['metadata'].get('namespace') != args.namespace:
            raise ValueError('base policy name/namespace must match this session')
        if (args.workload or args.selector) and base['spec']['target'] != target:
            raise ValueError('existing policy target is immutable; omit target flags to preserve it')
        manifest = {'apiVersion': base['apiVersion'], 'kind': base['kind'],
                    'metadata': {k: v for k, v in base['metadata'].items() if k in ('name', 'namespace', 'labels', 'annotations')},
                    'spec': copy.deepcopy(base['spec'])}
        manifest['metadata'].get('annotations', {}).pop('kubectl.kubernetes.io/last-applied-configuration', None)
        policy = manifest['spec']['policy']
        network_rules(policy)['egress'] = egress
        if 'networkproxy' not in policy['enforcer'].lower():
            policy['enforcer'] += 'NetworkProxy'
        config = policy.setdefault('networkProxyConfig', {})
        if args.clear_mitm:
            config.pop('mitm', None)
        elif domains is not None:
            config.setdefault('mitm', {})['domains'] = domains
            mutations = config['mitm'].get('headerMutations', [])
            if any(m.get('domain') not in domains for m in mutations):
                raise ValueError('MITM domain change excludes existing header mutations; review the base policy explicitly')
        if not config:
            policy.pop('networkProxyConfig', None)
    # Policy changes must not delegate workload lifecycle changes to the controller,
    # including when the imported policy previously enabled automatic updates.
    manifest['spec']['updateExistingWorkloads'] = False
    domains = policy.get('networkProxyConfig', {}).get('mitm', {}).get('domains', [])
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    write(root / 'observe.yaml', manifest)  # JSON is valid YAML, avoiding a PyYAML dependency.
    if base:
        write(root / 'original-policy.json', base)
    write(root / 'session.json', {'version': 2, 'context': args.context, 'namespace': args.namespace,
          'policy': args.name, 'profile': f'varmor-{args.namespace}-{args.name}', 'createdAt': now(),
          'startedAt': args.since if args.since is not None else int(dt.datetime.now(dt.timezone.utc).timestamp()), 'mitmDomains': domains,
          'podUIDs': [], 'observation': args.observe, 'sessionId': uuid.uuid4().hex,
          'reportLanguage': getattr(args, 'language', None) or 'en',
          **({'historicalSince': args.since} if args.since is not None else {}),
          **({'policyUID': base['metadata']['uid']} if base and base['metadata'].get('uid') else {})})
    print(json.dumps({'session': str(root), 'manifest': str(root / 'observe.yaml')}, ensure_ascii=False))


def crd_compatibility(crd):
    """Check the API contract, allowing later releases that retain these capabilities."""
    versions = crd.get('spec', {}).get('versions', [])
    served = [v.get('name') for v in versions if v.get('served') is True]
    version = next((v for v in versions if v.get('name') == 'v1beta1' and v.get('served') is True), None)
    findings, missing = [], []
    if version is None:
        findings.append('CRD does not serve crd.varmor.org/v1beta1 required by this Skill; '
                        'check installed CRD/API compatibility for vArmor v0.10 and later')
    else:
        schema = version.get('schema', {}).get('openAPIV3Schema', {})
        # Check the default observation and allowlist contract. Optional MITM settings,
        # imported policy modes and detailed rule constraints also need server dry-run.
        paths = ('spec.updateExistingWorkloads', 'spec.policy.networkProxyConfig',
                 'spec.policy.enhanceProtect.networkProxyRawRules.egress.defaultAction',
                 'spec.policy.enhanceProtect.networkProxyRawRules.egress.httpRules',
                 'spec.policy.enhanceProtect.networkProxyRawRules.egress.rules')
        for path in paths:
            field = schema
            for part in path.split('.'):
                field = field.get('properties', {}).get(part) if isinstance(field, dict) else None
            if field is None:
                missing.append(path)
        if missing:
            findings.append('CRD is missing fields required by this Skill: ' + ', '.join(missing))
    return {'releaseRange': 'v0.10 and later', 'checkBasis': 'served API and CRD capabilities',
            'policyAPIVersion': 'crd.varmor.org/v1beta1', 'servedCRDVersions': served,
            'missingCRDFields': missing, 'compatibleCRD': not findings}, findings


def doctor(args):
    findings = []
    nodes = get(args.context, 'nodes')['items']
    ready = [n['metadata']['name'] for n in nodes if any(c['type'] == 'Ready' and c['status'] == 'True'
             for c in n['status'].get('conditions', []))]
    if not ready:
        findings.append('No Ready nodes; Pod exec, audit collection and traffic verification unavailable')
    crd = get(args.context, 'crd', name='varmorpolicies.crd.varmor.org')
    compatibility, crd_findings = crd_compatibility(crd)
    findings.extend(crd_findings)
    hooks = get(args.context, 'mutatingwebhookconfigurations')['items']
    varmor = [h for obj in hooks for h in obj.get('webhooks', []) if 'varmor' in h.get('name', '')]
    if not varmor:
        findings.append('No vArmor mutating webhook')
    result = {'context': args.context, 'readyNodes': ready, 'findings': findings, 'compatibility': compatibility,
              'webhooks': [{'name': h['name'], 'failurePolicy': h.get('failurePolicy'),
                            'objectSelector': h.get('objectSelector', {}),
                            'namespaceSelector': h.get('namespaceSelector', {}),
                            'clientConfig': {k: v for k, v in h['clientConfig'].items() if k != 'caBundle'}} for h in varmor]}
    if getattr(args, 'namespace', None):
        permissions = {}
        for verb, resource in (('get', 'varmorpolicies'), ('list', 'pods'), ('watch', 'pods'), ('create', 'pods/exec'),
                               ('create', 'varmorpolicies'), ('patch', 'varmorpolicies')):
            try:
                allowed = kube(args.context, 'auth', 'can-i', verb, resource, '-n', args.namespace).strip() == 'yes'
            except RuntimeError as exc:
                # can-i returns exit 1 for "no". Preserve other diagnostic failures separately.
                allowed = False
                if str(exc):
                    permissions[verb + ' ' + resource + ' diagnostic'] = str(exc)
            permissions[verb + ' ' + resource] = allowed
            if not allowed and (verb, resource) in (('get', 'varmorpolicies'), ('list', 'pods'), ('watch', 'pods'), ('create', 'pods/exec')):
                findings.append(f'Missing {verb} {resource} in {args.namespace}; live collection requires these permissions')
        result['namespace'] = args.namespace
        agent_permissions = {}
        agent_namespace = getattr(args, 'agent_namespace', 'varmor')
        for verb, resource in (('list', 'pods'), ('create', 'pods/exec')):
            try:
                agent_permissions[verb + ' ' + resource] = kube(args.context, 'auth', 'can-i', verb, resource,
                                                               '-n', agent_namespace).strip() == 'yes'
            except RuntimeError:
                agent_permissions[verb + ' ' + resource] = False
        result['agentNamespace'] = agent_namespace
        result['agentPermissions'] = agent_permissions
        result['permissions'] = permissions
    if args.output:
        write(args.output, result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 2 if findings else 0


def live_inventory(state, expected=None, allow_empty=False):
    context, ns = state['context'], state['namespace']
    policy = get(context, 'varmorpolicies', ns, state['policy'])
    if policy['spec'].get('updateExistingWorkloads', False):
        raise RuntimeError('Live policy enables automatic workload updates; apply the generated policy with updateExistingWorkloads=false')
    if state.get('policyUID') and state['policyUID'] != policy['metadata']['uid']:
        raise RuntimeError('Policy was recreated; start a new session to avoid mixing identities')
    if state.get('verificationOrigin') == 'approved-deployed-policy':
        frozen = state.get('initialPolicy', {}).get('specHash')
        if evidence_module().digest(policy['spec']) != frozen or expected is not None and \
                evidence_module().digest(expected) != state.get('initialCandidateHash'):
            raise RuntimeError('Approved full Policy spec or frozen candidate changed; initialize a new reviewed verification workflow')
    if expected:
        actual = policy['spec']['policy']
        wanted = expected['spec']['policy']
        if actual.get('mode') != wanted['mode'] or actual.get('enforcer') != wanted['enforcer'] or \
           network_rules(copy.deepcopy(actual)) != network_rules(copy.deepcopy(wanted)) or \
           actual.get('networkProxyConfig', {}).get('mitm') != wanted.get('networkProxyConfig', {}).get('mitm') or \
           policy['spec']['target'] != expected['spec']['target']:
            raise RuntimeError('Live policy differs from observation manifest; do not mix enforcement or MITM scopes')
    state['policyUID'] = policy['metadata']['uid']
    expected = f"varmor-{ns}-{state['policy']}"
    state['profile'] = policy.get('status', {}).get('profileName', expected)
    # Pod-level attribution is stronger than mutable labels or name prefixes.
    pods = get(context, 'pods', ns)['items']
    annotation = 'pod.networkproxy.security.beta.varmor.org'
    matched = [p for p in pods if p['metadata'].get('annotations', {}).get(annotation) == 'localhost/' + state['profile']]
    if state.get('purpose') == 'verification':
        if state.get('verificationMode') == 'new-pods':
            for p in matched:
                collector_module().register_pod(state, p, globals())
        selected = set(state['verifiedPodUIDs'])
        matched = [p for p in matched if p['metadata']['uid'] in selected]
        state['podUIDs'] = sorted(selected)
    baseline = set(state.get('baselinePodUIDs', []))
    if state.get('purpose') != 'verification':
        state['podUIDs'] = sorted(set(state['podUIDs']) | {p['metadata']['uid'] for p in matched
                                                      if p['metadata']['uid'] not in baseline})
    if not matched and not allow_empty:
        raise RuntimeError('No Pods with the policy NetworkProxy annotation; injection not verified')
    for p in matched:
        if not any(c['name'] == 'varmor-network-proxy' for c in p['spec']['containers']):
            raise RuntimeError('Policy annotation exists but proxy container is absent')
    return matched, policy


def status(args):
    """Read-only observation readiness check, including actual injection and Pod readiness."""
    root = Path(args.session)
    state = load(root / 'session.json')
    progress = load(root / 'collector.json') if (root / 'collector.json').exists() else None
    pods, policy = live_inventory(state, load(root / 'observe.yaml'), allow_empty=progress is not None)
    inventory = []
    for pod in pods:
        ready = any(c.get('type') == 'Ready' and c.get('status') == 'True'
                    for c in pod.get('status', {}).get('conditions', []))
        inventory.append({'name': pod['metadata']['name'], 'uid': pod['metadata']['uid'],
                          'observationEligible': pod['metadata']['uid'] not in state.get('baselinePodUIDs', []),
                          'createdAt': pod['metadata'].get('creationTimestamp'),
                          'node': pod['spec'].get('nodeName'), 'ready': ready,
                          'phase': pod.get('status', {}).get('phase'),
                          'terminating': bool(pod['metadata'].get('deletionTimestamp'))})
    eligible = [p for p in inventory if not p['terminating'] and p['observationEligible']]
    ready = policy.get('status', {}).get('ready') is True and bool(eligible) and all(p['ready'] for p in eligible)
    result = {'context': state['context'], 'namespace': state['namespace'], 'policy': state['policy'],
              'readyForCollection': ready, 'policyReady': policy.get('status', {}).get('ready', False),
              'pods': inventory, 'nextStep': 'collect' if ready else 'inspect policy status, Pod events and proxy logs',
              'note': 'Readiness does not prove a new Pod or startup coverage. The user manages workload creation/recreation; verify new Pod UIDs and startup audits.'}
    if progress:
        alive = None
        if os.name == 'posix':
            try:
                os.kill(progress['processId'], 0)
                alive = True
            except (ProcessLookupError, KeyError):
                alive = False
            except PermissionError:
                pass
        result['collector'] = {**progress, 'processAlive': alive,
                               'active': progress.get('phase') in ('ready', 'observing') and alive is not False}
        if result['collector']['active'] and not eligible:
            result['nextStep'] = 'User creates/recreates target Pods; collector is already watching'
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if ready else 2


def sources(state, args, pods):
    context, ns = state['context'], state['namespace']
    def read_log(*prefix, path='/var/log/varmor'):
        command = ['sh', '-c', 'cat ' + path + '/violations*.log'] if args.include_rotated else \
                  ['cat', path + '/violations.log']
        try:
            return kube(context, *prefix, '--', *command)
        except RuntimeError as exc:
            if not any(token in str(exc) for token in ('error reading from error stream', 'read message:')):
                raise
            # Retry only read-only transport failures. Smaller exec responses avoid
            # one large stream; reject rotation/truncation rather than mix snapshots.
            reader = collector_module().Reader(globals(), state)
            endpoint = {'id': 'snapshot', 'prefix': list(prefix), 'directory': path}
            files = reader.manifest(endpoint)
            files = {identity: value for identity, value in files.items()
                     if args.include_rotated or value['path'].endswith('/violations.log')}
            if not files:
                raise RuntimeError('Audit snapshot unavailable after exec stream failure; do not interpret this as no events')
            fragments = []
            for identity, value in sorted(files.items(), key=lambda item: item[1]['path']):
                chunks = []
                for offset in range(0, value['size'], 2 * 1024 * 1024):
                    length = min(2 * 1024 * 1024, value['size'] - offset)
                    raw = reader.read(endpoint, value['path'], offset, length)
                    if len(raw) != length:
                        raise RuntimeError('Audit snapshot changed during chunked retry; retry or use monitor')
                    chunks.append(raw)
                fragments.append(b''.join(chunks).decode('utf-8'))
            current = reader.manifest(endpoint)
            if any(identity not in current or current[identity]['path'] != value['path'] or
                   current[identity]['size'] < value['size'] for identity, value in files.items()):
                raise RuntimeError('Audit files rotated during chunked retry; retry or use monitor')
            return '\n'.join(fragments)
    source = args.source
    if source == 'auto':
        vm = [p for p in pods if not any(v.get('hostPath') for v in p['spec'].get('volumes', [])
              if v.get('name') == 'varmor-network-proxy-audit-als')]
        regular = [p for p in pods if p not in vm]
        output = sources(state, argparse.Namespace(**{**vars(args), 'source': 'sidecar'}), vm) if vm else []
        if regular:
            output += sources(state, argparse.Namespace(**{**vars(args), 'source': 'agent'}), regular)
        return output
    if args.source == 'sidecar':
        # Only micro-VM sidecars normally contain normalized violations.log.
        return [(p['metadata']['uid'], read_log('exec', '-n', ns, p['metadata']['name'],
                 '-c', 'varmor-network-proxy')) for p in pods]
    if args.source == 'agent':
        argv = ['get', 'pods', '-n', args.agent_namespace]
        if args.agent_selector:
            argv += ['-l', args.agent_selector]
        agents = json.loads(kube(context, *argv, '-o', 'json'))['items']
        nodes = {p['spec'].get('nodeName') for p in pods}
        selected = {}
        for p in agents:
            node = p['spec'].get('nodeName')
            if node not in nodes or p['metadata'].get('deletionTimestamp'):
                continue
            for c in p['spec']['containers']:
                command = c.get('command', []) + c.get('args', [])
                detected = any(token in ('--agent', '-agent', '--agent=true', '-agent=true') for token in command)
                if (args.agent_container and c['name'] == args.agent_container and (args.agent_selector or detected)) or \
                   (not args.agent_container and detected):
                    selected.setdefault(node, []).append((p, c['name']))
        if any(len(selected.get(node, [])) != 1 for node in nodes):
            if args.create_readers and not args.agent_selector and not args.agent_container:
                return sources(state, argparse.Namespace(**{**vars(args), 'source': 'nodes'}), pods)
            raise RuntimeError('Cannot identify one vArmor Agent per target node. Set --agent-selector and --agent-container, '
                               'or authorize --source nodes --create-readers; micro-VM uses --source sidecar')
        return [(node, read_log('exec', '-n', args.agent_namespace,
                p['metadata']['name'], '-c', container))
                for node, pairs in sorted(selected.items()) for p, container in pairs]
    # Explicit opt-in: short-lived node-pinned reader, no privileged mode/host network.
    if not args.create_readers:
        raise RuntimeError('--source nodes requires --create-readers (read-only hostPath Pods)')
    output = []
    for node in sorted({p['spec'].get('nodeName') for p in pods}):
        if not node:
            raise RuntimeError('Unscheduled target Pod')
        name = 'np-audit-reader-' + uuid.uuid4().hex[:10]
        reader = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': ns,
                   'labels': {'app.kubernetes.io/managed-by': 'varmor-network-advisor',
                              'varmor-advisor-session': state.get('sessionId', hashlib.sha256((context + '/' + ns + '/' + state['policy'] + state.get('createdAt', '')).encode()).hexdigest()[:16])}},
                  'spec': {'nodeName': node, 'restartPolicy': 'Never', 'automountServiceAccountToken': False,
                    'containers': [{'name': 'reader', 'image': args.reader_image,
                      'command': ['sh', '-c', 'sleep 300'],
                      'securityContext': {'runAsUser': 0, 'allowPrivilegeEscalation': False,
                         'readOnlyRootFilesystem': True,
                         'capabilities': {'drop': ['ALL'], 'add': ['DAC_READ_SEARCH']}},
                      'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'},
                                    'limits': {'cpu': '100m', 'memory': '64Mi'}},
                      'volumeMounts': [{'name': 'audit', 'mountPath': '/audit', 'readOnly': True}]}],
                    'volumes': [{'name': 'audit', 'hostPath': {'path': '/var/log/varmor', 'type': 'Directory'}}]}}
        kube(context, 'create', '-f', '-', data=json.dumps(reader))
        try:
            kube(context, 'wait', '-n', ns, '--for=condition=Ready', 'pod/' + name, '--timeout=60s')
            output.append((node, read_log('exec', '-n', ns, name, '-c', 'reader', path='/audit')))
        finally:
            kube(context, 'delete', 'pod', '-n', ns, name, '--wait=false', '--ignore-not-found')
    return output


def ingest(con, state, streams, offline=False, identities=None):
    stats = collections.Counter()
    seen_sources = set()
    since = state['startedAt']
    for source, raw in streams:
        # Each source snapshot has its own ordinal; overlapping copies must not multiply events.
        occurrences = collections.Counter()
        if source in seen_sources:
            stats['duplicateSources'] += 1
            continue
        seen_sources.add(source)
        for index, line in enumerate(raw.split('\n')):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                if not isinstance(rec, dict):
                    raise ValueError('record is not an object')
            except (ValueError, TypeError):
                stats['malformed'] += 1
                continue
            if rec.get('enforcer') != 'NetworkProxy' or rec.get('podNamespace') != state['namespace'] or rec.get('profileName') != state['profile']:
                stats['unrelated'] += 1
                continue
            if state.get('purpose') == 'verification' and state.get('verificationMode') != 'new-pods' and rec.get('podUID') not in state['verifiedPodUIDs']:
                stats['unselectedPod'] += 1
                continue
            if rec.get('policyName') not in (None, '', state['policy']) or rec.get('policyNamespace') not in (None, '', state['namespace']):
                stats['identityMismatch'] += 1
                continue
            ts = rec.get('eventTimestamp')
            if type(ts) is not int or ts <= 0:
                stats['missingTimestamp'] += 1
                continue
            if ts < since:
                stats['beforeObservation'] += 1
                continue
            if state.get('endedAt') is not None and ts > state['endedAt']:
                stats['afterWindow'] += 1
                continue
            if not offline and rec.get('podUID') in state.get('baselinePodUIDs', []):
                stats['baselinePodExcluded'] += 1
                continue
            if any(k in rec and not isinstance(rec[k], str) for k in ('action', 'nodeName', 'podUID', 'podName')):
                stats['invalidEvent'] += 1
                continue
            if rec.get('action') not in ('AUDIT', 'DENIED'):
                stats['invalidEvent'] += 1
                continue
            unknown_pod = not offline and rec.get('podUID') not in state['podUIDs']
            if unknown_pod and identities is None:
                stats['unknownPod'] += 1
                continue
            ev = rec.get('event')
            if not isinstance(ev, dict) or ev.get('layer') not in ('L4', 'L7'):
                stats['invalidEvent'] += 1
                continue
            strings = ('filterChain', 'dstAddress', 'sni', 'authority', 'method', 'path', 'reason')
            if any(key in ev and not isinstance(ev[key], str) for key in strings) or \
               ('responseCode' in ev and type(ev['responseCode']) is not int):
                stats['invalidEvent'] += 1
                continue
            # Drop unrelated metadata, credentials in query strings, and raw log messages.
            clean = {k: rec[k] for k in ('nodeName', 'podUID', 'podName', 'podNamespace', 'profileName',
                      'eventTimestamp', 'action', 'enforcer') if k in rec}
            clean['event'] = {k: ev[k] for k in ('layer', 'filterChain', 'dstAddress', 'sni', 'authority',
                             'method', 'path', 'responseCode', 'reason') if k in ev}
            if isinstance(clean['event'].get('path'), str):
                clean['event']['path'] = clean['event']['path'].split('?', 1)[0]
            # Identity uses full normalized source record, before redaction. Preserve identical
            # entries within a snapshot; repeated snapshots dedupe by occurrence number.
            digest = hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
            occurrences[digest] += 1
            key = identities[index] if identities is not None else digest + ':' + str(occurrences[digest])
            if unknown_pod:
                # A short-lived Pod's watch event can arrive after its audit record.
                # Keep only normalized, redacted evidence until its UID is verified.
                con.execute('INSERT OR IGNORE INTO pending_pods VALUES (?,?)', (key, json.dumps(clean, sort_keys=True)))
                stats['pendingPodIdentity'] += 1
                continue
            cur = con.execute('INSERT OR IGNORE INTO events VALUES (?,?)', (key, json.dumps(clean, sort_keys=True)))
            stats['newEvents' if cur.rowcount else 'duplicateEvents'] += 1
    return dict(stats)


def collect(args):
    root = Path(args.session)
    with locked(root):
        state = load(root / 'session.json')
        if state.get('purpose') in ('verification', 'verification-only'):
            raise ValueError('Use bounded monitor for enforcement evidence; never collect into observation modeling')
        if not args.offline and (root / 'collector.json').exists() and \
           'maxTransferMiBPerMinute' in load(root / 'collector.json').get('plan', {}):
            raise ValueError('This workflow has resource limits; use bounded monitor, not an unbounded collection snapshot')
        previous_mode = state.get('collectionMode')
        if previous_mode is None and (root / 'events.sqlite').exists():
            with contextlib.closing(database(root)) as con:
                modes = {'offline' if json.loads(r[0]).get('offline') else 'live'
                         for r in con.execute('SELECT summary FROM rounds')}
            previous_mode = next(iter(modes)) if len(modes) == 1 else ('mixed' if modes else None)
        requested_mode = 'offline' if args.offline else 'live'
        if previous_mode == 'live-incremental':
            raise RuntimeError('Incremental observation already owns this session; use monitor/analyze or a separate snapshot session')
        if previous_mode and previous_mode != requested_mode:
            raise RuntimeError('Live and offline evidence cannot share a session; create a separate session')
        if args.file:
            streams = [(str(Path(f).resolve()), Path(f).read_text()) for f in args.file]
            offline = args.offline
            if not offline:
                _, policy = live_inventory(state, load(root / 'observe.yaml'))
        else:
            if args.offline:
                raise ValueError('--offline requires --file')
            pods, policy = live_inventory(state, load(root / 'observe.yaml'))
            streams = sources(state, args, pods)
            offline = False
        state['collectionMode'] = 'offline' if offline else 'live'
        with contextlib.closing(database(root)) as con, con:
            stats = ingest(con, state, streams, offline=offline)
            stats.update({'at': now(), 'offline': offline, 'sources': [s for s, _ in streams]})
            if not offline:
                stats['policyUID'] = policy['metadata']['uid']
                stats['generation'] = policy['metadata'].get('generation')
            stats['totalEvents'] = con.execute('SELECT count(*) FROM events').fetchone()[0]
            con.execute('INSERT INTO rounds(time,summary) VALUES (?,?)', (stats['at'], json.dumps(stats)))
        write(root / 'session.json', state)
        write(root / 'last-collection.json', stats)
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 2 if any(stats.get(k) for k in ('malformed', 'unknownPod', 'identityMismatch', 'missingTimestamp', 'invalidEvent')) else 0


def propose(records, state, config):
    options_check(config)
    http, tcp = {}, {}
    excluded = collections.Counter()
    pending = []
    visible_destinations = set()
    for rec in records:
        if rec['event']['layer'] == 'L7':
            visible_destinations.add(rec['event'].get('dstAddress'))
    approved_tcp = {destination(address) for address in config.get('approvedTcp', [])} | {
        destination(item['destination']) for item in config.get('declaredTcp', []) if item['approved']}
    excluded_hosts = set(config.get('excludedHosts', []))
    excluded_tcp = {destination(address) for address in config.get('excludedTcp', [])}
    if approved_tcp & excluded_tcp:
        raise ValueError('the same TCP destination cannot be both approved and excluded')
    for rec in sorted(records, key=lambda r: r['event']['layer'] != 'L7'):
        ev = rec['event']
        if rec.get('action') != 'AUDIT':
            excluded['notAudit'] += 1
            continue
        try:
            ip, port = destination(ev.get('dstAddress'))
            if ev['layer'] == 'L4' and ev.get('reason') not in (None, '', '-'):
                excluded['connectionDetailsNeedReview'] += 1
                continue
            if ev['layer'] == 'L7':
                domain = http_host(ev.get('authority', ''), port)
                if domain in excluded_hosts:
                    excluded['businessExcludedHost'] += 1
                    continue
                opt = request_options(config, domain, port, ev.get('method'), ev.get('path', '').split('?', 1)[0])
                status = ev.get('responseCode', 0)
                if type(status) is not int or not 100 <= status <= 599:
                    raise ValueError('missing response code')
                if not 200 <= status < 400 and not opt.get('includeErrors', False):
                    excluded['upstreamErrorNeedsReview'] += 1
                    continue
                method, path = ev.get('method', ''), ev.get('path', '')
                if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", method) or not safe_text(method):
                    raise ValueError('invalid method')
                chain = ev.get('filterChain', '')
                if ('mitm' in chain or ev.get('sni')) and not mitm_applies(domain, state['mitmDomains']):
                    excluded['unapprovedMitm'] += 1
                    continue
                if ev.get('sni') and host(ev['sni']) != domain:
                    excluded['sniAuthorityMismatchNeedsReview'] += 1
                    continue
                match = {'hosts': [domain], 'ports': [{'port': port}]}
                if opt.get('path', 'exact') != 'host':
                    match['paths'] = [path_match(path, opt)]
                if opt.get('methods', True):
                    match['methods'] = [method]
                kind = 'http'
            elif ev.get('sni'):
                domain = host(ev['sni'])
                if domain in excluded_hosts:
                    excluded['businessExcludedHost'] += 1
                    continue
                if mitm_applies(domain, state['mitmDomains']):
                    excluded['mitmL4WouldBroaden'] += 1
                    continue
                match = {'hosts': [domain], 'ports': [{'port': port}]}
                if any(rule['match']['hosts'] == [domain] and rule['match']['ports'] == [{'port': port}]
                       for rule in http.values()):
                    excluded['tlsAlreadyCoveredWithoutBroaderHttpRule'] += 1
                    continue
                kind = 'http'
            else:
                address = ev['dstAddress']
                if (ip, port) in excluded_tcp:
                    excluded['businessExcludedTcp'] += 1
                    continue
                if (ip, port) not in approved_tcp:
                    pending.append({'destination': address, 'reason': 'TCP/IP authorization requires review',
                                    'overlapsVisibleHTTP': address in visible_destinations})
                    excluded['tcpNeedsReview'] += 1
                    continue
                match = {'ip': ip, 'ports': [{'port': port}]}
                kind = 'tcp'
            key = json.dumps(match, sort_keys=True)
            bucket = http if kind == 'http' else tcp
            bucket.setdefault(key, {'qualifiers': ['allow', 'audit'], **({'match': match} if kind == 'http' else match)})
        except (ValueError, TypeError, AttributeError, KeyError):
            excluded['invalidFields'] += 1
    for item in declared_tcp_status(records, config):
        ip, port = destination(item['destination'])
        if item['approved']:
            match = {'ip': ip, 'ports': [{'port': port}]}
            key = json.dumps(match, sort_keys=True)
            tcp.setdefault(key, {'qualifiers': ['allow', 'audit'], **match})
        elif (ip, port) not in excluded_tcp:
            pending.append({'destination': item['destination'], 'origin': 'user-declared',
                            'reason': 'Required business connection awaits whole IP/port approval',
                            'observed': item['observed'], 'overlapsVisibleHTTP': item['destination'] in visible_destinations})
    egress = {'defaultAction': 'deny'}
    if http:
        egress['httpRules'] = [http[k] for k in sorted(http)]
    if tcp:
        egress['rules'] = [tcp[k] for k in sorted(tcp)]
    observed_tcp = {destination(x['destination']) for x in declared_tcp_status(records,
                    {'declaredTcp': [{'destination': x, 'reason': 'approved audit destination', 'approved': True}
                                     for x in config.get('approvedTcp', [])]}) if x['observed']}
    declared_destinations = {destination(x['destination']) for x in config.get('declaredTcp', [])}
    for address in config.get('approvedTcp', []):
        if destination(address) not in observed_tcp | declared_destinations:
            pending.append({'destination': address, 'origin': 'approvedTcp',
                            'reason': 'Approved destination has no usable raw TCP evidence; collect evidence or explicitly declare the requirement'})
    return egress, dict(excluded), list({destination(x['destination']): x for x in pending}.values())


def replay_match(rec, egress, state):
    """Replay only generated literal rules; a coverage aid, never a substitute for Envoy."""
    denied = {key: [r for r in egress.get(key, []) if 'deny' in r.get('qualifiers', [])]
              for key in ('rules', 'httpRules')}
    if any(denied.values()) and _replay_rules(rec, denied, state):
        return False
    allowed = {key: [r for r in egress.get(key, []) if 'allow' in r.get('qualifiers', [])]
               for key in ('rules', 'httpRules')}
    return _replay_rules(rec, allowed, state)


def _replay_rules(rec, egress, state):
    ev = rec['event']
    try:
        ip, port = destination(ev.get('dstAddress'))
        for r in egress.get('rules', []):
            if r['ip'] == ip and any(p['port'] <= port <= p.get('endPort', p['port']) for p in r['ports']):
                return True
        visible = ev['layer'] == 'L7'
        domain = http_host(ev.get('authority', ''), port) if visible else host(ev.get('sni', ''))
        for r in egress.get('httpRules', []):
            m = r['match']
            if domain not in m['hosts'] or not any(p['port'] <= port <= p.get('endPort', p['port']) for p in m['ports']):
                continue
            # Paths/methods are ignored for TLS passthrough in vArmor. Never generate
            # this accidental permission for a domain known to be MITM.
            if not visible:
                if not mitm_applies(domain, state['mitmDomains']):
                    return True
                continue
            path = ev.get('path', '').split('?', 1)[0]
            if m.get('methods') and ev.get('method') not in m['methods']:
                continue
            if m.get('paths') and not any(path == p.get('exact') or
                      ('prefix' in p and path.startswith(p['prefix'])) for p in m['paths']):
                continue
            return True
    except (ValueError, KeyError, TypeError, AttributeError):
        pass
    return False


def http_protocol_impact(rule, egress, state):
    """Describe candidate scope, never claim proxy loading or traffic acceptance."""
    match = rule['match']
    domains = match.get('hosts', [])
    if domains and all(mitm_applies(domain, state['mitmDomains']) for domain in domains):
        return 'Plaintext HTTP and MITM-decrypted HTTPS share these host/port/method/path rules; not HTTPS-only'
    denies = [r.get('match', {}) for r in egress.get('httpRules', []) if 'deny' in r.get('qualifiers', [])]
    if not denies:
        return 'Plaintext HTTP; HTTPS passthrough checks SNI/port only, without path or method restrictions'

    def interval(port):
        start, end = port.get('port'), port.get('endPort', port.get('port'))
        if type(start) is not int or type(end) is not int or not 1 <= start <= end <= 65535:
            return None
        return start, end

    def covered(domain, required):
        # Only literal host equality is inferred here. Wildcards and unknown
        # matches keep a caveat, rather than being promoted to a scope proof.
        ranges = [interval(p) for m in denies if domain in m.get('hosts', []) for p in m.get('ports', [])]
        cursor = required[0]
        for start, end in sorted(r for r in ranges if r is not None):
            if start > cursor:
                break
            cursor = max(cursor, end + 1)
            if cursor > required[1]:
                return True
        return False

    ports = [interval(p) for p in match.get('ports', [])]
    if domains and ports and all(p is not None for p in ports) and \
            all(not mitm_applies(domain, state['mitmDomains']) and covered(domain, p) for domain in domains for p in ports):
        return 'Plaintext HTTP; approved HTTP deny constraints block matching TLS passthrough in this candidate'
    return 'Plaintext HTTP; TLS passthrough is subject to explicit deny constraints; inspect their host/port scope'


def analyze(args):
    root = Path(args.session)
    if load(root / 'session.json').get('purpose') == 'verification-only':
        raise ValueError('This workflow verifies an approved policy; it has no observation data to model')
    if load(root / 'session.json').get('purpose') == 'verification':
        return refinement_module().collection_report(args, globals())
    with locked(root):
        refinement_module().assert_candidate_owned(root, globals())
        state = load(root / 'session.json')
        manifest = load(root / 'observe.yaml')
        if manifest['spec'].get('updateExistingWorkloads', False):
            raise RuntimeError('Observation manifest enables automatic workload updates; create a new session with the current observe command')
        language = report_language(args, state, root)
        def tr(template, **values):
            return (ZH_REPORT_TEXT.get(template, template) if language == 'zh-CN' else template).format(**values)
        config = load(args.review) if args.review else (load(root / 'review.json') if (root / 'review.json').exists() else {})
        verification_path = getattr(args, 'verification', None) or state.get('verificationFile')
        verification = load(verification_path) if verification_path else None
        if verification is not None and (verification.get('kind') != 'NetworkProxyVerification' or
                verification.get('observationSession') != str(root.resolve())):
            raise ValueError('verification does not belong to this observation session')
        with contextlib.closing(database(root)) as con:
            records = [json.loads(r[0]) for r in con.execute('SELECT record FROM events ORDER BY id')]
            rounds = [json.loads(r[0]) for r in con.execute('SELECT summary FROM rounds ORDER BY id')]
            collection_health = collector_module().health(con)
        if state.get('collectionMode') != 'live-incremental':
            collection_health['status'] = 'not-assessed'
            collection_health['method'] = 'Snapshot/offline import has no file continuity tracking'
        collector_progress = load(root / 'collector.json') if (root / 'collector.json').exists() else None
        egress, excluded, pending = propose(records, state, config)
        refinements = load(root / 'refinement.json') if (root / 'refinement.json').exists() else {}
        available = refinement_module().permissions(refinement_module().authorized_rules(egress, refinements))
        explicit_deny_all = bool(available) and all(p['id'] in refinements.get('revokedRuleIds', []) for p in available)
        egress = refinement_module().merge(egress, refinements)
        if args.review:
            write(root / 'review.json', config)  # Preserve business decisions for later cycles.
        manifest['spec']['updateExistingWorkloads'] = False
        network_rules(manifest['spec']['policy'])['egress'] = egress
        # Preserve target and MITM config; candidate is a draft, never automatically applied.
        rule_count = len(refinement_module().permissions(egress))
        if rule_count or explicit_deny_all:
            write(root / 'candidate.yaml', manifest)
        elif (root / 'candidate.yaml').exists():
            os.replace(root / 'candidate.yaml', root / 'candidate.previous.yaml')
        network_rules(manifest['spec']['policy'])['egress'] = \
            network_rules(load(root / 'observe.yaml')['spec']['policy'])['egress']
        write(root / 'validation.yaml', manifest)
        inventory = collections.Counter()
        uncovered_inventory = collections.Counter()
        coverage_flags = [replay_match(r, egress, state) for r in records]
        for rec, covered in zip(records, coverage_flags):
            ev = rec['event']
            key = (ev.get('layer'), ev.get('authority') or ev.get('sni') or ev.get('dstAddress'),
                   ev.get('method'), ev.get('path'), rec.get('action'))
            inventory[key] += 1
            if not covered:
                uncovered_inventory[key] += 1
        rows = [{'layer': k[0], 'destination': k[1], 'method': k[2], 'path': k[3],
                 'action': k[4], 'count': v, 'covered': v - uncovered_inventory[k],
                 'uncovered': uncovered_inventory[k]} for k, v in sorted(inventory.items(), key=lambda x: str(x[0]))]
        previous = load(root / 'analysis.json') if (root / 'analysis.json').exists() else None
        def permissions(value):
            return {json.dumps({'layer': layer, 'action': 'deny' if 'deny' in rule.get('qualifiers', []) else 'allow',
                               **{k: v for k, v in rule.items() if k != 'qualifiers'}}, sort_keys=True) for layer, key in
                    (('HTTP/SNI', 'httpRules'), ('TCP', 'rules')) for rule in value.get(key, [])}
        current_permissions = permissions(egress)
        previous_permissions = permissions((previous or {}).get('generatedEgress', {}))
        changes = {'baselineAvailable': previous is not None and 'generatedEgress' in previous,
                   'added': [json.loads(r) for r in sorted(current_permissions - previous_permissions)],
                   'removed': [json.loads(r) for r in sorted(previous_permissions - current_permissions)]}
        candidate_for_hash = load(root / 'observe.yaml')
        candidate_for_hash['spec']['updateExistingWorkloads'] = False
        network_rules(candidate_for_hash['spec']['policy'])['egress'] = egress
        digest = hashlib.sha256(json.dumps(candidate_for_hash, sort_keys=True).encode()).hexdigest()
        if verification is not None:
            updates = [d['at'] for key in ('permissionDecisions', 'auditDecisions', 'constraintDecisions') for d in refinements.get(key, [])]
            changed_after_window = False
            if updates:
                try:
                    window_end = dt.datetime.fromisoformat(verification['until'].replace('Z', '+00:00'))
                    changed_after_window = any(dt.datetime.fromisoformat(at.replace('Z', '+00:00')) > window_end for at in updates)
                except (KeyError, ValueError, TypeError):
                    changed_after_window = True
            verification = {**verification, 'currentCandidate': verification.get('candidateHash') == digest and not changed_after_window,
                            'permissionChangesAfterWindow': changed_after_window}
            if getattr(args, 'verification', None):
                state['verificationFile'] = str(Path(args.verification).resolve())
                write(root / 'session.json', state)
        refinements = refinement_module().annotated_verification(refinements, verification, state, globals())
        healthy = [r for r in rounds if r.get('newEvents', 0) > 0 and not any(r.get(k) for k in
                   ('malformed', 'unknownPod', 'identityMismatch', 'missingTimestamp', 'invalidEvent',
                    'readFailures', 'backlogBytes', 'unresolvedPodEvents'))]
        timestamps = [r['eventTimestamp'] for r in records]
        coverage = sum(coverage_flags)
        unchanged = previous is not None and digest == previous.get('candidateHash')
        newer = len(healthy) > (previous or {}).get('healthyRounds', 0)
        stable = ((previous or {}).get('stableDataRounds', 0) + 1) if unchanged and newer else \
                 ((previous or {}).get('stableDataRounds', 0) if unchanged else 0)
        requirements = declared_tcp_status(records, config)
        for requirement in requirements:
            ip, port = destination(requirement['destination'])
            key = refinement_module().permission_id('TCP', {'ip': ip, 'ports': [{'port': port}]})
            requirement['authorizationState'] = 'revoked' if key in refinements.get('revokedRuleIds', []) else \
                'approved' if requirement['approved'] else 'pending'
        if verification and verification['currentCandidate']:
            for requirement in requirements:
                if requirement['authorizationState'] == 'revoked':
                    continue
                results = [c['result'] for c in verification.get('checks', []) if c.get('layer') == 'L4' and
                           c.get('expected') == 'allow' and destination(c['destination']) == destination(requirement['destination'])]
                if results:
                    requirement['verification'] = 'contradicted' if 'contradicted' in results else \
                                                  'confirmed' if all(r == 'confirmed' for r in results) else 'insufficient'
        required_pending = [x for x in requirements if not x['approved'] and
                            destination(x['destination']) not in {destination(y) for y in config.get('excludedTcp', [])}]
        report = {'at': now(), 'events': len(records), 'healthyRounds': len(healthy),
                  'reportLanguage': language,
                  'offlineRounds': sum(bool(r.get('offline')) for r in rounds),
                  'stableDataRounds': stable, 'observationSpanSeconds': max(timestamps) - min(timestamps) if timestamps else 0,
                  'candidateHash': digest, 'candidateRules': len(egress.get('rules', [])) + len(egress.get('httpRules', [])),
                  'replayCovered': coverage, 'replayUncovered': len(records) - coverage,
                  'excluded': excluded, 'pendingTcp': pending, 'inventory': rows,
                  'collectionIssues': {k: sum(r.get(k, 0) for r in rounds) for k in
                      ('malformed', 'unknownPod', 'identityMismatch', 'missingTimestamp', 'invalidEvent')
                      if any(r.get(k) for r in rounds)},
                  'businessExclusions': {'hosts': config.get('excludedHosts', []), 'tcp': config.get('excludedTcp', [])},
                  'tcpRequirements': requirements, 'requiredDecisionsPending': required_pending,
                  'legacyDomainWideReview': sorted(config.get('domains', {})),
                  'reviewState': 'incomplete-required-decisions' if required_pending else 'draft',
                  'verification': verification,
                  'generatedEgress': egress, 'ruleChanges': changes,
                  'permissions': refinement_module().permissions(egress), 'refinement': refinements,
                  'denyConstraints': list(refinements.get('denyConstraints', {}).values()),
                  'collectionHealth': collection_health,
                  'observation': collector_progress,
                  'baselinePodExcluded': sum(r.get('baselinePodExcluded', 0) for r in rounds),
                  'target': load(root / 'observe.yaml')['spec']['target'],
                  'session': str(root.resolve()),
                  'revokedPermissions': refinement_module().revocations(egress, refinements, state, globals()),
                  'explicitDenyAll': explicit_deny_all,
                  'decision': 'explicit-deny-all' if explicit_deny_all else 'review-required' if rule_count else 'insufficient-data',
                  'candidateFile': str((root / 'candidate.yaml').resolve()) if rule_count or explicit_deny_all else None,
                  'evidenceMode': state.get('collectionMode',
                      ('offline' if all(r.get('offline') for r in rounds) else
                       'live' if all(not r.get('offline') for r in rounds) else 'mixed') if rounds else 'none'),
                  'limitations': ['Observed activity is not evidence of business legitimacy.',
                    'Empty collection rounds do not prove convergence; offline replay is not Envoy verification.',
                    'TCP only; DNS/UDP, QUIC, loopback and traffic bypassing redirection are not covered.',
                    'Review startup, scheduled jobs, retry/failover and multi-replica coverage before enforcement.',
                    'Paths remain sensitive after query removal; keep session files private.',
                    'A host/port HTTP allow rule can authorize passthrough TLS by SNI unless explicit denies block it; HTTPS path/method limits require MITM.',
                    'HTTP rules do not select a URL scheme: MITM does not remove matching plaintext HTTP permissions, and explicit denies take precedence over grants.',
                    'Snapshot dedupe cannot distinguish identical entries across log rotation without an event ID.',
                    'No detected collection gap is not a guarantee of complete logs; upstream loss may be invisible.']}
        write(root / 'analysis.json', report)
        lines = [tr('# NetworkProxy allowlist recommendations'), '',
                 tr('Events: {events}; rules: {rules}; replay coverage: {covered}/{events}; collection rounds with new healthy data: {rounds}.',
                    events=len(records), rules=report['candidateRules'], covered=coverage, rounds=len(healthy)), '',
                 tr('Evidence source: {source}; stable data rounds: {stable}; event span: {span} seconds.',
                    source=report['evidenceMode'], stable=stable, span=report['observationSpanSeconds']), '',
                 tr('Collection continuity: {status}; excluded baseline Pod events: {excluded}. No detected gap does not guarantee complete logs.',
                    status=tr(collection_health['status']), excluded=report['baselinePodExcluded']), '',
                 tr('The candidate defaults to deny and requires business review and real traffic validation before deployment.' if rule_count or explicit_deny_all else
                    'Insufficient data or no acceptable rules: candidate.yaml was not generated. Collect additional evidence or review exclusions; do not enable enforcement with an empty allowlist.'), '',
                 tr('## Changes this round and next steps'), '',
                 (tr('Compared with the previous draft: {added} permissions added and {removed} removed.',
                     added=len(changes['added']), removed=len(changes['removed'])) if changes['baselineAvailable'] else
                  tr('Initial permission baseline established; later analysis will list added and removed permissions.')), '',
                 tr('1. Confirm that the destinations below are necessary for normal business. Unreviewed TCP is not automatically allowed.'),
                 '2. ' + tr('Review the extra paths and methods opened by generalization; users need not choose numeric path depths.'),
                 tr('3. Reuse injected Pods for rule-only tests. For additional startup observation, users create new instances after checking that collection is still ready; after observation ends, start a new session. Final startup acceptance uses a separate enforcement collection window. Review retries, low-frequency tasks and different replicas; reanalyzing old logs does not increase stability.'),
                 tr('4. After review, run allowed/denied traffic tests and keep observe.yaml as network-rule rollback material.'), '',
                 tr('## Actual permissions'), '',
                 tr('| Destination | Port | Path | Method | Granularity and impact |'),
                 '|---|---|---|---|---|']
        def cell(value):
            value = str(value).replace('|', '\\|').replace('\n', ' ')
            longest = max((len(x) for x in re.findall(r'`+', value)), default=0)
            fence = '`' * (longest + 1)
            return fence + ' ' + value + ' ' + fence
        if rule_count:
            lines[10:10] = [tr('Current draft: candidate.yaml. It is not automatically deployed.'), '']
        boundary = ('**回放覆盖只统计已保存的观察事件，不代表完整业务验收；拦截期 DENIED 与审核决定不增加成功观察次数。**'
                    if language == 'zh-CN' else
                    '**Replay covers saved observation records only, not full business acceptance. Enforcement DENIED and review decisions do not increase successful observation counts.**')
        status_lines = [boundary, '', ('证据与采集状态：' if language == 'zh-CN' else 'Evidence and collection state: ') +
                        json.dumps({'mode': report['evidenceMode'], 'continuity': collection_health['status'],
                            'phase': (collector_progress or {}).get('phase'), 'stopReason': (collector_progress or {}).get('stopReason'),
                            'backlogBytes': (collector_progress or {}).get('backlogBytes'),
                            'resourcePressure': (collector_progress or {}).get('resourcePressure', False)}, ensure_ascii=False), '']
        if (collector_progress or {}).get('resourcePressure'):
            status_lines += [('**已达到采集预算或仍有积压，存在遗漏风险；不会自动提高约定上限。**' if language == 'zh-CN'
                              else '**Resource budget reached or backlog remains: evidence may be incomplete. Agreed limits are not raised automatically.**'), '']
        lines[2:2] = status_lines
        if explicit_deny_all:
            lines[2:2] = [('**全部可用权限已由用户明确撤销：候选默认拒绝且没有放行规则。应用后会拒绝所有代理覆盖的出站访问；仍需审核并明确授权部署。**' if language == 'zh-CN'
                          else '**The user explicitly withdrew all available permissions: this candidate has no allow rules. Applying it denies all redirected egress; review and explicit deployment authorization are still required.**'), '']
        for rule in egress.get('httpRules', []):
            if 'allow' not in rule.get('qualifiers', []) or 'deny' in rule.get('qualifiers', []):
                continue
            match = rule['match']
            domain = match['hosts'][0]
            paths = ', '.join(k + ': ' + v for p in match.get('paths', []) for k, v in p.items()) or tr('All paths')
            methods = ', '.join(match.get('methods', [])) or tr('All methods')
            impact = tr(http_protocol_impact(rule, egress, state))
            if not match.get('paths') and not match.get('methods'):
                impact += tr('; the base grant matches all HTTP paths and methods; explicit denies still apply')
            lines.append('| ' + ' | '.join(map(cell, [domain, ','.join(str(p['port']) for p in match['ports']), paths, methods, impact])) + ' |')
        for rule in egress.get('rules', []):
            if 'allow' not in rule.get('qualifiers', []) or 'deny' in rule.get('qualifiers', []):
                continue
            lines.append('| ' + ' | '.join(map(cell, [rule['ip'], ','.join(str(p['port']) for p in rule['ports']),
                         tr('All paths'), tr('All methods'), tr('Entire IP/port allowed, including HTTP/TLS')])) + ' |')
        lines += ['',
                 tr('## Observed behavior not covered'), '',
                 tr('| Destination | Method | Path | Action | Uncovered events |'),
                 '|---|---|---|---|---|']
        for row in rows:
            if row['uncovered']:
                lines.append('| ' + ' | '.join(map(cell, [row['destination'], row['method'] or '-', row['path'] or '-',
                             row['action'], row['uncovered']])) + ' |')
        if requirements:
            lines += ['', tr('## Required business connections'), '',
                      tr('| Destination | Origin | Observed | Approval | Verification |'), '|---|---|---|---|---|']
            for item in requirements:
                lines.append('| ' + ' | '.join(map(cell, [item['destination'], tr(item['origin']),
                    tr('yes' if item['observed'] else 'no'),
                    ('已撤销' if language == 'zh-CN' else 'withdrawn') if item['authorizationState'] == 'revoked' else tr('approved' if item['approved'] else 'pending'),
                    (('通过' if item['verification'] == 'confirmed' else '证据不足') if language == 'zh-CN' and item['verification'] != 'not-assessed'
                     else ('尚未验证' if language == 'zh-CN' else 'not verified') if item['verification'] == 'not-assessed'
                     else item['verification'])])) + ' |')
            if required_pending:
                lines += ['', tr('Required connections awaiting approval: {count}. The draft does not yet include them.', count=len(required_pending))]
        lines += ['', tr('## TCP decisions still needed'), '', tr('| Destination | Why it needs review |'), '|---|---|']
        for item in pending:
            lines.append('| ' + ' | '.join(map(cell, [item['destination'], tr(item['reason'])])) + ' |')
        if not pending:
            lines.append(tr('No pending TCP approvals.'))
        if config.get('domains'):
            lines += ['', tr('Domain-wide review options affect every matching path and port: {domains}. Prefer scoped request decisions.',
                            domains=', '.join(config['domains']))]
        if verification:
            lines += ['', ('## 独立执行验证' if language == 'zh-CN' else '## Separate enforcement verification'), '',
                      (('对应当前候选策略' if verification['currentCandidate'] else '候选策略已变化：旧验证不能证明当前版本') if language == 'zh-CN'
                       else ('Matches the current candidate' if verification['currentCandidate'] else 'Candidate changed: previous verification is stale')),
                      (('通过：{confirmed}；冲突：{contradicted}；证据不足：{insufficient}。' if language == 'zh-CN'
                        else 'Confirmed: {confirmed}; contradicted: {contradicted}; insufficient: {insufficient}.').format(
                        **{k: verification.get('summary', {}).get(k, 0) for k in ('confirmed', 'contradicted', 'insufficient')})),
                      ('客户端与后端判断来自用户提供的结果；审计来自独立验证时间窗口。详见 verification.md。' if language == 'zh-CN'
                       else 'Client/backend judgments use supplied results; audit comes from a separate validation window. See verification.md.')]
        if refinements:
            lines += ['', ('以下是候选和保存窗口的验证记录，不代表当前线上部署状态；当前候选的独立验证与初次观察完整性分别列出。' if language == 'zh-CN'
                      else 'These are candidate and saved-window records, not current deployment status. Current-candidate checks and initial observation completeness are reported separately.')]
            lines += ['', ('## 拒绝项审核与静默权限' if language == 'zh-CN' else '## Denial review and silent permissions'), '',
                      ('拒绝项只在用户明确批准后增加权限；来源仍为 DENIED，后续成功验证单独保存。'
                       if language == 'zh-CN' else 'Permissions are added only after explicit user approval. Origin remains DENIED; successful validation is separate.'), '',
                      '| ID | ' + ('审计 | 权限 |' if language == 'zh-CN' else 'Audit | Permission |'), '|---|---|---|']
            for item in report['permissions']:
                lines.append('| ' + ' | '.join(map(cell, [item['id'],
                    ('记录' if item['audit'] else '静默') if language == 'zh-CN' else ('enabled' if item['audit'] else 'silent'),
                    json.dumps({k: v for k, v in item['rule'].items() if k != 'qualifiers'}, ensure_ascii=False)])) + ' |')
            for item in refinements.get('decisions', {}).values():
                lines += ['', json.dumps({k: item[k] for k in ('id', 'decision', 'authorizationState', 'reason', 'origin', 'observedSuccess', 'verificationFile', 'currentCandidateVerification', 'currentCandidateCheckIds') if k in item}, ensure_ascii=False)]
        if report['denyConstraints']:
            lines += ['', ('## 已批准的拒绝约束' if language == 'zh-CN' else '## Approved deny constraints'), '',
                      ('显式拒绝优先于允许。HTTP 拒绝在透传 TLS 中按主机和端口生效，不检查路径或方法；因此也可能拒绝整个 SNI/端口。静默和撤销允许权限不会删除这些约束。'
                       if language == 'zh-CN' else 'Explicit deny precedes allow. HTTP denies apply to passthrough TLS by host/port without path or method checks, so they may deny an entire SNI/port. Grant withdrawal and quiet audit do not remove these constraints.'), '',
                      '| ID | ' + ('规则 | 理由 |' if language == 'zh-CN' else 'Rule | Reason |'), '|---|---|---|']
            for item in report['denyConstraints']:
                lines.append('| ' + ' | '.join(map(cell, [item['id'], json.dumps(item['rule'], ensure_ascii=False), item['reason']])) + ' |')
        if report['revokedPermissions']:
            lines += ['', ('## 已撤销权限' if language == 'zh-CN' else '## Withdrawn permissions'), '',
                      ('撤销移除对应规则，不新增显式 deny。其他宽泛规则或 TLS 透传权限仍可能覆盖请求；需核对配置并用新连接验证实际拒绝。' if language == 'zh-CN'
                       else 'Withdrawal removes the selected rule, without adding an explicit deny. Other broad rules or passthrough TLS permissions may still cover requests; inspect effective config and test fresh connections.'), '',
                      '| ID | ' + ('理由 | 可能重叠的权限 ID |' if language == 'zh-CN' else 'Reason | Possibly overlapping permission IDs |'), '|---|---|---|']
            for item in report['revokedPermissions']:
                lines.append('| ' + ' | '.join(map(cell, [item['id'], item['reason'], ', '.join(item['possibleOverlapRuleIds']) or '-'])) + ' |')
        lines += ['', tr('Detailed collection state, exclusions and review data remain in analysis.json.'), '',
                 tr('## Coverage limitations'), '', *['- ' + tr(x) for x in report['limitations']], '',
                 tr('See analysis.json for the full behavior inventory and rule coverage. validation.yaml retains observation configuration.')]
        (root / 'report.md').write_text('\n'.join(lines) + '\n')
        workflow = workflow_module()
        workflow.write_summary(root, workflow.summary(root, globals(), language=language), globals())
    print(json.dumps({k: v for k, v in report.items() if k != 'inventory'}, ensure_ascii=False, indent=2))
    return 0 if report['candidateFile'] else 2


def cycle(args):
    global KUBE_DEADLINE, KUBE_WALL_DEADLINE
    if args.until:
        until = dt.datetime.fromisoformat(args.until.replace('Z', '+00:00'))
        if until.tzinfo is None:
            raise ValueError('--until must include an explicit timezone')
        if dt.datetime.now(dt.timezone.utc) >= until:
            print(json.dumps({'status': 'observation-ended', 'until': args.until}))
            return 0
        KUBE_DEADLINE = time.monotonic() + (until - dt.datetime.now(dt.timezone.utc)).total_seconds()
        KUBE_WALL_DEADLINE = until.timestamp()
    try:
        status = collect(args)
        if status:
            return status
        return analyze(args)
    finally:
        KUBE_DEADLINE = None
        KUBE_WALL_DEADLINE = None


def collector_module():
    spec = importlib.util.spec_from_file_location('varmor_incremental_collector', Path(__file__).with_name('collector.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def monitor(args):
    return collector_module().monitor(args, globals())


def refinement_module():
    spec = importlib.util.spec_from_file_location('varmor_refinement', Path(__file__).with_name('refinement.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def refine(args):
    if load(Path(args.session) / 'session.json').get('purpose') == 'verification-only':
        raise ValueError('Refine the source observation or review a new candidate; verification-only data cannot regenerate permissions')
    return refinement_module().refine(args, globals())


def init_verification(args):
    spec = importlib.util.spec_from_file_location('varmor_verification_init', Path(__file__).with_name('verification_init.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.initialize(args, globals())


def prepare_verification(args):
    return refinement_module().prepare(args, globals())


def stop(args):
    return collector_module().stop(args, globals())


def ready_check(args):
    result = collector_module().handoff_status(Path(args.session), globals(), args.min_remaining_seconds)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['readyForHandoff'] else 2


def reschedule(args):
    return collector_module().reschedule(args, globals())


def verify(args):
    spec = importlib.util.spec_from_file_location('varmor_verification', Path(__file__).with_name('verification.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.verify(args, globals())


def evidence_module():
    spec = importlib.util.spec_from_file_location('varmor_evidence', Path(__file__).with_name('evidence.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def active_config(args):
    return evidence_module().active_config(args, globals())


def workflow_module():
    spec = importlib.util.spec_from_file_location('varmor_workflow', Path(__file__).with_name('workflow.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def workflow_status(args):
    return workflow_module().status(args, globals())


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    d = sub.add_parser('doctor', help='read-only CRD, node and webhook preflight')
    d.add_argument('--context', required=True)
    d.add_argument('--output')
    d.add_argument('--namespace', help='also inspect policy/Pod/exec permissions for this target namespace')
    d.add_argument('--agent-namespace', default='varmor', help='report separate Agent Pod list/exec permissions')
    o = sub.add_parser('observe', help='create observation manifest locally; no cluster mutation')
    o.add_argument('--session', required=True)
    o.add_argument('--context', required=True)
    o.add_argument('--namespace', required=True)
    o.add_argument('--name', required=True)
    o.add_argument('--kind', choices=['Deployment', 'StatefulSet', 'DaemonSet', 'Pod'], default='Deployment')
    target = o.add_mutually_exclusive_group()
    target.add_argument('--workload')
    target.add_argument('--selector', help='exact label pairs, e.g. app=my-agent,tier=worker')
    o.add_argument('--observe', choices=['http', 'tcp', 'both'], default='both')
    mitm = o.add_mutually_exclusive_group()
    mitm.add_argument('--mitm-domain', action='append', default=[], help='user-approved literal DNS/IP only; existing scope preserved if omitted')
    mitm.add_argument('--clear-mitm', action='store_true', help='explicitly remove existing MITM configuration')
    o.add_argument('--base-policy', help='existing VarmorPolicy JSON export; preserve system enforcers, mode, target, config')
    o.add_argument('--since', type=int, help='explicit start Unix seconds for historical log analysis')
    o.add_argument('--language', choices=['en', 'zh-CN'], default='en', help="report language selected from the user's conversation")
    for name in ('collect', 'analyze', 'cycle'):
        q = sub.add_parser(name)
        q.add_argument('--session', required=True)
        if name != 'collect':
            q.add_argument('--review', help='JSON domain/path/method decisions')
            q.add_argument('--verification', help='separate verification.json associated with this session and candidate')
            q.add_argument('--language', choices=['en', 'zh-CN'], help='change and persist report language; omitted to reuse the session choice')
        if name == 'cycle':
            q.add_argument('--until', help='observation deadline, ISO 8601 with timezone')
        if name != 'analyze':
            q.add_argument('--file', action='append', help='normalized JSONL snapshot (repeatable)')
            q.add_argument('--offline', action='store_true', help='explicit offline import; no live Pod identity verification')
            q.add_argument('--source', choices=['auto', 'agent', 'sidecar', 'nodes'], default='auto')
            q.add_argument('--agent-namespace', default='varmor')
            q.add_argument('--agent-selector', help='optional explicit Agent label selector')
            q.add_argument('--agent-container', help='optional explicit Agent container name; otherwise discover --agent command')
            q.add_argument('--create-readers', action='store_true')
            q.add_argument('--reader-image', default='busybox:1.36')
            q.add_argument('--include-rotated', action=argparse.BooleanOptionalAction, default=True,
                           help='read retained violations*.log files by default; --no-include-rotated reads current file only')
    s = sub.add_parser('status', help='read-only check of observation policy, injected Pods and readiness')
    s.add_argument('--session', required=True)
    h = sub.add_parser('ready-check', help='local-only point-in-time collector check before a user handoff; no cluster reads')
    h.add_argument('--session', required=True)
    h.add_argument('--min-remaining-seconds', type=float,
                   help='handoff reserve; default one scan interval plus one read round; does not change the deadline')
    m = sub.add_parser('monitor', help='bounded incremental collection; start before user recreates Pods')
    m.add_argument('--session', required=True)
    deadline = m.add_mutually_exclusive_group()
    deadline.add_argument('--until', help='fixed ISO 8601 deadline with timezone')
    deadline.add_argument('--duration', type=int, help='positive seconds; default 3600')
    m.add_argument('--interval', type=float, default=30, help='file scan seconds; backlog drains sooner')
    m.add_argument('--discovery-interval', type=float, default=5, help='Pod LIST recovery seconds; watch also discovers short-lived Pods')
    m.add_argument('--analysis-interval', type=float, default=300, help='analyze new data every N seconds, and locally at stop')
    m.add_argument('--max-session-mb', type=int, default=512, help='local storage stop threshold, MiB; never delete unread evidence')
    m.add_argument('--max-read-mb', type=int, default=4, help='per-round byte budget, MiB; >=2')
    m.add_argument('--min-interval', type=float, help='backlog polling floor; default min(5, configured interval)')
    m.add_argument('--max-transfer-mb-per-minute', type=float, default=16,
                   help='rolling audit exec stdout quota, MiB; excludes API/watch/protocol bytes')
    m.add_argument('--max-concurrent-reads', type=int, default=2, help='maximum concurrent audit reads, 1..8')
    m.add_argument('--max-round-seconds', type=float, default=30, help='Kubernetes read round deadline, 1..120 seconds')
    m.add_argument('--source', choices=['auto', 'agent', 'sidecar'], default='auto')
    m.add_argument('--agent-namespace', default='varmor')
    m.add_argument('--agent-selector')
    m.add_argument('--agent-container')
    m.add_argument('--review', help='JSON decisions; omitted to reuse persisted review')
    t = sub.add_parser('stop', help='request that the local collector stop; leave policy unchanged')
    t.add_argument('--session', required=True)
    r = sub.add_parser('reschedule', help='user-requested deadline change for a running collector; verify acknowledgement')
    r.add_argument('--session', required=True)
    change = r.add_mutually_exclusive_group(required=True)
    change.add_argument('--until', help='new ISO 8601 deadline with explicit timezone')
    change.add_argument('--duration', type=int, help='remaining seconds from this request, not from original start')
    r.add_argument('--reason', default='User requested deadline change', help='brief reason for the user-requested change')
    v = sub.add_parser('verify', help='read-only, separate enforcement audit snapshot; never generates allowlist rules')
    for field in ('session', 'observation-session', 'policy-file', 'since', 'until'):
        v.add_argument('--' + field, required=True)
    v.add_argument('--pod-uid', action='append', required=True, help='explicit verified validation Pod UID; repeatable')
    v.add_argument('--checks', help='JSON client/backend results matched against normalized audit')
    v.add_argument('--receipts', help='hash-bound client/backend command receipts and active permission proofs; booleans alone cannot confirm checks')
    v.add_argument('--collection-session', help='stopped bounded enforcement monitor; saved evidence without snapshot reads')
    v.add_argument('--language', choices=['en', 'zh-CN'])
    v.add_argument('--source', choices=['auto', 'agent', 'sidecar'], default='auto')
    v.add_argument('--agent-namespace', default='varmor')
    v.add_argument('--agent-selector')
    v.add_argument('--agent-container')
    v.set_defaults(include_rotated=True, create_readers=False)
    proof = sub.add_parser('active-config', help='read-only, bounded proxy permission proof for supported literal HTTP/SNI candidates')
    for field in ('session', 'policy-file', 'pod-uid', 'output'):
        proof.add_argument('--' + field, required=True)
    workflow = sub.add_parser('workflow-status', help='summarize saved workflow stage, next actor and evidence links; no cluster changes')
    workflow.add_argument('--session', required=True)
    workflow.add_argument('--collection-session', help='current separate enforcement collection')
    workflow.add_argument('--verification', help='latest separate verification.json')
    workflow.add_argument('--language', choices=['en', 'zh-CN'], help='explicit language for this brief status; use analyze --language to persist the workflow report preference')
    prep = sub.add_parser('prepare-verification', help='prepare bounded enforcement evidence; no policy or workload changes')
    for field in ('session', 'observation-session', 'policy-file'):
        prep.add_argument('--' + field, required=True)
    selection = prep.add_mutually_exclusive_group(required=True)
    selection.add_argument('--pod-uid', action='append', help='existing verified Pod UID; repeatable')
    selection.add_argument('--new-pods', action='store_true', help='arm startup evidence before user recreation; verify and enroll new target UIDs')
    init = sub.add_parser('init-verification', help='initialize a new read-only verification workflow for an approved deployed policy; no observation or deployment')
    for field in ('session', 'context', 'namespace', 'name', 'policy-file', 'approval-evidence'):
        init.add_argument('--' + field, required=True)
    init.add_argument('--language', choices=['en', 'zh-CN'], default='en')
    init.add_argument('--budget-session', help='continue the same context/target budget ledger; preserve limits and storage accounting')
    selection = init.add_mutually_exclusive_group(required=True)
    selection.add_argument('--pod-uid', action='append', help='explicit currently injected Pod UID; repeatable')
    selection.add_argument('--new-pods', action='store_true', help='freeze current identities before later startup verification')
    for field, kind in (('interval', float), ('discovery-interval', float), ('analysis-interval', float),
                        ('max-session-mb', int), ('max-read-mb', int), ('min-interval', float),
                        ('max-transfer-mb-per-minute', float), ('max-concurrent-reads', int), ('max-round-seconds', float)):
        init.add_argument('--' + field, type=kind)
    init.add_argument('--source', choices=['auto', 'agent', 'sidecar'])
    for field in ('agent-namespace', 'agent-selector', 'agent-container'):
        init.add_argument('--' + field)
    f = sub.add_parser('refine', help='apply explicit denial/audit decisions locally; regenerate the single candidate, never deploy')
    f.add_argument('--session', required=True)
    f.add_argument('--decisions', required=True)
    f.add_argument('--verification', help='current candidate verification.json for reviewed DENIED items')
    return p


def main():
    args = parser().parse_args()
    try:
        return globals()[args.command.replace('-', '_')](args) or 0
    except (RuntimeError, ValueError, OSError, KeyError, subprocess.TimeoutExpired, sqlite3.Error) as exc:
        print(json.dumps({'error': str(exc), 'command': args.command}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
