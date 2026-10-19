#!/usr/bin/env python3
"""NICE MCP OAuth 2.1 Authorization Server 동작 점검 CLI.

서버 URL과 로그인 ID·비밀번호를 받아 메타데이터 → JWKS → Dynamic Client Registration → Authorization Code + PKCE
→ 로그인 → Token 교환 → JWT 검사 → Refresh → 부정 케이스 → (선택) 보호 자원 호출 → Revocation 순으로 확인하고
단계별 PASS/FAIL/SKIP을 표로 보여 준다. 표준 라이브러리만 사용한다.

비밀번호와 토큰 값은 화면에 출력하지 않는다. 토큰은 --save-tokens 를 준 경우에만 파일(0600)로 저장한다.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import html
import http.cookiejar
import json
import os
import re
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

DEFAULT_REDIRECT_URI = "http://127.0.0.1:6274/oauth/callback"
DEFAULT_SCOPE = "business.read offline_access"
DEFAULT_CLIENT_NAME = "NICEMCP OAuth Flow Test"
USER_AGENT = "nicemcp-oauth-flow-test/1.0"


# ---------------------------------------------------------------------------
# HTTP 도우미 (쿠키 유지, 리다이렉트 수동 제어)
# ---------------------------------------------------------------------------
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802 (urllib 시그니처)
        return None


@dataclass
class Response:
    status: int
    headers: dict
    body: bytes
    url: str

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.body.decode("utf-8")) if self.body else None

    @property
    def location(self) -> str | None:
        return self.headers.get("location")


class Http:
    def __init__(self, insecure: bool, timeout: float):
        self.jar = http.cookiejar.CookieJar()
        self.timeout = timeout
        context = ssl.create_default_context()
        if insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        https = urllib.request.HTTPSHandler(context=context)
        self.follow = urllib.request.build_opener(https, urllib.request.HTTPCookieProcessor(self.jar))
        self.nofollow = urllib.request.build_opener(https, urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())

    def request(self, method: str, url: str, *, data: bytes | None = None, headers: dict | None = None,
                follow_redirects: bool = True) -> Response:
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("User-Agent", USER_AGENT)
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        opener = self.follow if follow_redirects else self.nofollow
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                return Response(resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read(), resp.geturl())
        except urllib.error.HTTPError as error:
            body = error.read()
            return Response(error.code, {k.lower(): v for k, v in error.headers.items()}, body, url)
        except urllib.error.URLError as error:
            # 어느 주소로 가다 막혔는지 없으면 원인을 찾기 어렵다(2026-10-19: 리다이렉트를 따라가다 127.0.0.1:6274 연결 거부).
            raise urllib.error.URLError(f"{error.reason} — 요청 URL {url}") from error

    def get(self, url: str, **kw) -> Response:
        return self.request("GET", url, **kw)

    def post_form(self, url: str, fields: dict, **kw) -> Response:
        data = urllib.parse.urlencode(fields).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json, text/html;q=0.9"}
        headers.update(kw.pop("headers", {}) or {})
        return self.request("POST", url, data=data, headers=headers, **kw)

    def post_json(self, url: str, payload: dict, **kw) -> Response:
        data = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        headers.update(kw.pop("headers", {}) or {})
        return self.request("POST", url, data=data, headers=headers, **kw)


# ---------------------------------------------------------------------------
# 결과 기록
# ---------------------------------------------------------------------------
@dataclass
class Step:
    name: str
    status: str  # PASS / FAIL / SKIP / WARN
    detail: str = ""


@dataclass
class Report:
    steps: list[Step] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str = ""):
        self.steps.append(Step(name, status, detail))
        mark = {"PASS": "✔", "FAIL": "✘", "SKIP": "–", "WARN": "!"}[status]
        print(f"  [{status:<4}] {mark} {name}" + (f" — {detail}" if detail else ""))

    @property
    def failed(self) -> list[Step]:
        return [s for s in self.steps if s.status == "FAIL"]


class StepFailed(Exception):
    """이후 단계가 의미 없어지는 실패."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def short(value: str | None, keep: int = 6) -> str:
    """토큰처럼 비밀스러운 값은 길이와 앞 몇 글자만 보인다."""
    if not value:
        return "(없음)"
    return f"{value[:keep]}…(길이 {len(value)})"


def decode_jwt(token: str) -> tuple[dict, dict]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT 형식(헤더.본문.서명)이 아닙니다.")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload


def verify_rs256(token: str, jwks: dict) -> str:
    """cryptography 패키지가 있으면 서명을 검증하고, 없으면 'skipped'를 돌려준다."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization  # type: ignore
        from cryptography.hazmat.primitives.asymmetric import padding, rsa  # type: ignore
    except ImportError:
        return "skipped"
    header, _ = decode_jwt(token)
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
    if key is None or key.get("kty") != "RSA":
        raise ValueError(f"JWKS에 kid={header.get('kid')} RSA 키가 없습니다.")
    numbers = rsa.RSAPublicNumbers(
        int.from_bytes(b64url_decode(key["e"]), "big"), int.from_bytes(b64url_decode(key["n"]), "big"))
    public_key = numbers.public_key()
    signing_input, signature = token.rsplit(".", 1)
    public_key.verify(b64url_decode(signature), signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return "verified"


# ---------------------------------------------------------------------------
# OAuth 흐름
# ---------------------------------------------------------------------------
class OAuthFlowTest:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.base = args.server.rstrip("/")
        self.http = Http(args.insecure, args.timeout)
        self.report = Report()
        self.metadata: dict = {}
        self.metadata_url: str = ""
        self.jwks: dict = {}
        self.client_id: str | None = args.client_id
        self.client_secret: str | None = args.client_secret
        self.tokens: dict = {}
        self.second_tokens: dict = {}

    # -- 1. 메타데이터 --------------------------------------------------------
    def _metadata_candidates(self) -> list[str]:
        """RFC 8414: issuer에 경로가 있으면 /.well-known/oauth-authorization-server{path} 와 {path}/.well-known/... 둘 다 시도한다."""
        if self.args.metadata_url:
            return [self.args.metadata_url]
        parsed = urllib.parse.urlparse(self.base)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path.rstrip("/")
        names = ("oauth-authorization-server", "openid-configuration")
        urls = []
        for name in names:
            if path:
                urls.append(f"{origin}/.well-known/{name}{path}")
                urls.append(f"{origin}{path}/.well-known/{name}")
            else:
                urls.append(f"{origin}/.well-known/{name}")
        return urls

    ENDPOINT_KEYS = ("authorization_endpoint", "token_endpoint", "registration_endpoint", "jwks_uri",
                     "revocation_endpoint", "introspection_endpoint", "userinfo_endpoint", "end_session_endpoint")

    @staticmethod
    def _is_internal_host(netloc: str) -> bool:
        """localhost·loopback·사설망 주소(다른 기기에서는 닿지 않는 주소)만 내부 주소로 본다."""
        host = netloc.rsplit("@", 1)[-1].split(":")[0].strip("[]").lower()
        if host in ("localhost", "0.0.0.0", "::1") or host.endswith(".localhost") or host.endswith(".local"):
            return True
        parts = host.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            a, b = int(parts[0]), int(parts[1])
            return a in (10, 127) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
        return False

    def _rewrite_endpoints(self) -> list[str]:
        """프록시 뒤 서버가 localhost:9000 같은 내부 주소로 엔드포인트를 광고하면, 호스트만 입력 서버의 것으로 바꾼다.
        다른 공개 호스트(예: MCP origin 메타데이터가 가리키는 실제 OAuth 서버)는 그대로 쓴다. --rewrite-endpoints 로 전부 바꾸고,
        --keep-metadata-endpoints 로 아무것도 바꾸지 않는다. 경로는 그대로 두고 issuer 값은 바꾸지 않는다."""
        if self.args.keep_metadata_endpoints:
            return []
        server = urllib.parse.urlparse(self.base)
        changed = []
        for key in self.ENDPOINT_KEYS:
            value = self.metadata.get(key)
            if not value:
                continue
            parsed = urllib.parse.urlparse(value)
            if (parsed.scheme, parsed.netloc) == (server.scheme, server.netloc):
                continue
            if not self.args.rewrite_endpoints and not self._is_internal_host(parsed.netloc):
                continue
            self.metadata[key] = urllib.parse.urlunparse((server.scheme, server.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
            changed.append(f"{key}: {parsed.scheme}://{parsed.netloc} → {server.scheme}://{server.netloc}")
        return changed

    def step_metadata(self):
        attempts = []
        for url in self._metadata_candidates():
            resp = self.http.get(url, headers={"Accept": "application/json"})
            content_type = resp.headers.get("content-type", "")
            attempts.append(f"{url} → HTTP {resp.status} {content_type.split(';')[0] or ''}".rstrip())
            if resp.status == 200:
                try:
                    body = resp.json()
                except ValueError:
                    attempts[-1] += f" (JSON 아님: {resp.text[:80]!r})"
                    continue
                if isinstance(body, dict) and body.get("token_endpoint"):
                    self.metadata = body
                    self.metadata_url = url
                    break
                attempts[-1] += " (token_endpoint 없음)"
        if not self.metadata:
            self.report.add("1. Authorization Server 메타데이터", "FAIL",
                            "메타데이터를 찾지 못함. 시도: " + " | ".join(attempts)
                            + ". 서버가 다른 경로로 제공하면 --metadata-url 로 지정하세요")
            raise StepFailed
        issues, warnings = [], []
        for key in ("issuer", "authorization_endpoint", "token_endpoint"):
            if not self.metadata.get(key):
                issues.append(f"{key} 없음")
        rewritten = self._rewrite_endpoints()
        if rewritten:
            warnings.append("엔드포인트 호스트를 입력 서버로 바꿈: " + ", ".join(rewritten))
        issuer = (self.metadata.get("issuer") or "").rstrip("/")
        expected = (self.args.issuer or self.base).rstrip("/")
        if issuer and issuer != expected:
            warnings.append(f"issuer({issuer})가 {'--issuer' if self.args.issuer else '입력 URL'}({expected})과 다름 — JWT iss 검사는 메타데이터 issuer 기준")
        if "S256" not in (self.metadata.get("code_challenge_methods_supported") or []):
            warnings.append("code_challenge_methods_supported에 S256 없음(PKCE는 그대로 시도)")
        if "authorization_code" not in (self.metadata.get("grant_types_supported") or []):
            warnings.append("grant_types_supported에 authorization_code 없음")
        detail = (f"{self.metadata_url} | issuer={issuer}, authorize={self.metadata.get('authorization_endpoint')}, "
                  f"token={self.metadata.get('token_endpoint')}, "
                  f"DCR={'있음' if self.metadata.get('registration_endpoint') else '없음'}, "
                  f"revocation={'있음' if self.metadata.get('revocation_endpoint') else '없음'}")
        if issues:
            self.report.add("1. Authorization Server 메타데이터", "FAIL", "; ".join(issues + warnings) + " | " + detail)
            raise StepFailed
        self.report.add("1. Authorization Server 메타데이터", "WARN" if warnings else "PASS",
                        ("; ".join(warnings) + " | " if warnings else "") + detail)

    # -- 2. JWKS ------------------------------------------------------------
    def step_jwks(self):
        url = self.metadata.get("jwks_uri")
        if not url:
            self.report.add("2. JWKS", "SKIP", "메타데이터에 jwks_uri 없음")
            return
        resp = self.http.get(url, headers={"Accept": "application/json"})
        try:
            self.jwks = resp.json() or {}
        except ValueError:
            self.jwks = {}
        keys = self.jwks.get("keys") or []
        rsa_keys = [k for k in keys if k.get("kty") == "RSA" and k.get("kid")]
        if resp.status != 200 or not rsa_keys:
            self.report.add("2. JWKS", "FAIL", f"HTTP {resp.status}, RSA 키 {len(rsa_keys)}개")
            return
        self.report.add("2. JWKS", "PASS", f"RSA 키 {len(rsa_keys)}개, kid={', '.join(k['kid'][:8] + '…' for k in rsa_keys)}")

    # -- 3. Dynamic Client Registration ---------------------------------------
    def step_register(self):
        if self.client_id:
            self.report.add("3. Dynamic Client Registration", "SKIP", f"--client-id 사용 ({self.client_id[:8]}…)")
            return
        url = self.metadata.get("registration_endpoint")
        if not url:
            self.report.add("3. Dynamic Client Registration", "FAIL", "registration_endpoint 없음. --client-id 로 기존 Client를 지정하세요")
            raise StepFailed
        payload = {
            "client_name": self.args.client_name,
            "redirect_uris": [self.args.redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }
        resp = self.http.post_json(url, payload)
        try:
            body = resp.json() or {}
        except ValueError:
            body = {}
        if resp.status not in (200, 201) or not body.get("client_id"):
            self.report.add("3. Dynamic Client Registration", "FAIL", f"HTTP {resp.status}: {resp.text[:200]}")
            raise StepFailed
        self.client_id = body["client_id"]
        self.client_secret = body.get("client_secret")
        issues = []
        if body.get("token_endpoint_auth_method") not in (None, "none"):
            issues.append(f"auth_method={body.get('token_endpoint_auth_method')}")
        if self.args.redirect_uri not in (body.get("redirect_uris") or [self.args.redirect_uri]):
            issues.append("redirect_uris 응답에 요청 URI가 없음")
        if self.args.save_client:
            self._save_json(self.args.save_client, body)
        status = "WARN" if issues else "PASS"
        self.report.add("3. Dynamic Client Registration", status,
                        f"client_id={self.client_id[:8]}…" + (" | " + "; ".join(issues) if issues else ""))

    # -- 4~6. Authorization Code + PKCE + 로그인 --------------------------------
    def _pkce(self) -> tuple[str, str, str]:
        verifier = b64url(secrets.token_bytes(48))
        challenge = b64url(hashlib.sha256(verifier.encode()).digest())
        return verifier, challenge, secrets.token_hex(16)

    def _authorize_url(self, challenge: str, state: str) -> str:
        query = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.args.redirect_uri,
            "scope": self.args.scope,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if self.args.resource:
            query["resource"] = self.args.resource
        return f"{self.metadata['authorization_endpoint']}?{urllib.parse.urlencode(query)}"

    def _extract_code(self, location: str | None, state: str, step: str) -> str:
        if not location:
            raise ValueError("Location 헤더 없음")
        if not location.startswith(self.args.redirect_uri):
            raise ValueError(f"redirect_uri 가 아닌 곳으로 이동: {location[:120]}")
        query = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
        if query.get("error"):
            raise ValueError(f"error={query['error'][0]} {query.get('error_description', [''])[0]}")
        if query.get("state", [None])[0] != state:
            raise ValueError("state 불일치")
        code = query.get("code", [None])[0]
        if not code:
            raise ValueError("code 없음")
        return code

    def _handle_consent(self, resp: Response, state: str) -> Response:
        """동의 화면이 나오면 전체 scope에 동의해 제출한다(Spring Authorization Server 기본 폼 기준)."""
        page = resp.text
        if resp.status != 200 or "/oauth/authorize" not in page or 'name="client_id"' not in page:
            return resp
        fields = {"client_id": self.client_id, "state": state}
        csrf = self._csrf(page)
        if csrf:
            fields["_csrf"] = csrf
        scopes = re.findall(r'name="scope"[^>]*value="([^"]+)"', page)
        data = urllib.parse.urlencode(fields) + "".join(f"&scope={urllib.parse.quote(s)}" for s in scopes)
        return self.http.request("POST", self.metadata["authorization_endpoint"], data=data.encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded"}, follow_redirects=False)

    @staticmethod
    def _csrf(page: str) -> str | None:
        match = re.search(r'name="_csrf"[^>]*value="([^"]*)"', page) or re.search(r'value="([^"]*)"[^>]*name="_csrf"', page)
        return html.unescape(match.group(1)) if match else None

    def _resolve_redirect(self, base_url: str, location: str) -> tuple[str, str | None]:
        """Location을 절대 URL로 만들고, 프록시 뒤 서버가 localhost:9000 같은 내부 주소로 보내면 호스트만 입력 서버로 바꾼다.
        redirect_uri 로 가는 이동은 바꾸지 않는다. 반환: (이동할 URL, 보정 메모 또는 None)."""
        target = urllib.parse.urljoin(base_url, location)
        parsed = urllib.parse.urlparse(target)
        server = urllib.parse.urlparse(self.base)
        if (not parsed.netloc or (parsed.scheme, parsed.netloc) == (server.scheme, server.netloc)
                or target.startswith(self.args.redirect_uri) or self.args.keep_metadata_endpoints
                or not (self.args.rewrite_endpoints or self._is_internal_host(parsed.netloc))):
            return target, None
        rewritten = urllib.parse.urlunparse((server.scheme, server.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
        return rewritten, f"{parsed.scheme}://{parsed.netloc} → {server.scheme}://{server.netloc}"

    def _open_login_page(self, url: str, step_label: str) -> tuple[Response, list[str]]:
        """authorize 요청의 리다이렉트를 직접 따라가 로그인 화면(200)까지 연다. urllib가 자동으로 따라가면
        서버가 로그인 전에 redirect_uri(기본 127.0.0.1:6274, 수신 프로그램 없음)로 보낼 때 WinError 10061 같은 연결 거부만
        남고 서버가 보낸 error 파라미터를 볼 수 없으므로, redirect_uri 로의 이동은 여기서 멈추고 내용을 보고한다."""
        notes: list[str] = []
        for _ in range(6):
            resp = self.http.get(url, follow_redirects=False)
            if resp.status not in (301, 302, 303, 307, 308):
                return resp, notes
            location = resp.location or ""
            if location.startswith(self.args.redirect_uri):
                query = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
                if query.get("error"):
                    detail = f"로그인 전에 redirect_uri 로 돌려보냄: error={query['error'][0]} {query.get('error_description', [''])[0]}".rstrip()
                else:
                    detail = "로그인 없이 code를 발급해 redirect_uri 로 돌려보냄(세션 재사용 또는 인증 생략)"
                self.report.add(step_label, "FAIL", f"HTTP {resp.status}, {detail} — redirect_uri 에는 수신 프로그램이 없으므로 "
                                                    "따라가면 연결 거부가 납니다. 서버의 authorize 처리(client_id·redirect_uri·scope·resource 검증)를 확인하세요")
                raise StepFailed
            if not location:
                return resp, notes
            url, note = self._resolve_redirect(url, location)
            if note:
                notes.append(note)
        self.report.add(step_label, "FAIL", "리다이렉트가 6회를 넘어 로그인 화면에 닿지 못함")
        raise StepFailed

    def step_login_and_code(self, username: str, password: str) -> tuple[str, str]:
        verifier, challenge, state = self._pkce()
        label = "4. Authorization 요청 → 로그인 화면"
        resp, notes = self._open_login_page(self._authorize_url(challenge, state), label)
        page = resp.text
        has_form = 'name="username"' in page and 'name="password"' in page
        if resp.status != 200 or not has_form:
            self.report.add(label, "FAIL", f"HTTP {resp.status}, 최종 URL {resp.url[:80]}, 로그인 폼 {'있음' if has_form else '없음'}")
            raise StepFailed
        csrf = self._csrf(page)
        login_action = re.search(r'<form[^>]*id="login-form"[^>]*action="([^"]+)"', page)
        login_url = urllib.parse.urljoin(resp.url, html.unescape(login_action.group(1))) if login_action else self.base + "/login"
        login_url, note = self._resolve_redirect(resp.url, login_url)
        if note:
            notes.append(note)
        self.report.add(label, "PASS", f"로그인 폼 확인, CSRF {'있음' if csrf else '없음'}, action={urllib.parse.urlparse(login_url).path}"
                        + (f" | 내부 주소 보정: {'; '.join(notes)}" if notes else ""))

        fields = {"username": username, "password": password}
        if csrf:
            fields["_csrf"] = csrf
        resp = self.http.post_form(login_url, fields, follow_redirects=False)
        location = resp.location or ""
        if resp.status not in (302, 303) or "error" in urllib.parse.urlparse(location).query or location.endswith("/login?error"):
            self.report.add("5. 로그인 (ID/비밀번호)", "FAIL",
                            f"HTTP {resp.status}, Location={location[:100] or '(없음)'} — ID와 비밀번호, 로그인 API 연동을 확인하세요")
            raise StepFailed
        self.report.add("5. 로그인 (ID/비밀번호)", "PASS", f"HTTP {resp.status} → {urllib.parse.urlparse(location).path or location[:60]}")

        next_url, _ = self._resolve_redirect(login_url, location)
        resp = self.http.get(next_url, follow_redirects=False)
        resp = self._handle_consent(resp, state)
        try:
            code = self._extract_code(resp.location, state, "6")
        except ValueError as error:
            self.report.add("6. Authorization Code 수신 (redirect_uri)", "FAIL", f"HTTP {resp.status}: {error}")
            raise StepFailed
        self.report.add("6. Authorization Code 수신 (redirect_uri)", "PASS", f"state 일치, code={short(code)}")
        return code, verifier

    # -- 7. Token 교환 --------------------------------------------------------
    def _token_request(self, fields: dict) -> Response:
        fields = dict(fields)
        fields["client_id"] = self.client_id
        if self.client_secret:
            fields["client_secret"] = self.client_secret
        if self.args.resource and "resource" not in fields:
            fields["resource"] = self.args.resource
        return self.http.post_form(self.metadata["token_endpoint"], fields, follow_redirects=False)

    def step_token(self, code: str, verifier: str):
        resp = self._token_request({"grant_type": "authorization_code", "code": code,
                                    "redirect_uri": self.args.redirect_uri, "code_verifier": verifier})
        try:
            body = resp.json() or {}
        except ValueError:
            body = {}
        if resp.status != 200 or not body.get("access_token"):
            self.report.add("7. Token 교환 (authorization_code + PKCE)", "FAIL", f"HTTP {resp.status}: {resp.text[:200]}")
            raise StepFailed
        self.tokens = body
        issues = []
        if (body.get("token_type") or "").lower() != "bearer":
            issues.append(f"token_type={body.get('token_type')}")
        if "offline_access" in self.args.scope.split() and not body.get("refresh_token"):
            issues.append("refresh_token 없음")
        detail = (f"access_token={short(body['access_token'])}, expires_in={body.get('expires_in')}, "
                  f"refresh_token={'있음' if body.get('refresh_token') else '없음'}, scope={body.get('scope')}")
        self.report.add("7. Token 교환 (authorization_code + PKCE)", "WARN" if issues else "PASS",
                        detail + (" | " + "; ".join(issues) if issues else ""))
        if self.args.save_tokens:
            self._save_json(self.args.save_tokens, body)

    # -- 8. JWT 검사 ---------------------------------------------------------
    def step_jwt(self):
        token = self.tokens.get("access_token", "")
        try:
            header, payload = decode_jwt(token)
        except ValueError as error:
            self.report.add("8. Access Token JWT 검사", "WARN", f"JWT가 아님({error}); 불투명 토큰이면 정상일 수 있음")
            return
        issues = []
        if header.get("alg") != "RS256":
            issues.append(f"alg={header.get('alg')}")
        kids = {k.get("kid") for k in self.jwks.get("keys", [])}
        if self.jwks and header.get("kid") not in kids:
            issues.append("kid가 JWKS에 없음")
        issuer = (self.metadata.get("issuer") or "").rstrip("/")
        if (payload.get("iss") or "").rstrip("/") != issuer:
            issues.append(f"iss={payload.get('iss')}")
        aud = payload.get("aud")
        aud_list = aud if isinstance(aud, list) else [aud]
        if self.args.resource and self.args.resource not in aud_list:
            issues.append(f"aud={aud_list}에 resource 없음")
        now = int(time.time())
        if not isinstance(payload.get("exp"), int) or payload["exp"] <= now:
            issues.append("exp가 없거나 이미 만료")
        missing_claims = [c for c in self.args.expect_claims if not payload.get(c)]
        if missing_claims:
            issues.append("claim 비어 있음: " + ", ".join(missing_claims))
        signature = "skipped"
        try:
            signature = verify_rs256(token, self.jwks) if self.jwks else "skipped"
        except Exception as error:  # noqa: BLE001 - 검증 실패는 결과에 기록
            issues.append(f"서명 검증 실패: {error}")
        remaining = payload.get("exp", now) - now
        detail = (f"alg={header.get('alg')}, kid={str(header.get('kid'))[:8]}…, aud={aud_list}, scope={payload.get('scope')}, "
                  f"token_use={payload.get('token_use')}, client_app={payload.get('client_app')}, 만료까지 {remaining}s, "
                  f"서명={'검증됨' if signature == 'verified' else '미검증(cryptography 패키지 없음)'}")
        self.report.add("8. Access Token JWT 검사", "FAIL" if issues else "PASS",
                        detail + (" | " + "; ".join(issues) if issues else ""))

    # -- 9. Refresh ----------------------------------------------------------
    def step_refresh(self):
        refresh = self.tokens.get("refresh_token")
        if not refresh:
            self.report.add("9. Refresh Token 교환", "SKIP", "refresh_token 없음")
            return
        resp = self._token_request({"grant_type": "refresh_token", "refresh_token": refresh})
        try:
            body = resp.json() or {}
        except ValueError:
            body = {}
        if resp.status != 200 or not body.get("access_token"):
            self.report.add("9. Refresh Token 교환", "FAIL", f"HTTP {resp.status}: {resp.text[:200]}")
            return
        rotated = body.get("refresh_token") not in (None, refresh)
        changed = body["access_token"] != self.tokens["access_token"]
        self.tokens = {**self.tokens, **body}
        self.report.add("9. Refresh Token 교환", "PASS",
                        f"새 access_token {'발급' if changed else '동일(주의)'}, refresh_token {'회전됨' if rotated else '재사용'}, expires_in={body.get('expires_in')}")

    # -- 10~11. 부정 케이스 ----------------------------------------------------
    def step_negative(self):
        # 같은 세션으로 두 번째 code를 받아(재로그인 없이) 잘못된 code_verifier 교환을 시도한다.
        verifier, challenge, state = self._pkce()
        resp = self.http.get(self._authorize_url(challenge, state), follow_redirects=False)
        resp = self._handle_consent(resp, state)
        try:
            code = self._extract_code(resp.location, state, "10")
        except ValueError as error:
            self.report.add("10. 세션 재사용으로 두 번째 code 발급", "WARN", f"HTTP {resp.status}: {error} (SSO 세션 없이는 정상일 수 있음)")
            code = None
        else:
            self.report.add("10. 세션 재사용으로 두 번째 code 발급", "PASS", "재로그인 없이 code 수신")
        if code:
            resp = self._token_request({"grant_type": "authorization_code", "code": code,
                                        "redirect_uri": self.args.redirect_uri, "code_verifier": b64url(secrets.token_bytes(48))})
            try:
                error = (resp.json() or {}).get("error")
            except ValueError:
                error = None
            if resp.status in (400, 401) and error:
                self.report.add("11. 잘못된 code_verifier 거부", "PASS", f"HTTP {resp.status} error={error}")
            else:
                self.report.add("11. 잘못된 code_verifier 거부", "FAIL", f"HTTP {resp.status}: {resp.text[:160]}")
        if self.args.resource and self.tokens.get("refresh_token"):
            resp = self._token_request({"grant_type": "refresh_token", "refresh_token": self.tokens["refresh_token"],
                                        "resource": self.args.resource.rstrip("/") + "/not-the-resource"})
            try:
                error = (resp.json() or {}).get("error")
            except ValueError:
                error = None
            if resp.status in (400, 401) and error:
                self.report.add("12. 잘못된 resource 거부 (RFC 8707)", "PASS", f"HTTP {resp.status} error={error}")
            else:
                self.report.add("12. 잘못된 resource 거부 (RFC 8707)", "WARN", f"HTTP {resp.status}: resource 검증이 없거나 다른 값 허용")
        else:
            self.report.add("12. 잘못된 resource 거부 (RFC 8707)", "SKIP", "--resource 미지정 또는 refresh_token 없음")

    # -- 13. 보호 자원 호출(MCP) -------------------------------------------------
    def step_resource(self):
        if not self.args.resource or not self.args.check_resource:
            self.report.add("13. 보호 자원(MCP) 호출", "SKIP", "--resource 와 --check-resource 가 있을 때 실행")
            return
        payload = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                              "clientInfo": {"name": "nicemcp-oauth-flow-test", "version": "1.0"}}}
        headers = {"Accept": "application/json, text/event-stream"}
        unauth = self.http.post_json(self.args.resource, payload, headers=headers, follow_redirects=False)
        auth = self.http.post_json(self.args.resource, payload,
                                   headers={**headers, "Authorization": f"Bearer {self.tokens.get('access_token', '')}"},
                                   follow_redirects=False)
        body = auth.text
        if body.startswith("event:") or "\ndata:" in body or body.startswith("data:"):
            body = "".join(line[5:].strip() for line in body.splitlines() if line.startswith("data:"))
        try:
            result = json.loads(body).get("result", {})
        except (ValueError, AttributeError):
            result = {}
        server = result.get("serverInfo", {})
        perf = (result.get("capabilities", {}).get("experimental", {}) or {}).get("nicemcp/performance", {})
        issues = []
        if unauth.status != 401:
            issues.append(f"토큰 없이 HTTP {unauth.status} (401 기대)")
        if auth.status != 200 or not server:
            issues.append(f"토큰으로 HTTP {auth.status}: {auth.text[:120]}")
        detail = (f"무토큰 {unauth.status}, 토큰 {auth.status}, server={server.get('name')} {server.get('version')}, "
                  f"performance={perf.get('version') or '-'}")
        self.report.add("13. 보호 자원(MCP) 호출", "FAIL" if issues else "PASS", detail + (" | " + "; ".join(issues) if issues else ""))

    # -- 14. Revocation ---------------------------------------------------------
    def step_revoke(self):
        url = self.metadata.get("revocation_endpoint")
        refresh = self.tokens.get("refresh_token")
        if self.args.no_revoke:
            self.report.add("14. Refresh Token 폐기", "SKIP", "--no-revoke")
            return
        if not url or not refresh:
            self.report.add("14. Refresh Token 폐기", "SKIP", "revocation_endpoint 또는 refresh_token 없음")
            return
        fields = {"token": refresh, "token_type_hint": "refresh_token", "client_id": self.client_id}
        if self.client_secret:
            fields["client_secret"] = self.client_secret
        resp = self.http.post_form(url, fields, follow_redirects=False)
        if resp.status != 200:
            self.report.add("14. Refresh Token 폐기", "FAIL", f"HTTP {resp.status}: {resp.text[:160]}")
            return
        again = self._token_request({"grant_type": "refresh_token", "refresh_token": refresh})
        try:
            error = (again.json() or {}).get("error")
        except ValueError:
            error = None
        if again.status in (400, 401) and error:
            self.report.add("14. Refresh Token 폐기", "PASS", f"폐기 200, 재사용 시 HTTP {again.status} error={error}")
        else:
            self.report.add("14. Refresh Token 폐기", "FAIL", f"폐기 200이지만 재사용이 HTTP {again.status}로 통과")

    # -- 저장 ------------------------------------------------------------------
    @staticmethod
    def _save_json(path: str, data: dict):
        with open(path, "w", encoding="utf-8", opener=lambda p, f: os.open(p, f, 0o600)) as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
        os.chmod(path, 0o600)

    # -- 실행 ------------------------------------------------------------------
    def run(self, username: str | None, password: str | None) -> int:
        print(f"\nOAuth 서버: {self.base}")
        if self.args.resource:
            print(f"resource   : {self.args.resource}")
        print(f"redirect   : {self.args.redirect_uri}\nscope      : {self.args.scope}\n")
        try:
            self.step_metadata()
            self.step_jwks()
            self.step_register()
            if self.args.dry_run:
                verifier, challenge, state = self._pkce()
                label = "4. Authorization 요청 → 로그인 화면"
                resp, notes = self._open_login_page(self._authorize_url(challenge, state), label)
                has_form = 'name="username"' in resp.text and 'name="password"' in resp.text
                self.report.add(label, "PASS" if (resp.status == 200 and has_form) else "FAIL",
                                f"HTTP {resp.status}, 로그인 폼 {'있음' if has_form else '없음'}, CSRF {'있음' if self._csrf(resp.text) else '없음'}"
                                + (f" | 내부 주소 보정: {'; '.join(notes)}" if notes else ""))
                self.report.add("5~14", "SKIP", "--dry-run: 로그인 이후 단계는 실행하지 않음")
            else:
                code, verifier = self.step_login_and_code(username or "", password or "")
                password = None  # noqa: F841 - 가능한 한 빨리 참조를 끊는다
                self.step_token(code, verifier)
                self.step_jwt()
                self.step_refresh()
                self.step_negative()
                self.step_resource()
                self.step_revoke()
        except StepFailed:
            pass
        except (urllib.error.URLError, OSError) as error:
            hint = " — 자체 서명 인증서면 --insecure, 사내망이면 프록시·DNS 확인" if "CERTIFICATE" in str(error).upper() or "SSL" in str(error).upper() or "resolve" in str(error).lower() else ""
            self.report.add("연결", "FAIL", f"{error}{hint}")
        return self._summary()

    def _summary(self) -> int:
        counts = {s: sum(1 for step in self.report.steps if step.status == s) for s in ("PASS", "FAIL", "WARN", "SKIP")}
        print("\n결과: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
        if self.args.json:
            with open(self.args.json, "w", encoding="utf-8") as handle:
                json.dump({"server": self.base, "resource": self.args.resource, "client_id": self.client_id,
                           "steps": [step.__dict__ for step in self.report.steps]}, handle, ensure_ascii=False, indent=2)
            print(f"결과 JSON: {self.args.json}")
        if self.report.failed:
            print("실패 단계: " + ", ".join(step.name for step in self.report.failed))
            return 1
        print("OAuth 흐름이 정상 동작합니다." if not self.args.dry_run else "사전 점검 통과 (로그인 이후는 미실행).")
        return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NICE MCP OAuth Authorization Server 동작 점검", formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog="예:\n  python3 oauth_flow_test.py --server https://auth.example.com --resource https://mcp.example.com/mcp\n"
                                            "  python3 oauth_flow_test.py --server https://auth.example.com --dry-run   # 로그인 전 단계만")
    parser.add_argument("--server", help="OAuth 서버 URL (예: https://auth.youngmincho.com). 없으면 물어봄")
    parser.add_argument("--id", dest="user_id", help="로그인 ID. 없으면 물어봄")
    parser.add_argument("--password-env", default="OAUTH_TEST_PASSWORD", help="비밀번호를 읽을 환경 변수 이름(기본 OAUTH_TEST_PASSWORD). 없으면 숨김 입력")
    parser.add_argument("--resource", help="RFC 8707 resource 값(= MCP 서버 URL). 주면 aud 검사와 보호 자원 호출에 사용")
    parser.add_argument("--metadata-url", help="메타데이터 문서 URL을 직접 지정(기본: /.well-known/oauth-authorization-server, openid-configuration 순서로 탐색)")
    parser.add_argument("--issuer", help="기대하는 issuer 값. 프록시 뒤에서 입력 URL과 issuer가 다를 때 지정")
    parser.add_argument("--keep-metadata-endpoints", action="store_true",
                        help="메타데이터의 엔드포인트 주소를 그대로 사용(기본은 localhost·사설망 주소만 입력 서버 호스트로 바꿈)")
    parser.add_argument("--rewrite-endpoints", action="store_true",
                        help="메타데이터의 엔드포인트 호스트를 전부 입력 서버로 바꿈(MCP origin의 패스스루 경로를 강제로 시험할 때)")
    parser.add_argument("--redirect-uri", default=DEFAULT_REDIRECT_URI, help=f"등록할 redirect_uri (기본 {DEFAULT_REDIRECT_URI})")
    parser.add_argument("--scope", default=DEFAULT_SCOPE, help=f"요청 scope (기본 '{DEFAULT_SCOPE}')")
    parser.add_argument("--client-id", help="DCR을 건너뛰고 쓸 client_id")
    parser.add_argument("--client-secret", help="기밀 Client의 client_secret (공개 Client는 생략)")
    parser.add_argument("--client-name", default=DEFAULT_CLIENT_NAME, help="DCR에 쓸 client_name")
    parser.add_argument("--expect-claims", default="token_use,user_hmac,company_id",
                        help="비어 있으면 안 되는 Access Token claim 목록(쉼표 구분). 기본 token_use,user_hmac,company_id")
    parser.add_argument("--check-resource", action="store_true", help="--resource 로 MCP initialize 호출(무토큰 401, 토큰 200)까지 확인")
    parser.add_argument("--no-revoke", action="store_true", help="마지막 Refresh Token 폐기 단계를 건너뜀")
    parser.add_argument("--dry-run", action="store_true", help="메타데이터·JWKS·DCR·로그인 화면까지만 확인(ID/비밀번호 불필요)")
    parser.add_argument("--insecure", action="store_true", help="TLS 인증서 검증 생략(사내 자체 서명 인증서)")
    parser.add_argument("--timeout", type=float, default=20.0, help="HTTP 시간 제한(초), 기본 20")
    parser.add_argument("--save-client", metavar="PATH", help="DCR 응답을 저장할 파일(0600)")
    parser.add_argument("--save-tokens", metavar="PATH", help="Token 응답을 저장할 파일(0600)")
    parser.add_argument("--json", metavar="PATH", help="단계별 결과를 JSON으로 저장")
    args = parser.parse_args(argv)
    args.expect_claims = [c.strip() for c in args.expect_claims.split(",") if c.strip()]
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.server:
        args.server = input("OAuth 서버 URL: ").strip()
    if not re.match(r"^https?://", args.server):
        args.server = "https://" + args.server
    username = password = None
    if not args.dry_run:
        username = args.user_id or input("로그인 ID: ").strip()
        password = os.environ.get(args.password_env) or getpass.getpass("로그인 비밀번호(입력 숨김): ")
        if not username or not password:
            print("ID와 비밀번호가 필요합니다.", file=sys.stderr)
            return 2
    return OAuthFlowTest(args).run(username, password)


if __name__ == "__main__":
    sys.exit(main())
