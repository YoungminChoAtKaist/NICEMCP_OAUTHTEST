# NICEMCP OAuth 흐름 점검 CLI

리팩토링한 NICEMCP OAuth Authorization Server가 실제로 동작하는지 터미널에서 확인하는 Python 프로그램입니다.
서버 URL과 로그인 ID·비밀번호만 있으면 되고, Python 3.10 이상의 표준 라이브러리만 사용합니다.

## 실행

```bash
python3 oauth_flow_test.py --server https://auth.example.com --resource https://mcp.example.com/mcp --check-resource
```

- `--server`를 생략하면 URL을 물어보고, `--id`를 생략하면 ID를 물어봅니다. 비밀번호는 항상 숨김 입력으로 받습니다
  (자동화하려면 `OAUTH_TEST_PASSWORD` 환경 변수, 또는 `--password-env` 로 변수 이름 지정).
- `--dry-run`: 메타데이터·JWKS·Client 등록·로그인 화면까지만 확인합니다. ID/비밀번호가 필요 없습니다.
- `--insecure`: 사내 자체 서명 인증서면 TLS 검증을 생략합니다.
- `--metadata-url`: 메타데이터 문서 경로가 다르면 직접 지정. `--issuer`: 프록시 뒤에서 issuer가 입력 URL과 다를 때 기대값 지정(다르면 1단계는 경고로만 표시).
- 메타데이터의 엔드포인트가 `http://localhost:9000/...`처럼 localhost·사설망 주소면(프록시 뒤 배포) 호스트를 입력한 `--server` 주소로 바꿔 호출합니다. 공개 호스트(예: MCP origin 메타데이터가 가리키는 실제 OAuth 서버)는 그대로 씁니다. `--rewrite-endpoints`는 전부 바꾸고 `--keep-metadata-endpoints`는 아무것도 바꾸지 않습니다. issuer 값은 바꾸지 않고 JWT `iss` 검사에 그대로 씁니다.
- `--client-id`: 이미 등록된 Client로 시험할 때(Dynamic Client Registration 건너뜀).
- `--no-revoke`: 마지막 Refresh Token 폐기를 건너뜁니다.
- `--json 결과.json`: 단계별 결과를 파일로 남깁니다. `--save-client`·`--save-tokens` 는 응답을 0600 권한 파일로 저장합니다.

## 확인 단계

| 단계 | 내용 | 기대 |
| --- | --- | --- |
| 1 | `/.well-known/oauth-authorization-server` | issuer가 입력 URL과 같고 PKCE S256·authorization_code 지원 |
| 2 | JWKS | kid가 있는 RSA 키 1개 이상 |
| 3 | Dynamic Client Registration | 공개 Client(`none`) 등록, `client_id` 수신 |
| 4 | `/oauth/authorize` (PKCE S256, state, resource) | 로그인 화면 200, CSRF 토큰 |
| 5 | `/login` POST (username, password, _csrf) | 302, `/login?error` 아님 |
| 6 | authorize 계속 → `redirect_uri`로 302 | `code`와 일치하는 `state` |
| 7 | `/oauth/token` authorization_code + code_verifier (+ resource) | 200, Bearer, refresh_token(offline_access 요청 시) |
| 8 | Access Token JWT | RS256, kid가 JWKS에 있음, iss·aud·exp, `token_use`·`user_hmac`·`company_id` 비어 있지 않음, `cryptography` 패키지가 있으면 서명 검증 |
| 9 | refresh_token grant | 새 access_token, refresh_token 회전/재사용 여부 표시 |
| 10 | 같은 세션으로 두 번째 code | 재로그인 없이 발급(SSO 세션) |
| 11 | 잘못된 code_verifier | 400 `invalid_grant` 등 오류 |
| 12 | 잘못된 resource (RFC 8707) | 400 `invalid_target` 등 오류 (`--resource` 지정 시) |
| 13 | 보호 자원(MCP) `initialize` | 무토큰 401, 토큰 200 (`--resource --check-resource` 지정 시) |
| 14 | Revocation | 폐기 200, 폐기된 refresh_token 재사용은 오류 |

종료 코드는 실패 단계가 없으면 0, 있으면 1입니다. 비밀번호와 토큰 값은 화면에 출력하지 않습니다.

## 리팩토링 서버와 다를 수 있는 부분

- 로그인 폼 필드명은 `username`·`password`·`_csrf`, 폼 id는 `login-form`을 기준으로 합니다. 다르면 4~5단계에서 실패하며 `oauth_flow_test.py`의 `step_login_and_code`를 고칩니다.
- 동의(consent) 화면이 켜져 있으면 모든 scope에 동의해 제출합니다(Spring Authorization Server 기본 폼 기준).
- `--expect-claims`로 필수 claim 목록을 바꿀 수 있습니다(기본 `token_use,user_hmac,company_id`).

## Change log
- 2026-10-15 (KST) — feat: OAuth flow test CLI (oauth_flow_test.py).
  메타데이터·JWKS·DCR·PKCE 로그인·Token 교환·JWT 검사·Refresh·부정 케이스·보호 자원 호출·Revocation 14단계를 표준 라이브러리만으로 점검하는 첫 버전.
- 2026-10-15 (KST) — fix: step 1 shows every metadata URL tried with its status, treats issuer mismatch as a warning, adds --metadata-url/--issuer.
  리팩토링 서버의 `--dry-run` 1단계 실패를 원인별로 구분할 수 있게 했다.
- 2026-10-15 (KST) — fix: rewrite metadata endpoint hosts (e.g. localhost:9000) to the entered server when running from another machine.
  데스크톱에서 사내 서버를 시험할 때 메타데이터가 내부 주소를 광고해도 입력 서버로 호출한다(--keep-metadata-endpoints로 해제).
- 2026-10-15 (KST) — fix: rewrite only localhost/private endpoint hosts; public hosts advertised by an MCP origin stay as-is (--rewrite-endpoints forces all).
  MCP origin에 대고 돌릴 때 JWKS가 MCP origin으로 바뀌어 401이 나던 문제를 고쳤다.
