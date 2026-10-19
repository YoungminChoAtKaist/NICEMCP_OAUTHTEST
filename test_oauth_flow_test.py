"""리다이렉트 처리 단위 테스트: python3 -m unittest test_oauth_flow_test"""
import argparse
import unittest

import oauth_flow_test as m


def make_flow(server="https://auth.example.com", **over):
    args = argparse.Namespace(server=server, redirect_uri="http://127.0.0.1:6274/oauth/callback", scope="business.read",
                              resource=None, insecure=False, timeout=5.0, keep_metadata_endpoints=False, rewrite_endpoints=False,
                              json=None, dry_run=False, metadata_url=None, issuer=None, client_id=None, client_secret=None, client_name="oauth-flow-test", save_client=None)
    for k, v in over.items():
        setattr(args, k, v)
    flow = m.OAuthFlowTest(args)
    flow.client_id = "client-1"
    return flow


class FakeHttp:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kw):
        self.calls.append((url, kw.get("follow_redirects", True)))
        return self.responses.pop(0)


def redirect(location, status=302):
    return m.Response(status, {"location": location}, b"", "")


class ResolveRedirectTest(unittest.TestCase):
    def test_internal_host_is_rewritten_to_entered_server(self):
        flow = make_flow()
        url, note = flow._resolve_redirect("https://auth.example.com/oauth/authorize", "http://localhost:9000/login")
        self.assertEqual(url, "https://auth.example.com/login")
        self.assertEqual(note, "http://localhost:9000 → https://auth.example.com")

    def test_relative_same_host_and_redirect_uri_are_left_alone(self):
        flow = make_flow()
        self.assertEqual(flow._resolve_redirect("https://auth.example.com/oauth/authorize", "/login"), ("https://auth.example.com/login", None))
        public = "https://other.example.org/login"
        self.assertEqual(flow._resolve_redirect("https://auth.example.com/x", public), (public, None))
        callback = "http://127.0.0.1:6274/oauth/callback?code=abc"
        self.assertEqual(flow._resolve_redirect("https://auth.example.com/x", callback), (callback, None))

    def test_flags_control_rewrite(self):
        self.assertIsNone(make_flow(keep_metadata_endpoints=True)._resolve_redirect("https://auth.example.com/x", "http://10.0.0.5:9000/login")[1])
        self.assertEqual(make_flow(rewrite_endpoints=True)._resolve_redirect("https://auth.example.com/x", "https://public.example.net/login")[0],
                         "https://auth.example.com/login")


class OpenLoginPageTest(unittest.TestCase):
    def test_follows_internal_redirect_to_login_page(self):
        flow = make_flow()
        page = m.Response(200, {}, b'<form id="login-form" action="/login"><input name="username"><input name="password"></form>', "https://auth.example.com/login")
        flow.http = FakeHttp([redirect("http://localhost:9000/login"), page])
        resp, notes = flow._open_login_page("https://auth.example.com/oauth/authorize?x=1", "4")
        self.assertEqual(resp.status, 200)
        self.assertEqual(notes, ["http://localhost:9000 → https://auth.example.com"])
        self.assertEqual([u for u, _ in flow.http.calls], ["https://auth.example.com/oauth/authorize?x=1", "https://auth.example.com/login"])
        self.assertTrue(all(follow is False for _, follow in flow.http.calls))

    def test_stops_and_reports_when_server_redirects_to_redirect_uri_before_login(self):
        flow = make_flow()
        flow.http = FakeHttp([redirect("http://127.0.0.1:6274/oauth/callback?error=invalid_request&error_description=bad%20resource&state=s")])
        with self.assertRaises(m.StepFailed):
            flow._open_login_page("https://auth.example.com/oauth/authorize", "4")
        step = flow.report.steps[-1]
        self.assertEqual(step.status, "FAIL")
        self.assertIn("error=invalid_request bad resource", step.detail)
        self.assertEqual(len(flow.http.calls), 1)  # redirect_uri 로는 따라가지 않는다


class ScopeNegotiationTest(unittest.TestCase):
    def test_trims_to_supported_when_scope_is_the_default(self):
        self.assertEqual(m.OAuthFlowTest.negotiate_scope("business.read offline_access", ["business.read"], explicit=False),
                         ("business.read", "scopes_supported에 맞춰 scope를 'business.read offline_access' → 'business.read'로 조정"))
        scope, note = m.OAuthFlowTest.negotiate_scope("business.read offline_access", ["mcp.read"], explicit=False)
        self.assertEqual(scope, "mcp.read")
        self.assertIn("'mcp.read'", note)

    def test_keeps_scope_when_supported_or_explicit_or_unknown(self):
        self.assertEqual(m.OAuthFlowTest.negotiate_scope("a b", ["a", "b", "c"], explicit=False), ("a b", None))
        self.assertEqual(m.OAuthFlowTest.negotiate_scope("a b", None, explicit=False), ("a b", None))
        scope, note = m.OAuthFlowTest.negotiate_scope("a b", ["a"], explicit=True)
        self.assertEqual(scope, "a b")
        self.assertIn("없는 scope 요청: b", note)

    def test_register_adopts_the_scope_the_server_stored(self):
        flow = make_flow()
        flow.client_id = None
        flow.metadata = {"registration_endpoint": "https://auth.example.com/oauth/register"}

        class Http:
            def post_json(self, url, payload, **kw):
                assert payload["scope"] == "business.read"
                return m.Response(201, {}, b'{"client_id":"abc12345","redirect_uris":["http://127.0.0.1:6274/oauth/callback"],"token_endpoint_auth_method":"none","scope":"mcp.read"}', url)
        flow.http = Http()
        flow.step_register()
        self.assertEqual(flow.scope, "mcp.read")
        self.assertEqual(flow.report.steps[-1].status, "WARN")
        self.assertIn("서버가 scope를 'mcp.read'로 등록", flow.report.steps[-1].detail)


if __name__ == "__main__":
    unittest.main()
