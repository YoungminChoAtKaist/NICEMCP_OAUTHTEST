"""리다이렉트 처리 단위 테스트: python3 -m unittest test_oauth_flow_test"""
import argparse
import unittest

import oauth_flow_test as m


def make_flow(server="https://auth.example.com", **over):
    args = argparse.Namespace(server=server, redirect_uri="http://127.0.0.1:6274/oauth/callback", scope="business.read",
                              resource=None, insecure=False, timeout=5.0, keep_metadata_endpoints=False, rewrite_endpoints=False,
                              json=None, dry_run=False, metadata_url=None, issuer=None, client_id=None, client_secret=None)
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


if __name__ == "__main__":
    unittest.main()
