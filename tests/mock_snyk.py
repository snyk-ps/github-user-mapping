"""In-process mock of the Snyk API endpoints used by snyk-access-sync.sh."""

import json
import re
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

GROUP_ID = "11111111-1111-1111-1111-111111111111"
ORG_ID = "22222222-2222-2222-2222-222222222222"
OTHER_ORG_ID = "33333333-3333-3333-3333-333333333333"
ADMIN_ROLE_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
DEVELOPER_ROLE_ID = "dddddddd-dddd-dddd-dddd-dddddddddddd"
TOKEN = "test-token"


@dataclass
class SnykState:
    roles: list = field(
        default_factory=lambda: [
            {"name": "Org Admin", "publicId": ADMIN_ROLE_ID},
            {"name": "Developer", "publicId": DEVELOPER_ROLE_ID},
        ]
    )
    orgs: dict = field(default_factory=lambda: {ORG_ID: {"name": "payments", "group_id": GROUP_ID}})
    # email -> user id, for users in the Snyk Group
    group_users: dict = field(default_factory=dict)
    # (org_id, user_id) -> role id
    org_memberships: dict = field(default_factory=dict)
    # repository url -> list of org ids
    assets: dict = field(default_factory=dict)
    # orgs on the package asset that Asset Search returns next to each repository
    package_orgs: list = field(default_factory=lambda: [OTHER_ORG_ID])
    # path regex -> status code to force
    failures: dict = field(default_factory=dict)
    requests: list = field(default_factory=list)

    def posts(self, path_fragment):
        return [r for r in self.requests if r["method"] == "POST" and path_fragment in r["path"]]


class MockSnyk:
    def __init__(self):
        self.state = SnykState()
        state = self.state

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, payload=None):
                body = json.dumps(payload or {}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/vnd.api+json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _handle(self, method):
                url = urlparse(self.path)
                query = {k: v[0] for k, v in parse_qs(url.query).items()}
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                state.requests.append(
                    {
                        "method": method,
                        "path": url.path,
                        "query": query,
                        "body": body,
                        "auth": self.headers.get("Authorization"),
                        "content_type": self.headers.get("Content-Type"),
                    }
                )
                if self.headers.get("Authorization") != f"token {TOKEN}":
                    return self._send(401, {"errors": [{"detail": "bad token"}]})
                if url.path.startswith("/rest/") and "version" not in query:
                    return self._send(400, {"errors": [{"detail": "version is required"}]})
                for pattern, status in state.failures.items():
                    if re.search(pattern, f"{method} {url.path}"):
                        return self._send(status, {"errors": [{"detail": "forced failure"}]})
                return self._route(method, url.path, query, body)

            def _route(self, method, path, query, body):
                m = re.fullmatch(r"/v1/group/([^/]+)/roles", path)
                if method == "GET" and m:
                    return self._send(200, state.roles) if m[1] == GROUP_ID else self._send(404)

                m = re.fullmatch(r"/rest/orgs/([^/]+)", path)
                if method == "GET" and m:
                    org = state.orgs.get(m[1])
                    if not org:
                        return self._send(404, {"errors": [{"detail": "org not found"}]})
                    return self._send(200, {"data": {"id": m[1], "type": "org", "attributes": org}})

                m = re.fullmatch(r"/rest/groups/([^/]+)/assets/search", path)
                if method == "POST" and m:
                    if int(query.get("limit", 10)) < 10:
                        return self._send(400, {"errors": [{"detail": "limit cannot be less than: 10"}]})
                    wanted = body["query"]["attributes"]["values"][0].lower()
                    data = [
                        {
                            "id": f"asset-{i}",
                            "type": asset_type,
                            "attributes": {"repository_url": url},
                            "relationships": {"organizations": {"data": [{"id": o, "type": "org"} for o in orgs]}},
                        }
                        for i, (url, orgs) in enumerate(state.assets.items())
                        if url.lower() == wanted
                        for asset_type, orgs in [("repository", orgs), ("package", state.package_orgs)]
                    ]
                    return self._send(200, {"data": data, "links": {}})

                m = re.fullmatch(r"/rest/groups/([^/]+)/memberships", path)
                if method == "GET" and m:
                    email = query.get("email", "").lower()
                    data = [
                        {
                            "id": f"gm-{uid}",
                            "type": "group_membership",
                            "relationships": {
                                "user": {"data": {"id": uid, "type": "user", "attributes": {"email": e}}}
                            },
                        }
                        for e, uid in state.group_users.items()
                        if email in e.lower()
                    ]
                    return self._send(200, {"data": data, "links": {}})

                m = re.fullmatch(r"/rest/orgs/([^/]+)/memberships", path)
                if method == "GET" and m:
                    user_id = query.get("user_id")
                    data = [
                        {
                            "id": f"om-{uid}",
                            "type": "org_membership",
                            "relationships": {
                                "user": {"data": {"id": uid, "attributes": {}}},
                                "role": {
                                    "data": {
                                        "id": rid,
                                        "attributes": {
                                            "name": next((r["name"] for r in state.roles if r["publicId"] == rid), rid)
                                        },
                                    }
                                },
                            },
                        }
                        for (oid, uid), rid in state.org_memberships.items()
                        if oid == m[1] and (user_id is None or uid == user_id)
                    ]
                    return self._send(200, {"data": data, "links": {}})
                if method == "POST" and m:
                    rel = body["data"]["relationships"]
                    key = (rel["org"]["data"]["id"], rel["user"]["data"]["id"])
                    if key in state.org_memberships:
                        return self._send(409, {"errors": [{"detail": "already a member"}]})
                    state.org_memberships[key] = rel["role"]["data"]["id"]
                    return self._send(201, {"data": {"id": "new"}})

                return self._send(404, {"errors": [{"detail": f"no route for {method} {path}"}]})

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
