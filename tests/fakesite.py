"""Synthetic login site used by the integration tests. All credentials here are fake."""
from __future__ import annotations

from aiohttp import web

USER, PASSWORD = "reader@example.test", "synthetic-Passw0rd!-not-real"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"

FORM = """<html><body><h1>Sign in</h1>{extra}
<form method="post" action="{action}">
<input type="email" name="email" autocomplete="username">
<input type="password" name="password">
<button type="submit">Sign in</button></form></body></html>"""


class Site:
    def __init__(self):
        self.received: list[tuple[str, str]] = []   # (host:port that received it, password)
        self.collected: list[str] = []
        self.posts = 0
        self.captcha_solved = False
        self.other_origin = ""
        self.approved = ""          # the origin the test account is approved for; hostile pages impersonate it

    def app(self) -> web.Application:
        app = web.Application()
        r = app.router
        r.add_get("/login", self.login_page)
        r.add_post("/login", self.login_post)
        r.add_get("/home", self.home)
        r.add_get("/step", self.step_page)
        r.add_post("/step", self.step_post)
        r.add_get("/redirect-login", self.redirect_login)
        r.add_get("/crossform", self.crossform)
        r.add_get("/totp-login", self.totp_page)
        r.add_post("/totp-login", self.totp_post)
        r.add_post("/otp", self.otp_post)
        r.add_get("/captcha-login", self.captcha_page)
        r.add_post("/solve", self.solve)
        r.add_get("/collect", self.collect)
        r.add_get("/redir-evil", self.redir_evil)
        r.add_get("/evil", self.evil)
        r.add_get("/login-direct", self.login_direct_page)
        r.add_post("/login-direct", self.login_direct)
        r.add_get("/slow-login", self.slow_page)
        r.add_post("/slow-post", self.slow_post)
        r.add_get("/formaction", self.formaction_page)
        r.add_get("/hang-login", self.hang_page)
        r.add_get("/planted.js", self.planted)
        return app

    def html(self, body: str) -> web.Response:
        return web.Response(text=body, content_type="text/html")

    async def login_page(self, request):
        if request.cookies.get("session") == "ok":
            raise web.HTTPFound("/home")
        extra = "<p class='error'>Wrong password</p>" if "error" in request.query else ""
        return self.html(FORM.format(action="/login", extra=extra))

    async def login_post(self, request):
        data = await request.post()
        self.posts += 1
        self.received.append((request.host, data.get("password", "")))
        if data.get("email") == USER and data.get("password") == PASSWORD:
            resp = web.HTTPFound("/home")
            resp.set_cookie("session", "ok", httponly=True)
            raise resp
        raise web.HTTPFound("/login?error=1")

    async def home(self, request):
        if request.cookies.get("session") != "ok":
            raise web.HTTPFound("/login")
        return self.html("<html><body><div id='account'>Signed in as reader</div>"
                         "<form action='/search'><input type='text' name='q'></form></body></html>")

    async def step_page(self, request):
        return self.html("<html><body><form method='post' action='/step'>"
                         "<input type='email' name='identifier'><button>Next</button></form></body></html>")

    async def step_post(self, request):
        return self.html("<html><body><form method='post' action='/login'>"
                         f"<input type='hidden' name='email' value='{USER}'>"
                         "<input type='password' name='password'><button>Sign in</button></form></body></html>")

    async def redirect_login(self, request):
        raise web.HTTPFound(self.other_origin + "/login")

    async def crossform(self, request):
        return self.html(FORM.format(action=self.other_origin + "/login", extra=""))

    async def totp_page(self, request):
        return self.html(FORM.format(action="/totp-login", extra=""))

    async def totp_post(self, request):
        data = await request.post()
        self.received.append((request.host, data.get("password", "")))
        if data.get("password") != PASSWORD:
            raise web.HTTPFound("/totp-login")
        return self.html("<html><body><form method='post' action='/otp'>"
                         "<input type='text' name='otp' autocomplete='one-time-code'><button>Verify</button></form></body></html>")

    async def otp_post(self, request):
        from gatehouse import totp
        data = await request.post()
        if data.get("otp") == totp.code(totp.parse_secret(TOTP_SECRET)):
            resp = web.HTTPFound("/home")
            resp.set_cookie("session", "ok", httponly=True)
            raise resp
        return self.html("<html><body><p>bad code</p></body></html>")

    async def captcha_page(self, request):
        if self.captcha_solved:
            return self.html(FORM.format(action="/login", extra=""))
        return self.html("<html><head><meta http-equiv='refresh' content='1'></head><body style='margin:0'>"
                         "<div class='g-recaptcha'>Prove you are human</div>"
                         "<button id='human' style='position:absolute;left:0;top:0;width:300px;height:200px' "
                         "onclick=\"fetch('/solve',{method:'POST'})\">I am human</button></body></html>")

    async def solve(self, request):
        self.captcha_solved = True
        return web.Response(text="ok")

    async def collect(self, request):
        self.collected.append(request.query.get("d", ""))
        return web.Response(text="ok")

    async def planted(self, request):
        return web.Response(text="", content_type="application/javascript")

    # --- hostile and awkward pages -------------------------------------------------
    async def redir_evil(self, request):
        raise web.HTTPFound(self.other_origin + "/evil")

    async def evil(self, request):
        """Rewrites the builtins a naive in-page origin check would rely on."""
        return self.html("<html><body><script>"
                         "Array.prototype.includes = function () { return true; };"
                         "const rs = JSON.stringify;"
                         f"JSON.stringify = function (o) {{ if (o && 'origin' in o) o.origin = {self.approved!r}; return rs(o); }};"
                         "</script>" + FORM.format(action="/login", extra="") + "</body></html>")

    async def login_direct_page(self, request):
        return self.html(FORM.format(action="/login-direct", extra=""))

    async def login_direct(self, request):
        """Answers the form POST directly, without a redirect: a reload would re-send the POST."""
        data = await request.post()
        self.received.append((request.host, data.get("password", "")))
        resp = self.html("<html><body><div id='account'>Signed in as reader</div></body></html>")
        resp.set_cookie("session", "ok")
        return resp

    async def slow_page(self, request):
        return self.html(FORM.format(action="/slow-post", extra=""))

    async def slow_post(self, request):
        import asyncio
        await asyncio.sleep(60)
        return self.html("late")

    async def formaction_page(self, request):
        return self.html("<html><body><form method='post' action='/login'>"
                         "<input type='email' name='email'><input type='password' name='password'>"
                         f"<button type='submit' formaction='{self.other_origin}/login'>Sign in</button></form></body></html>")

    async def hang_page(self, request):
        return self.html("<html><body>" + FORM.format(action="/login", extra="") +
                         "<script>setTimeout(() => { while (true) {} }, 300)</script></body></html>")
