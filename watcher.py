"""Mystery Dining visit watcher.

Logs in to the Mystery Dining assessor portal as you, polls the list of
available visits, and sends an ntfy push notification when a visit inside
your radius appears. It never books anything.

Configuration comes from environment variables (see README.md).
"""

import base64
import hashlib
import json
import os
import random
import re
import secrets
import sys
import time
from datetime import datetime
from urllib.parse import parse_qs, urlparse
from zoneinfo import ZoneInfo

import requests

# --- Fixed details of the Mystery Dining portal -----------------------------
TENANT = "hgemproductionb2c"
POLICY = "B2C_1_mystery-dining-login-production"
B2C = f"https://{TENANT}.b2clogin.com/{TENANT}.onmicrosoft.com/{POLICY}"
CLIENT_ID = "74b56817-71db-4312-8747-54fb4ff2206b"
PORTAL = "https://assessors.mysterydining.com"
REDIRECT_URI = f"{PORTAL}/loading"
SCOPE = f"openid {CLIENT_ID} offline_access profile email"
VISITS_URL = (
    "https://production-gateways.hgem.com/diner-gateway"
    "/guestservices-visitsapi/AvailableVisits"
)
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0 Safari/537.36"
)
METRES_PER_MILE = 1609.344
STATE_FILE = os.environ.get("STATE_FILE", "state.json")


class LoginError(Exception):
    pass


class FetchError(Exception):
    def __init__(self, status, detail):
        super().__init__(f"HTTP {status}")
        self.status = status
        self.detail = detail


# --- Authentication ----------------------------------------------------------
class Auth:
    """Signs in through the portal's normal login page and keeps a token fresh."""

    def __init__(self, email, password):
        self.email = email
        self.password = password
        self.access_token = None
        self.refresh_token = None
        self.expires_at = 0

    def _store(self, tok):
        if "access_token" not in tok:
            raise LoginError(f"no access token in response: {tok.get('error', 'unknown')}")
        self.access_token = tok["access_token"]
        self.refresh_token = tok.get("refresh_token") or self.refresh_token
        self.expires_at = time.time() + int(tok.get("expires_in", 3600))

    def login(self):
        s = requests.Session()
        s.headers["User-Agent"] = USER_AGENT
        verifier = secrets.token_urlsafe(64)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        r = s.get(
            f"{B2C}/oauth2/v2.0/authorize",
            params={
                "client_id": CLIENT_ID,
                "response_type": "code",
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": secrets.token_urlsafe(8),
                "prompt": "login",
            },
            timeout=30,
        )
        r.raise_for_status()
        m = re.search(r"var SETTINGS = (\{.*?\});", r.text, re.S)
        if not m:
            raise LoginError("login page layout not recognised")
        settings = json.loads(m.group(1))
        csrf, tx = settings["csrf"], settings["transId"]

        r2 = s.post(
            f"{B2C}/SelfAsserted",
            params={"tx": tx, "p": POLICY},
            data={
                "request_type": "RESPONSE",
                "email": self.email,
                "password": self.password,
            },
            headers={
                "X-CSRF-TOKEN": csrf,
                "X-Requested-With": "XMLHttpRequest",
                "Referer": r.url,
            },
            timeout=30,
        )
        try:
            result = r2.json()
        except ValueError:
            raise LoginError(f"unexpected sign-in response (HTTP {r2.status_code})")
        if str(result.get("status")) != "200":
            raise LoginError(f"sign-in rejected: {result.get('message', 'no reason given')}")

        r3 = s.get(
            f"{B2C}/api/{settings.get('api', 'CombinedSigninAndSignup')}/confirmed",
            params={"rememberMe": "false", "csrf_token": csrf, "tx": tx, "p": POLICY},
            allow_redirects=False,
            timeout=30,
        )
        query = parse_qs(urlparse(r3.headers.get("Location", "")).query)
        if "code" not in query:
            reason = query.get("error_description", ["the site asked for an extra step"])[0]
            raise LoginError(f"no login code returned: {reason[:150]}")

        r4 = s.post(
            f"{B2C}/oauth2/v2.0/token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": query["code"][0],
                "redirect_uri": REDIRECT_URI,
                "code_verifier": verifier,
                "scope": SCOPE,
            },
            headers={"Origin": PORTAL},
            timeout=30,
        )
        self._store(r4.json())

    def _refresh(self):
        r = requests.post(
            f"{B2C}/oauth2/v2.0/token",
            data={
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "refresh_token": self.refresh_token,
                "scope": SCOPE,
            },
            headers={"Origin": PORTAL, "User-Agent": USER_AGENT},
            timeout=30,
        )
        self._store(r.json())

    def token(self, force=False):
        if force or not self.access_token:
            self.login()
        elif time.time() > self.expires_at - 300:
            try:
                self._refresh()
            except Exception:
                self.login()
        return self.access_token


# --- Visits ------------------------------------------------------------------
def fetch_visits(auth, lat, lon):
    params = {
        "CurrentPosition.Latitude": lat,
        "CurrentPosition.Longitude": lon,
        "pageStart": 0,
        "pageSize": 50,
        "DateFilterType": 0,
        "FilterType": 0,
        "SortType": 0,
    }
    for attempt in (1, 2):
        r = requests.get(
            VISITS_URL,
            params=params,
            headers={
                "Authorization": f"Bearer {auth.token(force=(attempt == 2))}",
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
            },
            timeout=30,
        )
        if r.status_code == 401 and attempt == 1:
            continue
        if r.status_code >= 400:
            detail = re.sub(r"\s+", " ", r.text or "")[:200]
            raise FetchError(r.status_code, detail)
        data = r.json()
        if not isinstance(data, list):
            raise ValueError("visit list was not in the expected format")
        return data


def describe(v):
    miles = v.get("distance", 0) / METRES_PER_MILE
    money = v.get("questionnaireReimbursement") or {}
    amount = money.get("maxReimbursement")
    parts = [f"{miles:.1f} mi"]
    if amount is not None:
        prefix = "" if money.get("isSetAmount") else "Up to "
        per = " pp" if money.get("isPerPerson") else ""
        parts.append(f"{prefix}{v.get('currencySymbol', '£')}{amount:g}{per}")
    dates = sorted(d[:10] for d in v.get("availableDates") or [])
    if dates:
        parts.append(dates[0] if len(dates) == 1 else f"{dates[0]} to {dates[-1]}")
    criteria = re.sub(r"<[^>]+>", " ", v.get("criteria") or "")
    criteria = re.sub(r"\s+", " ", criteria).strip()
    text = " · ".join(parts)
    if criteria:
        text += "\n" + criteria[:180]
    return text


def find_new(visits, state, radius_miles, cooldown_s, now):
    """Return visits to alert on and update state in place."""
    near = [
        v for v in visits
        if v.get("distance") is not None
        and v["distance"] <= radius_miles * METRES_PER_MILE
    ]
    ids = [str(v["visitId"]) for v in near]
    previous = set(state.get("present", []))
    alerted = state.setdefault("alerted", {})
    fresh = []
    if state.get("initialised"):
        for v, vid in zip(near, ids):
            recently = vid in alerted and now - alerted[vid] <= cooldown_s
            if vid not in previous and not recently:
                fresh.append(v)
                alerted[vid] = now
    state["present"] = ids
    state["initialised"] = True
    # forget alert times older than a week
    for vid in [k for k, t in alerted.items() if now - t > 7 * 86400]:
        del alerted[vid]
    return fresh, len(near)


# --- Notifications -----------------------------------------------------------
def notify(topic, title, message, priority=4, tags=("fork_and_knife",)):
    server = os.environ.get("NTFY_SERVER", "https://ntfy.sh").rstrip("/")
    requests.post(
        server,
        json={
            "topic": topic,
            "title": title,
            "message": message,
            "priority": priority,
            "tags": list(tags),
            "click": PORTAL,
        },
        timeout=20,
    ).raise_for_status()


def send_alerts(topic, fresh):
    if len(fresh) > 5:
        lines = [
            f"{v.get('visitName', 'Visit')} ({v['distance'] / METRES_PER_MILE:.1f} mi)"
            for v in fresh
        ]
        notify(topic, f"{len(fresh)} new Mystery Dining visits", "\n".join(lines)[:3500])
        return
    for v in fresh:
        notify(topic, f"New visit: {v.get('visitName', 'Mystery Dining')}", describe(v))


# --- State -------------------------------------------------------------------
def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


# --- Active hours ------------------------------------------------------------
def in_active_hours(now=None):
    """True if the current UK time is inside ACTIVE_HOURS (e.g. '07:30-22:30')."""
    window = os.environ.get("ACTIVE_HOURS", "").strip()
    if not window:
        return True
    start, end = (tuple(int(x) for x in part.split(":")) for part in window.split("-"))
    now = now or datetime.now(ZoneInfo(os.environ.get("TIMEZONE", "Europe/London")))
    current = (now.hour, now.minute)
    if start <= end:
        return start <= current < end
    return current >= start or current < end


# --- Main --------------------------------------------------------------------
def main():
    env = os.environ
    topic = env["NTFY_TOPIC"]
    if env.get("SEND_TEST", "").lower() == "true":
        notify(topic, "Mystery Dining watcher", "Test message: notifications are working.", 3)
        print("test notification sent")
        return 0

    if not in_active_hours():
        print("outside active hours, nothing to do")
        return 0

    lat, lon = float(env["HOME_LAT"]), float(env["HOME_LON"])
    radius = float(env.get("RADIUS_MILES", "20"))
    poll = max(30, int(env.get("POLL_SECONDS", "120")))
    run_minutes = float(env.get("RUN_MINUTES", "0"))
    cooldown = float(env.get("REALERT_HOURS", "3")) * 3600
    deadline = time.time() + run_minutes * 60

    auth = Auth(env["MD_EMAIL"], env["MD_PASSWORD"])
    try:
        auth.token()
    except Exception as e:  # login problems should reach your phone
        reason = str(e) if isinstance(e, LoginError) else type(e).__name__
        notify(topic, "Mystery Dining watcher: login failed", reason[:300], 3, ("warning",))
        print(f"login failed: {type(e).__name__}")
        return 1
    print("logged in")

    state = load_state()
    failures, warned, checks = 0, False, 0
    while True:
        try:
            visits = fetch_visits(auth, lat, lon)
            if visits:  # an empty list is treated as a glitch, not "everything gone"
                fresh, near = find_new(visits, state, radius, cooldown, time.time())
                save_state(state)
                if fresh:
                    send_alerts(topic, fresh)
                checks += 1
                # counts only: this log may be public
                print(f"check {checks}: {near} in range, {len(fresh)} new")
            failures = 0
        except Exception as e:
            failures += 1
            what = f"HTTP {e.status}" if isinstance(e, FetchError) else type(e).__name__
            detail = e.detail if isinstance(e, FetchError) else ""
            print(f"check failed ({what}), {failures} in a row")
            if failures == 5 and not warned:
                warned = True
                try:
                    notify(
                        topic,
                        "Mystery Dining watcher is having trouble",
                        f"5 checks in a row failed ({what}). It will keep trying.\n{detail}".strip(),
                        3,
                        ("warning",),
                    )
                except Exception:
                    pass
        if time.time() + poll >= deadline or not in_active_hours():
            break
        time.sleep(poll + random.uniform(0, 10))
    return 1 if failures >= 5 else 0


if __name__ == "__main__":
    sys.exit(main())
