# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""HTTP to a registry: the token dance, the TLS policy, and the errors both produce.

Everything above this file talks to a registry through `get_auth_token`, which returns
both a token and the base URL every later request for that image must use. Resolving
the two together is the point: the scheme is not known until the registry has answered,
so a caller that built its own URL would use the wrong one.

Docker Hub takes a fixed token endpoint. Any other registry needs the full dance, and a
public one is no exception: it answers 401 with a challenge naming the realm to ask (or,
for a registry that checks passwords itself, a Basic challenge), so the /v2/ probe
happens even when no credentials exist. A registry that answers the probe outright needs
no credential, and an empty one is the normal result, not a failure. What
`get_auth_token` returns is the Authorization header value itself: `Bearer <token>` from
a token service, `Basic <credentials>` for a Basic registry, or empty for nothing.

TLS is enforced by default and downgraded only on request. A handshake error that looks
like a plaintext reply, or failing that an active HTTP re-probe, is what distinguishes
"this registry is HTTP-only" from "this registry is unreachable", and only the first
gets the `--allow-insecure` hint. With `--allow-insecure` the whole probe is retried
over http; an untrusted certificate is reported as such and never silently accepted,
since the insecure opener skips verification and so cannot produce that error at all.

`AuthStrippingRedirectHandler` exists because Docker Hub redirects blob reads to
pre-signed CDN URLs that answer 400 if a Bearer token comes with them, and urllib
forwards every header across a redirect. Dropping Authorization on a cross-host hop is
also the right thing for a credential regardless of what the CDN would do. It is a
subclass of download's redirect handler, so a hop from HTTPS to plain HTTP is refused
unless `--allow-insecure`, and a hop that is followed under it still loses the header.

`CD_DOCKER_AUTH` is `username:secret` and nothing else, and the secret half is a
password or a personal access token: every registry that issues tokens takes either
in the same Basic header. What has nowhere to go is a bare token with no username,
since registry auth is a token exchange that needs Basic credentials, so that form is
refused with an explanation rather than sent and failed. Only transient failures are
retried; an HTTP status, the expected 401 included, goes straight to the caller, which
is the only layer that knows whether it means "authenticate" or "does not exist". The
`*_denied_msg` helpers phrase that difference for a user, and branch on whether
credentials were supplied at all.
"""

import base64
import json
import math
import os
import re
import typing
import urllib.error
import urllib.parse
import urllib.request

from chroot_distro.constants import PROGRAM_NAME, PROGRAM_VERSION
from chroot_distro.helpers.download import (
    RedirectPolicyHandler,
    certificate_error_msg,
    http_opener,
    is_cert_verification_error,
    is_plaintext_http_tls_error,
    retry_after,
    retry_http,
)

REGISTRY_URL = "https://registry-1.docker.io"
AUTH_URL = "https://auth.docker.io/token"
HUB_SERVICE = "registry.docker.io"


def _ua() -> dict:
    return {"User-Agent": f"{PROGRAM_NAME}/{PROGRAM_VERSION}"}


_DEFAULT_PORTS = {"http": 80, "https": 443}


def same_auth_origin(from_url: str, to_url: str) -> bool:
    """Whether a credential sent with *from_url* may also go to *to_url*.

    An Authorization header is addressed to an origin (scheme, host and
    port), and carrying it to another hands the secret to whoever answers
    there. The one scheme change allowed is an upgrade to HTTPS on the
    default ports, which reaches the same server more securely. A URL
    that cannot be read is not the same origin as anything.
    """
    try:
        src = urllib.parse.urlsplit(from_url)
        dst = urllib.parse.urlsplit(to_url)
        src_host, dst_host = src.hostname, dst.hostname
        src_port, dst_port = src.port, dst.port
    except ValueError:
        return False
    if not src_host or src_host != dst_host:
        return False
    if src.scheme == dst.scheme:
        default = _DEFAULT_PORTS.get(src.scheme)
        return (src_port or default) == (dst_port or default)
    return (
        src.scheme == "http" and dst.scheme == "https" and src_port in (None, 80) and dst_port in (None, 443)
    )


class AuthStrippingRedirectHandler(RedirectPolicyHandler):
    """Strip the Authorization header when following a redirect off-origin.

    Docker Hub blob endpoints redirect to CDN pre-signed URLs. Those CDN
    hosts return HTTP 400 when they receive a Bearer token. Python's
    default redirect handler forwards all headers unchanged, so we
    override it to drop Authorization whenever the redirect target is not
    the origin the request was addressed to (same_auth_origin).

    Whether a redirect is followed at all is the base class's question,
    asked first: a step down from HTTPS to plain HTTP is refused unless
    *allow_plaintext* (--allow-insecure), and one that is followed there
    still loses the header, since it is not the same origin.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Forward the redirect, dropping Authorization off-origin."""
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is None:
            return None
        if not same_auth_origin(req.full_url, newurl):
            new_req.headers.pop("Authorization", None)
        return new_req


def opener(insecure: bool = False) -> urllib.request.OpenerDirector:
    """Build and return a new opener that strips Auth across hosts.

    The *insecure* variant skips certificate verification, so HTTPS endpoints
    presenting an untrusted certificate can be reached under
    ``--allow-insecure``, and lets a redirect step down from HTTPS to plain
    HTTP, which the verifying one refuses. Every request made through the
    returned opener gets a default socket timeout.
    """
    return http_opener(insecure=insecure, redirect=AuthStrippingRedirectHandler(allow_plaintext=insecure))


def auth_opener():
    """Build and return a new opener that strips Auth across hosts."""
    return opener(False)


def insecure_for(registry: str, insecure: bool) -> bool:
    """Whether --allow-insecure reaches *registry* at all.

    The flag is an opt-in for a registry the user names, served over plain
    HTTP or behind a certificate that does not verify. Docker Hub (the
    empty registry) is never one of those, so its manifests and blobs stay
    on verified HTTPS whatever the flag says.
    """
    return bool(insecure and registry)


def registry_base_url(registry: str, insecure: bool = False) -> str:
    """Return the base URL for *registry* (empty string ⇒ Docker Hub)."""
    if not registry:
        return REGISTRY_URL
    scheme = "http" if insecure else "https"
    return f"{scheme}://{registry}"


def insecure_registry_msg(registry: str) -> str:
    """Return the error shown when an HTTPS-only pull hits an HTTP registry."""
    return (
        f"Registry '{registry}' is served over plain HTTP, not HTTPS. "
        f"{PROGRAM_NAME} enforces TLS by default. If you trust this registry "
        f"and the network path to it, re-run with '--allow-insecure' to "
        f"permit the unencrypted connection."
    )


def _http_registry_reachable(registry: str, timeout: float = 6.0) -> bool:
    """Return True if *registry* answers a /v2/ probe over plaintext HTTP.

    Fallback used on the error path when the TLS error itself is not a
    conclusive plaintext signal (see is_plaintext_http_tls_error), to
    decide whether an HTTPS failure is because the registry is HTTP-only
    (so we can point the user at ``--allow-insecure``) rather than simply
    unreachable. Any HTTP-level response, 401 and 404 included, confirms the
    host speaks HTTP on that endpoint.
    """
    req = urllib.request.Request(f"http://{registry}/v2/", headers=_ua())
    try:
        with http_opener().open(req, timeout=timeout) as resp:
            resp.read(64)
        return True
    except urllib.error.HTTPError:
        return True
    except (urllib.error.URLError, OSError):
        return False


def credentials_rejected_msg(registry: str, code: int) -> str:
    """Return the error shown when a registry refuses CD_DOCKER_AUTH itself.

    Not access to an image: the account. _check_credentials asks with no
    repository named, so the answer is about the username and password
    alone, unlike auth_denied_msg, which cannot tell the two apart.
    """
    who = f"Registry '{registry}'" if registry else "Docker Hub"
    return (
        f"{who} rejected the credentials in CD_DOCKER_AUTH (HTTP {code}). "
        f"Check the username and password. An access token may also have "
        f"expired or lack the required permissions."
    )


def auth_denied_msg(image_ref: str, code: int) -> str:
    """Return a descriptive error string for 401/403 registry responses."""
    if os.environ.get("CD_DOCKER_AUTH"):
        return (
            f"Access denied to '{image_ref}' (HTTP {code}). "
            f"Check that CD_DOCKER_AUTH=username:password-or-token is correct "
            f"and the account has pull access to the image."
        )
    return (
        f"Unauthorized: '{image_ref}' does not exist or is a private image. "
        f"Set CD_DOCKER_AUTH=username:password-or-token to authenticate."
    )


def _wait_text(seconds: float) -> str:
    """A Retry-After, rounded to what a person would say."""
    if not math.isfinite(seconds) or seconds >= 86400:
        return "more than a day"
    if seconds >= 5400:
        return f"about {round(seconds / 3600)} hours"
    if seconds >= 90:
        return f"about {round(seconds / 60)} minutes"
    return f"{math.ceil(seconds)} seconds"


def _relays_docker_hub(registry: str, exc: urllib.error.HTTPError) -> bool:
    """Whether *registry* answered *exc* on Docker Hub's behalf.

    Docker Hub marks every answer it counts against a pull quota with
    Docker-RateLimit-Source, the address or account the pull was counted
    against. The same header on a refusal from another registry is a front
    end passing requests on to Docker Hub, such as a vanity name like
    docker.n8n.io. The refusal has to have come from that registry itself:
    one that redirected the request to Docker Hub got its answer from
    Docker Hub, counted against this machine's own address.
    """
    if not registry or exc.headers is None:
        return False
    if exc.headers.get("Docker-RateLimit-Source") is None:
        return False
    try:
        host = urllib.parse.urlsplit(getattr(exc, "url", "") or "").netloc
    except ValueError:
        return False
    return host.lower() == registry.lower()


def rate_limited_msg(
    image_ref: str, ref: tuple[str, str, str], exc: urllib.error.HTTPError, action: str = "pull"
) -> str:
    """Return the error shown when a registry answers 429 Too Many Requests.

    *ref* is the parsed *image_ref*, and *action* is "pull" or "push". The
    advice depends on whose limit it is. With CD_DOCKER_AUTH set it is the
    account's, and there is nothing to do but wait. Anonymous pulls from
    Docker Hub are counted per network address, which a mobile carrier's
    NAT shares among many people. A front end relaying Docker Hub is one
    address to Docker Hub however many people pull through it, so its
    anonymous quota is spent by all of them at once and is often simply
    gone; the image is usually on Docker Hub under the same repository,
    and pulling it from there is counted against this machine's own
    address instead.

    A push is told the same, less what only a pull can act on: the
    per-address limit is Docker Hub's pull limit, and a push cannot simply
    go to the Docker Hub name, since the image has to be built under it
    first.
    """
    pulling = action == "pull"
    registry, repo, tag = ref
    who = f"Registry '{registry}'" if registry else "Docker Hub"
    text = (
        f"{who} refused to {'serve' if pulling else 'accept'} "
        f"'{image_ref}' (HTTP 429 Too Many Requests): its rate limit is "
        f"reached"
    )
    wait = retry_after(exc)
    when = f"in {_wait_text(wait)}" if wait else "later"
    if os.environ.get("CD_DOCKER_AUTH"):
        return f"{text} for the account in CD_DOCKER_AUTH. Try again {when}."
    hub_account = (
        f"set CD_DOCKER_AUTH=username:password to {action} with a Docker "
        f"Hub account, which has a limit of its own"
    )
    if not registry:
        why = (
            "Docker Hub limits anonymous pulls per network address, which "
            "mobile and shared networks give to many people at once. "
            if pulling
            else ""
        )
        return f"{text}. {why}Try again {when}, or {hub_account}."
    if _relays_docker_hub(registry, exc):
        shared = (
            f"{text}. '{registry}' passes requests on to Docker Hub, and "
            f"everyone using it anonymously shares one Docker Hub limit."
        )
        if not pulling:
            return f"{shared} Try again {when}, or {hub_account}."
        hub_ref = f"{repo}:{tag}" if tag else repo
        return (
            f"{shared} If the image is published on Docker Hub too, "
            f"install it from there: '{hub_ref}'. Otherwise try again "
            f"{when}, or {hub_account}."
        )
    return (
        f"{text}. Try again {when}, or set "
        f"CD_DOCKER_AUTH=username:password to {action} with an account; "
        f"registries usually allow signed-in users more."
    )


def push_denied_msg(image_ref: str, code: int) -> str:
    """Return a context-sensitive error string for 401/403 on push."""
    if os.environ.get("CD_DOCKER_AUTH"):
        return (
            f"Push denied for '{image_ref}' (HTTP {code}). "
            f"Check that CD_DOCKER_AUTH=username:password-or-token is correct "
            f"and the account has push access to the repository."
        )
    return (
        f"Push denied for '{image_ref}' (HTTP {code}). "
        f"Set CD_DOCKER_AUTH=username:password-or-token to authenticate, or, "
        f"for self-hosted registries that allow anonymous push, check "
        f"the registry configuration."
    )


_CHALLENGE_PARAM_RE = re.compile(r'(\w+)\s*=\s*(?:"([^"]*)"|([^",\s]+))')


def _parse_bearer_challenge(header_value: str) -> dict:
    """Return the key=value pairs from a Bearer WWW-Authenticate header."""
    return {key: (quoted if quoted else bare) for key, quoted, bare in _CHALLENGE_PARAM_RE.findall(header_value)}


def _bearer(token: str) -> str:
    """The Authorization value for a granted *token*; '' for no token."""
    return f"Bearer {token}" if token else ""


def _request_body(open_fn, req, what: str) -> bytes:
    """Open *req* via *open_fn* and return the full response body.

    Transient network failures are retried (same policy as the URL
    downloader). HTTP errors, including the expected 401 that carries the
    Bearer challenge, and deterministic TLS failures are not retried; they
    propagate to the caller, which knows how to handle them.
    """

    def _attempt():
        with open_fn(req) as resp:
            return resp.read()

    return typing.cast(bytes, retry_http(_attempt, what=what))


def _release(exc: urllib.error.HTTPError) -> None:
    """Close the connection behind *exc*, whose body nobody will read.

    An HTTPError holds the response it was raised for, socket and all, and
    one that ends up in a chained exception sits in a reference cycle that
    only the cyclic garbage collector frees. Until it runs the socket stays
    open. Called once the status and headers have been read, which do not
    need the connection.
    """
    fp = getattr(exc, "fp", None)
    if fp is not None:
        fp.close()


def env_basic_auth() -> str:
    """Return a Basic auth header value from CD_DOCKER_AUTH, or ''.

    Accepts 'username:password' or 'username:token'; the colon is the required
    separator, and the secret half is passed through as given.
    """
    raw = os.environ.get("CD_DOCKER_AUTH", "")
    if not raw:
        return ""
    if ":" not in raw:
        raise RuntimeError(
            "CD_DOCKER_AUTH must be in 'username:password' format "
            "(e.g. 'myuser:mypassword' or 'myuser:ghp_xxx', since a "
            "personal access token takes the password's place). "
            "A bare token without a username cannot be used: registries "
            "take a username and a password (or access token) as Basic "
            "credentials."
        )
    return "Basic " + base64.b64encode(raw.encode()).decode()


def _token_url(realm: str, service: str, scope: str = "") -> str:
    """The token request URL for *realm*, naming *service* and *scope*.

    Either may be empty and is then left out: a challenge need not name a
    service, and the credential check asks for no scope at all.
    """
    params = []
    if service:
        params.append(f"service={urllib.parse.quote(service, safe='')}")
    if scope:
        params.append(f"scope={scope}")
    if not params:
        return realm
    sep = "&" if "?" in realm else "?"
    return f"{realm}{sep}{'&'.join(params)}"


# What the server judging CD_DOCKER_AUTH answers credentials it refuses.
# Token services say 401 (Docker Hub, GitLab, Quay, Google) or 403 (GHCR).
# A registry checking them itself says 401 or 403 too, and Amazon ECR 400.
_REJECTED_BY_TOKEN_SERVICE = (401, 403)
_REJECTED_BY_REGISTRY = (400, 401, 403)


def _check_credentials(open_fn, url: str, basic_auth: str, registry: str, rejected: tuple) -> None:
    """Have CD_DOCKER_AUTH checked by the server that judges it, or raise.

    *url* is that server: the token service with no scope requested, or a
    registry that checks passwords itself at its /v2/ endpoint. This is the
    request `docker login` makes, so its answer is about the account alone:
    a 401 or 403 to a request naming a repository can be the password or
    the repository, and not every registry says which.

    A status in *rejected* raises a RuntimeError saying the credentials were
    refused. A Basic registry's 400 counts: its /v2/ just answered the same
    request without them with 401, so a 400 can only be about what was
    added. Anything else propagates as it would from the request the check
    comes before.
    """
    req = urllib.request.Request(url, headers={**_ua(), "Authorization": basic_auth})
    try:
        _request_body(open_fn, req, "Checking credentials")
    except urllib.error.HTTPError as exc:
        if exc.code in rejected:
            _release(exc)
            raise RuntimeError(credentials_rejected_msg(registry, exc.code)) from exc
        raise


def get_auth_token(
    repo: str,
    registry: str = "",
    actions: str = "pull",
    insecure: bool = False,
) -> tuple[str, str]:
    """Resolve a registry's base URL and the credential for *repo*.

    Returns ``(authorization, base_url)`` where *base_url* is the resolved
    ``scheme://registry`` that every subsequent request for this image must
    use, and *authorization* the value of the Authorization header every one
    of them carries: ``Bearer <token>`` for a registry with a token service,
    ``Basic <credentials>`` for one that checks passwords itself, and empty
    when there is nothing to send. The header goes only to *base_url*'s
    origin: a redirect elsewhere drops it (AuthStrippingRedirectHandler), and
    so does an upload Location elsewhere (push._headers_for).

    A Basic challenge means the registry takes the credentials itself on
    every request, so CD_DOCKER_AUTH is what it gets. It goes to the origin
    that was probed, over the scheme the probe settled on, so plain HTTP still
    needs *insecure*, as for a realm.
    """
    basic_auth = env_basic_auth()

    if not registry:
        # Through the auth-stripping opener, never urlopen(): the default
        # redirect handler carries the Basic header to whatever host a
        # redirect names, and these are the requests with the user's password
        # in them. Docker Hub is always verified HTTPS, so it is the
        # verifying opener whatever `insecure` says.
        if basic_auth:
            _check_credentials(
                auth_opener().open,
                _token_url(AUTH_URL, HUB_SERVICE),
                basic_auth,
                registry,
                _REJECTED_BY_TOKEN_SERVICE,
            )
        url = _token_url(AUTH_URL, HUB_SERVICE, f"repository:{repo}:{actions}")
        req = urllib.request.Request(url, headers=_ua())
        if basic_auth:
            req.add_header("Authorization", basic_auth)
        data = json.loads(_request_body(auth_opener().open, req, f"Authenticating {repo}"))
        token = data.get("token") or data.get("access_token", "")
        return _bearer(token), REGISTRY_URL

    # Custom registry: probe /v2/ to resolve the scheme and discover the
    # Bearer realm. A registry serving public images still requires the dance:
    # it answers 401 to an unauthenticated request and embeds the token
    # endpoint in the challenge.
    op = opener(insecure)
    scheme = "https"
    while True:
        base = f"{scheme}://{registry}"
        probe_req = urllib.request.Request(f"{base}/v2/", headers=_ua())
        try:
            _request_body(op.open, probe_req, f"Probing {base}/v2/")
            return "", base  # registry is wide open; no token required
        except urllib.error.HTTPError as exc:
            if exc.code != 401:
                raise
            www_auth = exc.headers.get("WWW-Authenticate", "").strip()
            auth_scheme, _, challenge = www_auth.partition(" ")
            auth_scheme = auth_scheme.lower()
            _release(exc)
            if auth_scheme == "basic":
                # A registry that checks passwords itself (distribution with
                # htpasswd auth, Nexus, Artifactory) has no token service and
                # wants the credentials on every request. Taken for an open
                # registry, nothing was ever sent and the refusal that
                # followed told the user to check credentials it had not used.
                # It is asked with them once now, at the /v2/ it just
                # challenged from, so a wrong password is said to be one here
                # rather than as a refused manifest or upload later.
                if basic_auth:
                    _check_credentials(op.open, f"{base}/v2/", basic_auth, registry, _REJECTED_BY_REGISTRY)
                return basic_auth, base
            if auth_scheme != "bearer":
                return "", base
            params = _parse_bearer_challenge(challenge)
            realm = params.get("realm", "")
            if not realm:
                return "", base
            service = params.get("service", "")
            if basic_auth:
                _check_credentials(op.open, _token_url(realm, service), basic_auth, registry, _REJECTED_BY_TOKEN_SERVICE)
            token_req = urllib.request.Request(
                _token_url(realm, service, f"repository:{repo}:{actions}"), headers=_ua()
            )
            if basic_auth:
                token_req.add_header("Authorization", basic_auth)
            data = json.loads(_request_body(op.open, token_req, "Requesting auth token"))
            token = data.get("token") or data.get("access_token", "")
            return _bearer(token), base
        except urllib.error.URLError as exc:
            # The server speaks TLS but its certificate is untrusted. Only
            # reachable when enforcing HTTPS (the insecure opener skips
            # verification, so no cert error occurs there).
            if not insecure and is_cert_verification_error(exc):
                raise RuntimeError(certificate_error_msg(registry)) from exc
            # The registry answered the HTTPS probe with plaintext (or only
            # responds over plain HTTP): it is HTTP-only. Two signals,
            # cheapest first: the handshake error itself (WRONG_VERSION_NUMBER
            # and friends), else an active HTTP re-probe.
            if scheme == "https" and (is_plaintext_http_tls_error(exc) or _http_registry_reachable(registry)):
                if insecure:
                    scheme = "http"  # retry the whole probe over plain HTTP
                    continue
                raise RuntimeError(insecure_registry_msg(registry)) from exc
            raise


def auth_note(prefix_space: bool = True) -> str:
    """Return ' (user credentials)' or ' (anonymous)' for log lines."""
    head = " " if prefix_space else ""
    if os.environ.get("CD_DOCKER_AUTH"):
        return f"{head}(user credentials)"
    return f"{head}(anonymous)"
