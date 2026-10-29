package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
)

func (s *Server) registerIdP() {
	h := func(pattern string, fn http.HandlerFunc) { s.mux.Handle(pattern, s.traced(fn)) }
	h("GET /t/{tenant}/.well-known/openid-configuration", s.discovery)
	h("GET /t/{tenant}/jwks", s.jwks)
	h("GET /t/{tenant}/authorize", s.authorize)
	h("POST /t/{tenant}/authorize", s.authorize)
	h("POST /t/{tenant}/token", s.token)
	h("GET /t/{tenant}/userinfo", s.userinfo)
	h("POST /t/{tenant}/userinfo", s.userinfo)
	h("GET /t/{tenant}/logout", s.logout)
	h("GET /t/{tenant}/login", s.login)
	h("POST /t/{tenant}/login", s.login)
	h("GET /t/{tenant}/cert.pem", s.certPEM)
	h("GET /t/{tenant}/saml/{app}/metadata", s.samlMetadata)
	h("GET /t/{tenant}/saml/{app}/sso", s.samlSSO)
	h("POST /t/{tenant}/saml/{app}/sso", s.samlSSO)
	h("GET /t/{tenant}/saml/{app}/init", s.samlSSO)
	h("GET /t/{tenant}/saml/{app}/slo", s.samlSLO)
	h("POST /t/{tenant}/saml/{app}/slo", s.samlSLO)
	s.registerAuth0API()
	s.registerGoogleAdminAPI()
	s.registerKeycloakAPI()
}

func (s *Server) issuer(tid string) string { return s.base + "/t/" + tid }

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "oidc.discovery"
	if s.network(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.lookup(w, r, true)
	if t == nil {
		return
	}
	iss := s.issuer(t.ID)
	subjects := []string{"public"}
	if t.Provider == "entra" {
		subjects = []string{"pairwise"}
	}
	writeJSON(w, 200, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/authorize",
		"token_endpoint":                        iss + "/token",
		"userinfo_endpoint":                     iss + "/userinfo",
		"jwks_uri":                              iss + "/jwks",
		"end_session_endpoint":                  iss + "/logout",
		"response_types_supported":              []string{"code", "id_token", "id_token token", "code id_token"},
		"response_modes_supported":              []string{"query", "fragment", "form_post"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials", "password"},
		"subject_types_supported":               subjects,
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "email_verified", "name", "given_name", "family_name", "preferred_username", "groups"},
	})
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "oidc.jwks"
	if s.network(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.lookup(w, r, true)
	if t == nil {
		return
	}
	pub := &t.key.PublicKey
	thumb := sha1.Sum(t.cert.Raw)
	writeJSON(w, 200, map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid(pub),
		"n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes()),
		"x5c": []string{base64.StdEncoding.EncodeToString(t.cert.Raw)}, "x5t": b64(thumb[:]),
	}}})
}

func (s *Server) certPEM(w http.ResponseWriter, r *http.Request) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if t := s.lookup(w, r, true); t != nil {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="`+t.ID+`-signing.pem"`)
		w.Write([]byte(t.CertPEM))
	}
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "oidc.authorize"
	if s.network(w, r) {
		return
	}
	r.ParseForm()
	q := r.Form
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.lookup(w, r, false)
	if t == nil {
		return
	}
	app := t.appByClientID(q.Get("client_id"))
	if app == nil {
		s.errorPage(w, r, t, 400, "Unknown client_id", "No OIDC app in "+t.Name+" has client_id "+q.Get("client_id")+". Copy it from the dashboard.")
		return
	}
	e.App = app.ID
	in := &interaction{Kind: "oidc", Tenant: t.ID, App: app.ID,
		RedirectURI: q.Get("redirect_uri"), State: q.Get("state"), Nonce: q.Get("nonce"), Scope: q.Get("scope"),
		ResponseType: q.Get("response_type"), ResponseMode: q.Get("response_mode"), Prompt: q.Get("prompt"),
		Challenge: q.Get("code_challenge"), ChallengeMethod: q.Get("code_challenge_method"), LoginHint: q.Get("login_hint")}
	e.Summary = "authorize: " + app.Name
	e.decode("authorize request", "json", flatten(q))
	if !slices.Contains(app.RedirectURIs, in.RedirectURI) {
		// Never redirect to an unregistered URI: show the error here instead.
		s.errorPage(w, r, t, 400, "redirect_uri not registered", "The app sent redirect_uri "+in.RedirectURI+" but the registered ones are: "+strings.Join(app.RedirectURIs, ", ")+". Real IdPs stop here too.")
		return
	}
	switch {
	case in.ResponseType != "code" && !strings.Contains(in.ResponseType, "id_token"):
		s.oidcError(w, r, t, in, "unsupported_response_type", "response_type must be code, id_token, or a mix")
		return
	case app.RequirePKCE && in.Challenge == "":
		s.oidcError(w, r, t, in, "invalid_request", "this app requires PKCE: send code_challenge")
		return
	case strings.Contains(in.ResponseType, "id_token") && in.Nonce == "":
		s.oidcError(w, r, t, in, "invalid_request", "nonce is required when the response includes an id_token")
		return
	}
	if !slices.Contains(strings.Fields(in.Scope), "openid") {
		e.warn("scope has no openid: this is plain OAuth, no ID token will be issued")
	}
	if in.Challenge == "" {
		e.warn("no PKCE: fine for a confidential client, required for SPAs and mobile apps")
	}
	if code := t.Sims.AuthError; code != "" {
		s.oidcError(w, r, t, in, code, "simulated by mock-idp")
		s.consumeOnce(t)
		return
	}
	s.beginLogin(w, r, t, in)
}

func flatten(v url.Values) map[string]string {
	out := map[string]string{}
	for k := range v {
		out[k] = v.Get(k)
	}
	return out
}

func (s *Server) oidcError(w http.ResponseWriter, r *http.Request, t *Tenant, in *interaction, code, desc string) {
	entry(r).warn("OIDC error to app: %s (%s)", code, desc)
	p := url.Values{"error": {code}, "error_description": {desc}}
	if in.State != "" {
		p.Set("state", in.State)
	}
	s.deliverOIDC(w, r, t, in, p)
}

func (s *Server) oidcComplete(w http.ResponseWriter, r *http.Request, t *Tenant, app *App, in *interaction, u *User) {
	e := entry(r)
	p := url.Values{}
	if in.State != "" {
		p.Set("state", in.State)
	}
	if t.Sims.OIDCWrongState {
		p.Set("state", "tampered-"+randHex(4))
		e.warn("simulation: returned state %s instead of %q", p.Get("state"), in.State)
	}
	amr := []string{"pwd"}
	if in.MFADone {
		amr = append(amr, "mfa")
	}
	rt := strings.Fields(in.ResponseType)
	if slices.Contains(rt, "code") {
		code := randHex(24)
		put(&s.mem, s.mem.codes, code, &authCode{Tenant: t.ID, App: app.ID, UserID: u.ID, RedirectURI: in.RedirectURI,
			Scope: in.Scope, Nonce: in.Nonce, Challenge: in.Challenge, Method: in.ChallengeMethod,
			AuthTime: time.Now(), Created: time.Now(), AMR: amr, Sims: t.Sims})
		p.Set("code", code)
	}
	if slices.Contains(rt, "id_token") || slices.Contains(rt, "token") {
		tok := s.mintTokens(t, t.Sims, app, u, in.Scope, in.Nonce, time.Now(), amr, e)
		if slices.Contains(rt, "token") {
			p.Set("access_token", str(tok["access_token"]))
			p.Set("token_type", "Bearer")
			p.Set("expires_in", "3600")
		}
		if v := str(tok["id_token"]); v != "" {
			p.Set("id_token", v)
		}
	}
	s.deliverOIDC(w, r, t, in, p)
}

// deliverOIDC sends the authorization response back to the app with the
// response mode the app asked for.
func (s *Server) deliverOIDC(w http.ResponseWriter, r *http.Request, t *Tenant, in *interaction, p url.Values) {
	e := entry(r)
	mode := in.ResponseMode
	if mode == "" {
		mode = "query"
		if in.ResponseType != "" && in.ResponseType != "code" {
			mode = "fragment"
		}
	}
	e.decode("sent to app ("+mode+")", "json", flatten(p))
	var fields [][2]string
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fields = append(fields, [2]string{k, p.Get(k)})
	}
	decoded := ""
	if idt := p.Get("id_token"); idt != "" {
		decoded = prettyJSON(decodeAny(idt))
	}
	if mode == "form_post" {
		if t.Sims.PauseBeforeSend {
			s.page(w, 200, "pause", t, pageData{Title: "Paused", Wide: true, Target: in.RedirectURI, Method: "POST", Fields: fields, Decoded: decoded})
			return
		}
		s.page(w, 200, "autopost", t, pageData{Target: in.RedirectURI, Fields: fields})
		return
	}
	sep := "?"
	if strings.Contains(in.RedirectURI, "?") {
		sep = "&"
	}
	if mode == "fragment" {
		sep = "#"
	}
	target := in.RedirectURI + sep + p.Encode()
	if t.Sims.PauseBeforeSend {
		s.page(w, 200, "pause", t, pageData{Title: "Paused", Wide: true, Target: in.RedirectURI, TargetURL: template.URL(target), Method: "GET (" + mode + ")", Fields: fields, Decoded: decoded})
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func oauthErr(w http.ResponseWriter, r *http.Request, status int, code, desc string) {
	entry(r).warn("%s: %s", code, desc)
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func pkceOK(verifier, challenge, method string) bool {
	if verifier == "" {
		return false
	}
	if method == "plain" {
		return verifier == challenge
	}
	sum := sha256.Sum256([]byte(verifier))
	return b64(sum[:]) == challenge
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "oidc.token"
	if s.network(w, r) {
		return
	}
	r.ParseForm()
	f := r.PostForm
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.lookup(w, r, true)
	if t == nil {
		return
	}
	grant := f.Get("grant_type")
	e.Summary = "token: " + grant
	e.decode("token request", "json", flatten(f))
	cid, sec, basic := r.BasicAuth()
	if basic {
		cid, _ = url.QueryUnescape(cid)
		sec, _ = url.QueryUnescape(sec)
	} else {
		cid, sec = f.Get("client_id"), f.Get("client_secret")
	}
	app := t.appByClientID(cid)
	if app == nil {
		oauthErr(w, r, 401, "invalid_client", "no OIDC app has client_id "+cid)
		return
	}
	e.App = app.ID
	if !app.Public && subtle.ConstantTimeCompare([]byte(sec), []byte(app.ClientSecret)) != 1 {
		how := "client_secret_post"
		if basic {
			how = "client_secret_basic"
		}
		if sec == "" {
			how = "no secret sent"
		}
		oauthErr(w, r, 401, "invalid_client", "client authentication failed ("+how+")")
		return
	}
	sims := t.Sims
	if grant == "authorization_code" {
		if c := peek(&s.mem, s.mem.codes, f.Get("code")); c != nil {
			sims = c.Sims
		}
	}
	if code := sims.TokenError; code != "" {
		oauthErr(w, r, 400, code, "simulated by mock-idp")
		s.consumeOnce(t)
		return
	}

	var u *User
	var scope, nonce string
	authTime, amr := time.Now(), []string{"pwd"}
	switch grant {
	case "authorization_code":
		c := take(&s.mem, s.mem.codes, f.Get("code"))
		switch {
		case c == nil:
			oauthErr(w, r, 400, "invalid_grant", "unknown or already used code. Codes work once.")
			return
		case c.Tenant != t.ID || c.App != app.ID:
			oauthErr(w, r, 400, "invalid_grant", "this code was issued to another client")
			return
		case time.Since(c.Created) > 10*time.Minute:
			oauthErr(w, r, 400, "invalid_grant", "code expired (codes live 10 minutes)")
			return
		case c.RedirectURI != f.Get("redirect_uri"):
			oauthErr(w, r, 400, "invalid_grant", "redirect_uri must equal the one sent to /authorize: "+c.RedirectURI)
			return
		case c.Challenge != "" && !pkceOK(f.Get("code_verifier"), c.Challenge, c.Method):
			oauthErr(w, r, 400, "invalid_grant", "code_verifier does not match the code_challenge")
			return
		}
		u, scope, nonce, authTime, amr = t.user(c.UserID), c.Scope, c.Nonce, c.AuthTime, c.AMR
	case "refresh_token":
		g := take(&s.mem, s.mem.refresh, f.Get("refresh_token"))
		if g == nil || g.Tenant != t.ID || g.App != app.ID {
			oauthErr(w, r, 400, "invalid_grant", "unknown or already used refresh token (they rotate on every use)")
			return
		}
		u, scope, authTime, amr = t.user(g.UserID), g.Scope, g.AuthTime, g.AMR
	case "password":
		u = t.user(f.Get("username"))
		if u == nil || !(t.Sims.AnyPassword || u.Password == f.Get("password")) {
			oauthErr(w, r, 400, "invalid_grant", "wrong username or password")
			return
		}
		scope = f.Get("scope")
	case "client_credentials":
		if app.Public {
			oauthErr(w, r, 400, "unauthorized_client", "public clients cannot use client_credentials")
			return
		}
		scope = f.Get("scope")
	default:
		oauthErr(w, r, 400, "unsupported_grant_type", "grant_type "+grant+" is not supported")
		return
	}
	if grant != "client_credentials" && (u == nil || !u.Active) {
		oauthErr(w, r, 400, "invalid_grant", "the user was deleted or deactivated")
		return
	}
	out := s.mintTokens(t, sims, app, u, scope, nonce, authTime, amr, e)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, out)
	s.consumeOnce(t)
}

func scopeSet(scope string) map[string]bool {
	m := map[string]bool{}
	for _, s := range strings.Fields(scope) {
		m[s] = true
	}
	return m
}

// mintTokens issues the access, ID and refresh tokens, applying the OIDC
// simulations. u is nil for client_credentials.
func (s *Server) mintTokens(t *Tenant, sims Simulations, app *App, u *User, scope, nonce string, authTime time.Time, amr []string, e *LogEntry) map[string]any {
	now := time.Now().Add(time.Duration(sims.ClockSkewSec) * time.Second)
	if sims.ClockSkewSec != 0 {
		e.note("simulated clock skew: %+ds", sims.ClockSkewSec)
	}
	scopes := scopeSet(scope)
	ttl := app.AccessTokenTTL
	if ttl <= 0 {
		ttl = 3600
	}
	iss := s.issuer(t.ID)
	hdr := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid(&t.key.PublicKey)}

	at := map[string]any{"iss": iss, "aud": app.ClientID, "iat": now.Unix(), "exp": now.Unix() + int64(ttl), "jti": randHex(12), "client_id": app.ClientID}
	switch t.Provider {
	case "okta":
		at["aud"], at["cid"], at["scp"] = "api://default", app.ClientID, strings.Fields(scope)
	case "entra":
		at["scp"], at["tid"] = scope, t.ExternalID
	default:
		at["scope"] = scope
	}
	if u != nil {
		at["sub"] = subject(t, app, u)
		if t.Provider == "okta" {
			at["uid"] = u.ID
		}
		if t.Provider == "entra" {
			at["oid"] = u.ID
		}
	} else {
		at["sub"] = app.ClientID
	}
	access := signJWT(t.key, map[string]any{"alg": "RS256", "typ": "at+jwt", "kid": hdr["kid"]}, at)
	out := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": ttl, "scope": scope}
	e.decode("access_token", "json", map[string]any{"claims": at})

	if u != nil && scopes["openid"] {
		idttl := app.IDTokenTTL
		if idttl <= 0 {
			idttl = 3600
		}
		c := profileClaims(t, app, u, scopes)
		c["iss"], c["aud"], c["iat"], c["exp"] = iss, app.ClientID, now.Unix(), now.Unix()+int64(idttl)
		c["auth_time"], c["amr"], c["at_hash"] = authTime.Unix(), amr, atHash(access)
		if t.Provider == "google" || t.Provider == "keycloak" {
			c["azp"] = app.ClientID
		}
		if nonce != "" {
			c["nonce"] = nonce
		}
		key := t.key
		if sims.OIDCExpired {
			c["iat"], c["exp"] = now.Add(-2*time.Hour).Unix(), now.Add(-time.Hour).Unix()
			e.warn("simulation: ID token expired an hour ago")
		}
		if sims.OIDCWrongIssuer {
			c["iss"] = "https://wrong-issuer.example"
			e.warn("simulation: iss is %s", c["iss"])
		}
		if sims.OIDCWrongAudience {
			c["aud"] = "some-other-client"
			e.warn("simulation: aud is some-other-client")
		}
		if sims.OIDCWrongNonce {
			c["nonce"] = "wrong-" + randHex(4)
			e.warn("simulation: nonce is %s", c["nonce"])
		}
		if sims.OIDCWrongAtHash {
			c["at_hash"] = b64([]byte(randHex(8)))
			e.warn("simulation: at_hash does not match the access token")
		}
		if sims.OIDCMissingEmail {
			delete(c, "email")
			delete(c, "email_verified")
			e.warn("simulation: no email claim")
		}
		if sims.OIDCEmailUnverified {
			if _, ok := c["email"]; ok {
				c["email_verified"] = false
				e.warn("simulation: email_verified=false")
			}
		}
		if sims.OIDCUnknownKid {
			hdr["kid"], key = "unknown-"+randHex(4), t.key2
			e.warn("simulation: signed with a key that is not in the JWKS (kid %s)", hdr["kid"])
		}
		if sims.OIDCAlgNone {
			hdr = map[string]any{"alg": "none", "typ": "JWT"}
			e.warn("simulation: alg=none, the ID token is unsigned")
		}
		id := signJWT(key, hdr, c)
		if sims.OIDCBadSignature && !sims.OIDCAlgNone {
			forged := map[string]any{}
			for k, v := range c {
				forged[k] = v
			}
			forged["email"] = "attacker@evil.example"
			fb, _ := json.Marshal(forged)
			parts := strings.Split(id, ".")
			id = parts[0] + "." + b64(fb) + "." + parts[2]
			e.warn("simulation: email changed to attacker@evil.example after signing")
			c = forged
		}
		out["id_token"] = id
		e.decode("id_token", "json", map[string]any{"header": hdr, "claims": c, "times": jwtTimes(c)})
	}
	if u != nil && scopes["offline_access"] {
		rt := randHex(24)
		put(&s.mem, s.mem.refresh, rt, &refreshGrant{Tenant: t.ID, App: app.ID, UserID: u.ID, Scope: scope, AuthTime: authTime, AMR: amr})
		out["refresh_token"] = rt
	}
	return out
}

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "oidc.userinfo"
	if s.network(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.lookup(w, r, true)
	if t == nil {
		return
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" || tok == r.Header.Get("Authorization") {
		r.ParseForm()
		tok = r.PostForm.Get("access_token")
	}
	unauthorized := func(why string) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+why+`"`)
		oauthErr(w, r, 401, "invalid_token", why)
	}
	if tok == "" {
		unauthorized("no access token: send Authorization: Bearer <token>")
		return
	}
	_, c, err := decodeJWT(tok)
	if err != nil {
		unauthorized("access token is not a JWT from this IdP")
		return
	}
	if err := verifyJWT(tok, &t.key.PublicKey); err != nil {
		unauthorized("access token signature is invalid")
		return
	}
	if num(c["exp"]) < time.Now().Unix() {
		unauthorized("access token expired")
		return
	}
	app := t.appByClientID(str(c["client_id"]))
	if app == nil {
		unauthorized("the app for this token was deleted")
		return
	}
	scope := str(c["scope"])
	if v, ok := c["scp"].([]any); ok {
		for _, x := range v {
			scope += " " + str(x)
		}
	} else if v := str(c["scp"]); v != "" {
		scope = v
	}
	for _, u := range t.Users {
		if subject(t, app, u) == str(c["sub"]) {
			e.Summary = "userinfo: " + u.UserName
			writeJSON(w, 200, profileClaims(t, app, u, scopeSet(scope)))
			return
		}
	}
	unauthorized("the user for this token was deleted")
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "oidc.logout"
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.lookup(w, r, false)
	if t == nil {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie(t.ID), Path: "/t/" + t.ID, MaxAge: -1})
	e.note("IdP session cleared")
	target := r.URL.Query().Get("post_logout_redirect_uri")
	if target == "" {
		s.page(w, 200, "message", t, pageData{Title: "Signed out", Info: "Your " + providers[t.Provider].Name + " session has ended."})
		return
	}
	for _, a := range t.Apps {
		if slices.Contains(a.PostLogoutURIs, target) || slices.Contains(a.RedirectURIs, target) {
			if st := r.URL.Query().Get("state"); st != "" {
				target += map[bool]string{true: "&", false: "?"}[strings.Contains(target, "?")] + "state=" + url.QueryEscape(st)
			}
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
	}
	s.errorPage(w, r, t, 400, "post_logout_redirect_uri not registered", target+" is not a registered post-logout or redirect URI of any app.")
}
