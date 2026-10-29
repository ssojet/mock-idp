package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

type route struct {
	Method string   `json:"method"`
	Path   string   `json:"path"`
	Name   string   `json:"name"`
	Desc   string   `json:"description"`
	Query  []string `json:"query,omitempty"`
	Body   any      `json:"exampleBody,omitempty"`
}

func (s *Server) api(method, path, name, desc string, body any, h http.HandlerFunc, query ...string) {
	s.routes = append(s.routes, &route{method, path, name, desc, query, body})
	s.mux.HandleFunc(method+" "+path, func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			writeJSON(w, 401, map[string]string{"error": "set Authorization: Bearer <MOCKIDP_API_TOKEN>"})
			return
		}
		if err := s.localOnly(r); err != nil {
			writeJSON(w, 403, map[string]string{"error": err.Error()})
			return
		}
		h(w, r)
	})
}

func (s *Server) authorized(r *http.Request) bool {
	if s.apiToken == "" {
		return true
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.apiToken)) == 1
}

// localOnly blocks the two ways a web page can drive a mock-idp running on a
// developer's machine. Cross-site requests: any site may POST a "simple"
// request to localhost with no preflight, so it could flip faults, wipe data
// or aim the SCIM client at any URL. DNS rebinding: a hostile name that
// resolves to 127.0.0.1 looks same-origin and could read client secrets.
// curl, scripts and agents send no Origin and keep working; a valid API
// token skips the check. The IdP endpoints under /t/ are not affected.
func (s *Server) localOnly(r *http.Request) error {
	if s.apiToken != "" {
		return nil // authorized() already demanded the token
	}
	if !s.allowedHost(r.Host) {
		return fmt.Errorf("host %q is not allowed. Open mock-idp at %s, or add the name to MOCKIDP_ALLOWED_HOSTS", r.Host, s.base)
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" || !(strings.EqualFold(u.Host, r.Host) || isLoopback(u.Hostname())) {
			return fmt.Errorf("request from the web page %s refused: the API answers only the dashboard and non-browser clients", o)
		}
	}
	return nil
}

// allowedHost accepts names a rebinding attacker cannot make a browser send:
// IP literals, single-label names such as a compose service ("mock-idp"),
// the base URL's host and MOCKIDP_ALLOWED_HOSTS. An attacker's name always
// has a dot in it, because it has to be a domain they control.
func (s *Server) allowedHost(hostport string) bool {
	h := hostport
	if hh, _, err := net.SplitHostPort(hostport); err == nil {
		h = hh
	}
	h = strings.ToLower(strings.Trim(h, "[]"))
	if net.ParseIP(h) != nil || !strings.Contains(h, ".") || h == "host.docker.internal" {
		return true
	}
	if u, err := url.Parse(s.base); err == nil && strings.EqualFold(u.Hostname(), h) {
		return true
	}
	for _, a := range strings.Split(os.Getenv("MOCKIDP_ALLOWED_HOSTS"), ",") {
		if a = strings.TrimSpace(strings.ToLower(a)); a != "" && a == h {
			return true
		}
	}
	return false
}

func isLoopback(h string) bool {
	h = strings.ToLower(h)
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip != nil && ip.IsLoopback()
}

func readBody(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil
	}
	if err := json.Unmarshal(b, v); err != nil {
		return errf(400, "bad JSON body: %v", err)
	}
	return nil
}

// tx runs fn under the store lock with the path's tenant, saves after a
// successful write and answers with fn's result as JSON.
func (s *Server) tx(w http.ResponseWriter, r *http.Request, write bool, fn func(t *Tenant) (any, error)) {
	s.store.mu.Lock()
	t := s.store.tenant(r.PathValue("tenant"))
	var v any
	var err error
	if t == nil {
		err = errf(404, "unknown tenant %q", r.PathValue("tenant"))
	} else {
		v, err = fn(t)
	}
	var b []byte
	if err == nil {
		if write {
			s.store.save()
		}
		b, err = json.MarshalIndent(v, "", "  ")
	}
	s.store.mu.Unlock()
	if err != nil {
		writeErr(w, err)
		return
	}
	if write {
		s.logs.publish("change", map[string]string{"tenant": r.PathValue("tenant")})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func publicTenant(t *Tenant) Tenant {
	v := *t
	v.KeyPEM, v.Key2PEM, v.Cert2PEM = "", "", ""
	return v
}

type tenantSummary struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Provider string   `json:"provider"`
	Domain   string   `json:"domain"`
	Users    int      `json:"users"`
	Groups   int      `json:"groups"`
	Apps     int      `json:"apps"`
	Targets  int      `json:"scimTargets"`
	Sims     []string `json:"activeSimulations"`
}

func (s *Server) registerAPI() {
	s.api("GET", "/api", "describe_api", "Every API route with its description and an example body.", nil, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, s.routes)
	})
	s.api("GET", "/api/info", "get_info", "Server facts: base URL, the providers and their quirks, the simulation catalogue and presets. Read this first.", nil, s.apiInfo)
	s.api("GET", "/api/test-sp-certificate", "get_test_sp_certificate", "The built-in test SP's certificate. Its apps already use it; paste it as spEncryptionCert / spSigningCert to use encryption or signed requests with the built-in test SP.", nil, func(w http.ResponseWriter, r *http.Request) {
		s.store.mu.Lock()
		pemText := s.store.SPCertPEM
		s.store.mu.Unlock()
		writeJSON(w, 200, map[string]string{"certificatePem": pemText})
	})
	s.api("GET", "/api/tenants", "list_tenants", "List simulated identity providers (tenants) with counts and active simulations.", nil, s.listTenants)
	s.api("POST", "/api/tenants", "create_tenant", "Create a simulated IdP. provider is a key from get_info. seed adds sample users, groups and two test apps.",
		map[string]any{"name": "Acme", "provider": "okta", "domain": "acme.example", "seed": true}, s.createTenant)
	s.api("GET", "/api/tenants/{tenant}", "get_tenant", "Everything in a tenant: users, groups, apps, SCIM targets, simulations.", nil, func(w http.ResponseWriter, r *http.Request) {
		s.tx(w, r, false, func(t *Tenant) (any, error) { return publicTenant(t), nil })
	})
	s.api("PATCH", "/api/tenants/{tenant}", "update_tenant", "Rename a tenant or change its domain.", map[string]any{"name": "Acme Inc", "domain": "acme.example"}, func(w http.ResponseWriter, r *http.Request) {
		s.tx(w, r, true, func(t *Tenant) (any, error) {
			var in struct{ Name, Domain *string }
			if err := readBody(r, &in); err != nil {
				return nil, err
			}
			if in.Name != nil {
				t.Name = *in.Name
			}
			if in.Domain != nil {
				t.Domain = *in.Domain
			}
			return publicTenant(t), nil
		})
	})
	s.api("DELETE", "/api/tenants/{tenant}", "delete_tenant", "Delete a tenant and everything in it.", nil, s.deleteTenant)
	s.api("GET", "/api/tenants/{tenant}/endpoints", "get_endpoints", "Every URL and value an app needs: OIDC issuer and endpoints, client ids and secrets, per-app SAML metadata and SSO URLs, the signing certificate, and test-login links.", nil, func(w http.ResponseWriter, r *http.Request) {
		s.tx(w, r, false, func(t *Tenant) (any, error) { return s.endpoints(t), nil })
	})
	s.api("POST", "/api/tenants/{tenant}/rotate-keys", "rotate_keys", "Rotate the signing key. Apps that cached the old certificate or JWKS start failing, as after a real rotation.", nil, func(w http.ResponseWriter, r *http.Request) {
		s.tx(w, r, true, func(t *Tenant) (any, error) {
			k, c, err := newKeyPair(t.Name + " signing")
			if err != nil {
				return nil, err
			}
			t.KeyPEM, t.CertPEM = k, c
			if err := t.loadKeys(); err != nil {
				return nil, err
			}
			return s.endpoints(t), nil
		})
	})

	// users
	s.api("GET", "/api/tenants/{tenant}/users", "list_users", "List users.", nil, func(w http.ResponseWriter, r *http.Request) {
		s.tx(w, r, false, func(t *Tenant) (any, error) { return t.Users, nil })
	})
	s.api("POST", "/api/tenants/{tenant}/users", "create_user", "Create a user. Only userName is required; email defaults to userName, password to 'password'. groups is a list of group names or ids.",
		map[string]any{"userName": "jane@acme.example", "givenName": "Jane", "familyName": "Doe", "groups": []string{"Engineering"}}, s.createUser)
	s.api("PATCH", "/api/tenants/{tenant}/users/{user}", "update_user", "Change a user. {user} is an id, userName or email. Send only the fields to change. active:false deactivates (and deprovisions over SCIM when auto-push is on).",
		map[string]any{"active": false}, s.updateUser)
	s.api("DELETE", "/api/tenants/{tenant}/users/{user}", "delete_user", "Delete a user. {user} is an id, userName or email.", nil, s.deleteUser)
	s.api("POST", "/api/tenants/{tenant}/users/generate", "generate_users", "Add N realistic fake users, for load and paging tests.", map[string]any{"count": 50}, s.generateUsers)

	// groups
	s.api("POST", "/api/tenants/{tenant}/groups", "create_group", "Create a group. members are user ids, userNames or emails.", map[string]any{"name": "Support", "members": []string{"alice@acme.example"}}, s.createGroup)
	s.api("PATCH", "/api/tenants/{tenant}/groups/{group}", "update_group", "Rename a group or replace its members. {group} is an id or name.", map[string]any{"members": []string{"alice@acme.example", "bob@acme.example"}}, s.updateGroup)
	s.api("DELETE", "/api/tenants/{tenant}/groups/{group}", "delete_group", "Delete a group.", nil, s.deleteGroup)

	// apps
	s.api("POST", "/api/tenants/{tenant}/apps", "create_app", "Register an app. type is saml or oidc. SAML needs entityId and acsUrl; OIDC needs redirectUris. Anything left out takes the provider's default (client id format, NameID, attributes, signing).",
		map[string]any{"type": "oidc", "name": "My app", "redirectUris": []string{"http://localhost:3000/callback"}}, s.createApp)
	s.api("PATCH", "/api/tenants/{tenant}/apps/{app}", "update_app", "Change an app. Send only the fields to change.", map[string]any{"acsUrl": "http://localhost:3000/saml/acs"}, s.updateApp)
	s.api("DELETE", "/api/tenants/{tenant}/apps/{app}", "delete_app", "Delete an app.", nil, s.deleteApp)
	s.api("POST", "/api/tenants/{tenant}/apps/{app}/tokens", "mint_tokens", "Headless sign-in for an OIDC app: returns tokens for a user without a browser, with simulations applied. Good for API tests.",
		map[string]any{"user": "alice@acme.example", "scope": "openid profile email", "nonce": "n-123"}, s.mintTokensAPI)
	s.api("POST", "/api/tenants/{tenant}/apps/{app}/saml-response", "make_saml_response", "Headless sign-in for a SAML app: returns a signed SAMLResponse (XML and base64) for a user, with simulations applied. POST it to the ACS yourself.",
		map[string]any{"user": "alice@acme.example", "inResponseTo": "", "relayState": ""}, s.samlResponseAPI)

	// simulations
	s.api("GET", "/api/tenants/{tenant}/simulations", "get_simulations", "Current simulations of a tenant.", nil, func(w http.ResponseWriter, r *http.Request) {
		s.tx(w, r, false, func(t *Tenant) (any, error) { return t.Sims, nil })
	})
	s.api("PATCH", "/api/tenants/{tenant}/simulations", "set_simulations", "Turn simulations on or off. Send only the keys to change; get_info lists them all. once:true clears them after the next sign-in.",
		map[string]any{"samlExpired": true, "once": true}, func(w http.ResponseWriter, r *http.Request) {
			s.tx(w, r, true, func(t *Tenant) (any, error) {
				if err := readBody(r, &t.Sims); err != nil {
					return nil, err
				}
				return t.Sims, nil
			})
		})
	s.api("DELETE", "/api/tenants/{tenant}/simulations", "reset_simulations", "Turn every simulation off.", nil, func(w http.ResponseWriter, r *http.Request) {
		s.tx(w, r, true, func(t *Tenant) (any, error) { t.Sims = Simulations{}; return t.Sims, nil })
	})
	s.api("POST", "/api/tenants/{tenant}/simulations/presets/{preset}", "apply_preset", "Apply a named preset on top of the current simulations. get_info lists presets.", nil, func(w http.ResponseWriter, r *http.Request) {
		s.tx(w, r, true, func(t *Tenant) (any, error) {
			for _, p := range presets {
				if p.Key == r.PathValue("preset") {
					b, _ := json.Marshal(p.Set)
					json.Unmarshal(b, &t.Sims)
					return t.Sims, nil
				}
			}
			return nil, errf(404, "unknown preset %q", r.PathValue("preset"))
		})
	})

	// SCIM
	s.api("POST", "/api/tenants/{tenant}/scim-targets", "create_scim_target", "Point this IdP's SCIM client at your app's SCIM base URL. flavor imitates a provider's client (default: the tenant's provider). autoPush provisions on every user and group change.",
		map[string]any{"name": "My app", "baseUrl": "http://localhost:3000/scim/v2", "token": "secret", "autoPush": true}, s.createTarget)
	s.api("PATCH", "/api/tenants/{tenant}/scim-targets/{target}", "update_scim_target", "Change a SCIM target.", map[string]any{"autoPush": false}, s.updateTarget)
	s.api("DELETE", "/api/tenants/{tenant}/scim-targets/{target}", "delete_scim_target", "Delete a SCIM target.", nil, s.deleteTarget)
	s.api("POST", "/api/tenants/{tenant}/scim-targets/{target}/test", "test_scim_target", "The provider's 'Test connection' call.", nil, s.scimAction("test"))
	s.api("POST", "/api/tenants/{tenant}/scim-targets/{target}/sync", "sync_scim_target", "Push every user and group to the app, as a full provisioning cycle does.", nil, s.scimAction("sync"))
	s.api("POST", "/api/tenants/{tenant}/scim-targets/{target}/conformance", "scim_conformance", "Run the conformance suite against the app's SCIM server with a throwaway user and group. flavor picks whose client behaviour to test (okta, entra…). Each check links to a log entry.",
		map[string]any{"flavor": "entra"}, s.scimAction("conformance"))
	s.api("POST", "/api/tenants/{tenant}/scim-targets/{target}/push", "push_scim", "Push one user or group. kind is user or group, action is upsert, deactivate or delete.",
		map[string]any{"kind": "user", "id": "alice@acme.example", "action": "upsert"}, s.scimAction("push"))

	// logs and tools
	s.api("GET", "/api/logs", "list_logs", "Recent IdP traffic, newest last: every authorize, token, SAML, SCIM and test-app exchange with decoded messages and notes on what the IdP decided. Filter by tenant, kind prefix (oidc, saml, scim, sp, login), text q, or after an id.",
		nil, s.listLogs, "tenant", "kind", "q", "run", "after", "limit")
	s.api("GET", "/api/logs/{id}", "get_log", "One log entry in full: headers, bodies, decoded SAML/JWT, notes.", nil, func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if e := s.logs.get(id); e != nil {
			writeJSON(w, 200, e)
			return
		}
		writeErr(w, errf(404, "no log entry %s", r.PathValue("id")))
	})
	s.api("DELETE", "/api/logs", "clear_logs", "Clear the log.", nil, func(w http.ResponseWriter, r *http.Request) {
		s.logs.clear()
		s.logs.publish("change", map[string]string{})
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	s.mux.HandleFunc("GET /api/logs/stream", s.logStream)
	s.api("POST", "/api/decode", "decode", "Decode a JWT, a SAMLRequest/SAMLResponse (base64, deflated or not), raw XML, or a URL carrying any of those.",
		map[string]any{"input": "eyJhbGciOi..."}, func(w http.ResponseWriter, r *http.Request) {
			var in struct{ Input string }
			if err := readBody(r, &in); err != nil {
				writeErr(w, err)
				return
			}
			writeJSON(w, 200, decodeAny(in.Input))
		})
	s.api("POST", "/api/reset", "reset_all", "Delete every tenant and recreate the demo tenants. Logs are kept.", nil, func(w http.ResponseWriter, r *http.Request) {
		s.store.mu.Lock()
		s.store.Tenants = nil
		err := s.seed()
		s.store.mu.Unlock()
		if err != nil {
			writeErr(w, err)
			return
		}
		s.logs.publish("change", map[string]string{})
		s.listTenants(w, r)
	})
}

func (s *Server) apiInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"version": version, "baseUrl": s.base, "mcp": s.base + "/mcp",
		"providers": providerList, "simulations": simCatalog, "presets": presets,
		"attributeFields": []string{"id", "username", "email", "givenName", "familyName", "displayName", "title", "department", "phone", "employeeNumber", "manager", "groups", "groupIds", "tenantId", "attr.<name>", "const:<value>"},
		"nameIdFormats":   []string{nidEmail, nidUnspecified, nidPersistent, nidTransient},
	})
}

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	s.store.mu.Lock()
	out := []tenantSummary{}
	for _, t := range s.store.Tenants {
		out = append(out, tenantSummary{t.ID, t.Name, t.Provider, t.Domain, len(t.Users), len(t.Groups), len(t.Apps), len(t.ScimTargets), activeSims(t.Sims)})
	}
	s.store.mu.Unlock()
	writeJSON(w, 200, out)
}

func (s *Server) createTenant(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID, Name, Provider, Domain string
		Seed                       *bool
	}
	if err := readBody(r, &in); err != nil {
		writeErr(w, err)
		return
	}
	if in.Provider == "" {
		in.Provider = "generic"
	}
	if providers[in.Provider] == nil {
		writeErr(w, errf(400, "unknown provider %q", in.Provider))
		return
	}
	if in.Name == "" {
		in.Name = providers[in.Provider].Name + " tenant"
	}
	if in.ID == "" {
		in.ID = in.Name
	}
	s.store.mu.Lock()
	id := uniqueID(slug(in.ID), func(id string) bool { return s.store.tenant(id) != nil })
	t, err := s.newTenant(id, in.Name, in.Provider, in.Domain, in.Seed == nil || *in.Seed)
	if err == nil {
		s.store.Tenants = append(s.store.Tenants, t)
		s.store.save()
	}
	var v Tenant
	if t != nil {
		v = publicTenant(t)
	}
	s.store.mu.Unlock()
	if err != nil {
		writeErr(w, err)
		return
	}
	s.logs.publish("change", map[string]string{"tenant": id})
	writeJSON(w, 201, v)
}

func (s *Server) deleteTenant(w http.ResponseWriter, r *http.Request) {
	s.store.mu.Lock()
	n := len(s.store.Tenants)
	s.store.Tenants = slices.DeleteFunc(s.store.Tenants, func(t *Tenant) bool { return t.ID == r.PathValue("tenant") })
	gone := n != len(s.store.Tenants)
	s.store.save()
	s.store.mu.Unlock()
	if !gone {
		writeErr(w, errf(404, "unknown tenant %q", r.PathValue("tenant")))
		return
	}
	s.logs.publish("change", map[string]string{})
	writeJSON(w, 200, map[string]bool{"deleted": true})
}

func (s *Server) endpoints(t *Tenant) map[string]any {
	iss := s.issuer(t.ID)
	sha := sha256.Sum256(t.cert.Raw)
	sh1 := sha1.Sum(t.cert.Raw)
	apps := []map[string]any{}
	for _, a := range t.Apps {
		m := map[string]any{"id": a.ID, "name": a.Name, "type": a.Type}
		if a.Type == "saml" {
			base := s.base + "/t/" + t.ID + "/saml/" + a.ID
			m["metadataUrl"], m["ssoUrl"], m["sloUrl"], m["idpInitiatedUrl"] = base+"/metadata", base+"/sso", base+"/slo", base+"/init"
			m["idpEntityId"], m["spEntityId"], m["acsUrl"] = s.samlIssuer(t, a), a.EntityID, a.ACSURL
			if strings.HasPrefix(a.ACSURL, s.base+"/sp/") {
				m["testLogin"] = s.base + "/sp/saml/" + t.ID + "/" + a.ID + "/login"
			} else {
				m["testLogin"] = base + "/init"
			}
		} else {
			m["issuer"], m["discoveryUrl"], m["clientId"], m["clientSecret"], m["redirectUris"] = iss, iss+"/.well-known/openid-configuration", a.ClientID, a.ClientSecret, a.RedirectURIs
			cb := s.base + "/sp/oidc/" + t.ID + "/" + a.ID + "/callback"
			if slices.Contains(a.RedirectURIs, cb) {
				m["testLogin"] = s.base + "/sp/oidc/" + t.ID + "/" + a.ID + "/login"
			} else if len(a.RedirectURIs) > 0 {
				m["testLogin"] = iss + "/authorize?" + url.Values{"client_id": {a.ClientID}, "redirect_uri": {a.RedirectURIs[0]}, "response_type": {"code"},
					"scope": {"openid profile email"}, "state": {"test"}, "nonce": {"test"}}.Encode()
			}
		}
		apps = append(apps, m)
	}
	return map[string]any{
		"oidc": map[string]string{"issuer": iss, "discovery": iss + "/.well-known/openid-configuration", "authorize": iss + "/authorize",
			"token": iss + "/token", "userinfo": iss + "/userinfo", "jwks": iss + "/jwks", "logout": iss + "/logout"},
		"scim": map[string]string{
			"baseUrl":               iss + "/scim/v2",
			"serviceProviderConfig": iss + "/scim/v2/ServiceProviderConfig",
			"resourceTypes":         iss + "/scim/v2/ResourceTypes",
			"schemas":               iss + "/scim/v2/Schemas",
			"users":                 iss + "/scim/v2/Users",
			"groups":                iss + "/scim/v2/Groups",
		},
		"apps":              apps,
		"certificatePem":    t.CertPEM,
		"certificateUrl":    iss + "/cert.pem",
		"certificateSha256": strings.ToUpper(hex.EncodeToString(sha[:])),
		"certificateSha1":   strings.ToUpper(hex.EncodeToString(sh1[:])),
		"kid":               kid(&t.key.PublicKey),
	}
}

// ---- users ----

type userInput struct {
	User
	Active        *bool    `json:"active"`
	EmailVerified *bool    `json:"emailVerified"`
	Groups        []string `json:"groups"`
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var snap User
	s.tx(w, r, true, func(t *Tenant) (any, error) {
		var in userInput
		if err := readBody(r, &in); err != nil {
			return nil, err
		}
		u := in.User
		if u.UserName == "" {
			return nil, errf(400, "userName is required")
		}
		if t.user(u.UserName) != nil {
			return nil, errf(409, "a user %s already exists", u.UserName)
		}
		u.ID = newID(providers[t.Provider].IDStyle, "user")
		if u.Email == "" && strings.Contains(u.UserName, "@") {
			u.Email = u.UserName
		}
		if u.DisplayName == "" {
			u.DisplayName = strings.TrimSpace(u.GivenName + " " + u.FamilyName)
		}
		if u.Password == "" {
			u.Password = "password"
		}
		u.Active = in.Active == nil || *in.Active
		u.EmailVerified = in.EmailVerified == nil || *in.EmailVerified
		t.Users = append(t.Users, &u)
		for _, ref := range in.Groups {
			g := t.group(ref)
			if g == nil {
				return nil, errf(400, "unknown group %q", ref)
			}
			g.Members = append(g.Members, u.ID)
		}
		snap = u
		return u, nil
	})
	if snap.ID != "" {
		s.autoPush(r.PathValue("tenant"), []User{snap}, nil, "upsert")
	}
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	var snap User
	s.tx(w, r, true, func(t *Tenant) (any, error) {
		u := t.user(r.PathValue("user"))
		if u == nil {
			return nil, errf(404, "unknown user %q", r.PathValue("user"))
		}
		var in struct {
			Groups []string `json:"groups"`
		}
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if len(strings.TrimSpace(string(b))) == 0 {
			b = []byte("{}")
		}
		id := u.ID
		if err := json.Unmarshal(b, u); err != nil {
			return nil, errf(400, "bad JSON body: %v", err)
		}
		u.ID = id
		json.Unmarshal(b, &in)
		if in.Groups != nil {
			for _, g := range t.Groups {
				g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return m == id })
			}
			for _, ref := range in.Groups {
				if g := t.group(ref); g != nil {
					g.Members = append(g.Members, id)
				}
			}
		}
		snap = *u
		return u, nil
	})
	if snap.ID != "" {
		s.autoPush(r.PathValue("tenant"), []User{snap}, nil, "upsert")
	}
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	var snap User
	s.tx(w, r, true, func(t *Tenant) (any, error) {
		u := t.user(r.PathValue("user"))
		if u == nil {
			return nil, errf(404, "unknown user %q", r.PathValue("user"))
		}
		snap = *u
		t.Users = slices.DeleteFunc(t.Users, func(x *User) bool { return x == u })
		for _, g := range t.Groups {
			g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return m == u.ID })
		}
		return map[string]bool{"deleted": true}, nil
	})
	if snap.ID != "" {
		s.autoPush(r.PathValue("tenant"), []User{snap}, nil, "delete")
	}
}

var (
	firstNames = []string{"Ava", "Liam", "Mia", "Noah", "Aarav", "Sofia", "Mateo", "Yuki", "Chen", "Fatima", "Olu", "Ingrid", "Diego", "Priya", "Kwame", "Léa", "Søren", "Amara", "Hiro", "Zara"}
	lastNames  = []string{"Smith", "Garcia", "Kim", "Patel", "Nguyen", "Müller", "O'Connor", "Rossi", "Okafor", "Silva", "Kowalski", "Haddad", "Tanaka", "Johansson", "Dubois", "Novak", "Mensah", "Costa", "Ivanova", "Lee"}
	depts      = []string{"Engineering", "Sales", "Support", "Finance", "Marketing", "Legal", "Operations"}
)

func (s *Server) generateUsers(w http.ResponseWriter, r *http.Request) {
	var made []User
	s.tx(w, r, true, func(t *Tenant) (any, error) {
		var in struct{ Count int }
		if err := readBody(r, &in); err != nil {
			return nil, err
		}
		if in.Count <= 0 || in.Count > 5000 {
			return nil, errf(400, "count must be 1 to 5000")
		}
		p := providers[t.Provider]
		for i := 0; i < in.Count; i++ {
			gn, fn := firstNames[randInt(len(firstNames))], lastNames[randInt(len(lastNames))]
			login := uniqueID(slug(gn+"."+fn), func(id string) bool { return t.user(id+"@"+t.Domain) != nil })
			login = strings.ReplaceAll(login, "-", ".")
			u := &User{ID: newID(p.IDStyle, "user"), UserName: login + "@" + t.Domain, Email: login + "@" + t.Domain, EmailVerified: true,
				GivenName: gn, FamilyName: fn, DisplayName: gn + " " + fn, Password: "password", Active: true,
				Department: depts[randInt(len(depts))], EmployeeNumber: randFrom(digits, 5)}
			t.Users = append(t.Users, u)
			made = append(made, *u)
		}
		return map[string]int{"created": len(made), "total": len(t.Users)}, nil
	})
	if len(made) > 0 {
		s.autoPush(r.PathValue("tenant"), made, nil, "upsert")
	}
}

func randInt(n int) int {
	b := randFrom(digits, 6)
	v, _ := strconv.Atoi(b)
	return v % n
}

// ---- groups ----

func resolveMembers(t *Tenant, refs []string) ([]string, error) {
	out := []string{}
	for _, ref := range refs {
		u := t.user(ref)
		if u == nil {
			return nil, errf(400, "unknown user %q", ref)
		}
		if !slices.Contains(out, u.ID) {
			out = append(out, u.ID)
		}
	}
	return out, nil
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	var snap Group
	s.tx(w, r, true, func(t *Tenant) (any, error) {
		var in struct {
			Name    string
			Members []string
		}
		if err := readBody(r, &in); err != nil {
			return nil, err
		}
		if in.Name == "" {
			return nil, errf(400, "name is required")
		}
		if t.group(in.Name) != nil {
			return nil, errf(409, "group %q exists", in.Name)
		}
		m, err := resolveMembers(t, in.Members)
		if err != nil {
			return nil, err
		}
		g := &Group{ID: newID(providers[t.Provider].IDStyle, "group"), Name: in.Name, Members: m}
		t.Groups = append(t.Groups, g)
		snap = *g
		return g, nil
	})
	if snap.ID != "" {
		s.autoPush(r.PathValue("tenant"), nil, []Group{snap}, "upsert")
	}
}

func (s *Server) updateGroup(w http.ResponseWriter, r *http.Request) {
	var snap Group
	s.tx(w, r, true, func(t *Tenant) (any, error) {
		g := t.group(r.PathValue("group"))
		if g == nil {
			return nil, errf(404, "unknown group %q", r.PathValue("group"))
		}
		var in struct {
			Name    *string
			Members []string
		}
		if err := readBody(r, &in); err != nil {
			return nil, err
		}
		if in.Name != nil {
			g.Name = *in.Name
		}
		if in.Members != nil {
			m, err := resolveMembers(t, in.Members)
			if err != nil {
				return nil, err
			}
			g.Members = m
		}
		snap = Group{ID: g.ID, Name: g.Name, Members: slices.Clone(g.Members)}
		return g, nil
	})
	if snap.ID != "" {
		s.autoPush(r.PathValue("tenant"), nil, []Group{snap}, "upsert")
	}
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	var snap Group
	s.tx(w, r, true, func(t *Tenant) (any, error) {
		g := t.group(r.PathValue("group"))
		if g == nil {
			return nil, errf(404, "unknown group %q", r.PathValue("group"))
		}
		snap = *g
		t.Groups = slices.DeleteFunc(t.Groups, func(x *Group) bool { return x == g })
		return map[string]bool{"deleted": true}, nil
	})
	if snap.ID != "" {
		s.autoPush(r.PathValue("tenant"), nil, []Group{snap}, "delete")
	}
}

// ---- apps ----

func validateApp(a *App) error {
	switch a.Type {
	case "saml":
		if a.EntityID == "" || a.ACSURL == "" {
			return errf(400, "a SAML app needs entityId and acsUrl")
		}
		if a.EncryptAssertion {
			if _, err := parseSPCert(a.SPEncryptionCert, "encryption"); err != nil {
				return errf(400, "encryptAssertion needs spEncryptionCert (PEM, base64 or SP metadata): %v", err)
			}
		}
		if a.EncryptionAlg != "" && blockAlgs[a.EncryptionAlg] == "" {
			return errf(400, "encryptionAlg must be aes128-cbc, aes256-cbc, aes128-gcm or aes256-gcm")
		}
		if a.KeyTransportAlg != "" && keyTransportAlgs[a.KeyTransportAlg] == "" {
			return errf(400, "keyTransportAlg must be rsa-oaep or rsa-1_5")
		}
		if a.SPSigningCert != "" {
			if _, err := parseSPCert(a.SPSigningCert, "signing"); err != nil {
				return errf(400, "spSigningCert: %v", err)
			}
		} else if a.RequireSignedRequests {
			return errf(400, "requireSignedRequests needs spSigningCert, to verify the signatures with")
		}
	case "oidc":
		if len(a.RedirectURIs) == 0 {
			return errf(400, "an OIDC app needs at least one redirectUris entry")
		}
	default:
		return errf(400, "type must be saml or oidc")
	}
	return nil
}

func (s *Server) createApp(w http.ResponseWriter, r *http.Request) {
	s.tx(w, r, true, func(t *Tenant) (any, error) {
		var a App
		if err := readBody(r, &a); err != nil {
			return nil, err
		}
		if err := validateApp(&a); err != nil {
			return nil, err
		}
		if a.Name == "" {
			a.Name = strings.ToUpper(a.Type) + " app"
		}
		if a.ClientID != "" && t.appByClientID(a.ClientID) != nil {
			return nil, errf(409, "client_id %s is taken", a.ClientID)
		}
		a.ID = uniqueID(slug(a.ID+" "+a.Name), func(id string) bool { return t.app(id) != nil })
		applyAppDefaults(t, &a)
		t.Apps = append(t.Apps, &a)
		return a, nil
	})
}

func (s *Server) updateApp(w http.ResponseWriter, r *http.Request) {
	s.tx(w, r, true, func(t *Tenant) (any, error) {
		a := t.app(r.PathValue("app"))
		if a == nil {
			return nil, errf(404, "unknown app %q", r.PathValue("app"))
		}
		next := *a
		if err := readBody(r, &next); err != nil {
			return nil, err
		}
		next.ID = a.ID
		if err := validateApp(&next); err != nil {
			return nil, err
		}
		applyAppDefaults(t, &next)
		*a = next
		return a, nil
	})
}

func (s *Server) deleteApp(w http.ResponseWriter, r *http.Request) {
	s.tx(w, r, true, func(t *Tenant) (any, error) {
		n := len(t.Apps)
		t.Apps = slices.DeleteFunc(t.Apps, func(a *App) bool { return a.ID == r.PathValue("app") })
		if n == len(t.Apps) {
			return nil, errf(404, "unknown app %q", r.PathValue("app"))
		}
		return map[string]bool{"deleted": true}, nil
	})
}

func (s *Server) mintTokensAPI(w http.ResponseWriter, r *http.Request) {
	e := &LogEntry{Kind: "api.tokens", Level: "info", Tenant: r.PathValue("tenant"), App: r.PathValue("app"), Method: r.Method, URL: s.base + r.URL.Path}
	s.tx(w, r, false, func(t *Tenant) (any, error) {
		var in struct{ User, Scope, Nonce string }
		if err := readBody(r, &in); err != nil {
			return nil, err
		}
		a := t.app(r.PathValue("app"))
		if a == nil || a.Type != "oidc" {
			return nil, errf(404, "no OIDC app %q", r.PathValue("app"))
		}
		var u *User
		if in.User != "" {
			if u = t.user(in.User); u == nil {
				return nil, errf(404, "unknown user %q", in.User)
			}
		}
		if in.Scope == "" {
			in.Scope = "openid profile email"
		}
		e.Sims = activeSims(t.Sims)
		e.Summary = "headless tokens for " + map[bool]string{true: in.User, false: "the client"}[u != nil]
		out := s.mintTokens(t, t.Sims, a, u, in.Scope, in.Nonce, time.Now(), []string{"pwd"}, e)
		s.consumeOnce(t)
		return out, nil
	})
	e.Status = 200
	s.logs.add(e)
}

func (s *Server) samlResponseAPI(w http.ResponseWriter, r *http.Request) {
	e := &LogEntry{Kind: "api.saml", Level: "info", Tenant: r.PathValue("tenant"), App: r.PathValue("app"), Method: r.Method, URL: s.base + r.URL.Path}
	s.tx(w, r, false, func(t *Tenant) (any, error) {
		var in struct{ User, InResponseTo, RelayState string }
		if err := readBody(r, &in); err != nil {
			return nil, err
		}
		a := t.app(r.PathValue("app"))
		if a == nil || a.Type != "saml" {
			return nil, errf(404, "no SAML app %q", r.PathValue("app"))
		}
		u := t.user(in.User)
		if u == nil {
			return nil, errf(404, "unknown user %q", in.User)
		}
		e.Sims = activeSims(t.Sims)
		e.Summary = "headless SAMLResponse for " + u.UserName
		x, err := s.samlResponse(t, a, u, in.InResponseTo, "", e)
		if err != nil {
			return nil, err
		}
		e.decode("SAMLResponse", "xml", prettyXML(x))
		s.consumeOnce(t)
		return map[string]string{"acsUrl": a.ACSURL, "relayState": in.RelayState, "xml": x,
			"samlResponse": encodeB64Std(x)}, nil
	})
	e.Status = 200
	s.logs.add(e)
}

// ---- SCIM targets ----

func (s *Server) createTarget(w http.ResponseWriter, r *http.Request) {
	s.tx(w, r, true, func(t *Tenant) (any, error) {
		var g ScimTarget
		if err := readBody(r, &g); err != nil {
			return nil, err
		}
		if _, err := url.ParseRequestURI(g.BaseURL); err != nil || !strings.HasPrefix(g.BaseURL, "http") {
			return nil, errf(400, "baseUrl must be an http(s) URL, e.g. http://localhost:3000/scim/v2")
		}
		if g.Flavor != "" && providers[g.Flavor] == nil {
			return nil, errf(400, "unknown flavor %q", g.Flavor)
		}
		if g.Name == "" {
			g.Name = g.BaseURL
		}
		g.ID = uniqueID(slug(g.Name), func(id string) bool { return t.target(id) != nil })
		g.UserMap, g.GroupMap = map[string]string{}, map[string]string{}
		t.ScimTargets = append(t.ScimTargets, &g)
		return g, nil
	})
}

func (s *Server) updateTarget(w http.ResponseWriter, r *http.Request) {
	s.tx(w, r, true, func(t *Tenant) (any, error) {
		g := t.target(r.PathValue("target"))
		if g == nil {
			return nil, errf(404, "unknown SCIM target %q", r.PathValue("target"))
		}
		next := *g
		if err := readBody(r, &next); err != nil {
			return nil, err
		}
		if next.Flavor != "" && providers[next.Flavor] == nil {
			return nil, errf(400, "unknown flavor %q", next.Flavor)
		}
		next.ID = g.ID
		if next.BaseURL != g.BaseURL { // a new app knows none of our ids
			next.UserMap, next.GroupMap = map[string]string{}, map[string]string{}
		}
		*g = next
		return g, nil
	})
}

func (s *Server) deleteTarget(w http.ResponseWriter, r *http.Request) {
	s.tx(w, r, true, func(t *Tenant) (any, error) {
		n := len(t.ScimTargets)
		t.ScimTargets = slices.DeleteFunc(t.ScimTargets, func(g *ScimTarget) bool { return g.ID == r.PathValue("target") })
		if n == len(t.ScimTargets) {
			return nil, errf(404, "unknown SCIM target %q", r.PathValue("target"))
		}
		return map[string]bool{"deleted": true}, nil
	})
}

func (s *Server) scimAction(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Flavor, Kind, ID, Action string }
		if err := readBody(r, &in); err != nil {
			writeErr(w, err)
			return
		}
		c, err := s.newScimClient(r.PathValue("tenant"), r.PathValue("target"), in.Flavor)
		if err != nil {
			writeErr(w, err)
			return
		}
		var cs []check
		switch kind {
		case "test":
			cs = c.test()
		case "sync":
			cs = c.sync()
		case "conformance":
			cs = c.conformance()
		case "push":
			if in.Action == "" {
				in.Action = "upsert"
			}
			if !slices.Contains([]string{"upsert", "deactivate", "delete"}, in.Action) {
				writeErr(w, errf(400, "action must be upsert, deactivate or delete"))
				return
			}
			switch in.Kind {
			case "user", "":
				u, ok := c.findLocalUser(in.ID)
				if !ok {
					writeErr(w, errf(404, "unknown user %q", in.ID))
					return
				}
				cs = []check{c.pushUser(u, in.Action)}
			case "group":
				g, ok := c.findLocalGroup(in.ID)
				if !ok {
					writeErr(w, errf(404, "unknown group %q", in.ID))
					return
				}
				act := in.Action
				if act == "deactivate" {
					act = "delete"
				}
				cs = []check{c.pushGroup(g, act)}
			default:
				writeErr(w, errf(400, "kind must be user or group"))
				return
			}
		}
		writeJSON(w, 200, c.finish(kind, cs))
	}
}

func (c *scimClient) findLocalUser(ref string) (User, bool) {
	for _, u := range c.users {
		if u.ID == ref || strings.EqualFold(u.UserName, ref) || (u.Email != "" && strings.EqualFold(u.Email, ref)) {
			return u, true
		}
	}
	return User{}, false
}

func (c *scimClient) findLocalGroup(ref string) (Group, bool) {
	for _, g := range c.groups {
		if g.ID == ref || strings.EqualFold(g.Name, ref) {
			return g, true
		}
	}
	return Group{}, false
}

// ---- logs ----

func (s *Server) listLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	after, _ := strconv.ParseInt(q.Get("after"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 2000 {
		limit = 100
	}
	writeJSON(w, 200, s.logs.list(q.Get("tenant"), q.Get("kind"), q.Get("q"), q.Get("run"), after, limit))
}

func (s *Server) logStream(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) && r.URL.Query().Get("token") != s.apiToken {
		http.Error(w, "unauthorized", 401)
		return
	}
	if err := s.localOnly(r); err != nil {
		http.Error(w, err.Error(), 403)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ch := s.logs.subscribe()
	defer s.logs.unsubscribe(ch)
	fmt.Fprint(w, ": connected\n\n")
	fl.Flush()
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			b, _ := json.Marshal(ev.data)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.name, b)
			fl.Flush()
		case <-tick.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}
