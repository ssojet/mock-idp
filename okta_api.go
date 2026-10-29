package main

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

var oktaAPIRegistered sync.Map

func (s *Server) registerOktaAPI() {
	if _, loaded := oktaAPIRegistered.LoadOrStore(s.mux, true); loaded {
		return
	}
	h := func(pattern string, fn http.HandlerFunc) { s.mux.Handle(pattern, s.traced(fn)) }

	// Users
	h("GET /t/{tenant}/api/v1/users", s.oktaListUsers)
	h("POST /t/{tenant}/api/v1/users", s.oktaCreateUser)
	h("GET /t/{tenant}/api/v1/users/{id}", s.oktaGetUser)
	h("PUT /t/{tenant}/api/v1/users/{id}", s.oktaUpdateUser)
	h("POST /t/{tenant}/api/v1/users/{id}", s.oktaUpdateUser)
	h("DELETE /t/{tenant}/api/v1/users/{id}", s.oktaDeleteUser)
	h("POST /t/{tenant}/api/v1/users/{id}/lifecycle/activate", s.oktaLifecycleUser("ACTIVE", true))
	h("POST /t/{tenant}/api/v1/users/{id}/lifecycle/deactivate", s.oktaLifecycleUser("DEPROVISIONED", false))
	h("POST /t/{tenant}/api/v1/users/{id}/lifecycle/suspend", s.oktaLifecycleUser("SUSPENDED", false))
	h("GET /t/{tenant}/api/v1/users/{id}/groups", s.oktaListUserGroups)

	// Groups
	h("GET /t/{tenant}/api/v1/groups", s.oktaListGroups)
	h("POST /t/{tenant}/api/v1/groups", s.oktaCreateGroup)
	h("GET /t/{tenant}/api/v1/groups/{id}", s.oktaGetGroup)
	h("PUT /t/{tenant}/api/v1/groups/{id}", s.oktaUpdateGroup)
	h("DELETE /t/{tenant}/api/v1/groups/{id}", s.oktaDeleteGroup)
	h("GET /t/{tenant}/api/v1/groups/{id}/users", s.oktaListGroupUsers)
	h("PUT /t/{tenant}/api/v1/groups/{id}/users/{uid}", s.oktaAddGroupUser)
	h("DELETE /t/{tenant}/api/v1/groups/{id}/users/{uid}", s.oktaRemoveGroupUser)

	// Apps & System Log
	h("GET /t/{tenant}/api/v1/apps", s.oktaListApps)
	h("GET /t/{tenant}/api/v1/logs", s.oktaListLogs)
}

func oktaAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		oktaErr(w, r, http.StatusUnauthorized, "E0000011", "Invalid token provided")
		return false
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 {
		oktaErr(w, r, http.StatusUnauthorized, "E0000011", "Invalid token provided")
		return false
	}
	scheme := strings.ToUpper(strings.TrimSpace(parts[0]))
	tok := strings.TrimSpace(parts[1])
	if (scheme != "SSWS" && scheme != "BEARER") || tok == "" {
		oktaErr(w, r, http.StatusUnauthorized, "E0000011", "Invalid token provided")
		return false
	}
	return true
}

func oktaErr(w http.ResponseWriter, r *http.Request, status int, code, summary string, causes ...string) {
	entry(r).warn("okta error %s (%d): %s", code, status, summary)
	cs := make([]map[string]string, 0, len(causes))
	for _, c := range causes {
		cs = append(cs, map[string]string{"errorSummary": c})
	}
	writeJSON(w, status, map[string]any{
		"errorCode":    code,
		"errorSummary": summary,
		"errorLink":    code,
		"errorId":      "oae" + randFrom(alnum, 16),
		"errorCauses":  cs,
	})
}

func (s *Server) oktaTenant(w http.ResponseWriter, r *http.Request) *Tenant {
	id := r.PathValue("tenant")
	t := s.store.tenant(id)
	if t == nil {
		oktaErr(w, r, http.StatusNotFound, "E0000007", fmt.Sprintf("Not found: Resource not found: %s (Tenant)", id))
		return nil
	}
	entry(r).Sims = activeSims(t.Sims)
	return t
}

func oktaTime(t time.Time) string {
	if t.IsZero() {
		return "2025-01-01T00:00:00.000Z"
	}
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func oktaUserStatus(u *User) string {
	if u.Active {
		return "ACTIVE"
	}
	if u.Attributes != nil {
		if st := u.Attributes["oktaStatus"]; st != "" && st != "ACTIVE" {
			return st
		}
	}
	return "DEPROVISIONED"
}

func (s *Server) oktaUserJSON(t *Tenant, u *User) map[string]any {
	ts := oktaTime(t.Created)
	base := s.base + "/t/" + t.ID + "/api/v1"
	status := oktaUserStatus(u)
	var mobile any
	if u.Phone != "" {
		mobile = u.Phone
	}
	profile := map[string]any{
		"firstName":      u.GivenName,
		"lastName":       u.FamilyName,
		"mobilePhone":    mobile,
		"secondEmail":    nil,
		"login":          u.UserName,
		"email":          u.Email,
		"displayName":    u.DisplayName,
		"title":          u.Title,
		"department":     u.Department,
		"employeeNumber": u.EmployeeNumber,
	}
	return map[string]any{
		"id":            u.ID,
		"status":        status,
		"created":       ts,
		"activated":     ts,
		"statusChanged": ts,
		"lastLogin":     ts,
		"lastUpdated":   ts,
		"profile":       profile,
		"credentials": map[string]any{
			"provider": map[string]string{
				"type": "OKTA",
				"name": "OKTA",
			},
		},
		"_links": map[string]any{
			"self":       map[string]string{"href": base + "/users/" + u.ID},
			"activate":   map[string]string{"href": base + "/users/" + u.ID + "/lifecycle/activate", "method": "POST"},
			"deactivate": map[string]string{"href": base + "/users/" + u.ID + "/lifecycle/deactivate", "method": "POST"},
			"suspend":    map[string]string{"href": base + "/users/" + u.ID + "/lifecycle/suspend", "method": "POST"},
		},
	}
}

func (s *Server) oktaGroupJSON(t *Tenant, g *Group) map[string]any {
	ts := oktaTime(t.Created)
	base := s.base + "/t/" + t.ID + "/api/v1"
	return map[string]any{
		"id":                    g.ID,
		"created":               ts,
		"lastUpdated":           ts,
		"lastMembershipUpdated": ts,
		"objectClass":           []string{"okta:user_group"},
		"type":                  "OKTA_GROUP",
		"profile": map[string]any{
			"name":        g.Name,
			"description": g.Name + " group",
		},
		"_links": map[string]any{
			"users": map[string]string{"href": base + "/groups/" + g.ID + "/users"},
			"self":  map[string]string{"href": base + "/groups/" + g.ID},
		},
	}
}

func (s *Server) oktaAppJSON(t *Tenant, a *App) map[string]any {
	ts := oktaTime(t.Created)
	base := s.base + "/t/" + t.ID + "/api/v1"
	mode := "OPENID_CONNECT"
	if a.Type == "saml" {
		mode = "SAML_2_0"
	}
	out := map[string]any{
		"id":          a.ID,
		"name":        a.ID,
		"label":       a.Name,
		"status":      "ACTIVE",
		"created":     ts,
		"lastUpdated": ts,
		"signOnMode":  mode,
		"_links": map[string]any{
			"self":  map[string]string{"href": base + "/apps/" + a.ID},
			"users": map[string]string{"href": base + "/apps/" + a.ID + "/users"},
		},
	}
	if a.ClientID != "" {
		out["credentials"] = map[string]any{
			"oauthClient": map[string]any{
				"client_id": a.ClientID,
			},
		}
	}
	return out
}

// oktaPaginate slices items by after cursor and limit, setting RFC 5988 Link headers.
func (s *Server) oktaPaginate(w http.ResponseWriter, r *http.Request, items []map[string]any, idField string, defaultLimit int) []map[string]any {
	q := r.URL.Query()
	limit, err := strconv.Atoi(q.Get("limit"))
	if err != nil || limit <= 0 {
		limit = defaultLimit
	}
	after := q.Get("after")
	if after != "" {
		idx := -1
		for i, item := range items {
			if str(item[idField]) == after {
				idx = i
				break
			}
		}
		if idx >= 0 {
			items = items[idx+1:]
		} else {
			items = []map[string]any{}
		}
	}
	hasMore := false
	nextCursor := ""
	if len(items) > limit {
		hasMore = true
		items = items[:limit]
		nextCursor = str(items[len(items)-1][idField])
	}
	selfURL := s.base + r.URL.RequestURI()
	w.Header().Add("Link", fmt.Sprintf("<%s>; rel=\"self\"", selfURL))
	if hasMore && nextCursor != "" {
		nextVals := url.Values{}
		for k, v := range q {
			nextVals[k] = slices.Clone(v)
		}
		nextVals.Set("after", nextCursor)
		nextVals.Set("limit", strconv.Itoa(limit))
		nextURL := s.base + r.URL.Path + "?" + nextVals.Encode()
		w.Header().Add("Link", fmt.Sprintf("<%s>; rel=\"next\"", nextURL))
	}
	if items == nil {
		return []map[string]any{}
	}
	return items
}

// ---- Filtering ----

func oktaUserField(u *User, field string) string {
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "id":
		return u.ID
	case "status":
		return oktaUserStatus(u)
	case "profile.login", "login", "username":
		return u.UserName
	case "profile.email", "email":
		return u.Email
	case "profile.firstname", "firstname":
		return u.GivenName
	case "profile.lastname", "lastname":
		return u.FamilyName
	case "profile.displayname", "displayname":
		return u.DisplayName
	case "profile.department", "department":
		return u.Department
	case "profile.title", "title":
		return u.Title
	case "profile.mobilephone", "mobilephone":
		return u.Phone
	case "profile.employeenumber", "employeenumber":
		return u.EmployeeNumber
	}
	if u.Attributes != nil {
		if v, ok := u.Attributes[strings.TrimPrefix(field, "profile.")]; ok {
			return v
		}
	}
	return ""
}

func oktaGroupField(g *Group, field string) string {
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "id":
		return g.ID
	case "type":
		return "OKTA_GROUP"
	case "profile.name", "name":
		return g.Name
	case "profile.description", "description":
		return g.Name + " group"
	}
	return ""
}

func evalOktaExpr(expr string, getField func(string) string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return true
	}
	// Strip outer parens if balanced
	for strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") && oktaParensBalanced(expr[1:len(expr)-1]) {
		expr = strings.TrimSpace(expr[1 : len(expr)-1])
	}
	if parts := splitOktaLogical(expr, "or"); len(parts) > 1 {
		for _, p := range parts {
			if evalOktaExpr(p, getField) {
				return true
			}
		}
		return false
	}
	if parts := splitOktaLogical(expr, "and"); len(parts) > 1 {
		for _, p := range parts {
			if !evalOktaExpr(p, getField) {
				return false
			}
		}
		return true
	}
	// Check unary "pr" (present)
	lower := strings.ToLower(expr)
	if strings.HasSuffix(lower, " pr") {
		field := strings.TrimSpace(expr[:len(expr)-3])
		return getField(field) != ""
	}
	for _, op := range []string{" eq ", " ne ", " sw ", " co ", " gt ", " ge ", " lt ", " le "} {
		idx := indexOktaOp(expr, op)
		if idx < 0 {
			continue
		}
		field := strings.TrimSpace(expr[:idx])
		rhs := strings.TrimSpace(expr[idx+len(op):])
		rhs = strings.Trim(rhs, `"'`)
		got := getField(field)
		switch strings.TrimSpace(op) {
		case "eq":
			return strings.EqualFold(got, rhs)
		case "ne":
			return !strings.EqualFold(got, rhs)
		case "sw":
			return strings.HasPrefix(strings.ToLower(got), strings.ToLower(rhs))
		case "co":
			return strings.Contains(strings.ToLower(got), strings.ToLower(rhs))
		case "gt", "ge", "lt", "le":
			return true
		}
	}
	return true
}

func oktaParensBalanced(s string) bool {
	depth := 0
	inQuote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inQuote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0 && inQuote == 0
}

func splitOktaLogical(expr, kw string) []string {
	var parts []string
	depth := 0
	inQuote := byte(0)
	target := " " + kw + " "
	last := 0
	lower := strings.ToLower(expr)
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inQuote = c
		case '(':
			depth++
		case ')':
			depth--
		default:
			if depth == 0 && i+len(target) <= len(expr) && lower[i:i+len(target)] == target {
				parts = append(parts, expr[last:i])
				last = i + len(target)
				i += len(target) - 1
			}
		}
	}
	if len(parts) > 0 {
		parts = append(parts, expr[last:])
	}
	return parts
}

func indexOktaOp(expr, op string) int {
	depth := 0
	inQuote := byte(0)
	lower := strings.ToLower(expr)
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inQuote = c
		case '(':
			depth++
		case ')':
			depth--
		default:
			if depth == 0 && i+len(op) <= len(expr) && lower[i:i+len(op)] == op {
				return i
			}
		}
	}
	return -1
}

// ---- Users Handlers ----

func (s *Server) oktaListUsers(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "okta.api"
	e.Summary = "okta: list users"
	if s.network(w, r) {
		return
	}
	if !oktaAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.oktaTenant(w, r)
	if t == nil {
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	filter := strings.TrimSpace(r.URL.Query().Get("filter"))
	search := strings.TrimSpace(r.URL.Query().Get("search"))

	var matched []map[string]any
	for _, u := range t.Users {
		if q != "" {
			hay := strings.ToLower(u.GivenName + " " + u.FamilyName + " " + u.DisplayName + " " + u.Email + " " + u.UserName)
			if !strings.Contains(hay, q) {
				continue
			}
		}
		if filter != "" && !evalOktaExpr(filter, func(f string) string { return oktaUserField(u, f) }) {
			continue
		}
		if search != "" && !evalOktaExpr(search, func(f string) string { return oktaUserField(u, f) }) {
			continue
		}
		matched = append(matched, s.oktaUserJSON(t, u))
	}
	page := s.oktaPaginate(w, r, matched, "id", 200)
	writeJSON(w, http.StatusOK, page)
}

type oktaUserPayload struct {
	Profile struct {
		FirstName      *string `json:"firstName"`
		LastName       *string `json:"lastName"`
		Email          *string `json:"email"`
		Login          *string `json:"login"`
		DisplayName    *string `json:"displayName"`
		Title          *string `json:"title"`
		Department     *string `json:"department"`
		MobilePhone    *string `json:"mobilePhone"`
		EmployeeNumber *string `json:"employeeNumber"`
	} `json:"profile"`
	Credentials struct {
		Password struct {
			Value string `json:"value"`
		} `json:"password"`
	} `json:"credentials"`
	GroupIDs []string `json:"groupIds"`
}

func (s *Server) oktaCreateUser(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "okta.api"
	if s.network(w, r) {
		return
	}
	if !oktaAuth(w, r) {
		return
	}
	var in oktaUserPayload
	if err := readBody(r, &in); err != nil {
		oktaErr(w, r, http.StatusBadRequest, "E0000001", "Api validation failed: "+err.Error())
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.oktaTenant(w, r)
	if t == nil {
		return
	}
	login := ""
	if in.Profile.Login != nil {
		login = strings.TrimSpace(*in.Profile.Login)
	}
	email := ""
	if in.Profile.Email != nil {
		email = strings.TrimSpace(*in.Profile.Email)
	}
	if login == "" {
		login = email
	}
	if email == "" {
		email = login
	}
	if login == "" {
		oktaErr(w, r, http.StatusBadRequest, "E0000001", "Api validation failed: login", "login: The field cannot be left blank")
		return
	}
	if t.user(login) != nil {
		oktaErr(w, r, http.StatusBadRequest, "E0000001", "Api validation failed: login", "login: An object with this field already exists in the current organization")
		return
	}
	activate := true
	if strings.EqualFold(r.URL.Query().Get("activate"), "false") {
		activate = false
	}
	p := providers[t.Provider]
	style := "okta"
	if p != nil {
		style = p.IDStyle
	}
	u := &User{
		ID:            newID(style, "user"),
		UserName:      login,
		Email:         email,
		EmailVerified: true,
		Password:      "password",
		Active:        activate,
		Attributes:    map[string]string{},
	}
	if !activate {
		u.Attributes["oktaStatus"] = "STAGED"
	} else {
		u.Attributes["oktaStatus"] = "ACTIVE"
	}
	applyOktaProfile(u, &in)
	if u.DisplayName == "" {
		u.DisplayName = strings.TrimSpace(u.GivenName + " " + u.FamilyName)
	}
	t.Users = append(t.Users, u)
	for _, gid := range in.GroupIDs {
		if g := t.group(gid); g != nil && !slices.Contains(g.Members, u.ID) {
			g.Members = append(g.Members, u.ID)
		}
	}
	s.store.save()
	e.Summary = "okta: created user " + u.UserName
	writeJSON(w, http.StatusOK, s.oktaUserJSON(t, u))
}

func applyOktaProfile(u *User, in *oktaUserPayload) {
	if in.Profile.FirstName != nil {
		u.GivenName = *in.Profile.FirstName
	}
	if in.Profile.LastName != nil {
		u.FamilyName = *in.Profile.LastName
	}
	if in.Profile.Email != nil {
		u.Email = *in.Profile.Email
	}
	if in.Profile.Login != nil && *in.Profile.Login != "" {
		u.UserName = *in.Profile.Login
	}
	if in.Profile.DisplayName != nil {
		u.DisplayName = *in.Profile.DisplayName
	}
	if in.Profile.Title != nil {
		u.Title = *in.Profile.Title
	}
	if in.Profile.Department != nil {
		u.Department = *in.Profile.Department
	}
	if in.Profile.MobilePhone != nil {
		u.Phone = *in.Profile.MobilePhone
	}
	if in.Profile.EmployeeNumber != nil {
		u.EmployeeNumber = *in.Profile.EmployeeNumber
	}
	if in.Credentials.Password.Value != "" {
		u.Password = in.Credentials.Password.Value
	}
}

func (s *Server) oktaGetUser(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "okta.api"
	if s.network(w, r) {
		return
	}
	if !oktaAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.oktaTenant(w, r)
	if t == nil {
		return
	}
	ref, _ := url.PathUnescape(r.PathValue("id"))
	u := t.user(ref)
	if u == nil {
		oktaErr(w, r, http.StatusNotFound, "E0000007", fmt.Sprintf("Not found: Resource not found: %s (User)", ref))
		return
	}
	e.Summary = "okta: get user " + u.UserName
	writeJSON(w, http.StatusOK, s.oktaUserJSON(t, u))
}

func (s *Server) oktaUpdateUser(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "okta.api"
	if s.network(w, r) {
		return
	}
	if !oktaAuth(w, r) {
		return
	}
	var in oktaUserPayload
	if err := readBody(r, &in); err != nil {
		oktaErr(w, r, http.StatusBadRequest, "E0000001", "Api validation failed: "+err.Error())
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.oktaTenant(w, r)
	if t == nil {
		return
	}
	ref, _ := url.PathUnescape(r.PathValue("id"))
	u := t.user(ref)
	if u == nil {
		oktaErr(w, r, http.StatusNotFound, "E0000007", fmt.Sprintf("Not found: Resource not found: %s (User)", ref))
		return
	}
	applyOktaProfile(u, &in)
	if in.Profile.DisplayName == nil && (in.Profile.FirstName != nil || in.Profile.LastName != nil) {
		u.DisplayName = strings.TrimSpace(u.GivenName + " " + u.FamilyName)
	}
	s.store.save()
	e.Summary = "okta: update user " + u.UserName
	writeJSON(w, http.StatusOK, s.oktaUserJSON(t, u))
}

func (s *Server) oktaDeleteUser(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "okta.api"
	if s.network(w, r) {
		return
	}
	if !oktaAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.oktaTenant(w, r)
	if t == nil {
		return
	}
	ref, _ := url.PathUnescape(r.PathValue("id"))
	u := t.user(ref)
	if u == nil {
		oktaErr(w, r, http.StatusNotFound, "E0000007", fmt.Sprintf("Not found: Resource not found: %s (User)", ref))
		return
	}
	t.Users = slices.DeleteFunc(t.Users, func(x *User) bool { return x.ID == u.ID })
	for _, g := range t.Groups {
		g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return m == u.ID })
	}
	s.store.save()
	e.Summary = "okta: delete user " + u.UserName
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) oktaLifecycleUser(status string, active bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		e := entry(r)
		e.Kind = "okta.api"
		if s.network(w, r) {
			return
		}
		if !oktaAuth(w, r) {
			return
		}
		s.store.mu.Lock()
		defer s.store.mu.Unlock()
		t := s.oktaTenant(w, r)
		if t == nil {
			return
		}
		ref, _ := url.PathUnescape(r.PathValue("id"))
		u := t.user(ref)
		if u == nil {
			oktaErr(w, r, http.StatusNotFound, "E0000007", fmt.Sprintf("Not found: Resource not found: %s (User)", ref))
			return
		}
		u.Active = active
		if u.Attributes == nil {
			u.Attributes = map[string]string{}
		}
		u.Attributes["oktaStatus"] = status
		s.store.save()
		e.Summary = fmt.Sprintf("okta: lifecycle %s user %s", strings.ToLower(status), u.UserName)
		writeJSON(w, http.StatusOK, map[string]any{})
	}
}

func (s *Server) oktaListUserGroups(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "okta.api"
	if s.network(w, r) {
		return
	}
	if !oktaAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.oktaTenant(w, r)
	if t == nil {
		return
	}
	ref, _ := url.PathUnescape(r.PathValue("id"))
	u := t.user(ref)
	if u == nil {
		oktaErr(w, r, http.StatusNotFound, "E0000007", fmt.Sprintf("Not found: Resource not found: %s (User)", ref))
		return
	}
	groups := t.groupsOf(u.ID)
	out := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		out = append(out, s.oktaGroupJSON(t, g))
	}
	e.Summary = "okta: list groups for user " + u.UserName
	page := s.oktaPaginate(w, r, out, "id", 200)
	writeJSON(w, http.StatusOK, page)
}

// ---- Groups Handlers ----

func (s *Server) oktaListGroups(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "okta.api"
	e.Summary = "okta: list groups"
	if s.network(w, r) {
		return
	}
	if !oktaAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.oktaTenant(w, r)
	if t == nil {
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	filter := strings.TrimSpace(r.URL.Query().Get("filter"))
	search := strings.TrimSpace(r.URL.Query().Get("search"))

	var matched []map[string]any
	for _, g := range t.Groups {
		if q != "" && !strings.Contains(strings.ToLower(g.Name), q) {
			continue
		}
		if filter != "" && !evalOktaExpr(filter, func(f string) string { return oktaGroupField(g, f) }) {
			continue
		}
		if search != "" && !evalOktaExpr(search, func(f string) string { return oktaGroupField(g, f) }) {
			continue
		}
		matched = append(matched, s.oktaGroupJSON(t, g))
	}
	page := s.oktaPaginate(w, r, matched, "id", 200)
	writeJSON(w, http.StatusOK, page)
}

type oktaGroupPayload struct {
	Profile struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"profile"`
}

func (s *Server) oktaCreateGroup(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "okta.api"
	if s.network(w, r) {
		return
	}
	if !oktaAuth(w, r) {
		return
	}
	var in oktaGroupPayload
	if err := readBody(r, &in); err != nil {
		oktaErr(w, r, http.StatusBadRequest, "E0000001", "Api validation failed: "+err.Error())
		return
	}
	name := strings.TrimSpace(in.Profile.Name)
	if name == "" {
		oktaErr(w, r, http.StatusBadRequest, "E0000001", "Api validation failed: name", "name: The field cannot be left blank")
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.oktaTenant(w, r)
	if t == nil {
		return
	}
	if t.group(name) != nil {
		oktaErr(w, r, http.StatusBadRequest, "E0000001", "Api validation failed: name", "name: An object with this field already exists in the current organization")
		return
	}
	p := providers[t.Provider]
	style := "okta"
	if p != nil {
		style = p.IDStyle
	}
	g := &Group{
		ID:      newID(style, "group"),
		Name:    name,
		Members: []string{},
	}
	t.Groups = append(t.Groups, g)
	s.store.save()
	e.Summary = "okta: create group " + g.Name
	out := s.oktaGroupJSON(t, g)
	if in.Profile.Description != "" {
		out["profile"].(map[string]any)["description"] = in.Profile.Description
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) oktaGetGroup(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "okta.api"
	if s.network(w, r) {
		return
	}
	if !oktaAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.oktaTenant(w, r)
	if t == nil {
		return
	}
	ref := r.PathValue("id")
	g := t.group(ref)
	if g == nil {
		oktaErr(w, r, http.StatusNotFound, "E0000007", fmt.Sprintf("Not found: Resource not found: %s (UserGroup)", ref))
		return
	}
	e.Summary = "okta: get group " + g.Name
	writeJSON(w, http.StatusOK, s.oktaGroupJSON(t, g))
}

func (s *Server) oktaUpdateGroup(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "okta.api"
	if s.network(w, r) {
		return
	}
	if !oktaAuth(w, r) {
		return
	}
	var in oktaGroupPayload
	if err := readBody(r, &in); err != nil {
		oktaErr(w, r, http.StatusBadRequest, "E0000001", "Api validation failed: "+err.Error())
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.oktaTenant(w, r)
	if t == nil {
		return
	}
	ref := r.PathValue("id")
	g := t.group(ref)
	if g == nil {
		oktaErr(w, r, http.StatusNotFound, "E0000007", fmt.Sprintf("Not found: Resource not found: %s (UserGroup)", ref))
		return
	}
	if name := strings.TrimSpace(in.Profile.Name); name != "" {
		g.Name = name
	}
	s.store.save()
	e.Summary = "okta: update group " + g.Name
	out := s.oktaGroupJSON(t, g)
	if in.Profile.Description != "" {
		out["profile"].(map[string]any)["description"] = in.Profile.Description
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) oktaDeleteGroup(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "okta.api"
	if s.network(w, r) {
		return
	}
	if !oktaAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.oktaTenant(w, r)
	if t == nil {
		return
	}
	ref := r.PathValue("id")
	g := t.group(ref)
	if g == nil {
		oktaErr(w, r, http.StatusNotFound, "E0000007", fmt.Sprintf("Not found: Resource not found: %s (UserGroup)", ref))
		return
	}
	t.Groups = slices.DeleteFunc(t.Groups, func(x *Group) bool { return x.ID == g.ID })
	s.store.save()
	e.Summary = "okta: delete group " + g.Name
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) oktaListGroupUsers(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "okta.api"
	if s.network(w, r) {
		return
	}
	if !oktaAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.oktaTenant(w, r)
	if t == nil {
		return
	}
	ref := r.PathValue("id")
	g := t.group(ref)
	if g == nil {
		oktaErr(w, r, http.StatusNotFound, "E0000007", fmt.Sprintf("Not found: Resource not found: %s (UserGroup)", ref))
		return
	}
	var users []map[string]any
	for _, uid := range g.Members {
		if u := t.user(uid); u != nil {
			users = append(users, s.oktaUserJSON(t, u))
		}
	}
	e.Summary = "okta: list users in group " + g.Name
	page := s.oktaPaginate(w, r, users, "id", 200)
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) oktaAddGroupUser(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "okta.api"
	if s.network(w, r) {
		return
	}
	if !oktaAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.oktaTenant(w, r)
	if t == nil {
		return
	}
	g := t.group(r.PathValue("id"))
	if g == nil {
		oktaErr(w, r, http.StatusNotFound, "E0000007", fmt.Sprintf("Not found: Resource not found: %s (UserGroup)", r.PathValue("id")))
		return
	}
	u := t.user(r.PathValue("uid"))
	if u == nil {
		oktaErr(w, r, http.StatusNotFound, "E0000007", fmt.Sprintf("Not found: Resource not found: %s (User)", r.PathValue("uid")))
		return
	}
	if !slices.Contains(g.Members, u.ID) {
		g.Members = append(g.Members, u.ID)
		s.store.save()
	}
	e.Summary = fmt.Sprintf("okta: add %s to group %s", u.UserName, g.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) oktaRemoveGroupUser(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "okta.api"
	if s.network(w, r) {
		return
	}
	if !oktaAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.oktaTenant(w, r)
	if t == nil {
		return
	}
	g := t.group(r.PathValue("id"))
	if g == nil {
		oktaErr(w, r, http.StatusNotFound, "E0000007", fmt.Sprintf("Not found: Resource not found: %s (UserGroup)", r.PathValue("id")))
		return
	}
	u := t.user(r.PathValue("uid"))
	if u == nil {
		oktaErr(w, r, http.StatusNotFound, "E0000007", fmt.Sprintf("Not found: Resource not found: %s (User)", r.PathValue("uid")))
		return
	}
	g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return m == u.ID })
	s.store.save()
	e.Summary = fmt.Sprintf("okta: remove %s from group %s", u.UserName, g.Name)
	w.WriteHeader(http.StatusNoContent)
}

// ---- Applications & System Log ----

func (s *Server) oktaListApps(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "okta.api"
	e.Summary = "okta: list apps"
	if s.network(w, r) {
		return
	}
	if !oktaAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.oktaTenant(w, r)
	if t == nil {
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	var apps []map[string]any
	for _, a := range t.Apps {
		if q != "" && !strings.Contains(strings.ToLower(a.Name+" "+a.ID), q) {
			continue
		}
		apps = append(apps, s.oktaAppJSON(t, a))
	}
	page := s.oktaPaginate(w, r, apps, "id", 200)
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) oktaListLogs(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "okta.api"
	e.Summary = "okta: list system logs"
	if s.network(w, r) {
		return
	}
	if !oktaAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	t := s.oktaTenant(w, r)
	var firstUser *User
	var created time.Time
	if t != nil {
		created = t.Created
		if len(t.Users) > 0 {
			uCopy := *t.Users[0]
			firstUser = &uCopy
		}
	}
	s.store.mu.Unlock()
	if t == nil {
		return
	}

	q := r.URL.Query().Get("q")
	filter := strings.TrimSpace(r.URL.Query().Get("filter"))
	sinceStr := r.URL.Query().Get("since")
	untilStr := r.URL.Query().Get("until")
	sortOrder := strings.ToUpper(r.URL.Query().Get("sortOrder"))

	entries := s.logs.list(t.ID, "", q, "", 0, 500)
	var events []map[string]any

	actorID, actorLogin, actorName := "00u0000000000000000", "system@"+t.Domain, "System"
	if firstUser != nil {
		actorID, actorLogin, actorName = firstUser.ID, firstUser.UserName, firstUser.DisplayName
	}

	// Ensure a baseline seeded user.session.start event is always present
	seedTime := created
	if seedTime.IsZero() {
		seedTime = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	baseline := map[string]any{
		"uuid":           "evt-baseline-" + t.ID,
		"published":      oktaTime(seedTime),
		"eventType":      "user.session.start",
		"version":        "0",
		"severity":       "INFO",
		"legacyEventType": "core.user_auth.login_success",
		"displayMessage": "User login to Okta",
		"actor": map[string]any{
			"id":          actorID,
			"type":        "User",
			"alternateId": actorLogin,
			"displayName": actorName,
		},
		"client": map[string]any{
			"ipAddress": "127.0.0.1",
			"userAgent": map[string]any{"rawUserAgent": "mock-idp"},
		},
		"outcome": map[string]any{
			"result": "SUCCESS",
		},
	}
	if q == "" || strings.Contains(strings.ToLower("user.session.start User login to Okta "+actorLogin+" "+actorName), strings.ToLower(q)) {
		events = append(events, baseline)
	}

	for _, le := range entries {
		evType := "system.api.request"
		switch {
		case strings.HasPrefix(le.Kind, "login"), strings.HasPrefix(le.Kind, "oidc"), strings.HasPrefix(le.Kind, "saml"):
			evType = "user.session.start"
		case strings.Contains(le.Summary, "created user"):
			evType = "user.account.create"
		case strings.Contains(le.Summary, "update user"):
			evType = "user.account.update_profile"
		case strings.Contains(le.Summary, "lifecycle"):
			evType = "user.lifecycle.update"
		case strings.Contains(le.Summary, "group"):
			evType = "group.user_membership.change"
		}
		sev := "INFO"
		if le.Level == "warn" {
			sev = "WARN"
		} else if le.Level == "error" {
			sev = "ERROR"
		}
		res := "SUCCESS"
		if le.Status >= 400 || le.Level == "error" {
			res = "FAILURE"
		}
		ev := map[string]any{
			"uuid":           fmt.Sprintf("evt-%s-%d", t.ID, le.ID),
			"published":      oktaTime(le.Time),
			"eventType":      evType,
			"version":        "0",
			"severity":       sev,
			"displayMessage": le.Summary,
			"actor": map[string]any{
				"id":          actorID,
				"type":        "User",
				"alternateId": actorLogin,
				"displayName": actorName,
			},
			"client": map[string]any{
				"ipAddress": "127.0.0.1",
				"userAgent": map[string]any{"rawUserAgent": "mock-idp"},
			},
			"outcome": map[string]any{
				"result": res,
			},
		}
		events = append(events, ev)
	}

	if sinceStr != "" || untilStr != "" || filter != "" {
		sinceT, _ := time.Parse(time.RFC3339, sinceStr)
		untilT, _ := time.Parse(time.RFC3339, untilStr)
		var filtered []map[string]any
		for _, ev := range events {
			pubT, _ := time.Parse("2006-01-02T15:04:05.000Z", str(ev["published"]))
			if !sinceT.IsZero() && pubT.Before(sinceT) {
				continue
			}
			if !untilT.IsZero() && pubT.After(untilT) {
				continue
			}
			if filter != "" && !evalOktaExpr(filter, func(f string) string {
				switch strings.ToLower(strings.TrimSpace(f)) {
				case "eventtype":
					return str(ev["eventType"])
				case "severity":
					return str(ev["severity"])
				case "outcome.result":
					if m, ok := ev["outcome"].(map[string]any); ok {
						return str(m["result"])
					}
				case "actor.id":
					if m, ok := ev["actor"].(map[string]any); ok {
						return str(m["id"])
					}
				case "actor.alternateid":
					if m, ok := ev["actor"].(map[string]any); ok {
						return str(m["alternateId"])
					}
				case "uuid":
					return str(ev["uuid"])
				}
				return ""
			}) {
				continue
			}
			filtered = append(filtered, ev)
		}
		events = filtered
	}

	if sortOrder == "DESCENDING" {
		slices.Reverse(events)
	}
	page := s.oktaPaginate(w, r, events, "uuid", 100)
	writeJSON(w, http.StatusOK, page)
}
