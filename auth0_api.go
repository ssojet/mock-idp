package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

var auth0APIRegistered sync.Map

func (s *Server) registerAuth0API() {
	if _, loaded := auth0APIRegistered.LoadOrStore(s.mux, true); loaded {
		return
	}
	h := func(pattern string, fn http.HandlerFunc) { s.mux.Handle(pattern, s.traced(fn)) }

	// Users
	h("GET /t/{tenant}/api/v2/users", s.auth0ListUsers)
	h("POST /t/{tenant}/api/v2/users", s.auth0CreateUser)
	h("GET /t/{tenant}/api/v2/users/{id}", s.auth0GetUser)
	h("PATCH /t/{tenant}/api/v2/users/{id}", s.auth0UpdateUser)
	h("DELETE /t/{tenant}/api/v2/users/{id}", s.auth0DeleteUser)

	// User Roles
	h("GET /t/{tenant}/api/v2/users/{id}/roles", s.auth0GetUserRoles)
	h("POST /t/{tenant}/api/v2/users/{id}/roles", s.auth0AssignUserRoles)
	h("DELETE /t/{tenant}/api/v2/users/{id}/roles", s.auth0RemoveUserRoles)

	// Roles
	h("GET /t/{tenant}/api/v2/roles", s.auth0ListRoles)
	h("POST /t/{tenant}/api/v2/roles", s.auth0CreateRole)
	h("GET /t/{tenant}/api/v2/roles/{id}", s.auth0GetRole)
	h("PATCH /t/{tenant}/api/v2/roles/{id}", s.auth0UpdateRole)
	h("DELETE /t/{tenant}/api/v2/roles/{id}", s.auth0DeleteRole)
	h("GET /t/{tenant}/api/v2/roles/{id}/users", s.auth0GetRoleUsers)
	h("POST /t/{tenant}/api/v2/roles/{id}/users", s.auth0AssignRoleUsers)

	// Organizations
	h("GET /t/{tenant}/api/v2/organizations", s.auth0ListOrganizations)

	// Logs
	h("GET /t/{tenant}/api/v2/logs", s.auth0ListLogs)
}

func (s *Server) findAuth0Tenant(w http.ResponseWriter, r *http.Request) *Tenant {
	id := r.PathValue("tenant")
	t := s.store.tenant(id)
	if t == nil {
		for _, candidate := range s.store.Tenants {
			if strings.EqualFold(candidate.ID, id) || strings.EqualFold(candidate.Provider, id) || strings.EqualFold(slug(candidate.Name), id) {
				t = candidate
				break
			}
		}
	}
	if t == nil {
		entry(r).fail("unknown tenant %q", id)
		writeJSON(w, http.StatusNotFound, map[string]any{
			"statusCode": http.StatusNotFound,
			"error":      "Not Found",
			"message":    "Tenant not found: " + id,
		})
		return nil
	}
	return t
}

func auth0CheckAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"statusCode": http.StatusUnauthorized,
			"error":      "Unauthorized",
			"message":    "Missing or invalid Bearer token",
		})
		return false
	}
	return true
}

func auth0UserID(u *User) string {
	if strings.Contains(u.ID, "|") {
		return u.ID
	}
	return "auth0|" + u.ID
}

func findAuth0User(t *Tenant, rawID string) *User {
	cleanID := strings.TrimPrefix(rawID, "auth0|")
	for _, u := range t.Users {
		if u.ID == rawID || u.ID == cleanID || strings.TrimPrefix(u.ID, "auth0|") == cleanID {
			return u
		}
	}
	return t.user(rawID)
}

func toAuth0User(u *User) map[string]any {
	formattedID := auth0UserID(u)
	identityID := strings.TrimPrefix(formattedID, "auth0|")

	username := u.UserName
	if username == "" {
		username = u.Email
	}

	name := u.DisplayName
	if name == "" {
		name = strings.TrimSpace(u.GivenName + " " + u.FamilyName)
		if name == "" {
			name = u.Email
		}
	}

	nickname := username
	if idx := strings.Index(nickname, "@"); idx != -1 {
		nickname = nickname[:idx]
	}

	appMeta := map[string]any{}
	if u.Department != "" {
		appMeta["department"] = u.Department
	}
	if u.Title != "" {
		appMeta["title"] = u.Title
	}
	for k, v := range u.Attributes {
		if _, exists := appMeta[k]; !exists {
			appMeta[k] = v
		}
	}

	return map[string]any{
		"user_id":        formattedID,
		"email":          u.Email,
		"email_verified": u.EmailVerified,
		"username":       username,
		"name":           name,
		"given_name":     u.GivenName,
		"family_name":    u.FamilyName,
		"nickname":       nickname,
		"picture":        "https://www.gravatar.com/avatar/00000000000000000000000000000000?d=mp",
		"blocked":        !u.Active,
		"created_at":     "2025-01-01T00:00:00.000Z",
		"updated_at":     "2025-01-01T00:00:00.000Z",
		"identities": []map[string]any{
			{
				"connection": "Username-Password-Authentication",
				"user_id":    identityID,
				"provider":   "auth0",
				"isSocial":   false,
			},
		},
		"app_metadata":  appMeta,
		"user_metadata": map[string]any{},
	}
}

func matchAuth0Query(u *User, q string) bool {
	if q == "" {
		return true
	}
	q = strings.TrimSpace(q)
	parts := strings.Split(q, " AND ")
	if len(parts) == 1 {
		parts = strings.Fields(q)
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if k, v, ok := strings.Cut(part, ":"); ok {
			k = strings.TrimSpace(k)
			v = strings.Trim(strings.TrimSpace(v), `"'`)
			switch strings.ToLower(k) {
			case "email":
				if !matchWildcardOrSubstring(u.Email, v) {
					return false
				}
			case "name":
				name := u.DisplayName
				if name == "" {
					name = u.GivenName + " " + u.FamilyName
				}
				if !matchWildcardOrSubstring(name, v) && !matchWildcardOrSubstring(u.GivenName, v) && !matchWildcardOrSubstring(u.FamilyName, v) {
					return false
				}
			case "username":
				if !matchWildcardOrSubstring(u.UserName, v) {
					return false
				}
			case "blocked":
				blocked := strconv.FormatBool(!u.Active)
				if !strings.EqualFold(blocked, v) {
					return false
				}
			default:
				if val, ok := u.Attributes[k]; ok {
					if !matchWildcardOrSubstring(val, v) {
						return false
					}
				}
			}
		} else {
			term := strings.ToLower(part)
			text := strings.ToLower(fmt.Sprintf("%s %s %s %s %s", u.Email, u.UserName, u.DisplayName, u.GivenName, u.FamilyName))
			if !strings.Contains(text, term) {
				return false
			}
		}
	}
	return true
}

func matchWildcardOrSubstring(target, pattern string) bool {
	target = strings.ToLower(target)
	pattern = strings.ToLower(pattern)
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") && len(pattern) > 2 {
		return strings.Contains(target, pattern[1:len(pattern)-1])
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(target, strings.TrimPrefix(pattern, "*"))
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(target, strings.TrimSuffix(pattern, "*"))
	}
	return target == pattern || strings.Contains(target, pattern)
}

func (s *Server) auth0ListUsers(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "auth0.api"
	if s.network(w, r) {
		return
	}
	if !auth0CheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findAuth0Tenant(w, r)
	if t == nil {
		return
	}

	q := r.URL.Query().Get("q")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 0 {
		page = 0
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage <= 0 {
		perPage = 50
	}

	var filtered []*User
	for _, u := range t.Users {
		if matchAuth0Query(u, q) {
			filtered = append(filtered, u)
		}
	}

	total := len(filtered)
	start := page * perPage
	end := start + perPage
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	var paged []map[string]any
	for _, u := range filtered[start:end] {
		paged = append(paged, toAuth0User(u))
	}
	if paged == nil {
		paged = []map[string]any{}
	}

	if r.URL.Query().Get("include_totals") == "true" {
		writeJSON(w, http.StatusOK, map[string]any{
			"start":  start,
			"limit":  perPage,
			"length": len(paged),
			"total":  total,
			"users":  paged,
		})
		return
	}

	writeJSON(w, http.StatusOK, paged)
}

func (s *Server) auth0CreateUser(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "auth0.api"
	if s.network(w, r) {
		return
	}
	if !auth0CheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findAuth0Tenant(w, r)
	if t == nil {
		return
	}

	var body struct {
		Email         string            `json:"email"`
		UserID        string            `json:"user_id"`
		Name          string            `json:"name"`
		GivenName     string            `json:"given_name"`
		FamilyName    string            `json:"family_name"`
		Nickname      string            `json:"nickname"`
		Password      string            `json:"password"`
		Blocked       bool              `json:"blocked"`
		EmailVerified bool              `json:"email_verified"`
		AppMetadata   map[string]any    `json:"app_metadata"`
		UserMetadata  map[string]any    `json:"user_metadata"`
		Connection    string            `json:"connection"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"statusCode": http.StatusBadRequest,
			"error":      "Bad Request",
			"message":    err.Error(),
		})
		return
	}

	uid := body.UserID
	if uid == "" {
		uid = newID("auth0", "user")
	} else if !strings.HasPrefix(uid, "auth0|") && !strings.Contains(uid, "|") {
		uid = "auth0|" + uid
	}

	displayName := body.Name
	if displayName == "" {
		displayName = strings.TrimSpace(body.GivenName + " " + body.FamilyName)
	}

	attrs := map[string]string{}
	var dept, title string
	for k, v := range body.AppMetadata {
		sval := fmt.Sprint(v)
		if strings.EqualFold(k, "department") {
			dept = sval
		} else if strings.EqualFold(k, "title") {
			title = sval
		} else {
			attrs[k] = sval
		}
	}

	u := &User{
		ID:            uid,
		UserName:      body.Email,
		Email:         body.Email,
		EmailVerified: body.EmailVerified,
		GivenName:     body.GivenName,
		FamilyName:    body.FamilyName,
		DisplayName:   displayName,
		Password:      body.Password,
		Active:        !body.Blocked,
		Department:    dept,
		Title:         title,
		Attributes:    attrs,
	}
	t.Users = append(t.Users, u)
	s.store.save()

	writeJSON(w, http.StatusCreated, toAuth0User(u))
}

func (s *Server) auth0GetUser(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "auth0.api"
	if s.network(w, r) {
		return
	}
	if !auth0CheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findAuth0Tenant(w, r)
	if t == nil {
		return
	}

	u := findAuth0User(t, r.PathValue("id"))
	if u == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"statusCode": http.StatusNotFound,
			"error":      "Not Found",
			"message":    "The user does not exist.",
		})
		return
	}

	writeJSON(w, http.StatusOK, toAuth0User(u))
}

func (s *Server) auth0UpdateUser(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "auth0.api"
	if s.network(w, r) {
		return
	}
	if !auth0CheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findAuth0Tenant(w, r)
	if t == nil {
		return
	}

	u := findAuth0User(t, r.PathValue("id"))
	if u == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"statusCode": http.StatusNotFound,
			"error":      "Not Found",
			"message":    "The user does not exist.",
		})
		return
	}

	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"statusCode": http.StatusBadRequest,
			"error":      "Bad Request",
			"message":    err.Error(),
		})
		return
	}

	if v, ok := body["email"].(string); ok {
		u.Email = v
	}
	if v, ok := body["email_verified"].(bool); ok {
		u.EmailVerified = v
	}
	if v, ok := body["name"].(string); ok {
		u.DisplayName = v
	}
	if v, ok := body["given_name"].(string); ok {
		u.GivenName = v
	}
	if v, ok := body["family_name"].(string); ok {
		u.FamilyName = v
	}
	if v, ok := body["password"].(string); ok {
		u.Password = v
	}
	if v, ok := body["blocked"].(bool); ok {
		u.Active = !v
	}
	if v, ok := body["app_metadata"].(map[string]any); ok {
		if u.Attributes == nil {
			u.Attributes = map[string]string{}
		}
		for k, val := range v {
			sval := fmt.Sprint(val)
			if strings.EqualFold(k, "department") {
				u.Department = sval
			} else if strings.EqualFold(k, "title") {
				u.Title = sval
			} else {
				u.Attributes[k] = sval
			}
		}
	}

	s.store.save()
	writeJSON(w, http.StatusOK, toAuth0User(u))
}

func (s *Server) auth0DeleteUser(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "auth0.api"
	if s.network(w, r) {
		return
	}
	if !auth0CheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findAuth0Tenant(w, r)
	if t == nil {
		return
	}

	u := findAuth0User(t, r.PathValue("id"))
	if u == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"statusCode": http.StatusNotFound,
			"error":      "Not Found",
			"message":    "The user does not exist.",
		})
		return
	}

	t.Users = slices.DeleteFunc(t.Users, func(item *User) bool {
		return item.ID == u.ID
	})
	for _, g := range t.Groups {
		g.Members = slices.DeleteFunc(g.Members, func(mid string) bool {
			return mid == u.ID
		})
	}
	s.store.save()

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) auth0GetUserRoles(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "auth0.api"
	if s.network(w, r) {
		return
	}
	if !auth0CheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findAuth0Tenant(w, r)
	if t == nil {
		return
	}

	u := findAuth0User(t, r.PathValue("id"))
	if u == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"statusCode": http.StatusNotFound,
			"error":      "Not Found",
			"message":    "The user does not exist.",
		})
		return
	}

	var roles []map[string]any
	for _, g := range t.groupsOf(u.ID) {
		roles = append(roles, map[string]any{
			"id":          g.ID,
			"name":        g.Name,
			"description": g.Name + " role",
		})
	}
	if roles == nil {
		roles = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, roles)
}

func (s *Server) auth0AssignUserRoles(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "auth0.api"
	if s.network(w, r) {
		return
	}
	if !auth0CheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findAuth0Tenant(w, r)
	if t == nil {
		return
	}

	u := findAuth0User(t, r.PathValue("id"))
	if u == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"statusCode": http.StatusNotFound,
			"error":      "Not Found",
			"message":    "The user does not exist.",
		})
		return
	}

	var body struct {
		Roles []string `json:"roles"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"statusCode": http.StatusBadRequest,
			"error":      "Bad Request",
			"message":    err.Error(),
		})
		return
	}

	for _, rid := range body.Roles {
		g := t.group(rid)
		if g != nil && !slices.Contains(g.Members, u.ID) {
			g.Members = append(g.Members, u.ID)
		}
	}
	s.store.save()

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) auth0RemoveUserRoles(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "auth0.api"
	if s.network(w, r) {
		return
	}
	if !auth0CheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findAuth0Tenant(w, r)
	if t == nil {
		return
	}

	u := findAuth0User(t, r.PathValue("id"))
	if u == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"statusCode": http.StatusNotFound,
			"error":      "Not Found",
			"message":    "The user does not exist.",
		})
		return
	}

	var body struct {
		Roles []string `json:"roles"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"statusCode": http.StatusBadRequest,
			"error":      "Bad Request",
			"message":    err.Error(),
		})
		return
	}

	for _, rid := range body.Roles {
		g := t.group(rid)
		if g != nil {
			g.Members = slices.DeleteFunc(g.Members, func(mid string) bool {
				return mid == u.ID
			})
		}
	}
	s.store.save()

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) auth0ListRoles(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "auth0.api"
	if s.network(w, r) {
		return
	}
	if !auth0CheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findAuth0Tenant(w, r)
	if t == nil {
		return
	}

	nameFilter := strings.ToLower(r.URL.Query().Get("name_filter"))
	var roles []map[string]any
	for _, g := range t.Groups {
		if nameFilter == "" || strings.Contains(strings.ToLower(g.Name), nameFilter) {
			roles = append(roles, map[string]any{
				"id":          g.ID,
				"name":        g.Name,
				"description": g.Name + " role",
			})
		}
	}
	if roles == nil {
		roles = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, roles)
}

func (s *Server) auth0CreateRole(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "auth0.api"
	if s.network(w, r) {
		return
	}
	if !auth0CheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findAuth0Tenant(w, r)
	if t == nil {
		return
	}

	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"statusCode": http.StatusBadRequest,
			"error":      "Bad Request",
			"message":    err.Error(),
		})
		return
	}

	desc := body.Description
	if desc == "" {
		desc = body.Name + " role"
	}

	g := &Group{
		ID:      newID("auth0", "group"),
		Name:    body.Name,
		Members: []string{},
	}
	t.Groups = append(t.Groups, g)
	s.store.save()

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":          g.ID,
		"name":        g.Name,
		"description": desc,
	})
}

func (s *Server) auth0GetRole(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "auth0.api"
	if s.network(w, r) {
		return
	}
	if !auth0CheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findAuth0Tenant(w, r)
	if t == nil {
		return
	}

	g := t.group(r.PathValue("id"))
	if g == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"statusCode": http.StatusNotFound,
			"error":      "Not Found",
			"message":    "The role does not exist.",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":          g.ID,
		"name":        g.Name,
		"description": g.Name + " role",
	})
}

func (s *Server) auth0UpdateRole(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "auth0.api"
	if s.network(w, r) {
		return
	}
	if !auth0CheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findAuth0Tenant(w, r)
	if t == nil {
		return
	}

	g := t.group(r.PathValue("id"))
	if g == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"statusCode": http.StatusNotFound,
			"error":      "Not Found",
			"message":    "The role does not exist.",
		})
		return
	}

	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"statusCode": http.StatusBadRequest,
			"error":      "Bad Request",
			"message":    err.Error(),
		})
		return
	}

	if body.Name != "" {
		g.Name = body.Name
	}
	desc := body.Description
	if desc == "" {
		desc = g.Name + " role"
	}
	s.store.save()

	writeJSON(w, http.StatusOK, map[string]any{
		"id":          g.ID,
		"name":        g.Name,
		"description": desc,
	})
}

func (s *Server) auth0DeleteRole(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "auth0.api"
	if s.network(w, r) {
		return
	}
	if !auth0CheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findAuth0Tenant(w, r)
	if t == nil {
		return
	}

	g := t.group(r.PathValue("id"))
	if g == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"statusCode": http.StatusNotFound,
			"error":      "Not Found",
			"message":    "The role does not exist.",
		})
		return
	}

	t.Groups = slices.DeleteFunc(t.Groups, func(item *Group) bool {
		return item.ID == g.ID
	})
	s.store.save()

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) auth0GetRoleUsers(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "auth0.api"
	if s.network(w, r) {
		return
	}
	if !auth0CheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findAuth0Tenant(w, r)
	if t == nil {
		return
	}

	g := t.group(r.PathValue("id"))
	if g == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"statusCode": http.StatusNotFound,
			"error":      "Not Found",
			"message":    "The role does not exist.",
		})
		return
	}

	var users []map[string]any
	for _, uid := range g.Members {
		if u := t.user(uid); u != nil {
			users = append(users, toAuth0User(u))
		}
	}
	if users == nil {
		users = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, users)
}

func (s *Server) auth0AssignRoleUsers(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "auth0.api"
	if s.network(w, r) {
		return
	}
	if !auth0CheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findAuth0Tenant(w, r)
	if t == nil {
		return
	}

	g := t.group(r.PathValue("id"))
	if g == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"statusCode": http.StatusNotFound,
			"error":      "Not Found",
			"message":    "The role does not exist.",
		})
		return
	}

	var body struct {
		Users []string `json:"users"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"statusCode": http.StatusBadRequest,
			"error":      "Bad Request",
			"message":    err.Error(),
		})
		return
	}

	for _, uid := range body.Users {
		u := findAuth0User(t, uid)
		if u != nil && !slices.Contains(g.Members, u.ID) {
			g.Members = append(g.Members, u.ID)
		}
	}
	s.store.save()

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) auth0ListOrganizations(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "auth0.api"
	if s.network(w, r) {
		return
	}
	if !auth0CheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findAuth0Tenant(w, r)
	if t == nil {
		return
	}

	orgs := []map[string]any{
		{
			"id":           "org_" + t.ID,
			"name":         t.ID,
			"display_name": t.Name,
		},
	}
	writeJSON(w, http.StatusOK, orgs)
}

func (s *Server) auth0ListLogs(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "auth0.api"
	if s.network(w, r) {
		return
	}
	if !auth0CheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	t := s.findAuth0Tenant(w, r)
	s.store.mu.Unlock()
	if t == nil {
		return
	}

	entries := s.logs.list(t.ID, "", "", "", 0, 100)
	var events []map[string]any
	for _, e := range entries {
		evtType := "sapi"
		if strings.Contains(e.Kind, "login") || strings.Contains(e.URL, "login") || strings.Contains(e.URL, "token") {
			if e.Status >= 400 || e.Level == "error" {
				evtType = "f"
			} else {
				evtType = "s"
			}
		} else if e.Status >= 400 || e.Level == "error" {
			evtType = "fapi"
		}
		events = append(events, map[string]any{
			"_id":         fmt.Sprintf("log_%d", e.ID),
			"log_id":      fmt.Sprintf("log_%d", e.ID),
			"date":        e.Time.Format(time.RFC3339Nano),
			"type":        evtType,
			"description": e.Summary,
			"client_id":   "mock-client-id",
			"user_id":     "auth0|mock-user",
			"user_name":   "alice@" + t.Domain,
			"ip":          "127.0.0.1",
		})
	}

	if len(events) == 0 {
		events = append(events, map[string]any{
			"_id":         "log_init_001",
			"log_id":      "log_init_001",
			"date":        time.Now().UTC().Format(time.RFC3339Nano),
			"type":        "s",
			"description": "Successful login",
			"client_id":   "mock-client-id",
			"user_id":     "auth0|mock-user",
			"user_name":   "alice@" + t.Domain,
			"ip":          "127.0.0.1",
		})
	}

	writeJSON(w, http.StatusOK, events)
}
