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

var keycloakAPIRegistered sync.Map

func (s *Server) registerKeycloakAPI() {
	if _, loaded := keycloakAPIRegistered.LoadOrStore(s.mux, true); loaded {
		return
	}
	h := func(pattern string, fn http.HandlerFunc) { s.mux.Handle(pattern, s.traced(fn)) }

	// Users
	h("GET /t/{tenant}/admin/realms/{realm}/users", s.keycloakListUsers)
	h("GET /t/{tenant}/admin/realms/{realm}/users/count", s.keycloakCountUsers)
	h("POST /t/{tenant}/admin/realms/{realm}/users", s.keycloakCreateUser)
	h("GET /t/{tenant}/admin/realms/{realm}/users/{id}", s.keycloakGetUser)
	h("PUT /t/{tenant}/admin/realms/{realm}/users/{id}", s.keycloakUpdateUser)
	h("DELETE /t/{tenant}/admin/realms/{realm}/users/{id}", s.keycloakDeleteUser)
	h("GET /t/{tenant}/admin/realms/{realm}/users/{id}/groups", s.keycloakGetUserGroups)
	h("PUT /t/{tenant}/admin/realms/{realm}/users/{id}/groups/{groupId}", s.keycloakAddUserToGroup)
	h("DELETE /t/{tenant}/admin/realms/{realm}/users/{id}/groups/{groupId}", s.keycloakRemoveUserFromGroup)

	// Groups
	h("GET /t/{tenant}/admin/realms/{realm}/groups", s.keycloakListGroups)
	h("POST /t/{tenant}/admin/realms/{realm}/groups", s.keycloakCreateGroup)
	h("GET /t/{tenant}/admin/realms/{realm}/groups/{id}", s.keycloakGetGroup)
	h("PUT /t/{tenant}/admin/realms/{realm}/groups/{id}", s.keycloakUpdateGroup)
	h("DELETE /t/{tenant}/admin/realms/{realm}/groups/{id}", s.keycloakDeleteGroup)
	h("GET /t/{tenant}/admin/realms/{realm}/groups/{id}/members", s.keycloakGetGroupMembers)

	// Events
	h("GET /t/{tenant}/admin/realms/{realm}/events", s.keycloakListEvents)
	h("GET /t/{tenant}/admin/realms/{realm}/admin-events", s.keycloakListAdminEvents)
}

func (s *Server) findKeycloakTenant(w http.ResponseWriter, r *http.Request) *Tenant {
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
			"error": "unknown tenant " + id,
		})
		return nil
	}
	return t
}

func keycloakCheckAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "HTTP 401 Unauthorized",
		})
		return false
	}
	return true
}

func toKeycloakUser(u *User) map[string]any {
	attrs := map[string][]string{}
	if u.Department != "" {
		attrs["department"] = []string{u.Department}
	}
	if u.Title != "" {
		attrs["title"] = []string{u.Title}
	}
	if u.EmployeeNumber != "" {
		attrs["employeeNumber"] = []string{u.EmployeeNumber}
	}
	for k, v := range u.Attributes {
		if _, exists := attrs[k]; !exists {
			attrs[k] = []string{v}
		}
	}

	return map[string]any{
		"id":               u.ID,
		"createdTimestamp": time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli(),
		"username":         u.UserName,
		"enabled":          u.Active,
		"totp":             false,
		"emailVerified":    u.EmailVerified,
		"firstName":        u.GivenName,
		"lastName":         u.FamilyName,
		"email":            u.Email,
		"attributes":       attrs,
	}
}

func toKeycloakGroup(g *Group) map[string]any {
	return map[string]any{
		"id":        g.ID,
		"name":      g.Name,
		"path":      "/" + g.Name,
		"subGroups": []any{},
	}
}

func matchKeycloakUser(u *User, search, username, email, firstName, lastName string, exact bool, enabledStr string) bool {
	if enabledStr != "" {
		if en, err := strconv.ParseBool(enabledStr); err == nil {
			if u.Active != en {
				return false
			}
		}
	}

	if search != "" {
		searchLower := strings.ToLower(search)
		full := strings.ToLower(fmt.Sprintf("%s %s %s %s", u.UserName, u.Email, u.GivenName, u.FamilyName))
		if !strings.Contains(full, searchLower) {
			return false
		}
	}

	matchField := func(val, target string) bool {
		if target == "" {
			return true
		}
		if exact {
			return strings.EqualFold(val, target)
		}
		return strings.Contains(strings.ToLower(val), strings.ToLower(target))
	}

	if !matchField(u.UserName, username) {
		return false
	}
	if !matchField(u.Email, email) {
		return false
	}
	if !matchField(u.GivenName, firstName) {
		return false
	}
	if !matchField(u.FamilyName, lastName) {
		return false
	}

	return true
}

func (s *Server) filterKeycloakUsers(t *Tenant, r *http.Request) []*User {
	q := r.URL.Query()
	search := q.Get("search")
	username := q.Get("username")
	email := q.Get("email")
	firstName := q.Get("firstName")
	lastName := q.Get("lastName")
	exact, _ := strconv.ParseBool(q.Get("exact"))
	enabled := q.Get("enabled")

	var matched []*User
	for _, u := range t.Users {
		if matchKeycloakUser(u, search, username, email, firstName, lastName, exact, enabled) {
			matched = append(matched, u)
		}
	}
	return matched
}

func (s *Server) keycloakListUsers(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "keycloak.admin"
	if s.network(w, r) {
		return
	}
	if !keycloakCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findKeycloakTenant(w, r)
	if t == nil {
		return
	}

	matched := s.filterKeycloakUsers(t, r)
	first, _ := strconv.Atoi(r.URL.Query().Get("first"))
	if first < 0 {
		first = 0
	}
	max, _ := strconv.Atoi(r.URL.Query().Get("max"))
	if max <= 0 {
		max = 100
	}

	total := len(matched)
	if first > total {
		first = total
	}
	end := first + max
	if end > total {
		end = total
	}

	var res []map[string]any
	for _, u := range matched[first:end] {
		res = append(res, toKeycloakUser(u))
	}
	if res == nil {
		res = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, res)
}

func (s *Server) keycloakCountUsers(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "keycloak.admin"
	if s.network(w, r) {
		return
	}
	if !keycloakCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findKeycloakTenant(w, r)
	if t == nil {
		return
	}

	matched := s.filterKeycloakUsers(t, r)
	writeJSON(w, http.StatusOK, len(matched))
}

func (s *Server) keycloakCreateUser(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "keycloak.admin"
	if s.network(w, r) {
		return
	}
	if !keycloakCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findKeycloakTenant(w, r)
	if t == nil {
		return
	}

	var body struct {
		Username      string              `json:"username"`
		Email         string              `json:"email"`
		FirstName     string              `json:"firstName"`
		LastName      string              `json:"lastName"`
		Enabled       *bool               `json:"enabled"`
		EmailVerified bool                `json:"emailVerified"`
		Attributes    map[string][]string `json:"attributes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	username := body.Username
	if username == "" {
		username = body.Email
	}

	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}

	attrs := map[string]string{}
	var dept, title, empNum string
	for k, list := range body.Attributes {
		if len(list) > 0 {
			val := list[0]
			switch strings.ToLower(k) {
			case "department":
				dept = val
			case "title":
				title = val
			case "employeenumber":
				empNum = val
			default:
				attrs[k] = val
			}
		}
	}

	u := &User{
		ID:             newUUID(),
		UserName:       username,
		Email:          body.Email,
		EmailVerified:  body.EmailVerified,
		GivenName:      body.FirstName,
		FamilyName:     body.LastName,
		DisplayName:    strings.TrimSpace(body.FirstName + " " + body.LastName),
		Active:         enabled,
		Department:     dept,
		Title:          title,
		EmployeeNumber: empNum,
		Attributes:     attrs,
	}
	t.Users = append(t.Users, u)
	s.store.save()

	realm := r.PathValue("realm")
	loc := s.base + "/t/" + t.ID + "/admin/realms/" + realm + "/users/" + u.ID
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) keycloakGetUser(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "keycloak.admin"
	if s.network(w, r) {
		return
	}
	if !keycloakCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findKeycloakTenant(w, r)
	if t == nil {
		return
	}

	u := t.user(r.PathValue("id"))
	if u == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "User not found"})
		return
	}

	writeJSON(w, http.StatusOK, toKeycloakUser(u))
}

func (s *Server) keycloakUpdateUser(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "keycloak.admin"
	if s.network(w, r) {
		return
	}
	if !keycloakCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findKeycloakTenant(w, r)
	if t == nil {
		return
	}

	u := t.user(r.PathValue("id"))
	if u == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "User not found"})
		return
	}

	var body struct {
		Username      string              `json:"username"`
		Email         string              `json:"email"`
		FirstName     string              `json:"firstName"`
		LastName      string              `json:"lastName"`
		Enabled       *bool               `json:"enabled"`
		EmailVerified *bool               `json:"emailVerified"`
		Attributes    map[string][]string `json:"attributes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if body.Username != "" {
		u.UserName = body.Username
	}
	if body.Email != "" {
		u.Email = body.Email
	}
	if body.FirstName != "" {
		u.GivenName = body.FirstName
	}
	if body.LastName != "" {
		u.FamilyName = body.LastName
	}
	if body.FirstName != "" || body.LastName != "" {
		u.DisplayName = strings.TrimSpace(u.GivenName + " " + u.FamilyName)
	}
	if body.Enabled != nil {
		u.Active = *body.Enabled
	}
	if body.EmailVerified != nil {
		u.EmailVerified = *body.EmailVerified
	}
	if body.Attributes != nil {
		if u.Attributes == nil {
			u.Attributes = map[string]string{}
		}
		for k, list := range body.Attributes {
			if len(list) > 0 {
				val := list[0]
				switch strings.ToLower(k) {
				case "department":
					u.Department = val
				case "title":
					u.Title = val
				case "employeenumber":
					u.EmployeeNumber = val
				default:
					u.Attributes[k] = val
				}
			}
		}
	}

	s.store.save()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) keycloakDeleteUser(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "keycloak.admin"
	if s.network(w, r) {
		return
	}
	if !keycloakCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findKeycloakTenant(w, r)
	if t == nil {
		return
	}

	u := t.user(r.PathValue("id"))
	if u == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "User not found"})
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

func (s *Server) keycloakGetUserGroups(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "keycloak.admin"
	if s.network(w, r) {
		return
	}
	if !keycloakCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findKeycloakTenant(w, r)
	if t == nil {
		return
	}

	u := t.user(r.PathValue("id"))
	if u == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "User not found"})
		return
	}

	var res []map[string]any
	for _, g := range t.groupsOf(u.ID) {
		res = append(res, map[string]any{
			"id":   g.ID,
			"name": g.Name,
			"path": "/" + g.Name,
		})
	}
	if res == nil {
		res = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, res)
}

func (s *Server) keycloakAddUserToGroup(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "keycloak.admin"
	if s.network(w, r) {
		return
	}
	if !keycloakCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findKeycloakTenant(w, r)
	if t == nil {
		return
	}

	u := t.user(r.PathValue("id"))
	if u == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "User not found"})
		return
	}

	g := t.group(r.PathValue("groupId"))
	if g == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Group not found"})
		return
	}

	if !slices.Contains(g.Members, u.ID) {
		g.Members = append(g.Members, u.ID)
		s.store.save()
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) keycloakRemoveUserFromGroup(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "keycloak.admin"
	if s.network(w, r) {
		return
	}
	if !keycloakCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findKeycloakTenant(w, r)
	if t == nil {
		return
	}

	u := t.user(r.PathValue("id"))
	if u == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "User not found"})
		return
	}

	g := t.group(r.PathValue("groupId"))
	if g == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Group not found"})
		return
	}

	g.Members = slices.DeleteFunc(g.Members, func(mid string) bool {
		return mid == u.ID
	})
	s.store.save()

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) keycloakListGroups(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "keycloak.admin"
	if s.network(w, r) {
		return
	}
	if !keycloakCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findKeycloakTenant(w, r)
	if t == nil {
		return
	}

	search := strings.ToLower(r.URL.Query().Get("search"))
	first, _ := strconv.Atoi(r.URL.Query().Get("first"))
	if first < 0 {
		first = 0
	}
	max, _ := strconv.Atoi(r.URL.Query().Get("max"))
	if max <= 0 {
		max = 100
	}

	var matched []*Group
	for _, g := range t.Groups {
		if search == "" || strings.Contains(strings.ToLower(g.Name), search) {
			matched = append(matched, g)
		}
	}

	total := len(matched)
	if first > total {
		first = total
	}
	end := first + max
	if end > total {
		end = total
	}

	var res []map[string]any
	for _, g := range matched[first:end] {
		res = append(res, toKeycloakGroup(g))
	}
	if res == nil {
		res = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, res)
}

func (s *Server) keycloakCreateGroup(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "keycloak.admin"
	if s.network(w, r) {
		return
	}
	if !keycloakCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findKeycloakTenant(w, r)
	if t == nil {
		return
	}

	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	g := &Group{
		ID:      newUUID(),
		Name:    body.Name,
		Members: []string{},
	}
	t.Groups = append(t.Groups, g)
	s.store.save()

	realm := r.PathValue("realm")
	loc := s.base + "/t/" + t.ID + "/admin/realms/" + realm + "/groups/" + g.ID
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) keycloakGetGroup(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "keycloak.admin"
	if s.network(w, r) {
		return
	}
	if !keycloakCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findKeycloakTenant(w, r)
	if t == nil {
		return
	}

	g := t.group(r.PathValue("id"))
	if g == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Group not found"})
		return
	}

	writeJSON(w, http.StatusOK, toKeycloakGroup(g))
}

func (s *Server) keycloakUpdateGroup(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "keycloak.admin"
	if s.network(w, r) {
		return
	}
	if !keycloakCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findKeycloakTenant(w, r)
	if t == nil {
		return
	}

	g := t.group(r.PathValue("id"))
	if g == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Group not found"})
		return
	}

	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if body.Name != "" {
		g.Name = body.Name
	}
	s.store.save()

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) keycloakDeleteGroup(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "keycloak.admin"
	if s.network(w, r) {
		return
	}
	if !keycloakCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findKeycloakTenant(w, r)
	if t == nil {
		return
	}

	g := t.group(r.PathValue("id"))
	if g == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Group not found"})
		return
	}

	t.Groups = slices.DeleteFunc(t.Groups, func(item *Group) bool {
		return item.ID == g.ID
	})
	s.store.save()

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) keycloakGetGroupMembers(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "keycloak.admin"
	if s.network(w, r) {
		return
	}
	if !keycloakCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findKeycloakTenant(w, r)
	if t == nil {
		return
	}

	g := t.group(r.PathValue("id"))
	if g == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Group not found"})
		return
	}

	first, _ := strconv.Atoi(r.URL.Query().Get("first"))
	if first < 0 {
		first = 0
	}
	max, _ := strconv.Atoi(r.URL.Query().Get("max"))
	if max <= 0 {
		max = 100
	}

	var members []*User
	for _, mid := range g.Members {
		if u := t.user(mid); u != nil {
			members = append(members, u)
		}
	}

	total := len(members)
	if first > total {
		first = total
	}
	end := first + max
	if end > total {
		end = total
	}

	var res []map[string]any
	for _, u := range members[first:end] {
		res = append(res, toKeycloakUser(u))
	}
	if res == nil {
		res = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, res)
}

func (s *Server) keycloakListEvents(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "keycloak.admin"
	if s.network(w, r) {
		return
	}
	if !keycloakCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	t := s.findKeycloakTenant(w, r)
	s.store.mu.Unlock()
	if t == nil {
		return
	}

	realm := r.PathValue("realm")
	entries := s.logs.list(t.ID, "", "", "", 0, 100)
	var events []map[string]any
	for _, e := range entries {
		evtType := "LOGIN"
		if e.Status >= 400 || e.Level == "error" {
			evtType = "LOGIN_ERROR"
		}
		events = append(events, map[string]any{
			"time":      e.Time.UnixMilli(),
			"type":      evtType,
			"realmId":   realm,
			"clientId":  "account",
			"userId":    "user_1001",
			"ipAddress": "127.0.0.1",
			"details": map[string]string{
				"username": "alice@" + t.Domain,
			},
		})
	}

	if len(events) == 0 {
		events = append(events, map[string]any{
			"time":      time.Now().UnixMilli(),
			"type":      "LOGIN",
			"realmId":   realm,
			"clientId":  "account",
			"userId":    "user_1001",
			"ipAddress": "127.0.0.1",
			"details": map[string]string{
				"username": "alice@" + t.Domain,
			},
		})
	}

	writeJSON(w, http.StatusOK, events)
}

func (s *Server) keycloakListAdminEvents(w http.ResponseWriter, r *http.Request) {
	// For Keycloak admin events, return events array matching the endpoint
	s.keycloakListEvents(w, r)
}
