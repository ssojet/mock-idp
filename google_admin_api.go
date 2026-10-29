package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

var googleAdminAPIRegistered sync.Map

func (s *Server) registerGoogleAdminAPI() {
	if _, loaded := googleAdminAPIRegistered.LoadOrStore(s.mux, true); loaded {
		return
	}
	h := func(pattern string, fn http.HandlerFunc) { s.mux.Handle(pattern, s.traced(fn)) }

	// Directory v1 Users
	h("GET /t/{tenant}/admin/directory/v1/users", s.googleListUsers)
	h("POST /t/{tenant}/admin/directory/v1/users", s.googleCreateUser)
	h("GET /t/{tenant}/admin/directory/v1/users/{userKey}", s.googleGetUser)
	h("PUT /t/{tenant}/admin/directory/v1/users/{userKey}", s.googleUpdateUser)
	h("PATCH /t/{tenant}/admin/directory/v1/users/{userKey}", s.googlePatchUser)
	h("DELETE /t/{tenant}/admin/directory/v1/users/{userKey}", s.googleDeleteUser)

	// Directory v1 Groups
	h("GET /t/{tenant}/admin/directory/v1/groups", s.googleListGroups)
	h("POST /t/{tenant}/admin/directory/v1/groups", s.googleCreateGroup)
	h("GET /t/{tenant}/admin/directory/v1/groups/{groupKey}", s.googleGetGroup)
	h("PUT /t/{tenant}/admin/directory/v1/groups/{groupKey}", s.googleUpdateGroup)
	h("PATCH /t/{tenant}/admin/directory/v1/groups/{groupKey}", s.googlePatchGroup)
	h("DELETE /t/{tenant}/admin/directory/v1/groups/{groupKey}", s.googleDeleteGroup)

	// Directory v1 Group Members
	h("GET /t/{tenant}/admin/directory/v1/groups/{groupKey}/members", s.googleListGroupMembers)
	h("POST /t/{tenant}/admin/directory/v1/groups/{groupKey}/members", s.googleAddGroupMember)
	h("DELETE /t/{tenant}/admin/directory/v1/groups/{groupKey}/members/{memberKey}", s.googleRemoveGroupMember)

	// Reports v1 Activities
	h("GET /t/{tenant}/admin/reports/v1/activity/users/{userKey}/applications/{applicationName}", s.googleListActivities)
}

func writeGoogleErr(w http.ResponseWriter, code int, msg, reason string) {
	if reason == "" {
		reason = http.StatusText(code)
	}
	writeJSON(w, code, map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": msg,
			"errors": []map[string]any{
				{
					"message": msg,
					"domain":  "global",
					"reason":  reason,
				},
			},
		},
	})
}

func googleCheckAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == "" {
		writeGoogleErr(w, http.StatusUnauthorized, "Request had invalid authentication credentials.", "authError")
		return false
	}
	return true
}

func (s *Server) findGoogleTenant(w http.ResponseWriter, r *http.Request) *Tenant {
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
		writeGoogleErr(w, http.StatusNotFound, "Tenant not found: "+id, "notFound")
		return nil
	}
	return t
}

func findGoogleUser(t *Tenant, userKey string) *User {
	for _, u := range t.Users {
		if u.ID == userKey || strings.EqualFold(u.Email, userKey) || strings.EqualFold(u.UserName, userKey) {
			return u
		}
	}
	return nil
}

func findGoogleGroup(t *Tenant, groupKey string) *Group {
	for _, g := range t.Groups {
		groupEmail := slug(g.Name) + "@" + t.Domain
		if g.ID == groupKey || strings.EqualFold(g.Name, groupKey) || strings.EqualFold(groupEmail, groupKey) {
			return g
		}
	}
	return nil
}

func (s *Server) toGoogleUser(t *Tenant, u *User) map[string]any {
	isAdmin := u.Attributes != nil && u.Attributes["isAdmin"] == "true"
	for _, g := range t.Groups {
		if strings.EqualFold(g.Name, "Admins") || strings.EqualFold(g.Name, "Super Admins") {
			if slices.Contains(g.Members, u.ID) {
				isAdmin = true
				break
			}
		}
	}

	custID := t.ExternalID
	if custID == "" {
		custID = "C01234567"
	}

	displayName := u.DisplayName
	if displayName == "" {
		displayName = strings.TrimSpace(u.GivenName + " " + u.FamilyName)
		if displayName == "" {
			displayName = u.Email
		}
	}

	res := map[string]any{
		"kind":         "admin#directory#user",
		"id":           u.ID,
		"primaryEmail": u.Email,
		"name": map[string]any{
			"givenName":  u.GivenName,
			"familyName": u.FamilyName,
			"fullName":   displayName,
		},
		"isAdmin":                   isAdmin,
		"isDelegatedAdmin":          false,
		"suspended":                 !u.Active,
		"archived":                  false,
		"changePasswordAtNextLogin": false,
		"ipWhitelisted":             false,
		"creationTime":              "2025-01-01T00:00:00.000Z",
		"lastLoginTime":             "2025-01-01T00:00:00.000Z",
		"customerId":                custID,
		"orgUnitPath":               "/",
		"isMailboxSetup":            true,
		"emails": []map[string]any{
			{"address": u.Email, "primary": true},
		},
	}

	if u.Title != "" || u.Department != "" {
		res["organizations"] = []map[string]any{
			{
				"title":      u.Title,
				"department": u.Department,
				"primary":    true,
			},
		}
	} else {
		res["organizations"] = []map[string]any{}
	}

	if u.Phone != "" {
		res["phones"] = []map[string]any{
			{"value": u.Phone, "type": "work"},
		}
	} else {
		res["phones"] = []map[string]any{}
	}

	if u.EmployeeNumber != "" {
		res["externalIds"] = []map[string]any{
			{"value": u.EmployeeNumber, "type": "organization"},
		}
	} else {
		res["externalIds"] = []map[string]any{}
	}

	return res
}

func (s *Server) toGoogleGroup(t *Tenant, g *Group) map[string]any {
	return map[string]any{
		"kind":               "admin#directory#group",
		"id":                 g.ID,
		"email":              slug(g.Name) + "@" + t.Domain,
		"name":               g.Name,
		"description":        g.Name,
		"directMembersCount": fmt.Sprint(len(g.Members)),
	}
}

func matchGoogleQuery(u *User, q string) bool {
	if q == "" {
		return true
	}
	q = strings.TrimSpace(q)
	// Check for key:value or key=value query
	parts := strings.Fields(q)
	for _, part := range parts {
		var k, v string
		var found bool
		if strings.Contains(part, ":") {
			k, v, found = strings.Cut(part, ":")
		} else if strings.Contains(part, "=") {
			k, v, found = strings.Cut(part, "=")
		}
		if found {
			k = strings.TrimSpace(k)
			v = strings.Trim(strings.TrimSpace(v), `"'`)
			switch strings.ToLower(k) {
			case "email":
				if !matchWildcardOrSubstring(u.Email, v) {
					return false
				}
			case "givenname":
				if !matchWildcardOrSubstring(u.GivenName, v) {
					return false
				}
			case "familyname":
				if !matchWildcardOrSubstring(u.FamilyName, v) {
					return false
				}
			case "issuspended":
				suspended := strconv.FormatBool(!u.Active)
				if !strings.EqualFold(suspended, v) {
					return false
				}
			case "orgdepartment":
				if !strings.EqualFold(u.Department, v) && !strings.Contains(strings.ToLower(u.Department), strings.ToLower(v)) {
					return false
				}
			case "orgtitle":
				if !strings.EqualFold(u.Title, v) && !strings.Contains(strings.ToLower(u.Title), strings.ToLower(v)) {
					return false
				}
			default:
				if u.Attributes != nil {
					if val, ok := u.Attributes[k]; ok {
						if !matchWildcardOrSubstring(val, v) {
							return false
						}
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

func (s *Server) googleListUsers(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "google.admin"
	if s.network(w, r) {
		return
	}
	if !googleCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findGoogleTenant(w, r)
	if t == nil {
		return
	}

	domain := r.URL.Query().Get("domain")
	query := r.URL.Query().Get("query")
	maxResults, _ := strconv.Atoi(r.URL.Query().Get("maxResults"))
	if maxResults <= 0 {
		maxResults = 100
	}
	pageToken := r.URL.Query().Get("pageToken")

	offset := 0
	if pageToken != "" {
		if b, err := base64.StdEncoding.DecodeString(pageToken); err == nil {
			if n, err := strconv.Atoi(string(b)); err == nil && n >= 0 {
				offset = n
			}
		}
	}

	var matched []*User
	for _, u := range t.Users {
		if domain != "" && !strings.HasSuffix(strings.ToLower(u.Email), "@"+strings.ToLower(domain)) {
			continue
		}
		if matchGoogleQuery(u, query) {
			matched = append(matched, u)
		}
	}

	total := len(matched)
	if offset > total {
		offset = total
	}
	end := offset + maxResults
	if end > total {
		end = total
	}

	var usersList []map[string]any
	for _, u := range matched[offset:end] {
		usersList = append(usersList, s.toGoogleUser(t, u))
	}
	if usersList == nil {
		usersList = []map[string]any{}
	}

	resp := map[string]any{
		"kind":  "admin#directory#users",
		"users": usersList,
	}
	if end < total {
		resp["nextPageToken"] = base64.StdEncoding.EncodeToString([]byte(fmt.Sprint(end)))
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) googleCreateUser(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "google.admin"
	if s.network(w, r) {
		return
	}
	if !googleCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findGoogleTenant(w, r)
	if t == nil {
		return
	}

	var body struct {
		PrimaryEmail string `json:"primaryEmail"`
		Password     string `json:"password"`
		Suspended    bool   `json:"suspended"`
		Name         struct {
			GivenName  string `json:"givenName"`
			FamilyName string `json:"familyName"`
			FullName   string `json:"fullName"`
		} `json:"name"`
		Organizations []struct {
			Title      string `json:"title"`
			Department string `json:"department"`
		} `json:"organizations"`
		Phones []struct {
			Value string `json:"value"`
			Type  string `json:"type"`
		} `json:"phones"`
		ExternalIds []struct {
			Value string `json:"value"`
			Type  string `json:"type"`
		} `json:"externalIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeGoogleErr(w, http.StatusBadRequest, err.Error(), "badRequest")
		return
	}

	if body.PrimaryEmail == "" {
		writeGoogleErr(w, http.StatusBadRequest, "primaryEmail is required", "badRequest")
		return
	}

	fullName := body.Name.FullName
	if fullName == "" {
		fullName = strings.TrimSpace(body.Name.GivenName + " " + body.Name.FamilyName)
	}

	var title, dept string
	if len(body.Organizations) > 0 {
		title = body.Organizations[0].Title
		dept = body.Organizations[0].Department
	}
	var phone string
	if len(body.Phones) > 0 {
		phone = body.Phones[0].Value
	}
	var extID string
	if len(body.ExternalIds) > 0 {
		extID = body.ExternalIds[0].Value
	}

	u := &User{
		ID:             newID("google", "user"),
		UserName:       body.PrimaryEmail,
		Email:          body.PrimaryEmail,
		EmailVerified:  true,
		GivenName:      body.Name.GivenName,
		FamilyName:     body.Name.FamilyName,
		DisplayName:    fullName,
		Password:       body.Password,
		Active:         !body.Suspended,
		Title:          title,
		Department:     dept,
		Phone:          phone,
		EmployeeNumber: extID,
		Attributes:     map[string]string{},
	}
	t.Users = append(t.Users, u)
	s.store.save()

	writeJSON(w, http.StatusCreated, s.toGoogleUser(t, u))
}

func (s *Server) googleGetUser(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "google.admin"
	if s.network(w, r) {
		return
	}
	if !googleCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findGoogleTenant(w, r)
	if t == nil {
		return
	}

	u := findGoogleUser(t, r.PathValue("userKey"))
	if u == nil {
		writeGoogleErr(w, http.StatusNotFound, "Resource Not Found: userKey", "notFound")
		return
	}

	writeJSON(w, http.StatusOK, s.toGoogleUser(t, u))
}

func (s *Server) googleUpdateUser(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "google.admin"
	if s.network(w, r) {
		return
	}
	if !googleCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findGoogleTenant(w, r)
	if t == nil {
		return
	}

	u := findGoogleUser(t, r.PathValue("userKey"))
	if u == nil {
		writeGoogleErr(w, http.StatusNotFound, "Resource Not Found: userKey", "notFound")
		return
	}

	var body struct {
		PrimaryEmail string `json:"primaryEmail"`
		Password     string `json:"password"`
		Suspended    *bool  `json:"suspended"`
		Name         *struct {
			GivenName  string `json:"givenName"`
			FamilyName string `json:"familyName"`
			FullName   string `json:"fullName"`
		} `json:"name"`
		Organizations []struct {
			Title      string `json:"title"`
			Department string `json:"department"`
		} `json:"organizations"`
		Phones []struct {
			Value string `json:"value"`
			Type  string `json:"type"`
		} `json:"phones"`
		ExternalIds []struct {
			Value string `json:"value"`
			Type  string `json:"type"`
		} `json:"externalIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeGoogleErr(w, http.StatusBadRequest, err.Error(), "badRequest")
		return
	}

	if body.PrimaryEmail != "" {
		u.Email = body.PrimaryEmail
		u.UserName = body.PrimaryEmail
	}
	if body.Password != "" {
		u.Password = body.Password
	}
	if body.Suspended != nil {
		u.Active = !*body.Suspended
	}
	if body.Name != nil {
		if body.Name.GivenName != "" {
			u.GivenName = body.Name.GivenName
		}
		if body.Name.FamilyName != "" {
			u.FamilyName = body.Name.FamilyName
		}
		if body.Name.FullName != "" {
			u.DisplayName = body.Name.FullName
		} else {
			u.DisplayName = strings.TrimSpace(u.GivenName + " " + u.FamilyName)
		}
	}
	if len(body.Organizations) > 0 {
		u.Title = body.Organizations[0].Title
		u.Department = body.Organizations[0].Department
	}
	if len(body.Phones) > 0 {
		u.Phone = body.Phones[0].Value
	}
	if len(body.ExternalIds) > 0 {
		u.EmployeeNumber = body.ExternalIds[0].Value
	}

	s.store.save()
	writeJSON(w, http.StatusOK, s.toGoogleUser(t, u))
}

func (s *Server) googlePatchUser(w http.ResponseWriter, r *http.Request) {
	// PATCH has identical behavior to PUT in this context
	s.googleUpdateUser(w, r)
}

func (s *Server) googleDeleteUser(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "google.admin"
	if s.network(w, r) {
		return
	}
	if !googleCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findGoogleTenant(w, r)
	if t == nil {
		return
	}

	u := findGoogleUser(t, r.PathValue("userKey"))
	if u == nil {
		writeGoogleErr(w, http.StatusNotFound, "Resource Not Found: userKey", "notFound")
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

func (s *Server) googleListGroups(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "google.admin"
	if s.network(w, r) {
		return
	}
	if !googleCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findGoogleTenant(w, r)
	if t == nil {
		return
	}

	userKey := r.URL.Query().Get("userKey")
	var targetUser *User
	if userKey != "" {
		targetUser = findGoogleUser(t, userKey)
		if targetUser == nil {
			writeGoogleErr(w, http.StatusNotFound, "Resource Not Found: userKey", "notFound")
			return
		}
	}

	maxResults, _ := strconv.Atoi(r.URL.Query().Get("maxResults"))
	if maxResults <= 0 {
		maxResults = 100
	}
	pageToken := r.URL.Query().Get("pageToken")
	offset := 0
	if pageToken != "" {
		if b, err := base64.StdEncoding.DecodeString(pageToken); err == nil {
			if n, err := strconv.Atoi(string(b)); err == nil && n >= 0 {
				offset = n
			}
		}
	}

	var matched []*Group
	for _, g := range t.Groups {
		if targetUser != nil && !slices.Contains(g.Members, targetUser.ID) {
			continue
		}
		matched = append(matched, g)
	}

	total := len(matched)
	if offset > total {
		offset = total
	}
	end := offset + maxResults
	if end > total {
		end = total
	}

	var groupList []map[string]any
	for _, g := range matched[offset:end] {
		groupList = append(groupList, s.toGoogleGroup(t, g))
	}
	if groupList == nil {
		groupList = []map[string]any{}
	}

	resp := map[string]any{
		"kind":   "admin#directory#groups",
		"groups": groupList,
	}
	if end < total {
		resp["nextPageToken"] = base64.StdEncoding.EncodeToString([]byte(fmt.Sprint(end)))
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) googleCreateGroup(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "google.admin"
	if s.network(w, r) {
		return
	}
	if !googleCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findGoogleTenant(w, r)
	if t == nil {
		return
	}

	var body struct {
		Name        string `json:"name"`
		Email       string `json:"email"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeGoogleErr(w, http.StatusBadRequest, err.Error(), "badRequest")
		return
	}

	name := body.Name
	if name == "" && body.Email != "" {
		name = strings.Split(body.Email, "@")[0]
	}

	g := &Group{
		ID:      newID("google", "group"),
		Name:    name,
		Members: []string{},
	}
	t.Groups = append(t.Groups, g)
	s.store.save()

	writeJSON(w, http.StatusCreated, s.toGoogleGroup(t, g))
}

func (s *Server) googleGetGroup(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "google.admin"
	if s.network(w, r) {
		return
	}
	if !googleCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findGoogleTenant(w, r)
	if t == nil {
		return
	}

	g := findGoogleGroup(t, r.PathValue("groupKey"))
	if g == nil {
		writeGoogleErr(w, http.StatusNotFound, "Resource Not Found: groupKey", "notFound")
		return
	}

	writeJSON(w, http.StatusOK, s.toGoogleGroup(t, g))
}

func (s *Server) googleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "google.admin"
	if s.network(w, r) {
		return
	}
	if !googleCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findGoogleTenant(w, r)
	if t == nil {
		return
	}

	g := findGoogleGroup(t, r.PathValue("groupKey"))
	if g == nil {
		writeGoogleErr(w, http.StatusNotFound, "Resource Not Found: groupKey", "notFound")
		return
	}

	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeGoogleErr(w, http.StatusBadRequest, err.Error(), "badRequest")
		return
	}

	if body.Name != "" {
		g.Name = body.Name
	}
	s.store.save()

	writeJSON(w, http.StatusOK, s.toGoogleGroup(t, g))
}

func (s *Server) googlePatchGroup(w http.ResponseWriter, r *http.Request) {
	s.googleUpdateGroup(w, r)
}

func (s *Server) googleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "google.admin"
	if s.network(w, r) {
		return
	}
	if !googleCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findGoogleTenant(w, r)
	if t == nil {
		return
	}

	g := findGoogleGroup(t, r.PathValue("groupKey"))
	if g == nil {
		writeGoogleErr(w, http.StatusNotFound, "Resource Not Found: groupKey", "notFound")
		return
	}

	t.Groups = slices.DeleteFunc(t.Groups, func(item *Group) bool {
		return item.ID == g.ID
	})
	s.store.save()

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) googleListGroupMembers(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "google.admin"
	if s.network(w, r) {
		return
	}
	if !googleCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findGoogleTenant(w, r)
	if t == nil {
		return
	}

	g := findGoogleGroup(t, r.PathValue("groupKey"))
	if g == nil {
		writeGoogleErr(w, http.StatusNotFound, "Resource Not Found: groupKey", "notFound")
		return
	}

	var members []map[string]any
	for _, uid := range g.Members {
		if u := t.user(uid); u != nil {
			members = append(members, map[string]any{
				"kind":   "admin#directory#member",
				"id":     u.ID,
				"email":  u.Email,
				"role":   "MEMBER",
				"type":   "USER",
				"status": "ACTIVE",
			})
		}
	}
	if members == nil {
		members = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"kind":    "admin#directory#members",
		"members": members,
	})
}

func (s *Server) googleAddGroupMember(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "google.admin"
	if s.network(w, r) {
		return
	}
	if !googleCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findGoogleTenant(w, r)
	if t == nil {
		return
	}

	g := findGoogleGroup(t, r.PathValue("groupKey"))
	if g == nil {
		writeGoogleErr(w, http.StatusNotFound, "Resource Not Found: groupKey", "notFound")
		return
	}

	var body struct {
		Email string `json:"email"`
		ID    string `json:"id"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeGoogleErr(w, http.StatusBadRequest, err.Error(), "badRequest")
		return
	}

	ref := body.ID
	if ref == "" {
		ref = body.Email
	}
	u := findGoogleUser(t, ref)
	if u == nil {
		writeGoogleErr(w, http.StatusNotFound, "Resource Not Found: user", "notFound")
		return
	}

	if !slices.Contains(g.Members, u.ID) {
		g.Members = append(g.Members, u.ID)
		s.store.save()
	}

	role := body.Role
	if role == "" {
		role = "MEMBER"
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"kind":   "admin#directory#member",
		"id":     u.ID,
		"email":  u.Email,
		"role":   role,
		"type":   "USER",
		"status": "ACTIVE",
	})
}

func (s *Server) googleRemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "google.admin"
	if s.network(w, r) {
		return
	}
	if !googleCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.findGoogleTenant(w, r)
	if t == nil {
		return
	}

	g := findGoogleGroup(t, r.PathValue("groupKey"))
	if g == nil {
		writeGoogleErr(w, http.StatusNotFound, "Resource Not Found: groupKey", "notFound")
		return
	}

	memberKey := r.PathValue("memberKey")
	var targetUID string
	if u := findGoogleUser(t, memberKey); u != nil {
		targetUID = u.ID
	} else {
		targetUID = memberKey
	}

	g.Members = slices.DeleteFunc(g.Members, func(mid string) bool {
		return mid == targetUID
	})
	s.store.save()

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) googleListActivities(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "google.admin"
	if s.network(w, r) {
		return
	}
	if !googleCheckAuth(w, r) {
		return
	}
	s.store.mu.Lock()
	t := s.findGoogleTenant(w, r)
	s.store.mu.Unlock()
	if t == nil {
		return
	}

	userKey := r.PathValue("userKey")
	appName := r.PathValue("applicationName")

	custID := t.ExternalID
	if custID == "" {
		custID = "C01234567"
	}

	entries := s.logs.list(t.ID, "", "", "", 0, 100)
	var items []map[string]any
	for _, e := range entries {
		actorEmail := "alice@" + t.Domain
		actorID := "10000000001"
		if userKey != "all" {
			if strings.Contains(userKey, "@") {
				actorEmail = userKey
			}
		}

		evtName := "login_success"
		if e.Status >= 400 || e.Level == "error" {
			evtName = "login_failure"
		}

		items = append(items, map[string]any{
			"kind": "admin#reports#activity",
			"id": map[string]any{
				"time":            e.Time.Format(time.RFC3339Nano),
				"uniqueQualifier": fmt.Sprintf("%d", e.ID),
				"applicationName": appName,
				"customerId":      custID,
			},
			"actor": map[string]any{
				"email":     actorEmail,
				"profileId": actorID,
			},
			"ipAddress": "127.0.0.1",
			"events": []map[string]any{
				{
					"type": "login",
					"name": evtName,
					"parameters": []map[string]any{
						{
							"name":  "login_type",
							"value": "exchange",
						},
					},
				},
			},
		})
	}

	if len(items) == 0 {
		actorEmail := "alice@" + t.Domain
		if userKey != "all" && strings.Contains(userKey, "@") {
			actorEmail = userKey
		}
		items = append(items, map[string]any{
			"kind": "admin#reports#activity",
			"id": map[string]any{
				"time":            time.Now().UTC().Format(time.RFC3339Nano),
				"uniqueQualifier": "act_001",
				"applicationName": appName,
				"customerId":      custID,
			},
			"actor": map[string]any{
				"email":     actorEmail,
				"profileId": "10000000001",
			},
			"ipAddress": "127.0.0.1",
			"events": []map[string]any{
				{
					"type": "login",
					"name": "login_success",
					"parameters": []map[string]any{
						{
							"name":  "login_type",
							"value": "exchange",
						},
					},
				},
			},
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"kind":  "admin#reports#activities",
		"items": items,
	})
}
