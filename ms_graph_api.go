package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

var msGraphAPIRegistered sync.Map

func (s *Server) registerMSGraphAPI() {
	if _, loaded := msGraphAPIRegistered.LoadOrStore(s.mux, true); loaded {
		return
	}
	h := func(pattern string, fn http.HandlerFunc) { s.mux.Handle(pattern, s.traced(fn)) }

	// Organization & Me
	h("GET /t/{tenant}/v1.0/organization", s.graphOrganization)
	h("GET /t/{tenant}/v1.0/me", s.graphMe)
	h("GET /t/{tenant}/v1.0/me/memberOf", s.graphMeMemberOf)

	// Users
	h("GET /t/{tenant}/v1.0/users", s.graphListUsers)
	h("POST /t/{tenant}/v1.0/users", s.graphCreateUser)
	h("GET /t/{tenant}/v1.0/users/{id}", s.graphGetUser)
	h("PATCH /t/{tenant}/v1.0/users/{id}", s.graphUpdateUser)
	h("DELETE /t/{tenant}/v1.0/users/{id}", s.graphDeleteUser)
	h("GET /t/{tenant}/v1.0/users/{id}/memberOf", s.graphUserMemberOf)
	h("GET /t/{tenant}/v1.0/users/{id}/transitiveMemberOf", s.graphUserMemberOf)
	h("POST /t/{tenant}/v1.0/users/{id}/getMemberGroups", s.graphGetMemberObjects)
	h("POST /t/{tenant}/v1.0/users/{id}/getMemberObjects", s.graphGetMemberObjects)
	h("POST /t/{tenant}/v1.0/directoryObjects/{id}/getMemberObjects", s.graphGetMemberObjects)
	h("POST /t/{tenant}/users/{id}/getMemberObjects", s.graphGetMemberObjects)

	// Groups
	h("GET /t/{tenant}/v1.0/groups", s.graphListGroups)
	h("POST /t/{tenant}/v1.0/groups", s.graphCreateGroup)
	h("GET /t/{tenant}/v1.0/groups/{id}", s.graphGetGroup)
	h("PATCH /t/{tenant}/v1.0/groups/{id}", s.graphUpdateGroup)
	h("DELETE /t/{tenant}/v1.0/groups/{id}", s.graphDeleteGroup)
	h("GET /t/{tenant}/v1.0/groups/{id}/members", s.graphGroupMembers)
	h("GET /t/{tenant}/v1.0/groups/{id}/transitiveMembers", s.graphGroupMembers)
	h("POST /t/{tenant}/v1.0/groups/{id}/members/$ref", s.graphAddGroupMember)
	h("DELETE /t/{tenant}/v1.0/groups/{id}/members/{uid}/$ref", s.graphRemoveGroupMember)

	// ServicePrincipals, Applications & AuditLogs
	h("GET /t/{tenant}/v1.0/servicePrincipals", s.graphServicePrincipals)
	h("GET /t/{tenant}/v1.0/applications", s.graphApplications)
	h("GET /t/{tenant}/v1.0/auditLogs/signIns", s.graphSignIns)
	h("GET /t/{tenant}/v1.0/auditLogs/directoryAudits", s.graphDirectoryAudits)
}

func graphAuth(w http.ResponseWriter, r *http.Request) (string, bool) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(auth) < 7 || !strings.EqualFold(auth[:7], "Bearer ") {
		graphErr(w, r, http.StatusUnauthorized, "InvalidAuthenticationToken", "Access token is empty or invalid.")
		return "", false
	}
	tok := strings.TrimSpace(auth[7:])
	if tok == "" {
		graphErr(w, r, http.StatusUnauthorized, "InvalidAuthenticationToken", "Access token is empty or invalid.")
		return "", false
	}
	return tok, true
}

func graphErr(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	entry(r).warn("graph error %s (%d): %s", code, status, message)
	reqID := newUUID()
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
			"innerError": map[string]any{
				"date":              time.Now().UTC().Format("2006-01-02T15:04:05"),
				"request-id":        reqID,
				"client-request-id": reqID,
			},
		},
	})
}

func (s *Server) graphTenant(w http.ResponseWriter, r *http.Request) *Tenant {
	id := r.PathValue("tenant")
	t := s.store.tenant(id)
	if t == nil {
		graphErr(w, r, http.StatusNotFound, "Request_ResourceNotFound", fmt.Sprintf("Resource '%s' does not exist or one of its queried reference-property objects are not present.", id))
		return nil
	}
	entry(r).Sims = activeSims(t.Sims)
	return t
}

func resolveGraphMeUser(t *Tenant, r *http.Request, tok string) *User {
	if hdr := strings.TrimSpace(r.Header.Get("X-Ms-Graph-User")); hdr != "" {
		if u := t.user(hdr); u != nil {
			return u
		}
	}
	if parts := strings.Split(tok, "."); len(parts) == 3 {
		if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "=")); err == nil {
			var claims map[string]any
			if json.Unmarshal(b, &claims) == nil {
				for _, key := range []string{"oid", "sub", "upn", "preferred_username", "email", "unique_name", "uid"} {
					if ref := str(claims[key]); ref != "" {
						if u := t.user(ref); u != nil {
							return u
						}
					}
				}
				if sub := str(claims["sub"]); sub != "" {
					for _, app := range t.Apps {
						for _, u := range t.Users {
							if subject(t, app, u) == sub {
								return u
							}
						}
					}
				}
			}
		}
	}
	for _, u := range t.Users {
		if u.Active {
			return u
		}
	}
	if len(t.Users) > 0 {
		return t.Users[0]
	}
	return nil
}

// ---- Graph Resource Shapes ----

func (s *Server) graphUserJSON(t *Tenant, u *User, expand string) map[string]any {
	var mail any
	if u.Email != "" {
		mail = u.Email
	}
	var phone any
	if u.Phone != "" {
		phone = u.Phone
	}
	nick := u.UserName
	if idx := strings.Index(nick, "@"); idx > 0 {
		nick = nick[:idx]
	}
	userType := "Member"
	if strings.Contains(u.UserName, "#EXT#") {
		userType = "Guest"
	}
	m := map[string]any{
		"@odata.type":       "#microsoft.graph.user",
		"id":                u.ID,
		"displayName":       u.DisplayName,
		"givenName":         u.GivenName,
		"surname":           u.FamilyName,
		"userPrincipalName": u.UserName,
		"mail":              mail,
		"mailNickname":      nick,
		"jobTitle":          u.Title,
		"department":        u.Department,
		"mobilePhone":       phone,
		"employeeId":        u.EmployeeNumber,
		"accountEnabled":    u.Active,
		"userType":          userType,
		"businessPhones":    []string{},
	}
	if u.Phone != "" {
		m["businessPhones"] = []string{u.Phone}
	}
	for _, ex := range strings.Split(expand, ",") {
		if strings.EqualFold(strings.TrimSpace(ex), "memberOf") {
			groups := t.groupsOf(u.ID)
			mo := make([]map[string]any, 0, len(groups))
			for _, g := range groups {
				mo = append(mo, s.graphGroupJSON(t, g, ""))
			}
			m["memberOf"] = mo
		}
	}
	return m
}

func (s *Server) graphGroupJSON(t *Tenant, g *Group, expand string) map[string]any {
	m := map[string]any{
		"@odata.type":     "#microsoft.graph.group",
		"id":              g.ID,
		"displayName":     g.Name,
		"description":     g.Name + " group",
		"mail":            nil,
		"mailEnabled":     false,
		"mailNickname":    slug(g.Name),
		"securityEnabled": true,
		"groupTypes":      []string{},
	}
	for _, ex := range strings.Split(expand, ",") {
		if strings.EqualFold(strings.TrimSpace(ex), "members") {
			members := make([]map[string]any, 0, len(g.Members))
			for _, uid := range g.Members {
				if u := t.user(uid); u != nil {
					members = append(members, s.graphUserJSON(t, u, ""))
				}
			}
			m["members"] = members
		}
	}
	return m
}

// ---- OData $filter, $search, $select, $top, $skiptoken, $count ----

func applyGraphSelect(item map[string]any, selectParam, expandParam string) map[string]any {
	selectParam = strings.TrimSpace(selectParam)
	if selectParam == "" {
		return item
	}
	keep := map[string]bool{
		"@odata.type":    true,
		"@odata.context": true,
		"id":             true,
	}
	for _, f := range strings.Split(selectParam, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			keep[strings.ToLower(f)] = true
		}
	}
	for _, f := range strings.Split(expandParam, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			keep[strings.ToLower(f)] = true
		}
	}
	out := map[string]any{}
	for k, v := range item {
		if keep[k] || keep[strings.ToLower(k)] {
			out[k] = v
		}
	}
	return out
}

func (s *Server) graphCollectionResponse(r *http.Request, t *Tenant, entitySet string, items []map[string]any) map[string]any {
	q := r.URL.Query()
	selectParam := q.Get("$select")
	expandParam := q.Get("$expand")
	countParam := strings.EqualFold(q.Get("$count"), "true")
	totalCount := len(items)

	skiptoken := q.Get("$skiptoken")
	if skiptoken != "" {
		idx := -1
		for i, item := range items {
			if str(item["id"]) == skiptoken {
				idx = i
				break
			}
		}
		if idx >= 0 {
			items = items[idx+1:]
		} else if off, err := strconv.Atoi(skiptoken); err == nil && off >= 0 && off <= len(items) {
			items = items[off:]
		} else {
			items = []map[string]any{}
		}
	}

	top, err := strconv.Atoi(q.Get("$top"))
	if err != nil || top <= 0 {
		top = 100
	}
	hasMore := false
	nextToken := ""
	if len(items) > top {
		hasMore = true
		items = items[:top]
		nextToken = str(items[len(items)-1]["id"])
	}

	selected := make([]map[string]any, 0, len(items))
	for _, it := range items {
		selected = append(selected, applyGraphSelect(it, selectParam, expandParam))
	}

	out := map[string]any{
		"@odata.context": fmt.Sprintf("%s/t/%s/v1.0/$metadata#%s", s.base, t.ID, entitySet),
		"value":          selected,
	}
	if countParam {
		out["@odata.count"] = totalCount
	}
	if hasMore && nextToken != "" {
		nextVals := url.Values{}
		for k, v := range q {
			nextVals[k] = slices.Clone(v)
		}
		nextVals.Set("$skiptoken", nextToken)
		nextVals.Set("$top", strconv.Itoa(top))
		out["@odata.nextLink"] = s.base + r.URL.Path + "?" + nextVals.Encode()
	}
	return out
}

func evalGraphFilter(expr string, item map[string]any) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return true
	}
	for strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") && oktaParensBalanced(expr[1:len(expr)-1]) {
		expr = strings.TrimSpace(expr[1 : len(expr)-1])
	}
	if parts := splitOktaLogical(expr, "or"); len(parts) > 1 {
		for _, p := range parts {
			if evalGraphFilter(p, item) {
				return true
			}
		}
		return false
	}
	if parts := splitOktaLogical(expr, "and"); len(parts) > 1 {
		for _, p := range parts {
			if !evalGraphFilter(p, item) {
				return false
			}
		}
		return true
	}

	lower := strings.ToLower(expr)
	for _, fn := range []string{"startswith(", "endswith(", "contains("} {
		if strings.HasPrefix(lower, fn) && strings.HasSuffix(expr, ")") {
			inner := expr[len(fn) : len(expr)-1]
			comma := strings.Index(inner, ",")
			if comma < 0 {
				return true
			}
			field := strings.TrimSpace(inner[:comma])
			val := strings.Trim(strings.TrimSpace(inner[comma+1:]), `"'`)
			got := graphItemFieldString(item, field)
			switch fn {
			case "startswith(":
				return strings.HasPrefix(strings.ToLower(got), strings.ToLower(val))
			case "endswith(":
				return strings.HasSuffix(strings.ToLower(got), strings.ToLower(val))
			case "contains(":
				return strings.Contains(strings.ToLower(got), strings.ToLower(val))
			}
		}
	}

	for _, op := range []string{" eq ", " ne ", " ge ", " gt ", " le ", " lt "} {
		idx := indexOktaOp(expr, op)
		if idx < 0 {
			continue
		}
		field := strings.TrimSpace(expr[:idx])
		rhs := strings.TrimSpace(expr[idx+len(op):])
		unquoted := strings.Trim(rhs, `"'`)
		got := graphItemFieldString(item, field)
		switch strings.TrimSpace(op) {
		case "eq":
			if strings.EqualFold(rhs, "null") {
				return got == ""
			}
			return strings.EqualFold(got, unquoted)
		case "ne":
			if strings.EqualFold(rhs, "null") {
				return got != ""
			}
			return !strings.EqualFold(got, unquoted)
		default:
			return true
		}
	}
	return true
}

func graphItemFieldString(item map[string]any, field string) string {
	field = strings.TrimSpace(field)
	for k, v := range item {
		if strings.EqualFold(k, field) {
			if v == nil {
				return ""
			}
			return fmt.Sprint(v)
		}
	}
	return ""
}

func matchGraphSearch(search string, item map[string]any) bool {
	search = strings.Trim(strings.TrimSpace(search), `"`)
	if search == "" {
		return true
	}
	if idx := strings.Index(search, ":"); idx > 0 {
		field := search[:idx]
		val := strings.ToLower(search[idx+1:])
		return strings.Contains(strings.ToLower(graphItemFieldString(item, field)), val)
	}
	q := strings.ToLower(search)
	for _, k := range []string{"displayName", "userPrincipalName", "mail", "givenName", "surname", "description"} {
		if strings.Contains(strings.ToLower(graphItemFieldString(item, k)), q) {
			return true
		}
	}
	return false
}

// ---- Organization & Me Handlers ----

func (s *Server) graphOrganization(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	e.Summary = "graph: get organization"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	org := map[string]any{
		"@odata.type": "#microsoft.graph.organization",
		"id":          t.ExternalID,
		"displayName": t.Name,
		"tenantType":  "AAD",
		"verifiedDomains": []map[string]any{
			{
				"capabilities": "Email, OfficeCommunicationsOnline",
				"isDefault":    true,
				"isInitial":    true,
				"name":         t.Domain,
				"type":         "Managed",
			},
		},
	}
	writeJSON(w, http.StatusOK, s.graphCollectionResponse(r, t, "organization", []map[string]any{org}))
}

func (s *Server) graphMe(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	if s.network(w, r) {
		return
	}
	tok, ok := graphAuth(w, r)
	if !ok {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	u := resolveGraphMeUser(t, r, tok)
	if u == nil {
		graphErr(w, r, http.StatusNotFound, "Request_ResourceNotFound", "Resource 'me' does not exist.")
		return
	}
	e.Summary = "graph: get me (" + u.UserName + ")"
	q := r.URL.Query()
	obj := s.graphUserJSON(t, u, q.Get("$expand"))
	obj = applyGraphSelect(obj, q.Get("$select"), q.Get("$expand"))
	obj["@odata.context"] = fmt.Sprintf("%s/t/%s/v1.0/$metadata#users/$entity", s.base, t.ID)
	writeJSON(w, http.StatusOK, obj)
}

func (s *Server) graphMeMemberOf(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	if s.network(w, r) {
		return
	}
	tok, ok := graphAuth(w, r)
	if !ok {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	u := resolveGraphMeUser(t, r, tok)
	if u == nil {
		graphErr(w, r, http.StatusNotFound, "Request_ResourceNotFound", "Resource 'me' does not exist.")
		return
	}
	e.Summary = "graph: me/memberOf (" + u.UserName + ")"
	groups := t.groupsOf(u.ID)
	items := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		items = append(items, s.graphGroupJSON(t, g, ""))
	}
	writeJSON(w, http.StatusOK, s.graphCollectionResponse(r, t, "directoryObjects", items))
}

// ---- Users Handlers ----

func (s *Server) graphListUsers(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	e.Summary = "graph: list users"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	q := r.URL.Query()
	filter := q.Get("$filter")
	search := q.Get("$search")
	expand := q.Get("$expand")

	var items []map[string]any
	for _, u := range t.Users {
		obj := s.graphUserJSON(t, u, expand)
		if filter != "" && !evalGraphFilter(filter, obj) {
			continue
		}
		if search != "" && !matchGraphSearch(search, obj) {
			continue
		}
		items = append(items, obj)
	}
	writeJSON(w, http.StatusOK, s.graphCollectionResponse(r, t, "users", items))
}

type graphUserPayload struct {
	AccountEnabled    *bool   `json:"accountEnabled"`
	DisplayName       *string `json:"displayName"`
	GivenName         *string `json:"givenName"`
	Surname           *string `json:"surname"`
	MailNickname      *string `json:"mailNickname"`
	UserPrincipalName *string `json:"userPrincipalName"`
	Mail              *string `json:"mail"`
	JobTitle          *string `json:"jobTitle"`
	Department        *string `json:"department"`
	MobilePhone       *string `json:"mobilePhone"`
	EmployeeID        *string `json:"employeeId"`
	PasswordProfile   struct {
		Password string `json:"password"`
	} `json:"passwordProfile"`
}

func (s *Server) graphCreateUser(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	var in graphUserPayload
	if err := readBody(r, &in); err != nil {
		graphErr(w, r, http.StatusBadRequest, "Request_BadRequest", err.Error())
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	upn := ""
	if in.UserPrincipalName != nil {
		upn = strings.TrimSpace(*in.UserPrincipalName)
	}
	mail := ""
	if in.Mail != nil {
		mail = strings.TrimSpace(*in.Mail)
	}
	if upn == "" {
		upn = mail
	}
	if upn == "" {
		graphErr(w, r, http.StatusBadRequest, "Request_BadRequest", "Property 'userPrincipalName' is required.")
		return
	}
	if t.user(upn) != nil {
		graphErr(w, r, http.StatusBadRequest, "Request_BadRequest", "Another object with the same value for property userPrincipalName already exists.")
		return
	}
	if mail == "" && !strings.Contains(upn, "#EXT#") {
		mail = upn
	}
	p := providers[t.Provider]
	style := "guid"
	if p != nil {
		style = p.IDStyle
	}
	active := in.AccountEnabled == nil || *in.AccountEnabled
	u := &User{
		ID:            newID(style, "user"),
		UserName:      upn,
		Email:         mail,
		EmailVerified: true,
		Password:      "password",
		Active:        active,
	}
	applyGraphUserFields(u, &in)
	if u.DisplayName == "" {
		u.DisplayName = strings.TrimSpace(u.GivenName + " " + u.FamilyName)
	}
	t.Users = append(t.Users, u)
	s.store.save()
	e.Summary = "graph: create user " + u.UserName
	obj := s.graphUserJSON(t, u, "")
	obj["@odata.context"] = fmt.Sprintf("%s/t/%s/v1.0/$metadata#users/$entity", s.base, t.ID)
	writeJSON(w, http.StatusCreated, obj)
}

func applyGraphUserFields(u *User, in *graphUserPayload) {
	if in.AccountEnabled != nil {
		u.Active = *in.AccountEnabled
	}
	if in.DisplayName != nil {
		u.DisplayName = *in.DisplayName
	}
	if in.GivenName != nil {
		u.GivenName = *in.GivenName
	}
	if in.Surname != nil {
		u.FamilyName = *in.Surname
	}
	if in.UserPrincipalName != nil && *in.UserPrincipalName != "" {
		u.UserName = *in.UserPrincipalName
	}
	if in.Mail != nil {
		u.Email = *in.Mail
	}
	if in.JobTitle != nil {
		u.Title = *in.JobTitle
	}
	if in.Department != nil {
		u.Department = *in.Department
	}
	if in.MobilePhone != nil {
		u.Phone = *in.MobilePhone
	}
	if in.EmployeeID != nil {
		u.EmployeeNumber = *in.EmployeeID
	}
	if in.PasswordProfile.Password != "" {
		u.Password = in.PasswordProfile.Password
	}
}

func (s *Server) graphGetUser(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	ref, _ := url.PathUnescape(r.PathValue("id"))
	u := t.user(ref)
	if u == nil {
		graphErr(w, r, http.StatusNotFound, "Request_ResourceNotFound", fmt.Sprintf("Resource '%s' does not exist or one of its queried reference-property objects are not present.", ref))
		return
	}
	e.Summary = "graph: get user " + u.UserName
	q := r.URL.Query()
	obj := s.graphUserJSON(t, u, q.Get("$expand"))
	obj = applyGraphSelect(obj, q.Get("$select"), q.Get("$expand"))
	obj["@odata.context"] = fmt.Sprintf("%s/t/%s/v1.0/$metadata#users/$entity", s.base, t.ID)
	writeJSON(w, http.StatusOK, obj)
}

func (s *Server) graphUpdateUser(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	var in graphUserPayload
	if err := readBody(r, &in); err != nil {
		graphErr(w, r, http.StatusBadRequest, "Request_BadRequest", err.Error())
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	ref, _ := url.PathUnescape(r.PathValue("id"))
	u := t.user(ref)
	if u == nil {
		graphErr(w, r, http.StatusNotFound, "Request_ResourceNotFound", fmt.Sprintf("Resource '%s' does not exist.", ref))
		return
	}
	applyGraphUserFields(u, &in)
	s.store.save()
	e.Summary = "graph: update user " + u.UserName
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) graphDeleteUser(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	ref, _ := url.PathUnescape(r.PathValue("id"))
	u := t.user(ref)
	if u == nil {
		graphErr(w, r, http.StatusNotFound, "Request_ResourceNotFound", fmt.Sprintf("Resource '%s' does not exist.", ref))
		return
	}
	t.Users = slices.DeleteFunc(t.Users, func(x *User) bool { return x.ID == u.ID })
	for _, g := range t.Groups {
		g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return m == u.ID })
	}
	s.store.save()
	e.Summary = "graph: delete user " + u.UserName
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) graphUserMemberOf(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	ref, _ := url.PathUnescape(r.PathValue("id"))
	u := t.user(ref)
	if u == nil {
		graphErr(w, r, http.StatusNotFound, "Request_ResourceNotFound", fmt.Sprintf("Resource '%s' does not exist.", ref))
		return
	}
	e.Summary = "graph: user memberOf " + u.UserName
	groups := t.groupsOf(u.ID)
	items := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		items = append(items, s.graphGroupJSON(t, g, ""))
	}
	writeJSON(w, http.StatusOK, s.graphCollectionResponse(r, t, "directoryObjects", items))
}

func (s *Server) graphGetMemberObjects(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	ref, _ := url.PathUnescape(r.PathValue("id"))
	u := t.user(ref)
	if u == nil {
		graphErr(w, r, http.StatusNotFound, "Request_ResourceNotFound", fmt.Sprintf("Resource '%s' does not exist.", ref))
		return
	}
	groups := t.groupsOf(u.ID)
	ids := make([]string, 0, len(groups))
	for _, g := range groups {
		ids = append(ids, g.ID)
	}
	e.Summary = fmt.Sprintf("graph: getMemberObjects for %s (%d groups)", u.UserName, len(ids))
	writeJSON(w, http.StatusOK, map[string]any{
		"@odata.context": fmt.Sprintf("%s/t/%s/v1.0/$metadata#Collection(Edm.String)", s.base, t.ID),
		"value":          ids,
	})
}

// ---- Groups Handlers ----

func (s *Server) graphListGroups(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	e.Summary = "graph: list groups"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	q := r.URL.Query()
	filter := q.Get("$filter")
	search := q.Get("$search")
	expand := q.Get("$expand")

	var items []map[string]any
	for _, g := range t.Groups {
		obj := s.graphGroupJSON(t, g, expand)
		if filter != "" && !evalGraphFilter(filter, obj) {
			continue
		}
		if search != "" && !matchGraphSearch(search, obj) {
			continue
		}
		items = append(items, obj)
	}
	writeJSON(w, http.StatusOK, s.graphCollectionResponse(r, t, "groups", items))
}

type graphGroupPayload struct {
	DisplayName     *string  `json:"displayName"`
	Description     *string  `json:"description"`
	MailNickname    *string  `json:"mailNickname"`
	MailEnabled     *bool    `json:"mailEnabled"`
	SecurityEnabled *bool    `json:"securityEnabled"`
	MembersBind     []string `json:"members@odata.bind"`
}

func (s *Server) graphCreateGroup(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	var in graphGroupPayload
	if err := readBody(r, &in); err != nil {
		graphErr(w, r, http.StatusBadRequest, "Request_BadRequest", err.Error())
		return
	}
	name := ""
	if in.DisplayName != nil {
		name = strings.TrimSpace(*in.DisplayName)
	}
	if name == "" {
		graphErr(w, r, http.StatusBadRequest, "Request_BadRequest", "Property 'displayName' is required.")
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	p := providers[t.Provider]
	style := "guid"
	if p != nil {
		style = p.IDStyle
	}
	g := &Group{
		ID:      newID(style, "group"),
		Name:    name,
		Members: []string{},
	}
	for _, bind := range in.MembersBind {
		uid := extractODataTargetID(bind)
		if u := t.user(uid); u != nil && !slices.Contains(g.Members, u.ID) {
			g.Members = append(g.Members, u.ID)
		}
	}
	t.Groups = append(t.Groups, g)
	s.store.save()
	e.Summary = "graph: create group " + g.Name
	obj := s.graphGroupJSON(t, g, "")
	if in.Description != nil {
		obj["description"] = *in.Description
	}
	obj["@odata.context"] = fmt.Sprintf("%s/t/%s/v1.0/$metadata#groups/$entity", s.base, t.ID)
	writeJSON(w, http.StatusCreated, obj)
}

func (s *Server) graphGetGroup(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	ref := r.PathValue("id")
	g := t.group(ref)
	if g == nil {
		graphErr(w, r, http.StatusNotFound, "Request_ResourceNotFound", fmt.Sprintf("Resource '%s' does not exist.", ref))
		return
	}
	e.Summary = "graph: get group " + g.Name
	q := r.URL.Query()
	obj := s.graphGroupJSON(t, g, q.Get("$expand"))
	obj = applyGraphSelect(obj, q.Get("$select"), q.Get("$expand"))
	obj["@odata.context"] = fmt.Sprintf("%s/t/%s/v1.0/$metadata#groups/$entity", s.base, t.ID)
	writeJSON(w, http.StatusOK, obj)
}

func (s *Server) graphUpdateGroup(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	var in graphGroupPayload
	if err := readBody(r, &in); err != nil {
		graphErr(w, r, http.StatusBadRequest, "Request_BadRequest", err.Error())
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	ref := r.PathValue("id")
	g := t.group(ref)
	if g == nil {
		graphErr(w, r, http.StatusNotFound, "Request_ResourceNotFound", fmt.Sprintf("Resource '%s' does not exist.", ref))
		return
	}
	if in.DisplayName != nil && strings.TrimSpace(*in.DisplayName) != "" {
		g.Name = strings.TrimSpace(*in.DisplayName)
	}
	s.store.save()
	e.Summary = "graph: update group " + g.Name
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) graphDeleteGroup(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	ref := r.PathValue("id")
	g := t.group(ref)
	if g == nil {
		graphErr(w, r, http.StatusNotFound, "Request_ResourceNotFound", fmt.Sprintf("Resource '%s' does not exist.", ref))
		return
	}
	t.Groups = slices.DeleteFunc(t.Groups, func(x *Group) bool { return x.ID == g.ID })
	s.store.save()
	e.Summary = "graph: delete group " + g.Name
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) graphGroupMembers(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	ref := r.PathValue("id")
	g := t.group(ref)
	if g == nil {
		graphErr(w, r, http.StatusNotFound, "Request_ResourceNotFound", fmt.Sprintf("Resource '%s' does not exist.", ref))
		return
	}
	e.Summary = "graph: group members " + g.Name
	var items []map[string]any
	for _, uid := range g.Members {
		if u := t.user(uid); u != nil {
			items = append(items, s.graphUserJSON(t, u, ""))
		}
	}
	writeJSON(w, http.StatusOK, s.graphCollectionResponse(r, t, "directoryObjects", items))
}

func extractODataTargetID(odataID string) string {
	s := strings.TrimSpace(odataID)
	s = strings.TrimRight(s, "/")
	if idx := strings.LastIndex(s, "/"); idx >= 0 {
		s = s[idx+1:]
	}
	return s
}

func (s *Server) graphAddGroupMember(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	var in map[string]any
	if err := readBody(r, &in); err != nil {
		graphErr(w, r, http.StatusBadRequest, "Request_BadRequest", err.Error())
		return
	}
	refURL := str(in["@odata.id"])
	if refURL == "" {
		graphErr(w, r, http.StatusBadRequest, "Request_BadRequest", "Missing @odata.id in request body.")
		return
	}
	uid := extractODataTargetID(refURL)
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	g := t.group(r.PathValue("id"))
	if g == nil {
		graphErr(w, r, http.StatusNotFound, "Request_ResourceNotFound", fmt.Sprintf("Resource '%s' does not exist.", r.PathValue("id")))
		return
	}
	u := t.user(uid)
	if u == nil {
		graphErr(w, r, http.StatusNotFound, "Request_ResourceNotFound", fmt.Sprintf("Resource '%s' does not exist.", uid))
		return
	}
	if !slices.Contains(g.Members, u.ID) {
		g.Members = append(g.Members, u.ID)
		s.store.save()
	}
	e.Summary = fmt.Sprintf("graph: add member %s to group %s", u.UserName, g.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) graphRemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	g := t.group(r.PathValue("id"))
	if g == nil {
		graphErr(w, r, http.StatusNotFound, "Request_ResourceNotFound", fmt.Sprintf("Resource '%s' does not exist.", r.PathValue("id")))
		return
	}
	u := t.user(r.PathValue("uid"))
	if u == nil {
		graphErr(w, r, http.StatusNotFound, "Request_ResourceNotFound", fmt.Sprintf("Resource '%s' does not exist.", r.PathValue("uid")))
		return
	}
	g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return m == u.ID })
	s.store.save()
	e.Summary = fmt.Sprintf("graph: remove member %s from group %s", u.UserName, g.Name)
	w.WriteHeader(http.StatusNoContent)
}

// ---- ServicePrincipals, Applications & AuditLogs ----

func (s *Server) graphServicePrincipals(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	e.Summary = "graph: list servicePrincipals"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	filter := r.URL.Query().Get("$filter")
	var items []map[string]any
	for _, a := range t.Apps {
		appID := a.ClientID
		if appID == "" {
			appID = a.ID
		}
		sp := map[string]any{
			"@odata.type":          "#microsoft.graph.servicePrincipal",
			"id":                   a.ID,
			"appId":                appID,
			"displayName":          a.Name,
			"accountEnabled":       true,
			"appRoleAssignmentRequired": false,
			"servicePrincipalType": "Application",
			"signInAudience":       "AzureADMyOrg",
		}
		if filter != "" && !evalGraphFilter(filter, sp) {
			continue
		}
		items = append(items, sp)
	}
	writeJSON(w, http.StatusOK, s.graphCollectionResponse(r, t, "servicePrincipals", items))
}

func (s *Server) graphApplications(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	e.Summary = "graph: list applications"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.graphTenant(w, r)
	if t == nil {
		return
	}
	filter := r.URL.Query().Get("$filter")
	var items []map[string]any
	for _, a := range t.Apps {
		appID := a.ClientID
		if appID == "" {
			appID = a.ID
		}
		obj := map[string]any{
			"@odata.type":    "#microsoft.graph.application",
			"id":             a.ID,
			"appId":          appID,
			"displayName":    a.Name,
			"signInAudience": "AzureADMyOrg",
			"web": map[string]any{
				"redirectUris": a.RedirectURIs,
			},
		}
		if filter != "" && !evalGraphFilter(filter, obj) {
			continue
		}
		items = append(items, obj)
	}
	writeJSON(w, http.StatusOK, s.graphCollectionResponse(r, t, "applications", items))
}

func (s *Server) graphSignIns(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	e.Summary = "graph: auditLogs/signIns"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	s.store.mu.Lock()
	t := s.graphTenant(w, r)
	var firstUser *User
	var firstApp *App
	var created time.Time
	if t != nil {
		created = t.Created
		if len(t.Users) > 0 {
			uCopy := *t.Users[0]
			firstUser = &uCopy
		}
		if len(t.Apps) > 0 {
			aCopy := *t.Apps[0]
			firstApp = &aCopy
		}
	}
	s.store.mu.Unlock()
	if t == nil {
		return
	}

	entries := s.logs.list(t.ID, "", "", "", 0, 500)
	var items []map[string]any

	uid, upn, uname := "00000000-0000-0000-0000-000000000000", "system@"+t.Domain, "System"
	if firstUser != nil {
		uid, upn, uname = firstUser.ID, firstUser.UserName, firstUser.DisplayName
	}
	appID, appName := "test-oidc", "Built-in test app (OIDC)"
	if firstApp != nil {
		if firstApp.ClientID != "" {
			appID = firstApp.ClientID
		} else {
			appID = firstApp.ID
		}
		appName = firstApp.Name
	}
	seedTime := created
	if seedTime.IsZero() {
		seedTime = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	}

	items = append(items, map[string]any{
		"id":                "signin-baseline-" + t.ID,
		"createdDateTime":   seedTime.UTC().Format(time.RFC3339),
		"userDisplayName":   uname,
		"userPrincipalName": upn,
		"userId":            uid,
		"appId":             appID,
		"appDisplayName":    appName,
		"ipAddress":         "127.0.0.1",
		"clientAppUsed":     "Browser",
		"isInteractive":     true,
		"status": map[string]any{
			"errorCode":     0,
			"failureReason": nil,
		},
	})

	for _, le := range entries {
		if !strings.HasPrefix(le.Kind, "login") && !strings.HasPrefix(le.Kind, "oidc") && !strings.HasPrefix(le.Kind, "saml") {
			continue
		}
		errCode := 0
		var reason any
		if le.Status >= 400 || le.Level == "error" {
			errCode = 50126
			reason = le.Summary
		}
		items = append(items, map[string]any{
			"id":                fmt.Sprintf("signin-%s-%d", t.ID, le.ID),
			"createdDateTime":   le.Time.UTC().Format(time.RFC3339),
			"userDisplayName":   uname,
			"userPrincipalName": upn,
			"userId":            uid,
			"appId":             appID,
			"appDisplayName":    appName,
			"ipAddress":         "127.0.0.1",
			"clientAppUsed":     "Browser",
			"isInteractive":     true,
			"status": map[string]any{
				"errorCode":     errCode,
				"failureReason": reason,
			},
		})
	}

	filter := r.URL.Query().Get("$filter")
	if filter != "" {
		var filtered []map[string]any
		for _, it := range items {
			if evalGraphFilter(filter, it) {
				filtered = append(filtered, it)
			}
		}
		items = filtered
	}
	writeJSON(w, http.StatusOK, s.graphCollectionResponse(r, t, "auditLogs/signIns", items))
}

func (s *Server) graphDirectoryAudits(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "graph.api"
	e.Summary = "graph: auditLogs/directoryAudits"
	if s.network(w, r) {
		return
	}
	if _, ok := graphAuth(w, r); !ok {
		return
	}
	s.store.mu.Lock()
	t := s.graphTenant(w, r)
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

	entries := s.logs.list(t.ID, "", "", "", 0, 500)
	var items []map[string]any

	uid, upn, uname := "00000000-0000-0000-0000-000000000000", "system@"+t.Domain, "System"
	if firstUser != nil {
		uid, upn, uname = firstUser.ID, firstUser.UserName, firstUser.DisplayName
	}
	seedTime := created
	if seedTime.IsZero() {
		seedTime = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	}

	items = append(items, map[string]any{
		"id":                  "audit-baseline-" + t.ID,
		"activityDateTime":    seedTime.UTC().Format(time.RFC3339),
		"category":            "UserManagement",
		"activityDisplayName": "Update user",
		"loggedByService":     "Core Directory",
		"operationType":       "Update",
		"result":              "success",
		"initiatedBy": map[string]any{
			"user": map[string]any{
				"id":                uid,
				"displayName":       uname,
				"userPrincipalName": upn,
			},
		},
		"targetResources": []map[string]any{
			{
				"id":                uid,
				"displayName":       uname,
				"type":              "User",
				"userPrincipalName": upn,
			},
		},
	})

	for _, le := range entries {
		res := "success"
		if le.Status >= 400 || le.Level == "error" {
			res = "failure"
		}
		items = append(items, map[string]any{
			"id":                  fmt.Sprintf("audit-%s-%d", t.ID, le.ID),
			"activityDateTime":    le.Time.UTC().Format(time.RFC3339),
			"category":            "DirectoryManagement",
			"activityDisplayName": le.Summary,
			"loggedByService":     "Core Directory",
			"operationType":       le.Method,
			"result":              res,
			"initiatedBy": map[string]any{
				"user": map[string]any{
					"id":                uid,
					"displayName":       uname,
					"userPrincipalName": upn,
				},
			},
			"targetResources": []map[string]any{},
		})
	}

	filter := r.URL.Query().Get("$filter")
	if filter != "" {
		var filtered []map[string]any
		for _, it := range items {
			if evalGraphFilter(filter, it) {
				filtered = append(filtered, it)
			}
		}
		items = filtered
	}
	writeJSON(w, http.StatusOK, s.graphCollectionResponse(r, t, "auditLogs/directoryAudits", items))
}
