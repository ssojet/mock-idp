package main

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	schemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaEnt   = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	schemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaPatch = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	schemaList  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaError = "urn:ietf:params:scim:api:messages:2.0:Error"
	schemaSPC   = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	schemaRT    = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	schemaDef   = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

// ScimRun is the outcome of a test, sync, push or conformance run. Each
// check links to the log entry of the HTTP call behind it.
type ScimRun struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"`
	Flavor string    `json:"flavor"`
	Run    string    `json:"run"`
	Checks []check   `json:"checks"`
	Passed int       `json:"passed"`
	Failed int       `json:"failed"`
	Warned int       `json:"warned"`
}

// scimClient plays the IdP's provisioning engine against an app's SCIM
// server. It works on a snapshot so the store is not locked during HTTP.
type scimClient struct {
	s         *Server
	tenant    string
	target    ScimTarget
	flavor    ScimFlavor
	flavorKey string
	users     map[string]User
	groups    []Group
	run       string
	http      *http.Client
}

func (s *Server) newScimClient(tid, targetID, flavor string) (*scimClient, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.store.tenant(tid)
	if t == nil {
		return nil, errf(404, "unknown tenant %s", tid)
	}
	tg := t.target(targetID)
	if tg == nil {
		return nil, errf(404, "unknown SCIM target %s", targetID)
	}
	key := flavor
	if key == "" {
		key = tg.Flavor
	}
	if key == "" {
		key = t.Provider
	}
	p := providers[key]
	if p == nil {
		return nil, errf(400, "unknown flavor %q", key)
	}
	c := &scimClient{s: s, tenant: tid, target: *tg, flavor: p.Scim, flavorKey: key, users: map[string]User{},
		run: randHex(6), http: &http.Client{Timeout: 15 * time.Second}}
	c.target.UserMap = maps.Clone(tg.UserMap)
	c.target.GroupMap = maps.Clone(tg.GroupMap)
	if c.target.UserMap == nil {
		c.target.UserMap = map[string]string{}
	}
	if c.target.GroupMap == nil {
		c.target.GroupMap = map[string]string{}
	}
	for _, u := range t.Users {
		c.users[u.ID] = *u
	}
	for _, g := range t.Groups {
		c.groups = append(c.groups, Group{ID: g.ID, Name: g.Name, Members: slices.Clone(g.Members)})
	}
	return c, nil
}

// finish stores the id maps and the run summary on the target.
func (c *scimClient) finish(kind string, cs []check) *ScimRun {
	run := &ScimRun{Time: time.Now().UTC(), Kind: kind, Flavor: c.flavorKey, Run: c.run, Checks: cs}
	for _, x := range cs {
		switch x.Result {
		case "pass":
			run.Passed++
		case "fail":
			run.Failed++
		default:
			run.Warned++
		}
	}
	c.s.store.mu.Lock()
	if t := c.s.store.tenant(c.tenant); t != nil {
		if tg := t.target(c.target.ID); tg != nil {
			tg.UserMap, tg.GroupMap, tg.LastResult = c.target.UserMap, c.target.GroupMap, run
			c.s.store.save()
		}
	}
	c.s.store.mu.Unlock()
	c.s.logs.publish("change", map[string]string{"tenant": c.tenant})
	return run
}

type scimResp struct {
	status int
	body   map[string]any
	ctype  string
	log    int64
	err    error
}

func (c *scimClient) call(method, path string, body any, summary string) scimResp {
	u := strings.TrimRight(c.target.BaseURL, "/") + path
	var reqBody []byte
	if body != nil {
		reqBody, _ = json.MarshalIndent(body, "", "  ")
	}
	e := &LogEntry{Kind: "scim.out", Level: "info", Tenant: c.tenant, Method: method, URL: u, ReqBody: string(reqBody), Run: c.run,
		Summary: "SCIM " + method + " " + path + ": " + summary}
	req, err := http.NewRequest(method, u, bytes.NewReader(reqBody))
	if err != nil {
		e.fail("%v", err)
		c.s.logs.add(e)
		return scimResp{err: err, log: e.ID}
	}
	req.Header.Set("Accept", "application/scim+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json; charset=utf-8")
	}
	req.Header.Set("User-Agent", "mock-idp/"+version+" ("+providers[c.flavorKey].Name+" SCIM flavor)")
	if tok := c.target.Token; tok != "" {
		if !strings.HasPrefix(tok, "Bearer ") && !strings.HasPrefix(tok, "Basic ") {
			tok = "Bearer " + tok
		}
		req.Header.Set("Authorization", tok)
	}
	e.ReqHeaders = req.Header.Clone()
	start := time.Now()
	resp, err := c.http.Do(req)
	e.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		e.fail("request failed: %v", err)
		c.s.logs.add(e)
		return scimResp{err: err, log: e.ID}
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	e.Status, e.RespHeaders, e.RespBody = resp.StatusCode, resp.Header.Clone(), string(rb)
	if resp.StatusCode >= 400 {
		e.Level = "error"
	}
	var m map[string]any
	json.Unmarshal(rb, &m)
	c.s.logs.add(e)
	return scimResp{status: resp.StatusCode, body: m, ctype: resp.Header.Get("Content-Type"), log: e.ID}
}

func (c *scimClient) op(name, path string, value any) map[string]any {
	if c.flavor.OpCase == "title" {
		name = strings.ToUpper(name[:1]) + name[1:]
	}
	m := map[string]any{"op": name}
	if path != "" {
		m["path"] = path
	}
	if value != nil {
		m["value"] = value
	}
	return m
}

func (c *scimClient) boolean(b bool) any {
	if c.flavor.BoolStrings {
		return map[bool]string{true: "True", false: "False"}[b]
	}
	return b
}

func patchBody(ops ...map[string]any) map[string]any {
	return map[string]any{"schemas": []string{schemaPatch}, "Operations": ops}
}

func (c *scimClient) userResource(u User) map[string]any {
	schemas := []string{schemaUser}
	r := map[string]any{
		"userName":    u.UserName,
		"name":        map[string]any{"givenName": u.GivenName, "familyName": u.FamilyName, "formatted": u.DisplayName},
		"displayName": u.DisplayName,
		"active":      u.Active,
	}
	if u.Email != "" {
		r["emails"] = []any{map[string]any{"value": u.Email, "type": "work", "primary": true}}
	}
	switch c.flavorKey {
	case "entra":
		r["externalId"] = strings.Split(u.UserName, "@")[0] // mailNickname
	case "okta":
	default:
		r["externalId"] = u.ID
	}
	if u.Title != "" {
		r["title"] = u.Title
	}
	if u.Phone != "" {
		r["phoneNumbers"] = []any{map[string]any{"value": u.Phone, "type": "work"}}
	}
	if u.Department != "" || u.EmployeeNumber != "" || u.Manager != "" {
		ent := map[string]any{}
		if u.Department != "" {
			ent["department"] = u.Department
		}
		if u.EmployeeNumber != "" {
			ent["employeeNumber"] = u.EmployeeNumber
		}
		if m := c.target.UserMap[u.Manager]; m != "" {
			ent["manager"] = map[string]any{"value": m}
		}
		schemas = append(schemas, schemaEnt)
		r[schemaEnt] = ent
	}
	r["schemas"] = schemas
	return r
}

func (c *scimClient) deactivateOp() map[string]any {
	if c.flavor.Update == "PUT" { // Okta style: no path, an object value
		return patchBody(c.op("replace", "", map[string]any{"active": false}))
	}
	return patchBody(c.op("replace", "active", c.boolean(false)))
}

func (c *scimClient) updateBody(u User, id string) (string, map[string]any) {
	if c.flavor.Update == "PUT" {
		r := c.userResource(u)
		r["id"] = id
		return "PUT", r
	}
	ops := []map[string]any{
		c.op("replace", "displayName", u.DisplayName),
		c.op("replace", "name.givenName", u.GivenName),
		c.op("replace", "name.familyName", u.FamilyName),
		c.op("replace", "active", c.boolean(u.Active)),
	}
	if u.Email != "" {
		ops = append(ops, c.op("replace", `emails[type eq "work"].value`, u.Email))
	}
	if u.Title != "" {
		ops = append(ops, c.op("replace", "title", u.Title))
	}
	if u.Department != "" {
		ops = append(ops, c.op("replace", schemaEnt+":department", u.Department))
	}
	return "PATCH", patchBody(ops...)
}

func filterQ(attr, v string) string {
	return "?filter=" + url.QueryEscape(fmt.Sprintf(`%s eq "%s"`, attr, v))
}

func firstResourceID(body map[string]any) string {
	res, _ := body["Resources"].([]any)
	if len(res) == 0 {
		return ""
	}
	m, _ := res[0].(map[string]any)
	return str(m["id"])
}

func (c *scimClient) findUser(u User) string {
	if id := c.target.UserMap[u.ID]; id != "" {
		return id
	}
	r := c.call("GET", "/Users"+filterQ("userName", u.UserName), nil, "find "+u.UserName)
	if id := firstResourceID(r.body); r.status == 200 && id != "" {
		c.target.UserMap[u.ID] = id
		return id
	}
	return ""
}

func result(name string, r scimResp, ok bool, detail string, a ...any) check {
	c := check{Name: name, Result: "pass", Detail: fmt.Sprintf(detail, a...), Log: r.log}
	if r.err != nil {
		c.Result, c.Detail = "fail", r.err.Error()
	} else if !ok {
		c.Result = "fail"
	}
	return c
}

func okStatus(code int) bool { return code == 200 || code == 201 || code == 204 }

// pushUser does what the IdP does when a user is assigned, changed or
// removed: action is upsert, deactivate or delete.
func (c *scimClient) pushUser(u User, action string) check {
	name := action + " " + u.UserName
	switch action {
	case "upsert":
		if !u.Active {
			return c.pushUser(u, "deactivate")
		}
		id := c.findUser(u)
		if id == "" {
			r := c.call("POST", "/Users", c.userResource(u), "create "+u.UserName)
			id = str(r.body["id"])
			if id != "" {
				c.target.UserMap[u.ID] = id
			}
			return result(name, r, okStatus(r.status) && id != "", "HTTP %d, remote id %q", r.status, id)
		}
		method, body := c.updateBody(u, id)
		r := c.call(method, "/Users/"+id, body, "update "+u.UserName)
		return result(name, r, okStatus(r.status), "%s → HTTP %d", method, r.status)
	case "deactivate":
		id := c.findUser(u)
		if id == "" {
			return check{Name: name, Result: "warn", Detail: "not on the app; nothing to deactivate"}
		}
		r := c.call("PATCH", "/Users/"+id, c.deactivateOp(), "deactivate "+u.UserName)
		return result(name, r, okStatus(r.status), "HTTP %d", r.status)
	case "delete":
		id := c.findUser(u)
		if id == "" {
			return check{Name: name, Result: "warn", Detail: "not on the app; nothing to delete"}
		}
		var r scimResp
		if strings.Contains(c.flavor.OnDelete, "deactivate") {
			r = c.call("PATCH", "/Users/"+id, c.deactivateOp(), "deactivate "+u.UserName)
		}
		if strings.Contains(c.flavor.OnDelete, "delete") {
			r = c.call("DELETE", "/Users/"+id, nil, "delete "+u.UserName)
			delete(c.target.UserMap, u.ID)
		}
		return result(name, r, okStatus(r.status), "%s: HTTP %d", c.flavor.OnDelete, r.status)
	}
	return check{Name: name, Result: "fail", Detail: "unknown action " + action}
}

func memberIDs(body map[string]any) []string {
	var out []string
	ms, _ := body["members"].([]any)
	for _, m := range ms {
		if mm, ok := m.(map[string]any); ok {
			out = append(out, str(mm["value"]))
		}
	}
	return out
}

func (c *scimClient) removeMemberOps(ids []string) []map[string]any {
	if c.flavor.RemoveMember == "value-array" {
		var vals []any
		for _, id := range ids {
			vals = append(vals, map[string]any{"value": id})
		}
		return []map[string]any{c.op("remove", "members", vals)}
	}
	var ops []map[string]any
	for _, id := range ids {
		ops = append(ops, c.op("remove", fmt.Sprintf(`members[value eq "%s"]`, id), nil))
	}
	return ops
}

// pushGroup creates, updates (membership diff) or deletes a group.
func (c *scimClient) pushGroup(g Group, action string) check {
	name := action + " group " + g.Name
	id := c.target.GroupMap[g.ID]
	if id == "" {
		r := c.call("GET", "/Groups"+filterQ("displayName", g.Name), nil, "find group "+g.Name)
		if id = firstResourceID(r.body); id != "" {
			c.target.GroupMap[g.ID] = id
		}
	}
	if action == "delete" {
		if id == "" {
			return check{Name: name, Result: "warn", Detail: "not on the app"}
		}
		r := c.call("DELETE", "/Groups/"+id, nil, "delete group "+g.Name)
		delete(c.target.GroupMap, g.ID)
		return result(name, r, okStatus(r.status), "HTTP %d", r.status)
	}
	var want []any
	wantIDs := []string{}
	for _, uid := range g.Members {
		u, ok := c.users[uid]
		if !ok || !u.Active {
			continue
		}
		rid := c.target.UserMap[uid]
		if rid == "" {
			c.pushUser(u, "upsert")
			rid = c.target.UserMap[uid]
		}
		if rid != "" {
			want = append(want, map[string]any{"value": rid, "display": u.UserName})
			wantIDs = append(wantIDs, rid)
		}
	}
	if id == "" {
		body := map[string]any{"schemas": []string{schemaGroup}, "displayName": g.Name}
		if c.flavor.MembersOnCreate {
			body["members"] = want
		}
		r := c.call("POST", "/Groups", body, "create group "+g.Name)
		if id = str(r.body["id"]); id == "" || !okStatus(r.status) {
			return result(name, r, false, "HTTP %d, remote id %q", r.status, id)
		}
		c.target.GroupMap[g.ID] = id
		if !c.flavor.MembersOnCreate && len(want) > 0 {
			r = c.call("PATCH", "/Groups/"+id, patchBody(c.op("add", "members", want)), "add members to "+g.Name)
		}
		return result(name, r, okStatus(r.status), "created with %d member(s)", len(want))
	}
	r := c.call("GET", "/Groups/"+id, nil, "read group "+g.Name)
	have := memberIDs(r.body)
	var ops []map[string]any
	if str(r.body["displayName"]) != g.Name {
		ops = append(ops, c.op("replace", "displayName", g.Name))
	}
	var add []any
	for i, rid := range wantIDs {
		if !slices.Contains(have, rid) {
			add = append(add, want[i])
		}
	}
	if len(add) > 0 {
		ops = append(ops, c.op("add", "members", add))
	}
	var gone []string
	for _, rid := range have {
		if !slices.Contains(wantIDs, rid) {
			gone = append(gone, rid)
		}
	}
	if len(gone) > 0 {
		ops = append(ops, c.removeMemberOps(gone)...)
	}
	if len(ops) == 0 {
		return result(name, r, r.status == 200, "already in sync")
	}
	r = c.call("PATCH", "/Groups/"+id, patchBody(ops...), "update group "+g.Name)
	return result(name, r, okStatus(r.status), "+%d −%d member(s): HTTP %d", len(add), len(gone), r.status)
}

func (c *scimClient) sync() []check {
	var out []check
	for _, u := range c.users {
		if u.Active {
			out = append(out, c.pushUser(u, "upsert"))
		} else if c.target.UserMap[u.ID] != "" {
			out = append(out, c.pushUser(u, "deactivate"))
		}
	}
	for _, g := range c.groups {
		out = append(out, c.pushGroup(g, "upsert"))
	}
	return out
}

// test is the provider's "Test connection" button.
func (c *scimClient) test() []check {
	var out []check
	if c.flavor.Probe == "random-filter" {
		r := c.call("GET", "/Users"+filterQ("userName", newUUID()), nil, "connection test: filter for a random userName")
		out = append(out, result("Connection test", r, r.status == 200 && num(r.body["totalResults"]) == 0,
			"HTTP %d, totalResults %v. Entra wants 200 with totalResults 0.", r.status, r.body["totalResults"]))
	} else {
		r := c.call("GET", "/Users?startIndex=1&count=1", nil, "connection test: list one user")
		out = append(out, result("Connection test", r, r.status == 200, "HTTP %d", r.status))
	}
	return out
}

func hasSchema(body map[string]any, schema string) bool {
	ss, _ := body["schemas"].([]any)
	return slices.ContainsFunc(ss, func(v any) bool { return str(v) == schema })
}

// conformance runs the calls this provider makes, plus the edge cases they
// hit in production, against a throwaway user and group.
func (c *scimClient) conformance() []check {
	var out []check
	add := func(ch check) { out = append(out, ch) }
	soft := func(ch check) {
		if ch.Result == "fail" {
			ch.Result = "warn"
		}
		out = append(out, ch)
	}
	uname := "mockidp." + randHex(4) + "@example.com"

	r := c.call("GET", "/ServiceProviderConfig", nil, "conformance: discovery")
	soft(result("GET /ServiceProviderConfig", r, r.status == 200, "HTTP %d. Okta and Entra do not need it; other clients read it.", r.status))
	if r.err != nil {
		return out
	}

	r = c.call("GET", "/Users"+filterQ("userName", uname), nil, "conformance: filter with no match")
	add(result("Filter with no match", r, r.status == 200 && num(r.body["totalResults"]) == 0 && hasSchema(r.body, schemaList),
		"HTTP %d, totalResults %v. Want 200, 0 and the ListResponse schema. Entra's connection test sends exactly this.", r.status, r.body["totalResults"]))

	u := User{ID: "conformance", UserName: uname, Email: uname, GivenName: "Mock", FamilyName: "Tester", DisplayName: "Mock Tester", Active: true, Department: "QA"}
	r = c.call("POST", "/Users", c.userResource(u), "conformance: create user")
	id := str(r.body["id"])
	add(result("Create user", r, r.status == 201 && id != "", "HTTP %d, id %q. Want 201 Created with an id.", r.status, id))
	if id == "" {
		return out
	}
	add(result("Create echoes userName", r, str(r.body["userName"]) == uname, "got %q", r.body["userName"]))
	soft(result("Content-Type", r, strings.Contains(r.ctype, "application/scim+json"), "%q. SCIM says application/scim+json.", r.ctype))

	r = c.call("POST", "/Users", c.userResource(u), "conformance: create the same user again")
	add(result("Duplicate userName is 409", r, r.status == 409, "HTTP %d. Want 409 Conflict; otherwise IdP retries create duplicates.", r.status))
	if dup := str(r.body["id"]); okStatus(r.status) && dup != "" && dup != id {
		c.call("DELETE", "/Users/"+dup, nil, "conformance: clean up the duplicate")
	}

	r = c.call("GET", "/Users/"+id, nil, "conformance: get user")
	add(result("Get user by id", r, r.status == 200 && str(r.body["id"]) == id, "HTTP %d", r.status))

	r = c.call("GET", "/Users"+filterQ("userName", uname), nil, "conformance: filter by userName")
	add(result("Filter by userName", r, r.status == 200 && num(r.body["totalResults"]) == 1 && firstResourceID(r.body) == id, "HTTP %d, totalResults %v", r.status, r.body["totalResults"]))

	r = c.call("GET", "/Users"+filterQ("userName", strings.ToUpper(uname)), nil, "conformance: filter, different case")
	soft(result("userName filter ignores case", r, r.status == 200 && num(r.body["totalResults"]) == 1, "totalResults %v. userName is case-insensitive in SCIM (RFC 7643 §4.1.1).", r.body["totalResults"]))

	u.GivenName = "Updated"
	method, body := c.updateBody(u, id)
	r = c.call(method, "/Users/"+id, body, "conformance: update user")
	add(result("Update user ("+method+")", r, okStatus(r.status), "HTTP %d", r.status))
	r = c.call("GET", "/Users/"+id, nil, "conformance: read back the update")
	nm, _ := r.body["name"].(map[string]any)
	add(result("Update persisted", r, str(nm["givenName"]) == "Updated", "name.givenName is %v", nm["givenName"]))

	r = c.call("PATCH", "/Users/"+id, c.deactivateOp(), "conformance: deactivate")
	hint := ""
	if c.flavor.BoolStrings {
		hint = ` This flavor sends "False" as a string, as Entra does. Accept it.`
	}
	add(result("Deactivate (PATCH active)", r, okStatus(r.status), "HTTP %d.%s", r.status, hint))
	r = c.call("GET", "/Users/"+id, nil, "conformance: read back active")
	add(result("Deactivation persisted", r, r.body["active"] == false, "active is %v", r.body["active"]))

	r = c.call("GET", "/Users/"+newUUID(), nil, "conformance: unknown user")
	add(result("Unknown user is 404", r, r.status == 404, "HTTP %d", r.status))
	if r.status == 404 {
		soft(result("404 uses the SCIM Error schema", r, hasSchema(r.body, schemaError), "body: %v", r.body))
	}

	r = c.call("GET", "/Users?startIndex=1&count=1", nil, "conformance: pagination")
	res, _ := r.body["Resources"].([]any)
	add(result("Pagination (count=1)", r, r.status == 200 && len(res) <= 1, "HTTP %d, %d resource(s) returned", r.status, len(res)))

	gname := "mockidp-group-" + randHex(3)
	r = c.call("POST", "/Groups", map[string]any{"schemas": []string{schemaGroup}, "displayName": gname, "members": []any{}}, "conformance: create group")
	gid := str(r.body["id"])
	add(result("Create group", r, r.status == 201 && gid != "", "HTTP %d, id %q", r.status, gid))
	if gid != "" {
		r = c.call("PATCH", "/Groups/"+gid, patchBody(c.op("add", "members", []any{map[string]any{"value": id}})), "conformance: add member")
		add(result("Add member (PATCH)", r, okStatus(r.status), "HTTP %d", r.status))
		r = c.call("GET", "/Groups/"+gid, nil, "conformance: read members")
		add(result("Member persisted", r, slices.Contains(memberIDs(r.body), id), "members: %v", memberIDs(r.body)))
		r = c.call("PATCH", "/Groups/"+gid, patchBody(c.removeMemberOps([]string{id})...), "conformance: remove member")
		add(result("Remove member (PATCH, "+c.flavor.RemoveMember+")", r, okStatus(r.status), "HTTP %d", r.status))
		r = c.call("GET", "/Groups/"+gid, nil, "conformance: read members")
		add(result("Removal persisted", r, !slices.Contains(memberIDs(r.body), id), "members: %v", memberIDs(r.body)))
		r = c.call("DELETE", "/Groups/"+gid, nil, "conformance: delete group")
		add(result("Delete group", r, r.status == 204 || r.status == 200, "HTTP %d", r.status))
	}

	r = c.call("DELETE", "/Users/"+id, nil, "conformance: delete user")
	add(result("Delete user", r, r.status == 204 || r.status == 200, "HTTP %d", r.status))
	r = c.call("GET", "/Users/"+id, nil, "conformance: deleted user is gone")
	add(result("Deleted user is 404", r, r.status == 404, "HTTP %d", r.status))
	return out
}

// autoPush mirrors a change to every target with auto-push on, the way an
// IdP provisions on assignment changes. Callers must not hold store.mu.
func (s *Server) autoPush(tid string, users []User, groups []Group, action string) {
	s.store.mu.Lock()
	var ids []string
	if t := s.store.tenant(tid); t != nil {
		for _, tg := range t.ScimTargets {
			if tg.AutoPush && tg.BaseURL != "" {
				ids = append(ids, tg.ID)
			}
		}
	}
	s.store.mu.Unlock()
	for _, id := range ids {
		go func() {
			c, err := s.newScimClient(tid, id, "")
			if err != nil {
				return
			}
			var cs []check
			for _, u := range users {
				cs = append(cs, c.pushUser(u, action))
			}
			for _, g := range groups {
				cs = append(cs, c.pushGroup(g, action))
			}
			c.finish("auto-push", cs)
		}()
	}
}

// ---- Inbound SCIM 2.0 Server (RFC 7643 / RFC 7644) ----

var scimRegisteredMuxes sync.Map

func (s *Server) registerSCIM() {
	if _, loaded := scimRegisteredMuxes.LoadOrStore(s.mux, true); loaded {
		return
	}
	h := s.traced(s.handleSCIM)
	for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		s.mux.Handle(m+" /t/{tenant}/scim/v2/", h)
		s.mux.Handle(m+" /t/{tenant}/scim/v2", h)
	}
}

func writeSCIM(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	if v != nil && status != http.StatusNoContent {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(v)
	}
}

func writeSCIMErr(w http.ResponseWriter, r *http.Request, status int, scimType, detail string) {
	if scimType != "" {
		entry(r).fail("SCIM %d (%s): %s", status, scimType, detail)
	} else {
		entry(r).fail("SCIM %d: %s", status, detail)
	}
	m := map[string]any{
		"schemas": []string{schemaError},
		"status":  strconv.Itoa(status),
		"detail":  detail,
	}
	if scimType != "" {
		m["scimType"] = scimType
	}
	writeSCIM(w, status, m)
}

func (s *Server) scimAuthorized(r *http.Request, t *Tenant) bool {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return false
	}
	var tok string
	switch {
	case len(auth) >= 7 && strings.EqualFold(auth[:7], "Bearer "):
		tok = strings.TrimSpace(auth[7:])
	case len(auth) >= 5 && strings.EqualFold(auth[:5], "SSWS "):
		tok = strings.TrimSpace(auth[5:])
	default:
		return false
	}
	if tok == "" {
		return false
	}
	if s.apiToken == "" {
		return true
	}
	if tok == s.apiToken {
		return true
	}
	for _, tg := range t.ScimTargets {
		want := strings.TrimSpace(strings.TrimPrefix(tg.Token, "Bearer "))
		if want != "" && tok == want {
			return true
		}
	}
	return false
}

func (s *Server) handleSCIM(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "scim.in"
	if s.network(w, r) {
		return
	}
	tid := r.PathValue("tenant")
	prefix := "/t/" + tid + "/scim/v2"
	sub := strings.Trim(strings.TrimPrefix(r.URL.Path, prefix), "/")
	resource, resID, _ := strings.Cut(sub, "/")
	if unesc, err := url.PathUnescape(resID); err == nil {
		resID = unesc
	}
	e.Summary = "SCIM " + r.Method + " /" + sub
	if e.ReqBody != "" {
		var dec any
		if json.Unmarshal([]byte(e.ReqBody), &dec) == nil {
			e.decode("SCIM request", "json", dec)
		}
	}

	s.store.mu.Lock()
	t := s.store.tenant(tid)
	if t == nil {
		s.store.mu.Unlock()
		writeSCIMErr(w, r, http.StatusNotFound, "", "unknown tenant "+tid)
		return
	}
	e.Sims = activeSims(t.Sims)

	switch resource {
	case "ServiceProviderConfig":
		s.store.mu.Unlock()
		if r.Method != http.MethodGet || resID != "" {
			writeSCIMErr(w, r, http.StatusMethodNotAllowed, "", "only GET /ServiceProviderConfig is supported")
			return
		}
		writeSCIM(w, http.StatusOK, s.scimServiceProviderConfig(tid))
		return
	case "ResourceTypes":
		s.store.mu.Unlock()
		if r.Method != http.MethodGet {
			writeSCIMErr(w, r, http.StatusMethodNotAllowed, "", "only GET /ResourceTypes is supported")
			return
		}
		s.scimResourceTypes(w, r, tid, resID)
		return
	case "Schemas":
		s.store.mu.Unlock()
		if r.Method != http.MethodGet {
			writeSCIMErr(w, r, http.StatusMethodNotAllowed, "", "only GET /Schemas is supported")
			return
		}
		s.scimSchemas(w, r, tid, resID)
		return
	}

	if !s.scimAuthorized(r, t) {
		s.store.mu.Unlock()
		w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
		writeSCIMErr(w, r, http.StatusUnauthorized, "", "invalid or missing SCIM bearer token")
		return
	}

	switch resource {
	case "Users":
		s.scimUsers(w, r, t, resID)
	case "Groups":
		s.scimGroups(w, r, t, resID)
	default:
		s.store.mu.Unlock()
		writeSCIMErr(w, r, http.StatusNotFound, "", "unknown SCIM endpoint /"+sub)
	}
}

func (s *Server) scimServiceProviderConfig(tid string) map[string]any {
	return map[string]any{
		"schemas":          []string{schemaSPC},
		"documentationUri": "https://www.rfc-editor.org/rfc/rfc7644",
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": 1000},
		"changePassword":   map[string]any{"supported": true},
		"sort":             map[string]any{"supported": true},
		"etag":             map[string]any{"supported": true},
		"authenticationSchemes": []map[string]any{{
			"type":        "oauthbearertoken",
			"name":        "OAuth Bearer Token",
			"description": "OAuth 2.0 Bearer Token",
			"specUri":     "https://www.rfc-editor.org/info/rfc6750",
			"primary":     true,
		}},
		"meta": map[string]any{
			"resourceType": "ServiceProviderConfig",
			"location":     s.base + "/t/" + tid + "/scim/v2/ServiceProviderConfig",
		},
	}
}

func (s *Server) scimResourceTypes(w http.ResponseWriter, r *http.Request, tid, resID string) {
	userRT := map[string]any{
		"schemas":     []string{schemaRT},
		"id":          "User",
		"name":        "User",
		"endpoint":    "/Users",
		"description": "User Account",
		"schema":      schemaUser,
		"schemaExtensions": []map[string]any{{
			"schema":   schemaEnt,
			"required": false,
		}},
		"meta": map[string]any{
			"resourceType": "ResourceType",
			"location":     s.base + "/t/" + tid + "/scim/v2/ResourceTypes/User",
		},
	}
	groupRT := map[string]any{
		"schemas":          []string{schemaRT},
		"id":               "Group",
		"name":             "Group",
		"endpoint":         "/Groups",
		"description":      "Group",
		"schema":           schemaGroup,
		"schemaExtensions": []map[string]any{},
		"meta": map[string]any{
			"resourceType": "ResourceType",
			"location":     s.base + "/t/" + tid + "/scim/v2/ResourceTypes/Group",
		},
	}
	switch resID {
	case "":
		writeSCIM(w, http.StatusOK, map[string]any{
			"schemas":      []string{schemaList},
			"totalResults": 2,
			"startIndex":   1,
			"itemsPerPage": 2,
			"Resources":    []any{userRT, groupRT},
		})
	case "User":
		writeSCIM(w, http.StatusOK, userRT)
	case "Group":
		writeSCIM(w, http.StatusOK, groupRT)
	default:
		writeSCIMErr(w, r, http.StatusNotFound, "", "unknown ResourceType "+resID)
	}
}

func (s *Server) scimSchemas(w http.ResponseWriter, r *http.Request, tid, resID string) {
	attr := func(name, typ string, multi, req, caseExact bool, mutability, uniqueness string) map[string]any {
		return map[string]any{
			"name":        name,
			"type":        typ,
			"multiValued": multi,
			"required":    req,
			"caseExact":   caseExact,
			"mutability":  mutability,
			"returned":    "default",
			"uniqueness":  uniqueness,
		}
	}
	userSchema := map[string]any{
		"schemas":     []string{schemaDef},
		"id":          schemaUser,
		"name":        "User",
		"description": "User Account",
		"attributes": []map[string]any{
			attr("userName", "string", false, true, false, "readWrite", "server"),
			attr("name", "complex", false, false, false, "readWrite", "none"),
			attr("displayName", "string", false, false, false, "readWrite", "none"),
			attr("title", "string", false, false, false, "readWrite", "none"),
			attr("active", "boolean", false, false, false, "readWrite", "none"),
			attr("emails", "complex", true, false, false, "readWrite", "none"),
			attr("phoneNumbers", "complex", true, false, false, "readWrite", "none"),
			attr("groups", "complex", true, false, false, "readOnly", "none"),
		},
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     s.base + "/t/" + tid + "/scim/v2/Schemas/" + schemaUser,
		},
	}
	entSchema := map[string]any{
		"schemas":     []string{schemaDef},
		"id":          schemaEnt,
		"name":        "EnterpriseUser",
		"description": "Enterprise User",
		"attributes": []map[string]any{
			attr("employeeNumber", "string", false, false, false, "readWrite", "none"),
			attr("department", "string", false, false, false, "readWrite", "none"),
			attr("manager", "complex", false, false, false, "readWrite", "none"),
		},
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     s.base + "/t/" + tid + "/scim/v2/Schemas/" + schemaEnt,
		},
	}
	groupSchema := map[string]any{
		"schemas":     []string{schemaDef},
		"id":          schemaGroup,
		"name":        "Group",
		"description": "Group",
		"attributes": []map[string]any{
			attr("displayName", "string", false, true, false, "readWrite", "server"),
			attr("members", "complex", true, false, false, "readWrite", "none"),
		},
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     s.base + "/t/" + tid + "/scim/v2/Schemas/" + schemaGroup,
		},
	}
	all := []any{userSchema, entSchema, groupSchema}
	switch resID {
	case "":
		writeSCIM(w, http.StatusOK, map[string]any{
			"schemas":      []string{schemaList},
			"totalResults": len(all),
			"startIndex":   1,
			"itemsPerPage": len(all),
			"Resources":    all,
		})
	case schemaUser:
		writeSCIM(w, http.StatusOK, userSchema)
	case schemaEnt:
		writeSCIM(w, http.StatusOK, entSchema)
	case schemaGroup:
		writeSCIM(w, http.StatusOK, groupSchema)
	default:
		writeSCIMErr(w, r, http.StatusNotFound, "", "unknown Schema "+resID)
	}
}

// ---- SCIM Resource Serialization, ETag & Attribute Projection ----

func computeETag(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return `W/"` + hex.EncodeToString(sum[:8]) + `"`
}

func checkIfMatch(w http.ResponseWriter, r *http.Request, currentETag string) bool {
	ifMatch := strings.TrimSpace(r.Header.Get("If-Match"))
	if ifMatch == "" || ifMatch == "*" {
		return true
	}
	norm := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimPrefix(s, "W/")
		s = strings.TrimPrefix(s, "w/")
		return strings.Trim(s, `"`)
	}
	want := norm(currentETag)
	for _, part := range strings.Split(ifMatch, ",") {
		if norm(part) == want {
			return true
		}
	}
	writeSCIMErr(w, r, http.StatusPreconditionFailed, "", fmt.Sprintf("ETag precondition failed: got %s, current is %s", ifMatch, currentETag))
	return false
}

func (s *Server) toSCIMUser(t *Tenant, u *User) (map[string]any, string) {
	schemas := []string{schemaUser}
	r := map[string]any{
		"id":          u.ID,
		"userName":    u.UserName,
		"name":        map[string]any{"givenName": u.GivenName, "familyName": u.FamilyName, "formatted": u.DisplayName},
		"displayName": u.DisplayName,
		"active":      u.Active,
	}
	if ext := u.Attributes["externalId"]; ext != "" {
		r["externalId"] = ext
	}
	if u.Title != "" {
		r["title"] = u.Title
	}
	if u.Email != "" {
		r["emails"] = []any{map[string]any{"value": u.Email, "type": "work", "primary": true}}
	}
	if u.Phone != "" {
		r["phoneNumbers"] = []any{map[string]any{"value": u.Phone, "type": "work", "primary": true}}
	}
	gs := []any{}
	for _, g := range t.groupsOf(u.ID) {
		gs = append(gs, map[string]any{
			"value":   g.ID,
			"display": g.Name,
			"$ref":    s.base + "/t/" + t.ID + "/scim/v2/Groups/" + g.ID,
		})
	}
	r["groups"] = gs
	if u.Department != "" || u.EmployeeNumber != "" || u.Manager != "" {
		ent := map[string]any{}
		if u.Department != "" {
			ent["department"] = u.Department
		}
		if u.EmployeeNumber != "" {
			ent["employeeNumber"] = u.EmployeeNumber
		}
		if u.Manager != "" {
			ent["manager"] = map[string]any{"value": u.Manager}
		}
		schemas = append(schemas, schemaEnt)
		r[schemaEnt] = ent
	}
	r["schemas"] = schemas
	etag := computeETag(r)
	r["meta"] = map[string]any{
		"resourceType": "User",
		"created":      "2025-01-01T00:00:00Z",
		"lastModified": "2025-01-01T00:00:00Z",
		"location":     s.base + "/t/" + t.ID + "/scim/v2/Users/" + u.ID,
		"version":      etag,
	}
	return r, etag
}

func (s *Server) toSCIMGroup(t *Tenant, g *Group) (map[string]any, string) {
	ms := []any{}
	for _, uid := range g.Members {
		m := map[string]any{"value": uid}
		if u := t.user(uid); u != nil {
			m["display"] = u.UserName
			m["$ref"] = s.base + "/t/" + t.ID + "/scim/v2/Users/" + u.ID
		}
		ms = append(ms, m)
	}
	r := map[string]any{
		"schemas":     []string{schemaGroup},
		"id":          g.ID,
		"displayName": g.Name,
		"members":     ms,
	}
	etag := computeETag(r)
	r["meta"] = map[string]any{
		"resourceType": "Group",
		"created":      "2025-01-01T00:00:00Z",
		"lastModified": "2025-01-01T00:00:00Z",
		"location":     s.base + "/t/" + t.ID + "/scim/v2/Groups/" + g.ID,
		"version":      etag,
	}
	return r, etag
}

func stripCoreSchemaPrefix(attr string) string {
	for _, p := range []string{schemaUser + ":", schemaGroup + ":"} {
		if len(attr) > len(p) && strings.EqualFold(attr[:len(p)], p) {
			return attr[len(p):]
		}
	}
	return attr
}

func projectResource(res map[string]any, attrsParam, exclParam string) map[string]any {
	attrsParam = strings.TrimSpace(attrsParam)
	exclParam = strings.TrimSpace(exclParam)
	if attrsParam == "" && exclParam == "" {
		return res
	}
	out := maps.Clone(res)
	if attrsParam != "" {
		keepTop := map[string]bool{"schemas": true, "id": true, "meta": true}
		subKeep := map[string]map[string]bool{}
		for _, raw := range strings.Split(attrsParam, ",") {
			a := strings.TrimSpace(stripCoreSchemaPrefix(raw))
			if a == "" {
				continue
			}
			if strings.HasPrefix(strings.ToLower(a), strings.ToLower(schemaEnt)+":") {
				keepTop[ strings.ToLower(schemaEnt) ] = true
				sub := a[len(schemaEnt)+1:]
				if subKeep[strings.ToLower(schemaEnt)] == nil {
					subKeep[strings.ToLower(schemaEnt)] = map[string]bool{}
				}
				subKeep[strings.ToLower(schemaEnt)][strings.ToLower(sub)] = true
				continue
			}
			top, sub, hasSub := strings.Cut(a, ".")
			keepTop[strings.ToLower(top)] = true
			if hasSub {
				if subKeep[strings.ToLower(top)] == nil {
					subKeep[strings.ToLower(top)] = map[string]bool{}
				}
				subKeep[strings.ToLower(top)][strings.ToLower(sub)] = true
			}
		}
		for k, v := range out {
			lk := strings.ToLower(k)
			if !keepTop[lk] {
				delete(out, k)
				continue
			}
			if subs := subKeep[lk]; len(subs) > 0 {
				if m, ok := v.(map[string]any); ok {
					nm := map[string]any{}
					for sk, sv := range m {
						if subs[strings.ToLower(sk)] {
							nm[sk] = sv
						}
					}
					out[k] = nm
				}
			}
		}
		return out
	}

	for _, raw := range strings.Split(exclParam, ",") {
		a := strings.TrimSpace(stripCoreSchemaPrefix(raw))
		if a == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(a), strings.ToLower(schemaEnt)+":") {
			sub := a[len(schemaEnt)+1:]
			if m, ok := out[schemaEnt].(map[string]any); ok {
				nm := maps.Clone(m)
				for sk := range nm {
					if strings.EqualFold(sk, sub) {
						delete(nm, sk)
					}
				}
				out[schemaEnt] = nm
			}
			continue
		}
		top, sub, hasSub := strings.Cut(a, ".")
		if strings.EqualFold(top, "schemas") || strings.EqualFold(top, "id") || strings.EqualFold(top, "meta") {
			continue
		}
		for k, v := range out {
			if strings.EqualFold(k, top) {
				if !hasSub {
					delete(out, k)
				} else if m, ok := v.(map[string]any); ok {
					nm := maps.Clone(m)
					for sk := range nm {
						if strings.EqualFold(sk, sub) {
							delete(nm, sk)
						}
					}
					out[k] = nm
				}
			}
		}
	}
	return out
}

// ---- RFC 7644 Filter AST Parser & Evaluator ----

type filterNode interface {
	eval(res map[string]any) bool
}

type logicalNode struct {
	op          string // "and" | "or"
	left, right filterNode
}

func (n *logicalNode) eval(res map[string]any) bool {
	if n.op == "and" {
		return n.left.eval(res) && n.right.eval(res)
	}
	return n.left.eval(res) || n.right.eval(res)
}

type notNode struct {
	child filterNode
}

func (n *notNode) eval(res map[string]any) bool {
	return !n.child.eval(res)
}

type attrExprNode struct {
	attr   string
	op     string // eq, ne, co, sw, ew, pr, gt, ge, lt, le
	val    any
	quoted bool
}

func (n *attrExprNode) eval(res map[string]any) bool {
	vals := resolveAttrValues(res, n.attr)
	if n.op == "pr" {
		for _, v := range vals {
			if isPresent(v) {
				return true
			}
		}
		return false
	}
	if n.op == "ne" {
		if len(vals) == 0 {
			return true
		}
		for _, v := range vals {
			if compareVal(v, "eq", n.val, n.quoted) {
				return false
			}
		}
		return true
	}
	for _, v := range vals {
		if compareVal(v, n.op, n.val, n.quoted) {
			return true
		}
	}
	return false
}

type valuePathNode struct {
	attr    string
	filter  filterNode
	subAttr string
	op      string
	val     any
	quoted  bool
}

func (n *valuePathNode) eval(res map[string]any) bool {
	vals := resolveAttrValues(res, n.attr)
	for _, item := range vals {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if !n.filter.eval(m) {
			continue
		}
		if n.op == "" {
			return true
		}
		subPath := n.subAttr
		if subPath == "" {
			subPath = "value"
		}
		subExpr := &attrExprNode{attr: subPath, op: n.op, val: n.val, quoted: n.quoted}
		if subExpr.eval(m) {
			return true
		}
	}
	return false
}

func isPresent(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		if val, ok := x["value"]; ok {
			return isPresent(val)
		}
		return len(x) > 0
	default:
		return true
	}
}

func compareVal(actual any, op string, target any, quoted bool) bool {
	if actual == nil {
		return false
	}
	if m, ok := actual.(map[string]any); ok {
		if v, exists := m["value"]; exists {
			actual = v
		} else {
			return false
		}
	}
	switch a := actual.(type) {
	case bool:
		tb, ok := toBool(target)
		if !ok {
			return false
		}
		if op == "eq" {
			return a == tb
		}
		return false
	}

	as := strings.TrimSpace(fmt.Sprint(actual))
	ts := strings.TrimSpace(fmt.Sprint(target))
	if !quoted {
		if af, err1 := strconv.ParseFloat(as, 64); err1 == nil {
			if tf, err2 := strconv.ParseFloat(ts, 64); err2 == nil {
				switch op {
				case "eq":
					return af == tf
				case "gt":
					return af > tf
				case "ge":
					return af >= tf
				case "lt":
					return af < tf
				case "le":
					return af <= tf
				}
			}
		}
	} else if op == "gt" || op == "ge" || op == "lt" || op == "le" {
		if af, err1 := strconv.ParseFloat(as, 64); err1 == nil {
			if tf, err2 := strconv.ParseFloat(ts, 64); err2 == nil {
				switch op {
				case "gt":
					return af > tf
				case "ge":
					return af >= tf
				case "lt":
					return af < tf
				case "le":
					return af <= tf
				}
			}
		}
	}

	al := strings.ToLower(fmt.Sprint(actual))
	tl := strings.ToLower(fmt.Sprint(target))
	switch op {
	case "eq":
		return al == tl
	case "co":
		return strings.Contains(al, tl)
	case "sw":
		return strings.HasPrefix(al, tl)
	case "ew":
		return strings.HasSuffix(al, tl)
	case "gt":
		return al > tl
	case "ge":
		return al >= tl
	case "lt":
		return al < tl
	case "le":
		return al <= tl
	}
	return false
}

func toBool(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		if strings.EqualFold(x, "true") {
			return true, true
		}
		if strings.EqualFold(x, "false") {
			return false, true
		}
	}
	return false, false
}

func lookupCaseInsensitive(m map[string]any, key string) (any, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

func resolveAttrValues(res map[string]any, attrPath string) []any {
	p := stripCoreSchemaPrefix(strings.TrimSpace(attrPath))
	if strings.HasPrefix(strings.ToLower(p), strings.ToLower(schemaEnt)+":") {
		sub := p[len(schemaEnt)+1:]
		ent, ok := lookupCaseInsensitive(res, schemaEnt)
		if !ok {
			return nil
		}
		em, ok := ent.(map[string]any)
		if !ok {
			return nil
		}
		return resolveSegments(em, strings.Split(sub, "."))
	}
	return resolveSegments(res, strings.Split(p, "."))
}

func resolveSegments(curr any, segs []string) []any {
	if curr == nil {
		return nil
	}
	if len(segs) == 0 {
		if slice, ok := curr.([]any); ok {
			return slice
		}
		return []any{curr}
	}
	switch x := curr.(type) {
	case map[string]any:
		v, ok := lookupCaseInsensitive(x, segs[0])
		if !ok {
			return nil
		}
		return resolveSegments(v, segs[1:])
	case []any:
		var out []any
		for _, elem := range x {
			out = append(out, resolveSegments(elem, segs)...)
		}
		return out
	default:
		return nil
	}
}

type filterToken struct {
	kind string // "ident", "string", "lparen", "rparen", "lbrack", "rbrack"
	text string
}

func tokenizeFilter(input string) ([]filterToken, error) {
	var tokens []filterToken
	i := 0
	n := len(input)
	for i < n {
		c := input[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			i++
			continue
		}
		switch c {
		case '(':
			tokens = append(tokens, filterToken{kind: "lparen", text: "("})
			i++
		case ')':
			tokens = append(tokens, filterToken{kind: "rparen", text: ")"})
			i++
		case '[':
			tokens = append(tokens, filterToken{kind: "lbrack", text: "["})
			i++
		case ']':
			tokens = append(tokens, filterToken{kind: "rbrack", text: "]"})
			i++
		case '"':
			var b strings.Builder
			i++
			closed := false
			for i < n {
				if input[i] == '\\' && i+1 < n {
					i++
					b.WriteByte(input[i])
					i++
					continue
				}
				if input[i] == '"' {
					i++
					closed = true
					break
				}
				b.WriteByte(input[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated string literal in filter")
			}
			tokens = append(tokens, filterToken{kind: "string", text: b.String()})
		default:
			start := i
			for i < n {
				ch := input[i]
				if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '(' || ch == ')' || ch == '[' || ch == ']' || ch == '"' {
					break
				}
				i++
			}
			tokens = append(tokens, filterToken{kind: "ident", text: input[start:i]})
		}
	}
	return tokens, nil
}

type filterParser struct {
	tokens []filterToken
	pos    int
}

func (p *filterParser) peek() (filterToken, bool) {
	if p.pos >= len(p.tokens) {
		return filterToken{}, false
	}
	return p.tokens[p.pos], true
}

func (p *filterParser) next() (filterToken, bool) {
	if p.pos >= len(p.tokens) {
		return filterToken{}, false
	}
	t := p.tokens[p.pos]
	p.pos++
	return t, true
}

func isAttrOp(s string) bool {
	switch strings.ToLower(s) {
	case "eq", "ne", "co", "sw", "ew", "pr", "gt", "ge", "lt", "le":
		return true
	}
	return false
}

func parseFilter(raw string) (filterNode, error) {
	tokens, err := tokenizeFilter(raw)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty filter")
	}
	p := &filterParser{tokens: tokens}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if extra, ok := p.peek(); ok {
		return nil, fmt.Errorf("unexpected token %q in filter", extra.text)
	}
	return node, nil
}

func (p *filterParser) parseOr() (filterNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		tok, ok := p.peek()
		if !ok || tok.kind != "ident" || !strings.EqualFold(tok.text, "or") {
			break
		}
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &logicalNode{op: "or", left: left, right: right}
	}
	return left, nil
}

func (p *filterParser) parseAnd() (filterNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		tok, ok := p.peek()
		if !ok || tok.kind != "ident" || !strings.EqualFold(tok.text, "and") {
			break
		}
		p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &logicalNode{op: "and", left: left, right: right}
	}
	return left, nil
}

func (p *filterParser) parseUnary() (filterNode, error) {
	tok, ok := p.peek()
	if !ok {
		return nil, fmt.Errorf("unexpected end of filter")
	}
	if tok.kind == "ident" && strings.EqualFold(tok.text, "not") {
		p.next()
		child, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &notNode{child: child}, nil
	}
	if tok.kind == "lparen" {
		p.next()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		closeTok, ok := p.next()
		if !ok || closeTok.kind != "rparen" {
			return nil, fmt.Errorf("missing closing ')' in filter")
		}
		return inner, nil
	}
	return p.parsePrimary()
}

func (p *filterParser) parsePrimary() (filterNode, error) {
	attrTok, ok := p.next()
	if !ok || attrTok.kind != "ident" {
		return nil, fmt.Errorf("expected attribute name in filter")
	}
	if nextTok, ok := p.peek(); ok && nextTok.kind == "lbrack" {
		p.next() // consume '['
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		closeBrack, ok := p.next()
		if !ok || closeBrack.kind != "rbrack" {
			return nil, fmt.Errorf("missing closing ']' in value path filter")
		}
		vp := &valuePathNode{attr: attrTok.text, filter: inner}
		if subTok, ok := p.peek(); ok && subTok.kind == "ident" && strings.HasPrefix(subTok.text, ".") {
			p.next()
			vp.subAttr = strings.TrimPrefix(subTok.text, ".")
		}
		if opTok, ok := p.peek(); ok && opTok.kind == "ident" && isAttrOp(opTok.text) {
			p.next()
			vp.op = strings.ToLower(opTok.text)
			if vp.op != "pr" {
				val, quoted, err := p.parseCompValue()
				if err != nil {
					return nil, err
				}
				vp.val = val
				vp.quoted = quoted
			}
		} else if vp.subAttr != "" {
			return nil, fmt.Errorf("expected operator after value path sub-attribute %q", vp.subAttr)
		}
		return vp, nil
	}

	opTok, ok := p.next()
	if !ok || opTok.kind != "ident" || !isAttrOp(opTok.text) {
		return nil, fmt.Errorf("expected filter operator after %q", attrTok.text)
	}
	op := strings.ToLower(opTok.text)
	if op == "pr" {
		return &attrExprNode{attr: attrTok.text, op: "pr"}, nil
	}
	val, quoted, err := p.parseCompValue()
	if err != nil {
		return nil, err
	}
	return &attrExprNode{attr: attrTok.text, op: op, val: val, quoted: quoted}, nil
}

func (p *filterParser) parseCompValue() (any, bool, error) {
	tok, ok := p.next()
	if !ok {
		return nil, false, fmt.Errorf("missing comparison value in filter")
	}
	if tok.kind == "string" {
		return tok.text, true, nil
	}
	if tok.kind == "ident" {
		switch strings.ToLower(tok.text) {
		case "true":
			return true, false, nil
		case "false":
			return false, false, nil
		case "null":
			return nil, false, nil
		default:
			if _, err := strconv.ParseFloat(tok.text, 64); err == nil {
				return tok.text, false, nil
			}
			return nil, false, fmt.Errorf("unquoted literal %q in filter", tok.text)
		}
	}
	return nil, false, fmt.Errorf("invalid comparison value %q in filter", tok.text)
}

// ---- List Querying: Filter, Sort, Paginate, Project ----

func (s *Server) scimListResponse(w http.ResponseWriter, r *http.Request, resources []map[string]any) {
	q := r.URL.Query()
	filterStr := strings.TrimSpace(q.Get("filter"))
	var ast filterNode
	if filterStr != "" {
		var err error
		ast, err = parseFilter(filterStr)
		if err != nil {
			writeSCIMErr(w, r, http.StatusBadRequest, "invalidFilter", err.Error())
			return
		}
	}

	var matched []map[string]any
	for _, res := range resources {
		if ast == nil || ast.eval(res) {
			matched = append(matched, res)
		}
	}

	if sortBy := strings.TrimSpace(q.Get("sortBy")); sortBy != "" {
		desc := strings.EqualFold(strings.TrimSpace(q.Get("sortOrder")), "descending")
		slices.SortStableFunc(matched, func(a, b map[string]any) int {
			va := firstSortKey(resolveAttrValues(a, sortBy))
			vb := firstSortKey(resolveAttrValues(b, sortBy))
			c := cmp.Compare(va, vb)
			if desc {
				return -c
			}
			return c
		})
	}

	totalResults := len(matched)
	startIndex := 1
	if sIdx := q.Get("startIndex"); sIdx != "" {
		if v, err := strconv.Atoi(sIdx); err == nil && v >= 1 {
			startIndex = v
		}
	}
	count := 100
	if cStr := q.Get("count"); cStr != "" {
		if v, err := strconv.Atoi(cStr); err == nil {
			if v < 0 {
				v = 0
			}
			count = v
		}
	}

	page := []any{}
	start := startIndex - 1
	if count > 0 && start < totalResults {
		end := min(start+count, totalResults)
		attrsParam := q.Get("attributes")
		exclParam := q.Get("excludedAttributes")
		for _, item := range matched[start:end] {
			page = append(page, projectResource(item, attrsParam, exclParam))
		}
	}

	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{schemaList},
		"totalResults": totalResults,
		"startIndex":   startIndex,
		"itemsPerPage": len(page),
		"Resources":    page,
	})
}

func firstSortKey(vals []any) string {
	for _, v := range vals {
		if m, ok := v.(map[string]any); ok {
			if mv, exists := m["value"]; exists {
				return strings.ToLower(fmt.Sprint(mv))
			}
		}
		if v != nil {
			return strings.ToLower(fmt.Sprint(v))
		}
	}
	return ""
}

// ---- SCIM Users CRUD & PATCH ----

func findUserByID(t *Tenant, id string) *User {
	for _, u := range t.Users {
		if u.ID == id {
			return u
		}
	}
	return nil
}

func hasDuplicateUserName(t *Tenant, userName, excludeID string) bool {
	for _, u := range t.Users {
		if u.ID != excludeID && strings.EqualFold(u.UserName, userName) {
			return true
		}
	}
	return false
}

func parseSCIMBool(v any, def bool) bool {
	if b, ok := toBool(v); ok {
		return b
	}
	return def
}

func extractPrimaryValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case map[string]any:
		return str(x["value"])
	case []any:
		var first string
		for _, elem := range x {
			m, ok := elem.(map[string]any)
			if !ok {
				continue
			}
			val := str(m["value"])
			if first == "" {
				first = val
			}
			if b, ok := toBool(m["primary"]); ok && b {
				return val
			}
		}
		return first
	}
	return ""
}

func applySCIMUserBody(u *User, body map[string]any) {
	if un := strings.TrimSpace(str(body["userName"])); un != "" {
		u.UserName = un
	}
	if nm, ok := body["name"].(map[string]any); ok {
		if gn, has := nm["givenName"]; has {
			u.GivenName = str(gn)
		}
		if fn, has := nm["familyName"]; has {
			u.FamilyName = str(fn)
		}
		if fmtName := str(nm["formatted"]); fmtName != "" && str(body["displayName"]) == "" {
			u.DisplayName = fmtName
		}
	}
	if dn, has := body["displayName"]; has {
		u.DisplayName = str(dn)
	}
	if u.DisplayName == "" {
		u.DisplayName = strings.TrimSpace(u.GivenName + " " + u.FamilyName)
	}
	if act, has := body["active"]; has {
		u.Active = parseSCIMBool(act, true)
	}
	if title, has := body["title"]; has {
		u.Title = str(title)
	}
	if emails, has := body["emails"]; has {
		u.Email = extractPrimaryValue(emails)
	}
	if phones, has := body["phoneNumbers"]; has {
		u.Phone = extractPrimaryValue(phones)
	}
	if ext, has := body["externalId"]; has {
		if u.Attributes == nil {
			u.Attributes = map[string]string{}
		}
		if s := str(ext); s != "" {
			u.Attributes["externalId"] = s
		} else {
			delete(u.Attributes, "externalId")
		}
	}
	if entRaw, ok := lookupCaseInsensitive(body, schemaEnt); ok {
		if ent, ok := entRaw.(map[string]any); ok {
			if dept, has := ent["department"]; has {
				u.Department = str(dept)
			}
			if emp, has := ent["employeeNumber"]; has {
				u.EmployeeNumber = str(emp)
			}
			if mgr, has := ent["manager"]; has {
				if mm, ok := mgr.(map[string]any); ok {
					u.Manager = str(mm["value"])
				} else {
					u.Manager = str(mgr)
				}
			}
		}
	}
}

func (s *Server) scimUsers(w http.ResponseWriter, r *http.Request, t *Tenant, resID string) {
	q := r.URL.Query()
	attrsParam, exclParam := q.Get("attributes"), q.Get("excludedAttributes")

	if resID == "" {
		switch r.Method {
		case http.MethodGet:
			var list []map[string]any
			for _, u := range t.Users {
				ru, _ := s.toSCIMUser(t, u)
				list = append(list, ru)
			}
			s.store.mu.Unlock()
			s.scimListResponse(w, r, list)
		case http.MethodPost:
			var body map[string]any
			if err := readBody(r, &body); err != nil || body == nil {
				s.store.mu.Unlock()
				writeSCIMErr(w, r, http.StatusBadRequest, "invalidSyntax", "invalid JSON request body")
				return
			}
			un := strings.TrimSpace(str(body["userName"]))
			if un == "" {
				s.store.mu.Unlock()
				writeSCIMErr(w, r, http.StatusBadRequest, "invalidValue", "userName is required")
				return
			}
			if hasDuplicateUserName(t, un, "") {
				s.store.mu.Unlock()
				writeSCIMErr(w, r, http.StatusConflict, "uniqueness", "userName "+un+" already exists")
				return
			}
			u := &User{
				ID:            newID(providers[t.Provider].IDStyle, "user"),
				UserName:      un,
				Password:      "password",
				Active:        true,
				EmailVerified: true,
				Attributes:    map[string]string{},
			}
			applySCIMUserBody(u, body)
			t.Users = append(t.Users, u)
			s.store.save()
			ru, etag := s.toSCIMUser(t, u)
			snap := *u
			tid := t.ID
			s.store.mu.Unlock()

			s.logs.publish("change", map[string]string{"tenant": tid})
			s.autoPush(tid, []User{snap}, nil, "upsert")
			w.Header().Set("Location", s.base+"/t/"+tid+"/scim/v2/Users/"+snap.ID)
			w.Header().Set("ETag", etag)
			writeSCIM(w, http.StatusCreated, projectResource(ru, attrsParam, exclParam))
		default:
			s.store.mu.Unlock()
			writeSCIMErr(w, r, http.StatusMethodNotAllowed, "", "unsupported method on /Users")
		}
		return
	}

	u := findUserByID(t, resID)
	if u == nil {
		s.store.mu.Unlock()
		writeSCIMErr(w, r, http.StatusNotFound, "", "User "+resID+" not found")
		return
	}
	curRes, curETag := s.toSCIMUser(t, u)

	switch r.Method {
	case http.MethodGet:
		s.store.mu.Unlock()
		w.Header().Set("ETag", curETag)
		writeSCIM(w, http.StatusOK, projectResource(curRes, attrsParam, exclParam))
	case http.MethodDelete:
		if !checkIfMatch(w, r, curETag) {
			s.store.mu.Unlock()
			return
		}
		snap := *u
		tid := t.ID
		t.Users = slices.DeleteFunc(t.Users, func(x *User) bool { return x.ID == resID })
		for _, g := range t.Groups {
			g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return m == resID })
		}
		s.store.save()
		s.store.mu.Unlock()
		s.logs.publish("change", map[string]string{"tenant": tid})
		s.autoPush(tid, []User{snap}, nil, "delete")
		writeSCIM(w, http.StatusNoContent, nil)
	case http.MethodPut:
		if !checkIfMatch(w, r, curETag) {
			s.store.mu.Unlock()
			return
		}
		var body map[string]any
		if err := readBody(r, &body); err != nil || body == nil {
			s.store.mu.Unlock()
			writeSCIMErr(w, r, http.StatusBadRequest, "invalidSyntax", "invalid JSON request body")
			return
		}
		newUN := strings.TrimSpace(str(body["userName"]))
		if newUN == "" {
			s.store.mu.Unlock()
			writeSCIMErr(w, r, http.StatusBadRequest, "invalidValue", "userName is required")
			return
		}
		if hasDuplicateUserName(t, newUN, u.ID) {
			s.store.mu.Unlock()
			writeSCIMErr(w, r, http.StatusConflict, "uniqueness", "userName "+newUN+" already exists")
			return
		}
		u.GivenName, u.FamilyName, u.DisplayName, u.Title, u.Email, u.Phone = "", "", "", "", "", ""
		u.Department, u.EmployeeNumber, u.Manager = "", "", ""
		u.Active = true
		applySCIMUserBody(u, body)
		s.store.save()
		ru, etag := s.toSCIMUser(t, u)
		snap := *u
		tid := t.ID
		s.store.mu.Unlock()

		s.logs.publish("change", map[string]string{"tenant": tid})
		s.autoPush(tid, []User{snap}, nil, "upsert")
		w.Header().Set("ETag", etag)
		writeSCIM(w, http.StatusOK, projectResource(ru, attrsParam, exclParam))
	case http.MethodPatch:
		if !checkIfMatch(w, r, curETag) {
			s.store.mu.Unlock()
			return
		}
		var body map[string]any
		if err := readBody(r, &body); err != nil || body == nil {
			s.store.mu.Unlock()
			writeSCIMErr(w, r, http.StatusBadRequest, "invalidSyntax", "invalid JSON request body")
			return
		}
		opsRaw, _ := lookupCaseInsensitive(body, "Operations")
		ops, ok := opsRaw.([]any)
		if !ok {
			s.store.mu.Unlock()
			writeSCIMErr(w, r, http.StatusBadRequest, "invalidSyntax", "PATCH requires Operations array")
			return
		}
		for _, item := range ops {
			opMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			op := strings.ToLower(strings.TrimSpace(str(opMap["op"])))
			if op != "add" && op != "replace" && op != "remove" {
				s.store.mu.Unlock()
				writeSCIMErr(w, r, http.StatusBadRequest, "invalidSyntax", "unsupported PATCH op "+op)
				return
			}
			path := strings.TrimSpace(str(opMap["path"]))
			val := opMap["value"]
			if code, scimType, errMsg := applyUserPatchOp(t, u, op, path, val); code != 0 {
				s.store.mu.Unlock()
				writeSCIMErr(w, r, code, scimType, errMsg)
				return
			}
		}
		s.store.save()
		ru, etag := s.toSCIMUser(t, u)
		snap := *u
		tid := t.ID
		s.store.mu.Unlock()

		s.logs.publish("change", map[string]string{"tenant": tid})
		s.autoPush(tid, []User{snap}, nil, "upsert")
		w.Header().Set("ETag", etag)
		writeSCIM(w, http.StatusOK, projectResource(ru, attrsParam, exclParam))
	default:
		s.store.mu.Unlock()
		writeSCIMErr(w, r, http.StatusMethodNotAllowed, "", "unsupported method")
	}
}

func applyUserPatchOp(t *Tenant, u *User, op, path string, val any) (int, string, string) {
	if path == "" {
		m, ok := val.(map[string]any)
		if !ok {
			return http.StatusBadRequest, "invalidSyntax", "PATCH with empty path requires an object value"
		}
		for k, v := range m {
			if code, st, msg := applyUserPatchOp(t, u, op, k, v); code != 0 {
				return code, st, msg
			}
		}
		return 0, "", ""
	}

	p := stripCoreSchemaPrefix(path)
	if strings.EqualFold(p, schemaEnt) {
		if op == "remove" {
			u.Department, u.EmployeeNumber, u.Manager = "", "", ""
			return 0, "", ""
		}
		if m, ok := val.(map[string]any); ok {
			for k, v := range m {
				if code, st, msg := applyUserPatchOp(t, u, op, schemaEnt+":"+k, v); code != 0 {
					return code, st, msg
				}
			}
		}
		return 0, "", ""
	}
	if strings.HasPrefix(strings.ToLower(p), strings.ToLower(schemaEnt)+":") {
		p = p[len(schemaEnt)+1:]
	}

	lp := strings.ToLower(p)
	switch {
	case lp == "username":
		if op == "remove" {
			return http.StatusBadRequest, "mutability", "userName cannot be removed"
		}
		newUN := strings.TrimSpace(str(val))
		if newUN == "" {
			return http.StatusBadRequest, "invalidValue", "userName cannot be empty"
		}
		if hasDuplicateUserName(t, newUN, u.ID) {
			return http.StatusConflict, "uniqueness", "userName " + newUN + " already exists"
		}
		u.UserName = newUN
	case lp == "active":
		if op == "remove" {
			u.Active = false
		} else {
			u.Active = parseSCIMBool(val, u.Active)
		}
	case lp == "displayname" || lp == "name.formatted":
		if op == "remove" {
			u.DisplayName = ""
		} else {
			u.DisplayName = str(val)
		}
	case lp == "name":
		if op == "remove" {
			u.GivenName, u.FamilyName = "", ""
		} else if m, ok := val.(map[string]any); ok {
			if gn, has := m["givenName"]; has {
				u.GivenName = str(gn)
			}
			if fn, has := m["familyName"]; has {
				u.FamilyName = str(fn)
			}
			if fmtName, has := m["formatted"]; has {
				u.DisplayName = str(fmtName)
			}
		}
	case lp == "name.givenname":
		if op == "remove" {
			u.GivenName = ""
		} else {
			u.GivenName = str(val)
		}
	case lp == "name.familyname":
		if op == "remove" {
			u.FamilyName = ""
		} else {
			u.FamilyName = str(val)
		}
	case lp == "title":
		if op == "remove" {
			u.Title = ""
		} else {
			u.Title = str(val)
		}
	case lp == "externalid":
		if u.Attributes == nil {
			u.Attributes = map[string]string{}
		}
		if op == "remove" {
			delete(u.Attributes, "externalId")
		} else {
			u.Attributes["externalId"] = str(val)
		}
	case lp == "emails" || lp == "emails.value" || strings.HasPrefix(lp, "emails["):
		if op == "remove" {
			u.Email = ""
		} else {
			u.Email = extractPrimaryValue(val)
		}
	case lp == "phonenumbers" || lp == "phonenumbers.value" || strings.HasPrefix(lp, "phonenumbers["):
		if op == "remove" {
			u.Phone = ""
		} else {
			u.Phone = extractPrimaryValue(val)
		}
	case lp == "department":
		if op == "remove" {
			u.Department = ""
		} else {
			u.Department = str(val)
		}
	case lp == "employeenumber":
		if op == "remove" {
			u.EmployeeNumber = ""
		} else {
			u.EmployeeNumber = str(val)
		}
	case lp == "manager" || lp == "manager.value":
		if op == "remove" {
			u.Manager = ""
		} else if m, ok := val.(map[string]any); ok {
			u.Manager = str(m["value"])
		} else {
			u.Manager = str(val)
		}
	}
	return 0, "", ""
}

// ---- SCIM Groups CRUD & PATCH ----

func findGroupByID(t *Tenant, id string) *Group {
	for _, g := range t.Groups {
		if g.ID == id {
			return g
		}
	}
	return nil
}

func hasDuplicateGroupName(t *Tenant, name, excludeID string) bool {
	for _, g := range t.Groups {
		if g.ID != excludeID && strings.EqualFold(g.Name, name) {
			return true
		}
	}
	return false
}

func extractMemberIDs(v any) []string {
	out := []string{}
	switch x := v.(type) {
	case []any:
		for _, item := range x {
			if m, ok := item.(map[string]any); ok {
				if id := str(m["value"]); id != "" && !slices.Contains(out, id) {
					out = append(out, id)
				}
			} else if id := str(item); id != "" && !slices.Contains(out, id) {
				out = append(out, id)
			}
		}
	case map[string]any:
		if id := str(x["value"]); id != "" {
			out = append(out, id)
		}
	case string:
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

func (s *Server) scimGroups(w http.ResponseWriter, r *http.Request, t *Tenant, resID string) {
	q := r.URL.Query()
	attrsParam, exclParam := q.Get("attributes"), q.Get("excludedAttributes")

	if resID == "" {
		switch r.Method {
		case http.MethodGet:
			var list []map[string]any
			for _, g := range t.Groups {
				rg, _ := s.toSCIMGroup(t, g)
				list = append(list, rg)
			}
			s.store.mu.Unlock()
			s.scimListResponse(w, r, list)
		case http.MethodPost:
			var body map[string]any
			if err := readBody(r, &body); err != nil || body == nil {
				s.store.mu.Unlock()
				writeSCIMErr(w, r, http.StatusBadRequest, "invalidSyntax", "invalid JSON request body")
				return
			}
			name := strings.TrimSpace(str(body["displayName"]))
			if name == "" {
				s.store.mu.Unlock()
				writeSCIMErr(w, r, http.StatusBadRequest, "invalidValue", "displayName is required")
				return
			}
			if hasDuplicateGroupName(t, name, "") {
				s.store.mu.Unlock()
				writeSCIMErr(w, r, http.StatusConflict, "uniqueness", "group "+name+" already exists")
				return
			}
			g := &Group{
				ID:      newID(providers[t.Provider].IDStyle, "group"),
				Name:    name,
				Members: extractMemberIDs(body["members"]),
			}
			t.Groups = append(t.Groups, g)
			s.store.save()
			rg, etag := s.toSCIMGroup(t, g)
			snap := Group{ID: g.ID, Name: g.Name, Members: slices.Clone(g.Members)}
			tid := t.ID
			s.store.mu.Unlock()

			s.logs.publish("change", map[string]string{"tenant": tid})
			s.autoPush(tid, nil, []Group{snap}, "upsert")
			w.Header().Set("Location", s.base+"/t/"+tid+"/scim/v2/Groups/"+snap.ID)
			w.Header().Set("ETag", etag)
			writeSCIM(w, http.StatusCreated, projectResource(rg, attrsParam, exclParam))
		default:
			s.store.mu.Unlock()
			writeSCIMErr(w, r, http.StatusMethodNotAllowed, "", "unsupported method on /Groups")
		}
		return
	}

	g := findGroupByID(t, resID)
	if g == nil {
		s.store.mu.Unlock()
		writeSCIMErr(w, r, http.StatusNotFound, "", "Group "+resID+" not found")
		return
	}
	curRes, curETag := s.toSCIMGroup(t, g)

	switch r.Method {
	case http.MethodGet:
		s.store.mu.Unlock()
		w.Header().Set("ETag", curETag)
		writeSCIM(w, http.StatusOK, projectResource(curRes, attrsParam, exclParam))
	case http.MethodDelete:
		if !checkIfMatch(w, r, curETag) {
			s.store.mu.Unlock()
			return
		}
		snap := Group{ID: g.ID, Name: g.Name, Members: slices.Clone(g.Members)}
		tid := t.ID
		t.Groups = slices.DeleteFunc(t.Groups, func(x *Group) bool { return x.ID == resID })
		s.store.save()
		s.store.mu.Unlock()
		s.logs.publish("change", map[string]string{"tenant": tid})
		s.autoPush(tid, nil, []Group{snap}, "delete")
		writeSCIM(w, http.StatusNoContent, nil)
	case http.MethodPut:
		if !checkIfMatch(w, r, curETag) {
			s.store.mu.Unlock()
			return
		}
		var body map[string]any
		if err := readBody(r, &body); err != nil || body == nil {
			s.store.mu.Unlock()
			writeSCIMErr(w, r, http.StatusBadRequest, "invalidSyntax", "invalid JSON request body")
			return
		}
		name := strings.TrimSpace(str(body["displayName"]))
		if name == "" {
			s.store.mu.Unlock()
			writeSCIMErr(w, r, http.StatusBadRequest, "invalidValue", "displayName is required")
			return
		}
		if hasDuplicateGroupName(t, name, g.ID) {
			s.store.mu.Unlock()
			writeSCIMErr(w, r, http.StatusConflict, "uniqueness", "group "+name+" already exists")
			return
		}
		g.Name = name
		g.Members = extractMemberIDs(body["members"])
		s.store.save()
		rg, etag := s.toSCIMGroup(t, g)
		snap := Group{ID: g.ID, Name: g.Name, Members: slices.Clone(g.Members)}
		tid := t.ID
		s.store.mu.Unlock()

		s.logs.publish("change", map[string]string{"tenant": tid})
		s.autoPush(tid, nil, []Group{snap}, "upsert")
		w.Header().Set("ETag", etag)
		writeSCIM(w, http.StatusOK, projectResource(rg, attrsParam, exclParam))
	case http.MethodPatch:
		if !checkIfMatch(w, r, curETag) {
			s.store.mu.Unlock()
			return
		}
		var body map[string]any
		if err := readBody(r, &body); err != nil || body == nil {
			s.store.mu.Unlock()
			writeSCIMErr(w, r, http.StatusBadRequest, "invalidSyntax", "invalid JSON request body")
			return
		}
		opsRaw, _ := lookupCaseInsensitive(body, "Operations")
		ops, ok := opsRaw.([]any)
		if !ok {
			s.store.mu.Unlock()
			writeSCIMErr(w, r, http.StatusBadRequest, "invalidSyntax", "PATCH requires Operations array")
			return
		}
		for _, item := range ops {
			opMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			op := strings.ToLower(strings.TrimSpace(str(opMap["op"])))
			if op != "add" && op != "replace" && op != "remove" {
				s.store.mu.Unlock()
				writeSCIMErr(w, r, http.StatusBadRequest, "invalidSyntax", "unsupported PATCH op "+op)
				return
			}
			path := strings.TrimSpace(str(opMap["path"]))
			val := opMap["value"]
			if code, scimType, errMsg := applyGroupPatchOp(t, g, op, path, val); code != 0 {
				s.store.mu.Unlock()
				writeSCIMErr(w, r, code, scimType, errMsg)
				return
			}
		}
		s.store.save()
		rg, etag := s.toSCIMGroup(t, g)
		snap := Group{ID: g.ID, Name: g.Name, Members: slices.Clone(g.Members)}
		tid := t.ID
		s.store.mu.Unlock()

		s.logs.publish("change", map[string]string{"tenant": tid})
		s.autoPush(tid, nil, []Group{snap}, "upsert")
		w.Header().Set("ETag", etag)
		writeSCIM(w, http.StatusOK, projectResource(rg, attrsParam, exclParam))
	default:
		s.store.mu.Unlock()
		writeSCIMErr(w, r, http.StatusMethodNotAllowed, "", "unsupported method")
	}
}

func applyGroupPatchOp(t *Tenant, g *Group, op, path string, val any) (int, string, string) {
	if path == "" {
		m, ok := val.(map[string]any)
		if !ok {
			return http.StatusBadRequest, "invalidSyntax", "PATCH with empty path requires an object value"
		}
		for k, v := range m {
			if code, st, msg := applyGroupPatchOp(t, g, op, k, v); code != 0 {
				return code, st, msg
			}
		}
		return 0, "", ""
	}
	p := stripCoreSchemaPrefix(path)
	lp := strings.ToLower(p)
	switch {
	case lp == "displayname":
		if op == "remove" {
			return http.StatusBadRequest, "mutability", "displayName cannot be removed"
		}
		name := strings.TrimSpace(str(val))
		if name == "" {
			return http.StatusBadRequest, "invalidValue", "displayName cannot be empty"
		}
		if hasDuplicateGroupName(t, name, g.ID) {
			return http.StatusConflict, "uniqueness", "group " + name + " already exists"
		}
		g.Name = name
	case lp == "members":
		ids := extractMemberIDs(val)
		switch op {
		case "add":
			for _, id := range ids {
				if !slices.Contains(g.Members, id) {
					g.Members = append(g.Members, id)
				}
			}
		case "replace":
			g.Members = ids
		case "remove":
			if len(ids) == 0 && val == nil {
				g.Members = []string{}
			} else {
				g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return slices.Contains(ids, m) })
			}
		}
	case strings.HasPrefix(lp, "members["):
		lbrack := strings.IndexByte(p, '[')
		rbrack := strings.LastIndexByte(p, ']')
		if lbrack < 0 || rbrack <= lbrack {
			return http.StatusBadRequest, "invalidPath", "malformed members filter path"
		}
		innerStr := p[lbrack+1 : rbrack]
		innerNode, err := parseFilter(innerStr)
		if err != nil {
			return http.StatusBadRequest, "invalidPath", err.Error()
		}
		if op == "remove" {
			g.Members = slices.DeleteFunc(g.Members, func(uid string) bool {
				return innerNode.eval(map[string]any{"value": uid})
			})
		}
	}
	return 0, "", ""
}
