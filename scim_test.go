package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newSCIMTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s, ts := newTestServer(t)
	s.registerSCIM()
	return s, ts
}

func scimDo(t *testing.T, ts *httptest.Server, method, path string, headers map[string]string, body any) (int, http.Header, map[string]any, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			r = strings.NewReader(v)
		case []byte:
			r = strings.NewReader(string(v))
		default:
			b, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			r = strings.NewReader(string(b))
		}
	}
	req, err := http.NewRequest(method, ts.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if headers["Authorization"] == "" && headers["__no_auth__"] == "" {
		req.Header.Set("Authorization", "Bearer test-token")
	}
	for k, v := range headers {
		if k == "__no_auth__" {
			continue
		}
		req.Header.Set(k, v)
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, resp.Header, m, raw
}

func TestSCIMLoopbackConformanceAndSync(t *testing.T) {
	s, ts := newSCIMTestServer(t)

	// Create a fresh target tenant whose inbound SCIM server receives outbound calls from entra.
	call(t, ts, "POST", "/api/tenants", map[string]any{
		"id":       "scim-target",
		"name":     "SCIM Loopback Target",
		"provider": "generic",
	})
	s.store.mu.Lock()
	targetTenant := s.store.tenant("scim-target")
	targetTenant.Users = nil
	targetTenant.Groups = nil
	s.store.mu.Unlock()

	createdTarget := call(t, ts, "POST", "/api/tenants/entra/scim-targets", map[string]any{
		"name":     "Loopback Target",
		"baseUrl":  ts.URL + "/t/scim-target/scim/v2",
		"token":    "loopback-secret",
		"flavor":   "entra",
		"autoPush": false,
	})
	targetID := str(createdTarget["id"])
	if targetID == "" {
		t.Fatalf("expected scim target id, got %v", createdTarget)
	}

	for _, flavor := range []string{"entra", "okta", "generic"} {
		t.Run("conformance_"+flavor, func(t *testing.T) {
			res := call(t, ts, "POST", "/api/tenants/entra/scim-targets/"+targetID+"/conformance", map[string]any{
				"flavor": flavor,
			})
			if failed := int(num(res["failed"])); failed != 0 {
				t.Fatalf("flavor %s conformance failed=%d checks=%v", flavor, failed, res["checks"])
			}
			if passed := int(num(res["passed"])); passed < 10 {
				t.Fatalf("flavor %s expected >= 10 passed checks, got %d", flavor, passed)
			}
		})
	}

	// Test /test connection endpoint
	testRes := call(t, ts, "POST", "/api/tenants/entra/scim-targets/"+targetID+"/test", nil)
	if failed := int(num(testRes["failed"])); failed != 0 {
		t.Fatalf("expected scim /test failed=0, got %v", testRes)
	}

	// Test /sync endpoint (pushes all entra users and groups to scim-target)
	syncRes := call(t, ts, "POST", "/api/tenants/entra/scim-targets/"+targetID+"/sync", nil)
	if failed := int(num(syncRes["failed"])); failed != 0 {
		t.Fatalf("expected sync failed=0, got %v", syncRes)
	}
	if passed := int(num(syncRes["passed"])); passed == 0 {
		t.Fatalf("expected sync passed > 0, got %v", syncRes)
	}

	// Verify scim-target now has the synced users
	status, _, usersList, _ := scimDo(t, ts, "GET", "/t/scim-target/scim/v2/Users", nil, nil)
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}
	s.store.mu.Lock()
	activeEntraUsers := 0
	for _, u := range s.store.tenant("entra").Users {
		if u.Active {
			activeEntraUsers++
		}
	}
	u0ID := s.store.tenant("entra").Users[0].ID
	g0ID := s.store.tenant("entra").Groups[0].ID
	s.store.mu.Unlock()
	if int(num(usersList["totalResults"])) != activeEntraUsers {
		t.Fatalf("expected %d synced active users, got %v", activeEntraUsers, usersList["totalResults"])
	}

	// Test /push endpoint for a specific user (upsert, deactivate, delete) and group
	for _, act := range []string{"upsert", "deactivate", "delete"} {
		pushUserRes := call(t, ts, "POST", "/api/tenants/entra/scim-targets/"+targetID+"/push", map[string]any{
			"kind":   "user",
			"id":     u0ID,
			"action": act,
		})
		if failed := int(num(pushUserRes["failed"])); failed != 0 {
			t.Fatalf("expected user push (%s) failed=0, got %v", act, pushUserRes)
		}
	}
	pushGroupRes := call(t, ts, "POST", "/api/tenants/entra/scim-targets/"+targetID+"/push", map[string]any{
		"kind":   "group",
		"id":     g0ID,
		"action": "upsert",
	})
	if failed := int(num(pushGroupRes["failed"])); failed != 0 {
		t.Fatalf("expected group push failed=0, got %v", pushGroupRes)
	}

	// Verify inbound SCIM logs were recorded with Kind == "scim.in"
	inLogs := s.logs.list("scim-target", "scim.in", "", "", 0, 100)
	if len(inLogs) == 0 {
		t.Fatalf("expected scim.in log entries for scim-target, got 0")
	}
	if inLogs[0].Kind != "scim.in" || inLogs[0].Tenant != "scim-target" {
		t.Fatalf("unexpected log entry: %+v", inLogs[0])
	}
}

func TestSCIMDiscoveryEndpoints(t *testing.T) {
	_, ts := newSCIMTestServer(t)

	// ServiceProviderConfig (no auth required per RFC 7644 §4)
	status, hdr, spc, _ := scimDo(t, ts, "GET", "/t/okta/scim/v2/ServiceProviderConfig", map[string]string{"__no_auth__": "1"}, nil)
	if status != 200 {
		t.Fatalf("ServiceProviderConfig status=%d", status)
	}
	if !strings.HasPrefix(hdr.Get("Content-Type"), "application/scim+json") {
		t.Fatalf("expected Content-Type application/scim+json, got %s", hdr.Get("Content-Type"))
	}
	for _, feature := range []string{"patch", "filter", "changePassword", "sort", "etag"} {
		f, _ := spc[feature].(map[string]any)
		if f["supported"] != true {
			t.Fatalf("expected %s.supported=true, got %v", feature, spc[feature])
		}
	}
	if bulk, _ := spc["bulk"].(map[string]any); bulk["supported"] != false {
		t.Fatalf("expected bulk.supported=false, got %v", spc["bulk"])
	}

	// ResourceTypes list and single
	status, _, rts, _ := scimDo(t, ts, "GET", "/t/okta/scim/v2/ResourceTypes", map[string]string{"__no_auth__": "1"}, nil)
	if status != 200 || int(num(rts["totalResults"])) != 2 {
		t.Fatalf("ResourceTypes status=%d totalResults=%v", status, rts["totalResults"])
	}
	status, _, rtUser, _ := scimDo(t, ts, "GET", "/t/okta/scim/v2/ResourceTypes/User", map[string]string{"__no_auth__": "1"}, nil)
	if status != 200 || rtUser["id"] != "User" {
		t.Fatalf("ResourceTypes/User status=%d id=%v", status, rtUser["id"])
	}
	status, _, rtGroup, _ := scimDo(t, ts, "GET", "/t/okta/scim/v2/ResourceTypes/Group", map[string]string{"__no_auth__": "1"}, nil)
	if status != 200 || rtGroup["id"] != "Group" {
		t.Fatalf("ResourceTypes/Group status=%d id=%v", status, rtGroup["id"])
	}
	status, _, _, _ = scimDo(t, ts, "GET", "/t/okta/scim/v2/ResourceTypes/Unknown", map[string]string{"__no_auth__": "1"}, nil)
	if status != 404 {
		t.Fatalf("expected 404 for unknown ResourceType, got %d", status)
	}

	// Schemas list and single lookup
	status, _, schemas, _ := scimDo(t, ts, "GET", "/t/okta/scim/v2/Schemas", map[string]string{"__no_auth__": "1"}, nil)
	if status != 200 || int(num(schemas["totalResults"])) != 3 {
		t.Fatalf("Schemas status=%d totalResults=%v", status, schemas["totalResults"])
	}
	status, _, userSchema, _ := scimDo(t, ts, "GET", "/t/okta/scim/v2/Schemas/"+schemaUser, map[string]string{"__no_auth__": "1"}, nil)
	if status != 200 || userSchema["id"] != schemaUser {
		t.Fatalf("Schemas/%s status=%d id=%v", schemaUser, status, userSchema["id"])
	}
}

func TestSCIMFilterASTAndEvaluator(t *testing.T) {
	_, ts := newSCIMTestServer(t)

	// Seed specific users on okta tenant for rich filter testing
	u1Status, _, u1, _ := scimDo(t, ts, "POST", "/t/okta/scim/v2/Users", nil, map[string]any{
		"schemas":    []string{schemaUser, schemaEnt},
		"userName":   "charlie.filter@acme.test",
		"externalId": "ext-charlie-01",
		"active":     true,
		"title":      "Principal Architect",
		"name":       map[string]any{"givenName": "Charlie", "familyName": "Filter", "formatted": "Charlie Filter"},
		"emails":     []map[string]any{{"value": "charlie.filter@acme.test", "type": "work", "primary": true}},
		schemaEnt:    map[string]any{"department": "Platform", "employeeNumber": "E900"},
	})
	if u1Status != 201 {
		t.Fatalf("create u1 status=%d", u1Status)
	}
	u2Status, _, u2, _ := scimDo(t, ts, "POST", "/t/okta/scim/v2/Users", nil, map[string]any{
		"schemas":    []string{schemaUser, schemaEnt},
		"userName":   "dana.inactive@acme.test",
		"externalId": "ext-dana-02",
		"active":     false,
		"name":       map[string]any{"givenName": "Dana", "familyName": "Inactive", "formatted": "Dana Inactive"},
		"emails":     []map[string]any{{"value": "dana.inactive@acme.test", "type": "work", "primary": true}},
		schemaEnt:    map[string]any{"department": "Finance", "employeeNumber": "E100"},
	})
	if u2Status != 201 {
		t.Fatalf("create u2 status=%d", u2Status)
	}
	t.Cleanup(func() {
		scimDo(t, ts, "DELETE", "/t/okta/scim/v2/Users/"+str(u1["id"]), nil, nil)
		scimDo(t, ts, "DELETE", "/t/okta/scim/v2/Users/"+str(u2["id"]), nil, nil)
	})

	cases := []struct {
		name      string
		filter    string
		wantIDs   []string
		unwantIDs []string
	}{
		{
			name:    "eq_case_insensitive",
			filter:  `userName eq "CHARLIE.FILTER@acme.test"`,
			wantIDs: []string{str(u1["id"])},
		},
		{
			name:      "ne_and_active",
			filter:    `active eq false and userName ne "someone@else.test"`,
			wantIDs:   []string{str(u2["id"])},
			unwantIDs: []string{str(u1["id"])},
		},
		{
			name:      "co_sw_ew",
			filter:    `userName sw "charlie." and userName co ".filter@" and userName ew "@acme.test"`,
			wantIDs:   []string{str(u1["id"])},
			unwantIDs: []string{str(u2["id"])},
		},
		{
			name:      "pr_and_not",
			filter:    `title pr and not (active eq false)`,
			wantIDs:   []string{str(u1["id"])},
			unwantIDs: []string{str(u2["id"])},
		},
		{
			name:    "nested_subattribute",
			filter:  `name.givenName eq "Charlie" or name.familyName eq "Inactive"`,
			wantIDs: []string{str(u1["id"]), str(u2["id"])},
		},
		{
			name:      "value_path_with_subattr",
			filter:    `emails[type eq "work"].value eq "charlie.filter@acme.test"`,
			wantIDs:   []string{str(u1["id"])},
			unwantIDs: []string{str(u2["id"])},
		},
		{
			name:      "value_path_without_subattr",
			filter:    `emails[value sw "dana." and primary eq true]`,
			wantIDs:   []string{str(u2["id"])},
			unwantIDs: []string{str(u1["id"])},
		},
		{
			name:      "enterprise_extension_path",
			filter:    `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "Platform"`,
			wantIDs:   []string{str(u1["id"])},
			unwantIDs: []string{str(u2["id"])},
		},
		{
			name:      "comparison_gt_lt",
			filter:    `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber gt "E500" and urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber le "E999"`,
			wantIDs:   []string{str(u1["id"])},
			unwantIDs: []string{str(u2["id"])},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := "/t/okta/scim/v2/Users?filter=" + url.QueryEscape(tc.filter)
			status, _, m, raw := scimDo(t, ts, "GET", q, nil, nil)
			if status != 200 {
				t.Fatalf("filter %q returned %d: %s", tc.filter, status, raw)
			}
			resources, _ := m["Resources"].([]any)
			gotIDs := map[string]bool{}
			for _, r := range resources {
				rm, _ := r.(map[string]any)
				gotIDs[str(rm["id"])] = true
			}
			for _, id := range tc.wantIDs {
				if !gotIDs[id] {
					t.Fatalf("filter %q expected id %s in results, got %v", tc.filter, id, gotIDs)
				}
			}
			for _, id := range tc.unwantIDs {
				if gotIDs[id] {
					t.Fatalf("filter %q did not expect id %s in results", tc.filter, id)
				}
			}
		})
	}

	// Test Group members[value eq "..."] filter
	status, _, grp, _ := scimDo(t, ts, "POST", "/t/okta/scim/v2/Groups", nil, map[string]any{
		"schemas":     []string{schemaGroup},
		"displayName": "FilterTestGroup",
		"members":     []map[string]any{{"value": str(u1["id"])}},
	})
	if status != 201 {
		t.Fatalf("create group status=%d", status)
	}
	defer scimDo(t, ts, "DELETE", "/t/okta/scim/v2/Groups/"+str(grp["id"]), nil, nil)

	gf := `members[value eq "` + str(u1["id"]) + `"]`
	gStatus, _, gm, _ := scimDo(t, ts, "GET", "/t/okta/scim/v2/Groups?filter="+url.QueryEscape(gf), nil, nil)
	if gStatus != 200 || int(num(gm["totalResults"])) != 1 {
		t.Fatalf("group members filter status=%d total=%v", gStatus, gm["totalResults"])
	}

	// Invalid filter returns 400 invalidFilter
	badStatus, _, badBody, _ := scimDo(t, ts, "GET", "/t/okta/scim/v2/Users?filter="+url.QueryEscape("userName invalidOp 123"), nil, nil)
	if badStatus != 400 || badBody["scimType"] != "invalidFilter" {
		t.Fatalf("expected 400 invalidFilter, got %d %v", badStatus, badBody)
	}
}

func TestSCIMPaginationSortingAndProjection(t *testing.T) {
	_, ts := newSCIMTestServer(t)

	// Sort ascending by userName
	status, _, ascList, _ := scimDo(t, ts, "GET", "/t/entra/scim/v2/Users?sortBy=userName&sortOrder=ascending&startIndex=1&count=1", nil, nil)
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}
	if int(num(ascList["itemsPerPage"])) != 1 || int(num(ascList["startIndex"])) != 1 {
		t.Fatalf("unexpected pagination meta: %v", ascList)
	}
	ascRes, _ := ascList["Resources"].([]any)
	firstAsc := ascRes[0].(map[string]any)["userName"].(string)

	// Sort descending by userName
	_, _, descList, _ := scimDo(t, ts, "GET", "/t/entra/scim/v2/Users?sortBy=userName&sortOrder=descending&startIndex=1&count=1", nil, nil)
	descRes, _ := descList["Resources"].([]any)
	firstDesc := descRes[0].(map[string]any)["userName"].(string)
	if firstAsc == firstDesc {
		t.Fatalf("expected ascending first (%s) != descending first (%s)", firstAsc, firstDesc)
	}

	// count=0 returns totalResults > 0 and empty Resources=[]
	_, _, zeroList, _ := scimDo(t, ts, "GET", "/t/entra/scim/v2/Users?count=0", nil, nil)
	if int(num(zeroList["totalResults"])) < 2 || int(num(zeroList["itemsPerPage"])) != 0 {
		t.Fatalf("count=0 unexpected response: %v", zeroList)
	}
	if res, ok := zeroList["Resources"].([]any); !ok || len(res) != 0 {
		t.Fatalf("expected empty Resources slice on count=0, got %v", zeroList["Resources"])
	}

	// Attribute projection: attributes=userName,name.givenName
	_, _, projList, _ := scimDo(t, ts, "GET", "/t/entra/scim/v2/Users?attributes=userName,name.givenName", nil, nil)
	u0 := projList["Resources"].([]any)[0].(map[string]any)
	if u0["id"] == nil || u0["schemas"] == nil || u0["meta"] == nil || u0["userName"] == nil {
		t.Fatalf("expected id, schemas, meta, userName to be present in projection: %v", u0)
	}
	if u0["emails"] != nil {
		t.Fatalf("expected emails to be omitted when attributes=userName,name.givenName, got %v", u0["emails"])
	}
	nameObj, _ := u0["name"].(map[string]any)
	if nameObj["givenName"] == nil || nameObj["familyName"] != nil {
		t.Fatalf("expected only name.givenName in name object, got %v", nameObj)
	}

	// Excluded attributes: excludedAttributes=emails,groups
	_, _, exclList, _ := scimDo(t, ts, "GET", "/t/entra/scim/v2/Users?excludedAttributes=emails,groups", nil, nil)
	uExcl := exclList["Resources"].([]any)[0].(map[string]any)
	if uExcl["emails"] != nil || uExcl["groups"] != nil {
		t.Fatalf("expected emails and groups excluded, got %v", uExcl)
	}
	if uExcl["userName"] == nil {
		t.Fatalf("expected userName retained, got %v", uExcl)
	}
}

func TestSCIMETagPreconditionConflictAndAuth(t *testing.T) {
	s, ts := newSCIMTestServer(t)

	// Create user and check ETag header + meta.version
	status, hdr, created, _ := scimDo(t, ts, "POST", "/t/okta/scim/v2/Users", nil, map[string]any{
		"schemas":  []string{schemaUser},
		"userName": "etag.user@acme.test",
		"active":   true,
	})
	if status != 201 {
		t.Fatalf("expected 201, got %d", status)
	}
	id := str(created["id"])
	defer scimDo(t, ts, "DELETE", "/t/okta/scim/v2/Users/"+id, nil, nil)

	etag := hdr.Get("ETag")
	if !strings.HasPrefix(etag, `W/"`) {
		t.Fatalf("expected weak ETag W/\"...\", got %q", etag)
	}

	// Duplicate userName returns 409 Conflict with scimType="uniqueness"
	dupStatus, _, dupBody, _ := scimDo(t, ts, "POST", "/t/okta/scim/v2/Users", nil, map[string]any{
		"schemas":  []string{schemaUser},
		"userName": "ETAG.USER@acme.test",
	})
	if dupStatus != 409 || dupBody["scimType"] != "uniqueness" {
		t.Fatalf("expected 409 uniqueness on duplicate userName, got %d %v", dupStatus, dupBody)
	}

	// If-Match with stale ETag returns 412 Precondition Failed
	preStatus, _, _, _ := scimDo(t, ts, "PATCH", "/t/okta/scim/v2/Users/"+id, map[string]string{
		"If-Match": `W/"deadbeef"`,
	}, map[string]any{
		"schemas": []string{schemaPatch},
		"Operations": []map[string]any{
			{"op": "replace", "path": "title", "value": "Blocked"},
		},
	})
	if preStatus != 412 {
		t.Fatalf("expected 412 Precondition Failed, got %d", preStatus)
	}

	// If-Match with current ETag succeeds and rotates ETag
	okStatus, hdr2, _, _ := scimDo(t, ts, "PATCH", "/t/okta/scim/v2/Users/"+id, map[string]string{
		"If-Match": etag,
	}, map[string]any{
		"schemas": []string{schemaPatch},
		"Operations": []map[string]any{
			{"op": "replace", "path": "title", "value": "Updated"},
		},
	})
	if okStatus != 200 {
		t.Fatalf("expected 200 on matching ETag, got %d", okStatus)
	}
	if hdr2.Get("ETag") == etag {
		t.Fatalf("expected ETag to change after modification, still %q", etag)
	}

	// Duplicate group displayName returns 409 Conflict with scimType="uniqueness"
	gStatus1, _, grp1, _ := scimDo(t, ts, "POST", "/t/okta/scim/v2/Groups", nil, map[string]any{
		"schemas":     []string{schemaGroup},
		"displayName": "UniqueTeam",
	})
	if gStatus1 != 201 {
		t.Fatalf("expected 201 creating group, got %d", gStatus1)
	}
	defer scimDo(t, ts, "DELETE", "/t/okta/scim/v2/Groups/"+str(grp1["id"]), nil, nil)
	gDupStatus, _, gDupBody, _ := scimDo(t, ts, "POST", "/t/okta/scim/v2/Groups", nil, map[string]any{
		"schemas":     []string{schemaGroup},
		"displayName": "uniqueteam",
	})
	if gDupStatus != 409 || gDupBody["scimType"] != "uniqueness" {
		t.Fatalf("expected 409 uniqueness on duplicate group displayName, got %d %v", gDupStatus, gDupBody)
	}

	// Auth tests: Basic auth rejected, missing auth rejected, SSWS accepted, s.apiToken enforced
	unauthStatus, _, _, _ := scimDo(t, ts, "GET", "/t/okta/scim/v2/Users", map[string]string{"__no_auth__": "1"}, nil)
	if unauthStatus != 401 {
		t.Fatalf("expected 401 without Authorization header, got %d", unauthStatus)
	}
	basicStatus, _, _, _ := scimDo(t, ts, "GET", "/t/okta/scim/v2/Users", map[string]string{"Authorization": "Basic dXNlcjpwYXNz"}, nil)
	if basicStatus != 401 {
		t.Fatalf("expected 401 with Basic auth, got %d", basicStatus)
	}
	sswsStatus, _, _, _ := scimDo(t, ts, "GET", "/t/okta/scim/v2/Users", map[string]string{"Authorization": "SSWS my-okta-token"}, nil)
	if sswsStatus != 200 {
		t.Fatalf("expected 200 with SSWS auth, got %d", sswsStatus)
	}

	s.apiToken = "strict-server-token"
	defer func() { s.apiToken = "" }()
	wrongTokStatus, _, _, _ := scimDo(t, ts, "GET", "/t/okta/scim/v2/Users", map[string]string{"Authorization": "Bearer wrong-token"}, nil)
	if wrongTokStatus != 401 {
		t.Fatalf("expected 401 with wrong token when s.apiToken is set, got %d", wrongTokStatus)
	}
	rightTokStatus, _, _, _ := scimDo(t, ts, "GET", "/t/okta/scim/v2/Users", map[string]string{"Authorization": "Bearer strict-server-token"}, nil)
	if rightTokStatus != 200 {
		t.Fatalf("expected 200 with matching s.apiToken, got %d", rightTokStatus)
	}
}

func TestSCIMFaultSimulationOnce(t *testing.T) {
	_, ts := newSCIMTestServer(t)

	// Arm a one-shot 429 rate-limit fault on the okta tenant
	call(t, ts, "PATCH", "/api/tenants/okta/simulations", map[string]any{
		"httpStatus": 429,
		"once":       true,
	})
	defer call(t, ts, "DELETE", "/api/tenants/okta/simulations", nil)

	// First request hits 429
	status1, _, _, _ := scimDo(t, ts, "GET", "/t/okta/scim/v2/Users", nil, nil)
	if status1 != 429 {
		t.Fatalf("expected first request to return 429, got %d", status1)
	}

	// Second request succeeds with 200 because once: true cleared the fault
	status2, _, _, _ := scimDo(t, ts, "GET", "/t/okta/scim/v2/Users", nil, nil)
	if status2 != 200 {
		t.Fatalf("expected second request to return 200 after once fault, got %d", status2)
	}
}
