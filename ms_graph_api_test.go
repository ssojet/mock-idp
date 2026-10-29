package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func graphReq(t *testing.T, ts *httptest.Server, method, path, auth string, body any, extraHeaders ...string) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(extraHeaders); i += 2 {
		req.Header.Set(extraHeaders[i], extraHeaders[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, raw
}

func TestMSGraphAPIAuthAndOrganization(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerMSGraphAPI()

	// Missing Authorization -> 401 InvalidAuthenticationToken
	resp, raw := graphReq(t, ts, "GET", "/t/entra/v1.0/users", "", nil)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d: %s", resp.StatusCode, raw)
	}
	var errEnv map[string]any
	json.Unmarshal(raw, &errEnv)
	errObj, _ := errEnv["error"].(map[string]any)
	if str(errObj["code"]) != "InvalidAuthenticationToken" {
		t.Errorf("expected InvalidAuthenticationToken, got %v", errObj)
	}

	// GET /v1.0/organization
	auth := "Bearer test-token"
	resp, raw = graphReq(t, ts, "GET", "/t/entra/v1.0/organization", auth, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("organization failed: %d %s", resp.StatusCode, raw)
	}
	var orgResp map[string]any
	json.Unmarshal(raw, &orgResp)
	vals, _ := orgResp["value"].([]any)
	if len(vals) != 1 || vals[0].(map[string]any)["displayName"] != "Contoso" {
		t.Errorf("unexpected organization response: %v", orgResp)
	}
}

func TestMSGraphAPIMeAndTokenResolution(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerMSGraphAPI()

	// Opaque token defaults to first active user (Alice)
	resp, raw := graphReq(t, ts, "GET", "/t/entra/v1.0/me", "Bearer opaque-token", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("me failed: %d %s", resp.StatusCode, raw)
	}
	var me map[string]any
	json.Unmarshal(raw, &me)
	if me["userPrincipalName"] != "alice@contoso.example" {
		t.Errorf("expected alice@contoso.example, got %v", me["userPrincipalName"])
	}

	// X-Ms-Graph-User header selects Bob
	resp, raw = graphReq(t, ts, "GET", "/t/entra/v1.0/me", "Bearer opaque-token", nil, "X-Ms-Graph-User", "bob@contoso.example")
	if resp.StatusCode != 200 {
		t.Fatalf("me with header failed: %d", resp.StatusCode)
	}
	json.Unmarshal(raw, &me)
	if me["userPrincipalName"] != "bob@contoso.example" {
		t.Errorf("expected bob@contoso.example, got %v", me["userPrincipalName"])
	}

	// Real minted JWT for Dave resolves Dave on /v1.0/me and /v1.0/me/memberOf
	tokResp := call(t, ts, "POST", "/api/tenants/entra/apps/test-oidc/tokens", map[string]any{
		"user":  "dave@contoso.example",
		"scope": "openid profile email",
	})
	jwtTok := str(tokResp["access_token"])
	resp, raw = graphReq(t, ts, "GET", "/t/entra/v1.0/me", "Bearer "+jwtTok, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("me with JWT failed: %d %s", resp.StatusCode, raw)
	}
	json.Unmarshal(raw, &me)
	if me["userPrincipalName"] != "dave@contoso.example" {
		t.Errorf("expected dave@contoso.example from JWT, got %v", me["userPrincipalName"])
	}

	resp, raw = graphReq(t, ts, "GET", "/t/entra/v1.0/me/memberOf", "Bearer "+jwtTok, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("me/memberOf failed: %d %s", resp.StatusCode, raw)
	}
	var memberOf map[string]any
	json.Unmarshal(raw, &memberOf)
	if len(memberOf["value"].([]any)) < 2 {
		t.Errorf("expected Dave to be in at least 2 groups (Everyone, Sales), got %v", memberOf["value"])
	}
}

func TestMSGraphAPIUsersGroupsAndOData(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerMSGraphAPI()
	auth := "Bearer test-token"

	// Create user (201 Created)
	resp, raw := graphReq(t, ts, "POST", "/t/entra/v1.0/users", auth, map[string]any{
		"accountEnabled":    true,
		"displayName":       "Grace Hopper",
		"givenName":         "Grace",
		"surname":           "Hopper",
		"userPrincipalName": "grace@contoso.example",
		"mail":              "grace@contoso.example",
		"department":        "Engineering",
		"jobTitle":          "Rear Admiral",
	})
	if resp.StatusCode != 201 {
		t.Fatalf("create user expected 201, got %d: %s", resp.StatusCode, raw)
	}
	var created map[string]any
	json.Unmarshal(raw, &created)
	uid := str(created["id"])

	// PATCH user (204 No Content)
	resp, _ = graphReq(t, ts, "PATCH", "/t/entra/v1.0/users/"+uid, auth, map[string]any{
		"jobTitle":       "Fleet Admiral",
		"accountEnabled": false,
	})
	if resp.StatusCode != 204 {
		t.Fatalf("patch user expected 204, got %d", resp.StatusCode)
	}

	// GET user with $select and $expand=memberOf
	resp, raw = graphReq(t, ts, "GET", "/t/entra/v1.0/users/"+uid+"?$select=displayName,jobTitle,accountEnabled&$expand=memberOf", auth, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("get user failed: %d %s", resp.StatusCode, raw)
	}
	var selectedUser map[string]any
	json.Unmarshal(raw, &selectedUser)
	if selectedUser["jobTitle"] != "Fleet Admiral" || selectedUser["accountEnabled"] != false {
		t.Errorf("unexpected updated user fields: %v", selectedUser)
	}
	if _, hasGiven := selectedUser["givenName"]; hasGiven {
		t.Errorf("$select should have omitted givenName: %v", selectedUser)
	}

	// Test $filter with startswith, eq, and, $count=true
	resp, raw = graphReq(t, ts, "GET", "/t/entra/v1.0/users?$filter=startswith(displayName,'A')+and+accountEnabled+eq+true&$count=true", auth, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("filter users failed: %d %s", resp.StatusCode, raw)
	}
	var listResp map[string]any
	json.Unmarshal(raw, &listResp)
	if int(num(listResp["@odata.count"])) != 1 {
		t.Errorf("expected @odata.count=1 for Alice, got %v", listResp["@odata.count"])
	}

	// Test $top and $skiptoken pagination
	var pagedIDs []string
	nextPath := "/t/entra/v1.0/users?$top=2"
	for nextPath != "" {
		resp, raw = graphReq(t, ts, "GET", nextPath, auth, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("paged users failed: %d", resp.StatusCode)
		}
		var page map[string]any
		json.Unmarshal(raw, &page)
		for _, item := range page["value"].([]any) {
			pagedIDs = append(pagedIDs, str(item.(map[string]any)["id"]))
		}
		nl := str(page["@odata.nextLink"])
		nextPath = strings.TrimPrefix(nl, ts.URL)
	}
	if len(pagedIDs) != 7 { // 6 seeded + Grace
		t.Errorf("expected 7 users across pages, got %d", len(pagedIDs))
	}

	// Create group, add/remove member via $ref, test getMemberObjects (including groupsOverage endpoint)
	resp, raw = graphReq(t, ts, "POST", "/t/entra/v1.0/groups", auth, map[string]any{
		"displayName":     "Platform",
		"mailEnabled":     false,
		"mailNickname":    "platform",
		"securityEnabled": true,
	})
	if resp.StatusCode != 201 {
		t.Fatalf("create group expected 201, got %d: %s", resp.StatusCode, raw)
	}
	var grp map[string]any
	json.Unmarshal(raw, &grp)
	gid := str(grp["id"])

	// Add Grace to Platform group via $ref
	resp, raw = graphReq(t, ts, "POST", "/t/entra/v1.0/groups/"+gid+"/members/$ref", auth, map[string]any{
		"@odata.id": ts.URL + "/t/entra/v1.0/directoryObjects/" + uid,
	})
	if resp.StatusCode != 204 {
		t.Fatalf("add group member $ref expected 204, got %d: %s", resp.StatusCode, raw)
	}

	// Check group with $expand=members
	resp, raw = graphReq(t, ts, "GET", "/t/entra/v1.0/groups/"+gid+"?$expand=members", auth, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("get group with expand failed: %d", resp.StatusCode)
	}
	json.Unmarshal(raw, &grp)
	if len(grp["members"].([]any)) != 1 {
		t.Errorf("expected 1 expanded member in group, got %v", grp["members"])
	}

	// Test all getMemberObjects / getMemberGroups endpoints (including OIDC groupsOverage /t/{tenant}/users/{id}/getMemberObjects)
	for _, ep := range []string{
		"/t/entra/v1.0/users/" + uid + "/getMemberGroups",
		"/t/entra/v1.0/users/" + uid + "/getMemberObjects",
		"/t/entra/v1.0/directoryObjects/" + uid + "/getMemberObjects",
		"/t/entra/users/" + uid + "/getMemberObjects",
	} {
		resp, raw = graphReq(t, ts, "POST", ep, auth, map[string]any{"securityEnabledOnly": true})
		if resp.StatusCode != 200 {
			t.Fatalf("%s failed: %d %s", ep, resp.StatusCode, raw)
		}
		var mo map[string]any
		json.Unmarshal(raw, &mo)
		vals, _ := mo["value"].([]any)
		if len(vals) != 1 || str(vals[0]) != gid {
			t.Errorf("%s: expected [%s], got %v", ep, gid, vals)
		}
	}

	// Remove Grace from Platform group via $ref and delete user & group
	resp, _ = graphReq(t, ts, "DELETE", "/t/entra/v1.0/groups/"+gid+"/members/"+uid+"/$ref", auth, nil)
	if resp.StatusCode != 204 {
		t.Fatalf("remove member $ref expected 204, got %d", resp.StatusCode)
	}
	resp, _ = graphReq(t, ts, "DELETE", "/t/entra/v1.0/groups/"+gid, auth, nil)
	if resp.StatusCode != 204 {
		t.Fatalf("delete group expected 204, got %d", resp.StatusCode)
	}
	resp, _ = graphReq(t, ts, "DELETE", "/t/entra/v1.0/users/"+uid, auth, nil)
	if resp.StatusCode != 204 {
		t.Fatalf("delete user expected 204, got %d", resp.StatusCode)
	}
}

func TestMSGraphAPIServicePrincipalsAppsAuditLogsAndFaults(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerMSGraphAPI()
	auth := "Bearer test-token"

	for _, ep := range []string{
		"/t/entra/v1.0/servicePrincipals",
		"/t/entra/v1.0/applications",
		"/t/entra/v1.0/auditLogs/signIns",
		"/t/entra/v1.0/auditLogs/directoryAudits",
	} {
		resp, raw := graphReq(t, ts, "GET", ep, auth, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%s failed: %d %s", ep, resp.StatusCode, raw)
		}
		var col map[string]any
		json.Unmarshal(raw, &col)
		if len(col["value"].([]any)) == 0 {
			t.Errorf("%s returned empty value list", ep)
		}
	}

	// Fault simulation (503 outage)
	call(t, ts, "PATCH", "/api/tenants/entra/simulations", map[string]any{"httpStatus": 503, "once": true})
	resp, _ := graphReq(t, ts, "GET", "/t/entra/v1.0/users", auth, nil)
	if resp.StatusCode != 503 {
		t.Errorf("expected 503 outage simulation, got %d", resp.StatusCode)
	}
	resp, _ = graphReq(t, ts, "GET", "/t/entra/v1.0/users", auth, nil)
	if resp.StatusCode != 200 {
		t.Errorf("expected 200 after once outage cleared, got %d", resp.StatusCode)
	}
}
