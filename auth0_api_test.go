package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func auth0Req(t *testing.T, ts *httptest.Server, method, path, token string, body any) (int, []byte, http.Header) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, ts.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
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
	return resp.StatusCode, raw, resp.Header
}

func TestAuth0API_AuthRequired(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerAuth0API()

	// Missing token
	status, body, _ := auth0Req(t, ts, "GET", "/t/auth0/api/v2/users", "", nil)
	if status != 401 {
		t.Fatalf("expected 401, got %d: %s", status, body)
	}
	var errResp map[string]any
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Fatalf("failed to parse json: %v", err)
	}
	if errResp["error"] != "Unauthorized" {
		t.Errorf("expected error=Unauthorized, got %v", errResp["error"])
	}

	// Invalid empty bearer token
	status, body, _ = auth0Req(t, ts, "GET", "/t/auth0/api/v2/users", "   ", nil)
	if status != 401 {
		t.Fatalf("expected 401 for whitespace token, got %d", status)
	}
}

func TestAuth0API_UsersCRUDAndQuery(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerAuth0API()
	token := "mock-token-xyz"

	// 1. List users without totals
	status, body, _ := auth0Req(t, ts, "GET", "/t/auth0/api/v2/users", token, nil)
	if status != 200 {
		t.Fatalf("list users: %d %s", status, body)
	}
	var rawList []map[string]any
	if err := json.Unmarshal(body, &rawList); err != nil {
		t.Fatalf("failed to unmarshal raw users: %v", err)
	}
	if len(rawList) == 0 {
		t.Fatalf("expected seeded users in stark tenant, got 0")
	}

	// 2. List users with include_totals=true
	status, body, _ = auth0Req(t, ts, "GET", "/t/auth0/api/v2/users?include_totals=true&per_page=2&page=0", token, nil)
	if status != 200 {
		t.Fatalf("list with totals: %d %s", status, body)
	}
	var totalsResp map[string]any
	if err := json.Unmarshal(body, &totalsResp); err != nil {
		t.Fatalf("failed to unmarshal totals: %v", err)
	}
	if totalsResp["total"].(float64) < 2 {
		t.Errorf("expected total >= 2, got %v", totalsResp["total"])
	}
	if totalsResp["limit"].(float64) != 2 {
		t.Errorf("expected limit=2, got %v", totalsResp["limit"])
	}

	// 3. Query filter: email:"alice@stark.example"
	status, body, _ = auth0Req(t, ts, "GET", "/t/auth0/api/v2/users?q=email:\"alice@stark.example\"", token, nil)
	if status != 200 {
		t.Fatalf("query email: %d %s", status, body)
	}
	var aliceQuery []map[string]any
	json.Unmarshal(body, &aliceQuery)
	if len(aliceQuery) != 1 || !strings.Contains(aliceQuery[0]["email"].(string), "alice") {
		t.Errorf("expected 1 alice, got %d", len(aliceQuery))
	}

	// 4. Query filter: blocked:false
	status, body, _ = auth0Req(t, ts, "GET", "/t/auth0/api/v2/users?q=blocked:false", token, nil)
	if status != 200 {
		t.Fatalf("query blocked: %d %s", status, body)
	}
	var activeQuery []map[string]any
	json.Unmarshal(body, &activeQuery)
	for _, u := range activeQuery {
		if u["blocked"].(bool) {
			t.Errorf("user %v should not be blocked", u["user_id"])
		}
	}

	// 5. Create user
	newUser := map[string]any{
		"email":          "pepper.potts@stark.example",
		"name":           "Pepper Potts",
		"given_name":     "Pepper",
		"family_name":    "Potts",
		"password":       "TopSecret!",
		"blocked":        false,
		"email_verified": true,
		"app_metadata": map[string]any{
			"department": "Executive",
			"title":      "CEO",
		},
	}
	status, body, _ = auth0Req(t, ts, "POST", "/t/auth0/api/v2/users", token, newUser)
	if status != 201 {
		t.Fatalf("create user: %d %s", status, body)
	}
	var created map[string]any
	json.Unmarshal(body, &created)
	uid := created["user_id"].(string)
	if !strings.HasPrefix(uid, "auth0|") {
		t.Errorf("expected user_id prefix auth0|, got %s", uid)
	}
	if created["nickname"] != "pepper.potts" {
		t.Errorf("expected nickname pepper.potts, got %v", created["nickname"])
	}

	// 6. Get user by ID (both with and without auth0| prefix)
	status, body, _ = auth0Req(t, ts, "GET", "/t/auth0/api/v2/users/"+uid, token, nil)
	if status != 200 {
		t.Fatalf("get user with auth0| prefix: %d %s", status, body)
	}
	rawID := strings.TrimPrefix(uid, "auth0|")
	status, body, _ = auth0Req(t, ts, "GET", "/t/auth0/api/v2/users/"+rawID, token, nil)
	if status != 200 {
		t.Fatalf("get user without auth0| prefix: %d %s", status, body)
	}

	// 7. Update user (PATCH)
	status, body, _ = auth0Req(t, ts, "PATCH", "/t/auth0/api/v2/users/"+uid, token, map[string]any{
		"blocked": true,
		"name":    "Pepper Potts Stark",
	})
	if status != 200 {
		t.Fatalf("patch user: %d %s", status, body)
	}
	var patched map[string]any
	json.Unmarshal(body, &patched)
	if !patched["blocked"].(bool) {
		t.Errorf("expected blocked=true, got %v", patched["blocked"])
	}
	if patched["name"] != "Pepper Potts Stark" {
		t.Errorf("expected updated name, got %v", patched["name"])
	}

	// 8. Delete user
	status, _, _ = auth0Req(t, ts, "DELETE", "/t/auth0/api/v2/users/"+uid, token, nil)
	if status != 204 {
		t.Fatalf("delete user: expected 204, got %d", status)
	}

	// Verify 404 after deletion
	status, _, _ = auth0Req(t, ts, "GET", "/t/auth0/api/v2/users/"+uid, token, nil)
	if status != 404 {
		t.Fatalf("expected 404 for deleted user, got %d", status)
	}
}

func TestAuth0API_RolesAndMemberships(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerAuth0API()
	token := "mock-token-xyz"

	// List existing roles
	status, body, _ := auth0Req(t, ts, "GET", "/t/auth0/api/v2/roles", token, nil)
	if status != 200 {
		t.Fatalf("list roles: %d %s", status, body)
	}
	var roles []map[string]any
	json.Unmarshal(body, &roles)
	if len(roles) == 0 {
		t.Fatalf("expected seeded roles, got 0")
	}

	// Create new role
	newRole := map[string]any{
		"name":        "Security Officers",
		"description": "Security team members",
	}
	status, body, _ = auth0Req(t, ts, "POST", "/t/auth0/api/v2/roles", token, newRole)
	if status != 201 {
		t.Fatalf("create role: %d %s", status, body)
	}
	var createdRole map[string]any
	json.Unmarshal(body, &createdRole)
	rid := createdRole["id"].(string)

	// Get role
	status, body, _ = auth0Req(t, ts, "GET", "/t/auth0/api/v2/roles/"+rid, token, nil)
	if status != 200 {
		t.Fatalf("get role: %d %s", status, body)
	}

	// Update role
	status, body, _ = auth0Req(t, ts, "PATCH", "/t/auth0/api/v2/roles/"+rid, token, map[string]any{
		"name":        "Chief Security Officers",
		"description": "Senior security members",
	})
	if status != 200 {
		t.Fatalf("patch role: %d %s", status, body)
	}

	// Find Alice
	status, body, _ = auth0Req(t, ts, "GET", "/t/auth0/api/v2/users?q=email:\"alice@stark.example\"", token, nil)
	var users []map[string]any
	json.Unmarshal(body, &users)
	aliceID := users[0]["user_id"].(string)

	// Assign role to Alice
	status, _, _ = auth0Req(t, ts, "POST", "/t/auth0/api/v2/users/"+aliceID+"/roles", token, map[string]any{
		"roles": []string{rid},
	})
	if status != 204 {
		t.Fatalf("assign role: expected 204, got %d", status)
	}

	// Verify Alice has the role
	status, body, _ = auth0Req(t, ts, "GET", "/t/auth0/api/v2/users/"+aliceID+"/roles", token, nil)
	if status != 200 {
		t.Fatalf("get user roles: %d %s", status, body)
	}
	var userRoles []map[string]any
	json.Unmarshal(body, &userRoles)
	hasRole := false
	for _, r := range userRoles {
		if r["id"] == rid {
			hasRole = true
			break
		}
	}
	if !hasRole {
		t.Errorf("expected user to have role %s", rid)
	}

	// Verify role members
	status, body, _ = auth0Req(t, ts, "GET", "/t/auth0/api/v2/roles/"+rid+"/users", token, nil)
	if status != 200 {
		t.Fatalf("get role users: %d %s", status, body)
	}
	var roleUsers []map[string]any
	json.Unmarshal(body, &roleUsers)
	if len(roleUsers) != 1 {
		t.Errorf("expected 1 member in role, got %d", len(roleUsers))
	}

	// Remove role from Alice
	status, _, _ = auth0Req(t, ts, "DELETE", "/t/auth0/api/v2/users/"+aliceID+"/roles", token, map[string]any{
		"roles": []string{rid},
	})
	if status != 204 {
		t.Fatalf("delete user role: expected 204, got %d", status)
	}

	// Delete role
	status, _, _ = auth0Req(t, ts, "DELETE", "/t/auth0/api/v2/roles/"+rid, token, nil)
	if status != 204 {
		t.Fatalf("delete role: expected 204, got %d", status)
	}
}

func TestAuth0API_OrganizationsAndLogs(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerAuth0API()
	token := "mock-token-xyz"

	// Organizations
	status, body, _ := auth0Req(t, ts, "GET", "/t/auth0/api/v2/organizations", token, nil)
	if status != 200 {
		t.Fatalf("organizations: %d %s", status, body)
	}
	var orgs []map[string]any
	json.Unmarshal(body, &orgs)
	if len(orgs) != 1 || orgs[0]["id"] != "org_auth0" {
		t.Errorf("unexpected organizations response: %v", orgs)
	}

	// Logs
	status, body, _ = auth0Req(t, ts, "GET", "/t/auth0/api/v2/logs", token, nil)
	if status != 200 {
		t.Fatalf("logs: %d %s", status, body)
	}
	var logs []map[string]any
	json.Unmarshal(body, &logs)
	if len(logs) == 0 {
		t.Fatalf("expected logs, got 0")
	}
	if logs[0]["type"] == "" || logs[0]["date"] == "" {
		t.Errorf("invalid log format: %v", logs[0])
	}
}

func TestAuth0API_FaultSimulations(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerAuth0API()
	token := "mock-token-xyz"

	// Configure outage simulation with once: true
	call(t, ts, "PATCH", "/api/tenants/auth0/simulations", map[string]any{"httpStatus": 503, "once": true})

	// First call should fail with 503
	status, body, _ := auth0Req(t, ts, "GET", "/t/auth0/api/v2/users", token, nil)
	if status != 503 {
		t.Fatalf("expected 503 simulated outage, got %d: %s", status, body)
	}

	// Second call should succeed because once: true consumed the fault
	status, body, _ = auth0Req(t, ts, "GET", "/t/auth0/api/v2/users", token, nil)
	if status != 200 {
		t.Fatalf("expected 200 after once fault, got %d: %s", status, body)
	}
}
