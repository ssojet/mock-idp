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

func keycloakReq(t *testing.T, ts *httptest.Server, method, path, token string, body any) (int, []byte, http.Header) {
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

func TestKeycloakAPI_AuthRequired(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerKeycloakAPI()

	status, body, _ := keycloakReq(t, ts, "GET", "/t/keycloak/admin/realms/cyberdyne/users", "", nil)
	if status != 401 {
		t.Fatalf("expected 401, got %d: %s", status, body)
	}
	var errResp map[string]any
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Fatalf("failed to parse json: %v", err)
	}
	if errResp["error"] != "HTTP 401 Unauthorized" {
		t.Errorf("expected error='HTTP 401 Unauthorized', got %v", errResp["error"])
	}
}

func TestKeycloakAPI_UsersCRUDAndQuery(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerKeycloakAPI()
	token := "mock-token-xyz"

	// 1. List users
	status, body, _ := keycloakReq(t, ts, "GET", "/t/keycloak/admin/realms/cyberdyne/users", token, nil)
	if status != 200 {
		t.Fatalf("list users: %d %s", status, body)
	}
	var users []map[string]any
	json.Unmarshal(body, &users)
	if len(users) == 0 {
		t.Fatalf("expected seeded users in cyberdyne, got 0")
	}

	// Verify UserRepresentation fields
	u0 := users[0]
	if u0["id"] == nil || u0["username"] == nil || u0["enabled"] == nil || u0["email"] == nil {
		t.Errorf("missing standard user representation fields: %v", u0)
	}

	// 2. Count users
	status, body, _ = keycloakReq(t, ts, "GET", "/t/keycloak/admin/realms/cyberdyne/users/count", token, nil)
	if status != 200 {
		t.Fatalf("count users: %d %s", status, body)
	}
	var count int
	json.Unmarshal(body, &count)
	if count != len(users) {
		t.Errorf("expected count %d, got %d", len(users), count)
	}

	// 3. Search filter
	status, body, _ = keycloakReq(t, ts, "GET", "/t/keycloak/admin/realms/cyberdyne/users?search=alice", token, nil)
	if status != 200 {
		t.Fatalf("search users: %d %s", status, body)
	}
	var searched []map[string]any
	json.Unmarshal(body, &searched)
	if len(searched) != 1 {
		t.Errorf("expected 1 search result for alice, got %d", len(searched))
	}

	// Exact match filter
	status, body, _ = keycloakReq(t, ts, "GET", "/t/keycloak/admin/realms/cyberdyne/users?firstName=Alice&exact=true", token, nil)
	if status != 200 {
		t.Fatalf("exact match: %d %s", status, body)
	}
	var exactUsers []map[string]any
	json.Unmarshal(body, &exactUsers)
	if len(exactUsers) != 1 {
		t.Errorf("expected 1 exact user, got %d", len(exactUsers))
	}

	// 4. Create user
	newUser := map[string]any{
		"username":      "t800@cyberdyne.example",
		"email":         "t800@cyberdyne.example",
		"firstName":     "Cyberdyne",
		"lastName":      "Model 101",
		"enabled":       true,
		"emailVerified": true,
		"attributes": map[string][]string{
			"department":     {"Infiltration"},
			"title":          {"Terminator"},
			"employeeNumber": {"T-800"},
		},
	}
	status, _, headers := keycloakReq(t, ts, "POST", "/t/keycloak/admin/realms/cyberdyne/users", token, newUser)
	if status != 201 {
		t.Fatalf("create user: expected 201, got %d", status)
	}
	loc := headers.Get("Location")
	if loc == "" || !strings.Contains(loc, "/users/") {
		t.Fatalf("expected Location header with /users/<id>, got %s", loc)
	}
	parts := strings.Split(loc, "/users/")
	newUID := parts[len(parts)-1]

	// 5. Get user
	status, body, _ = keycloakReq(t, ts, "GET", "/t/keycloak/admin/realms/cyberdyne/users/"+newUID, token, nil)
	if status != 200 {
		t.Fatalf("get user: %d %s", status, body)
	}
	var createdUser map[string]any
	json.Unmarshal(body, &createdUser)
	if createdUser["username"] != "t800@cyberdyne.example" {
		t.Errorf("unexpected username: %v", createdUser["username"])
	}
	attrs := createdUser["attributes"].(map[string]any)
	if attrs["title"].([]any)[0] != "Terminator" {
		t.Errorf("unexpected title attribute: %v", attrs["title"])
	}

	// 6. Update user (PUT)
	updatePayload := map[string]any{
		"firstName": "Arnold",
		"lastName":  "Schwarzenegger",
		"enabled":   false,
	}
	status, _, _ = keycloakReq(t, ts, "PUT", "/t/keycloak/admin/realms/cyberdyne/users/"+newUID, token, updatePayload)
	if status != 204 {
		t.Fatalf("update user: expected 204, got %d", status)
	}

	// Verify update
	status, body, _ = keycloakReq(t, ts, "GET", "/t/keycloak/admin/realms/cyberdyne/users/"+newUID, token, nil)
	json.Unmarshal(body, &createdUser)
	if createdUser["enabled"].(bool) {
		t.Errorf("expected enabled=false, got true")
	}

	// 7. Delete user
	status, _, _ = keycloakReq(t, ts, "DELETE", "/t/keycloak/admin/realms/cyberdyne/users/"+newUID, token, nil)
	if status != 204 {
		t.Fatalf("delete user: expected 204, got %d", status)
	}

	// Verify 404
	status, _, _ = keycloakReq(t, ts, "GET", "/t/keycloak/admin/realms/cyberdyne/users/"+newUID, token, nil)
	if status != 404 {
		t.Fatalf("expected 404 for deleted user, got %d", status)
	}
}

func TestKeycloakAPI_GroupsAndMemberships(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerKeycloakAPI()
	token := "mock-token-xyz"

	// List groups
	status, body, _ := keycloakReq(t, ts, "GET", "/t/keycloak/admin/realms/cyberdyne/groups", token, nil)
	if status != 200 {
		t.Fatalf("list groups: %d %s", status, body)
	}
	var groups []map[string]any
	json.Unmarshal(body, &groups)
	if len(groups) == 0 {
		t.Fatalf("expected seeded groups, got 0")
	}

	// Create group
	newGroup := map[string]any{
		"name": "Skynet Development",
	}
	status, _, headers := keycloakReq(t, ts, "POST", "/t/keycloak/admin/realms/cyberdyne/groups", token, newGroup)
	if status != 201 {
		t.Fatalf("create group: expected 201, got %d", status)
	}
	loc := headers.Get("Location")
	if loc == "" || !strings.Contains(loc, "/groups/") {
		t.Fatalf("expected Location header with /groups/<id>, got %s", loc)
	}
	gid := strings.Split(loc, "/groups/")[1]

	// Get group
	status, body, _ = keycloakReq(t, ts, "GET", "/t/keycloak/admin/realms/cyberdyne/groups/"+gid, token, nil)
	if status != 200 {
		t.Fatalf("get group: %d %s", status, body)
	}
	var group map[string]any
	json.Unmarshal(body, &group)
	if group["path"] != "/Skynet Development" {
		t.Errorf("expected path '/Skynet Development', got %v", group["path"])
	}

	// Update group
	status, _, _ = keycloakReq(t, ts, "PUT", "/t/keycloak/admin/realms/cyberdyne/groups/"+gid, token, map[string]any{
		"name": "Skynet Core",
	})
	if status != 204 {
		t.Fatalf("update group: expected 204, got %d", status)
	}

	// Find Alice
	status, body, _ = keycloakReq(t, ts, "GET", "/t/keycloak/admin/realms/cyberdyne/users?search=alice", token, nil)
	var users []map[string]any
	json.Unmarshal(body, &users)
	aliceID := users[0]["id"].(string)

	// Add Alice to group
	status, _, _ = keycloakReq(t, ts, "PUT", "/t/keycloak/admin/realms/cyberdyne/users/"+aliceID+"/groups/"+gid, token, nil)
	if status != 204 {
		t.Fatalf("add user to group: expected 204, got %d", status)
	}

	// Get Alice's groups
	status, body, _ = keycloakReq(t, ts, "GET", "/t/keycloak/admin/realms/cyberdyne/users/"+aliceID+"/groups", token, nil)
	if status != 200 {
		t.Fatalf("get user groups: %d %s", status, body)
	}
	var userGroups []map[string]any
	json.Unmarshal(body, &userGroups)
	found := false
	for _, ug := range userGroups {
		if ug["id"] == gid {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected user to be in group %s", gid)
	}

	// Get group members
	status, body, _ = keycloakReq(t, ts, "GET", "/t/keycloak/admin/realms/cyberdyne/groups/"+gid+"/members", token, nil)
	if status != 200 {
		t.Fatalf("get group members: %d %s", status, body)
	}
	var members []map[string]any
	json.Unmarshal(body, &members)
	if len(members) != 1 || members[0]["id"] != aliceID {
		t.Errorf("unexpected group members: %v", members)
	}

	// Remove Alice from group
	status, _, _ = keycloakReq(t, ts, "DELETE", "/t/keycloak/admin/realms/cyberdyne/users/"+aliceID+"/groups/"+gid, token, nil)
	if status != 204 {
		t.Fatalf("remove user from group: expected 204, got %d", status)
	}

	// Delete group
	status, _, _ = keycloakReq(t, ts, "DELETE", "/t/keycloak/admin/realms/cyberdyne/groups/"+gid, token, nil)
	if status != 204 {
		t.Fatalf("delete group: expected 204, got %d", status)
	}
}

func TestKeycloakAPI_EventsAndSimulations(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerKeycloakAPI()
	token := "mock-token-xyz"

	// Events
	status, body, _ := keycloakReq(t, ts, "GET", "/t/keycloak/admin/realms/cyberdyne/events", token, nil)
	if status != 200 {
		t.Fatalf("get events: %d %s", status, body)
	}
	var events []map[string]any
	json.Unmarshal(body, &events)
	if len(events) == 0 {
		t.Fatalf("expected events, got 0")
	}
	if events[0]["type"] != "LOGIN" && events[0]["type"] != "LOGIN_ERROR" {
		t.Errorf("unexpected event type: %v", events[0]["type"])
	}

	// Admin events
	status, body, _ = keycloakReq(t, ts, "GET", "/t/keycloak/admin/realms/cyberdyne/admin-events", token, nil)
	if status != 200 {
		t.Fatalf("get admin events: %d %s", status, body)
	}

	// Fault simulation
	call(t, ts, "PATCH", "/api/tenants/keycloak/simulations", map[string]any{"httpStatus": 502, "once": true})
	status, _, _ = keycloakReq(t, ts, "GET", "/t/keycloak/admin/realms/cyberdyne/users", token, nil)
	if status != 502 {
		t.Fatalf("expected 502 outage, got %d", status)
	}
	// Second call recovers
	status, _, _ = keycloakReq(t, ts, "GET", "/t/keycloak/admin/realms/cyberdyne/users", token, nil)
	if status != 200 {
		t.Fatalf("expected 200 recovery, got %d", status)
	}
}
