package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func googleReq(t *testing.T, ts *httptest.Server, method, path, token string, body any) (int, []byte, http.Header) {
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

func TestGoogleAdminAPI_AuthRequired(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerGoogleAdminAPI()

	status, body, _ := googleReq(t, ts, "GET", "/t/google/admin/directory/v1/users", "", nil)
	if status != 401 {
		t.Fatalf("expected 401, got %d: %s", status, body)
	}
	var errResp map[string]any
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Fatalf("failed to parse json: %v", err)
	}
	errObj, ok := errResp["error"].(map[string]any)
	if !ok || errObj["code"].(float64) != 401 {
		t.Fatalf("unexpected error envelope: %v", errResp)
	}
}

func TestGoogleAdminAPI_UsersCRUDAndQuery(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerGoogleAdminAPI()
	token := "mock-token-xyz"

	// 1. List users
	status, body, _ := googleReq(t, ts, "GET", "/t/google/admin/directory/v1/users", token, nil)
	if status != 200 {
		t.Fatalf("list users: %d %s", status, body)
	}
	var usersResp map[string]any
	json.Unmarshal(body, &usersResp)
	if usersResp["kind"] != "admin#directory#users" {
		t.Errorf("expected kind admin#directory#users, got %v", usersResp["kind"])
	}
	usersList := usersResp["users"].([]any)
	if len(usersList) == 0 {
		t.Fatalf("expected users in globex, got 0")
	}

	// 2. Pagination test
	status, body, _ = googleReq(t, ts, "GET", "/t/google/admin/directory/v1/users?maxResults=2", token, nil)
	if status != 200 {
		t.Fatalf("paged users: %d %s", status, body)
	}
	var pagedResp map[string]any
	json.Unmarshal(body, &pagedResp)
	pageToken, ok := pagedResp["nextPageToken"].(string)
	if !ok || pageToken == "" {
		t.Errorf("expected nextPageToken, got none")
	}

	// Fetch next page
	status, body, _ = googleReq(t, ts, "GET", "/t/google/admin/directory/v1/users?maxResults=2&pageToken="+pageToken, token, nil)
	if status != 200 {
		t.Fatalf("fetch second page: %d %s", status, body)
	}

	// 3. Query filters
	status, body, _ = googleReq(t, ts, "GET", "/t/google/admin/directory/v1/users?query=email:alice*", token, nil)
	if status != 200 {
		t.Fatalf("query alice: %d %s", status, body)
	}
	var aliceResp map[string]any
	json.Unmarshal(body, &aliceResp)
	aliceList := aliceResp["users"].([]any)
	if len(aliceList) != 1 {
		t.Errorf("expected 1 user for email:alice*, got %d", len(aliceList))
	}

	// Query isSuspended=true (Carol is seeded with Active=false)
	status, body, _ = googleReq(t, ts, "GET", "/t/google/admin/directory/v1/users?query=isSuspended=true", token, nil)
	if status != 200 {
		t.Fatalf("query isSuspended: %d %s", status, body)
	}
	var suspendedResp map[string]any
	json.Unmarshal(body, &suspendedResp)
	suspendedList := suspendedResp["users"].([]any)
	if len(suspendedList) == 0 {
		t.Errorf("expected at least 1 suspended user (Carol), got 0")
	}

	// 4. Create user
	newUser := map[string]any{
		"primaryEmail": "homer.simpson@globex.example",
		"password":     "Doh12345!",
		"suspended":    false,
		"name": map[string]any{
			"givenName":  "Homer",
			"familyName": "Simpson",
		},
		"organizations": []map[string]any{
			{
				"title":      "Safety Inspector",
				"department": "Nuclear Safety",
			},
		},
		"phones": []map[string]any{
			{
				"value": "+1-555-0199",
				"type":  "work",
			},
		},
		"externalIds": []map[string]any{
			{
				"value": "EMP-777",
				"type":  "organization",
			},
		},
	}
	status, body, _ = googleReq(t, ts, "POST", "/t/google/admin/directory/v1/users", token, newUser)
	if status != 201 {
		t.Fatalf("create user: %d %s", status, body)
	}
	var created map[string]any
	json.Unmarshal(body, &created)
	uid := created["id"].(string)
	if created["primaryEmail"] != "homer.simpson@globex.example" {
		t.Errorf("unexpected primaryEmail: %v", created["primaryEmail"])
	}

	// 5. Get user by ID and by primaryEmail
	status, body, _ = googleReq(t, ts, "GET", "/t/google/admin/directory/v1/users/"+uid, token, nil)
	if status != 200 {
		t.Fatalf("get user by ID: %d %s", status, body)
	}
	status, body, _ = googleReq(t, ts, "GET", "/t/google/admin/directory/v1/users/homer.simpson@globex.example", token, nil)
	if status != 200 {
		t.Fatalf("get user by email: %d %s", status, body)
	}

	// 6. Update user (PATCH / PUT)
	patchBody := map[string]any{
		"suspended": true,
		"organizations": []map[string]any{
			{
				"title":      "Senior Safety Inspector",
				"department": "Nuclear Safety",
			},
		},
	}
	status, body, _ = googleReq(t, ts, "PATCH", "/t/google/admin/directory/v1/users/"+uid, token, patchBody)
	if status != 200 {
		t.Fatalf("patch user: %d %s", status, body)
	}
	var patched map[string]any
	json.Unmarshal(body, &patched)
	if !patched["suspended"].(bool) {
		t.Errorf("expected suspended=true, got %v", patched["suspended"])
	}

	// 7. Delete user
	status, _, _ = googleReq(t, ts, "DELETE", "/t/google/admin/directory/v1/users/"+uid, token, nil)
	if status != 204 {
		t.Fatalf("delete user: expected 204, got %d", status)
	}

	// Verify 404
	status, body, _ = googleReq(t, ts, "GET", "/t/google/admin/directory/v1/users/"+uid, token, nil)
	if status != 404 {
		t.Fatalf("expected 404 for deleted user, got %d: %s", status, body)
	}
}

func TestGoogleAdminAPI_GroupsAndMembers(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerGoogleAdminAPI()
	token := "mock-token-xyz"

	// List groups
	status, body, _ := googleReq(t, ts, "GET", "/t/google/admin/directory/v1/groups", token, nil)
	if status != 200 {
		t.Fatalf("list groups: %d %s", status, body)
	}
	var groupsResp map[string]any
	json.Unmarshal(body, &groupsResp)
	groupsList := groupsResp["groups"].([]any)
	if len(groupsList) == 0 {
		t.Fatalf("expected seeded groups in globex, got 0")
	}

	// Filter groups by userKey (Alice)
	status, body, _ = googleReq(t, ts, "GET", "/t/google/admin/directory/v1/groups?userKey=alice@globex.example", token, nil)
	if status != 200 {
		t.Fatalf("groups for alice: %d %s", status, body)
	}
	var aliceGroups map[string]any
	json.Unmarshal(body, &aliceGroups)
	if len(aliceGroups["groups"].([]any)) == 0 {
		t.Errorf("expected groups for alice, got 0")
	}

	// Create group
	newGroup := map[string]any{
		"name":  "Project Scorpio",
		"email": "scorpio@globex.example",
	}
	status, body, _ = googleReq(t, ts, "POST", "/t/google/admin/directory/v1/groups", token, newGroup)
	if status != 201 {
		t.Fatalf("create group: %d %s", status, body)
	}
	var createdGroup map[string]any
	json.Unmarshal(body, &createdGroup)
	gid := createdGroup["id"].(string)

	// Get group by ID, by Name, by Email
	status, _, _ = googleReq(t, ts, "GET", "/t/google/admin/directory/v1/groups/"+gid, token, nil)
	if status != 200 {
		t.Fatalf("get group by ID: %d", status)
	}
	status, _, _ = googleReq(t, ts, "GET", "/t/google/admin/directory/v1/groups/Project%20Scorpio", token, nil)
	if status != 200 {
		t.Fatalf("get group by Name: %d", status)
	}
	groupEmail := createdGroup["email"].(string)
	status, _, _ = googleReq(t, ts, "GET", "/t/google/admin/directory/v1/groups/"+groupEmail, token, nil)
	if status != 200 {
		t.Fatalf("get group by Email: %d", status)
	}

	// Add member
	memberReq := map[string]any{
		"email": "alice@globex.example",
		"role":  "MEMBER",
	}
	status, body, _ = googleReq(t, ts, "POST", "/t/google/admin/directory/v1/groups/"+gid+"/members", token, memberReq)
	if status != 201 {
		t.Fatalf("add member: %d %s", status, body)
	}
	var memberResp map[string]any
	json.Unmarshal(body, &memberResp)
	if memberResp["role"] != "MEMBER" {
		t.Errorf("expected role MEMBER, got %v", memberResp["role"])
	}

	// List members
	status, body, _ = googleReq(t, ts, "GET", "/t/google/admin/directory/v1/groups/"+gid+"/members", token, nil)
	if status != 200 {
		t.Fatalf("list members: %d %s", status, body)
	}
	var membersResp map[string]any
	json.Unmarshal(body, &membersResp)
	membersList := membersResp["members"].([]any)
	if len(membersList) != 1 {
		t.Errorf("expected 1 member, got %d", len(membersList))
	}

	// Remove member
	status, _, _ = googleReq(t, ts, "DELETE", "/t/google/admin/directory/v1/groups/"+gid+"/members/alice@globex.example", token, nil)
	if status != 204 {
		t.Fatalf("remove member: expected 204, got %d", status)
	}

	// Delete group
	status, _, _ = googleReq(t, ts, "DELETE", "/t/google/admin/directory/v1/groups/"+gid, token, nil)
	if status != 204 {
		t.Fatalf("delete group: expected 204, got %d", status)
	}
}

func TestGoogleAdminAPI_ReportsAndSimulations(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerGoogleAdminAPI()
	token := "mock-token-xyz"

	// Reports v1 Activities
	status, body, _ := googleReq(t, ts, "GET", "/t/google/admin/reports/v1/activity/users/all/applications/login", token, nil)
	if status != 200 {
		t.Fatalf("reports: %d %s", status, body)
	}
	var activities map[string]any
	json.Unmarshal(body, &activities)
	if activities["kind"] != "admin#reports#activities" {
		t.Errorf("unexpected kind: %v", activities["kind"])
	}
	items := activities["items"].([]any)
	if len(items) == 0 {
		t.Fatalf("expected at least 1 activity item, got 0")
	}

	// Fault simulation
	call(t, ts, "PATCH", "/api/tenants/google/simulations", map[string]any{"httpStatus": 500, "once": true})
	status, _, _ = googleReq(t, ts, "GET", "/t/google/admin/directory/v1/users", token, nil)
	if status != 500 {
		t.Fatalf("expected 500 simulated outage, got %d", status)
	}
	// Once fault consumed, second call succeeds
	status, _, _ = googleReq(t, ts, "GET", "/t/google/admin/directory/v1/users", token, nil)
	if status != 200 {
		t.Fatalf("expected 200 recovery, got %d", status)
	}
}
