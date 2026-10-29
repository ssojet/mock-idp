package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func oktaReq(t *testing.T, ts *httptest.Server, method, path, auth string, body any) (*http.Response, []byte) {
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

func TestOktaAPIAuthAndErrors(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerOktaAPI()

	// Missing Authorization -> 401 E0000011
	resp, raw := oktaReq(t, ts, "GET", "/t/okta/api/v1/users", "", nil)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d: %s", resp.StatusCode, raw)
	}
	var errEnv map[string]any
	json.Unmarshal(raw, &errEnv)
	if errEnv["errorCode"] != "E0000011" {
		t.Errorf("expected errorCode E0000011, got %v", errEnv["errorCode"])
	}

	// Invalid scheme -> 401 E0000011
	resp, _ = oktaReq(t, ts, "GET", "/t/okta/api/v1/users", "Basic dGVzdDp0ZXN0", nil)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 for Basic auth, got %d", resp.StatusCode)
	}

	// Both SSWS and Bearer work
	for _, auth := range []string{"SSWS test-okta-token", "Bearer test-bearer-token"} {
		resp, raw = oktaReq(t, ts, "GET", "/t/okta/api/v1/users", auth, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: expected 200, got %d: %s", auth, resp.StatusCode, raw)
		}
	}

	// Unknown user -> 404 E0000007
	resp, raw = oktaReq(t, ts, "GET", "/t/okta/api/v1/users/nonexistent-user", "SSWS tok", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	json.Unmarshal(raw, &errEnv)
	if errEnv["errorCode"] != "E0000007" {
		t.Errorf("expected E0000007, got %v", errEnv["errorCode"])
	}
}

func TestOktaAPIUsersCRUDAndLifecycle(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerOktaAPI()
	auth := "SSWS test-token"

	// Create user with activate=false -> STAGED
	createBody := map[string]any{
		"profile": map[string]any{
			"firstName":      "Frank",
			"lastName":       "Foster",
			"email":          "frank@acme.example",
			"login":          "frank@acme.example",
			"title":          "SRE",
			"department":     "Engineering",
			"mobilePhone":    "+1-555-0199",
			"employeeNumber": "99001",
		},
		"credentials": map[string]any{
			"password": map[string]any{"value": "Secret123!"},
		},
	}
	resp, raw := oktaReq(t, ts, "POST", "/t/okta/api/v1/users?activate=false", auth, createBody)
	if resp.StatusCode != 200 {
		t.Fatalf("create user failed: %d %s", resp.StatusCode, raw)
	}
	var created map[string]any
	json.Unmarshal(raw, &created)
	uid := str(created["id"])
	if !strings.HasPrefix(uid, "00u") {
		t.Errorf("expected 00u id, got %s", uid)
	}
	if created["status"] != "STAGED" {
		t.Errorf("expected STAGED, got %v", created["status"])
	}

	// Activate user
	resp, _ = oktaReq(t, ts, "POST", "/t/okta/api/v1/users/"+uid+"/lifecycle/activate", auth, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("activate failed: %d", resp.StatusCode)
	}
	resp, raw = oktaReq(t, ts, "GET", "/t/okta/api/v1/users/frank@acme.example", auth, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("get by login failed: %d", resp.StatusCode)
	}
	json.Unmarshal(raw, &created)
	if created["status"] != "ACTIVE" {
		t.Errorf("expected ACTIVE after activate, got %v", created["status"])
	}

	// Update user via POST (partial update) and PUT
	resp, raw = oktaReq(t, ts, "POST", "/t/okta/api/v1/users/"+uid, auth, map[string]any{
		"profile": map[string]any{"title": "Principal SRE"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("update user failed: %d %s", resp.StatusCode, raw)
	}
	json.Unmarshal(raw, &created)
	prof := created["profile"].(map[string]any)
	if prof["title"] != "Principal SRE" || prof["firstName"] != "Frank" {
		t.Errorf("unexpected profile after update: %v", prof)
	}

	// Suspend and Deactivate lifecycle
	resp, _ = oktaReq(t, ts, "POST", "/t/okta/api/v1/users/"+uid+"/lifecycle/suspend", auth, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("suspend failed: %d", resp.StatusCode)
	}
	_, raw = oktaReq(t, ts, "GET", "/t/okta/api/v1/users/"+uid, auth, nil)
	json.Unmarshal(raw, &created)
	if created["status"] != "SUSPENDED" {
		t.Errorf("expected SUSPENDED, got %v", created["status"])
	}

	resp, _ = oktaReq(t, ts, "POST", "/t/okta/api/v1/users/"+uid+"/lifecycle/deactivate", auth, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("deactivate failed: %d", resp.StatusCode)
	}
	_, raw = oktaReq(t, ts, "GET", "/t/okta/api/v1/users/"+uid, auth, nil)
	json.Unmarshal(raw, &created)
	if created["status"] != "DEPROVISIONED" {
		t.Errorf("expected DEPROVISIONED, got %v", created["status"])
	}

	// Delete user
	resp, _ = oktaReq(t, ts, "DELETE", "/t/okta/api/v1/users/"+uid, auth, nil)
	if resp.StatusCode != 204 {
		t.Fatalf("delete user expected 204, got %d", resp.StatusCode)
	}
	resp, _ = oktaReq(t, ts, "GET", "/t/okta/api/v1/users/"+uid, auth, nil)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 after delete, got %d", resp.StatusCode)
	}
}

func TestOktaAPIFilteringAndPagination(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerOktaAPI()
	auth := "SSWS test-token"

	// Filter by status eq "DEPROVISIONED" (Carol is inactive in seeded tenant)
	resp, raw := oktaReq(t, ts, "GET", `/t/okta/api/v1/users?filter=status+eq+"DEPROVISIONED"`, auth, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("filter status failed: %d", resp.StatusCode)
	}
	var users []map[string]any
	json.Unmarshal(raw, &users)
	if len(users) != 1 || users[0]["profile"].(map[string]any)["firstName"] != "Carol" {
		t.Fatalf("expected Carol for DEPROVISIONED filter, got %v", users)
	}

	// Search by profile.department eq "Engineering" and status eq "ACTIVE"
	resp, raw = oktaReq(t, ts, "GET", `/t/okta/api/v1/users?search=profile.department+eq+"Engineering"+and+status+eq+"ACTIVE"`, auth, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("search failed: %d", resp.StatusCode)
	}
	json.Unmarshal(raw, &users)
	if len(users) != 2 {
		t.Fatalf("expected 2 Engineering users (Alice, Bob), got %d", len(users))
	}

	// Query q=alice
	_, raw = oktaReq(t, ts, "GET", `/t/okta/api/v1/users?q=alice`, auth, nil)
	json.Unmarshal(raw, &users)
	if len(users) != 1 {
		t.Fatalf("expected 1 user for q=alice, got %d", len(users))
	}

	// Cursor pagination with limit=2
	var allIDs []string
	path := "/t/okta/api/v1/users?limit=2"
	pages := 0
	for path != "" {
		pages++
		if pages > 10 {
			t.Fatal("pagination loop did not terminate")
		}
		resp, raw = oktaReq(t, ts, "GET", path, auth, nil)
		var page []map[string]any
		json.Unmarshal(raw, &page)
		for _, u := range page {
			allIDs = append(allIDs, str(u["id"]))
		}
		links := resp.Header.Values("Link")
		hasSelf := false
		nextURL := ""
		for _, l := range links {
			if strings.Contains(l, `rel="self"`) {
				hasSelf = true
			}
			if strings.Contains(l, `rel="next"`) {
				start := strings.Index(l, "<")
				end := strings.Index(l, ">")
				if start >= 0 && end > start {
					nextURL = strings.TrimPrefix(l[start+1:end], ts.URL)
				}
			}
		}
		if !hasSelf {
			t.Errorf("missing rel=self Link header on page %d", pages)
		}
		path = nextURL
	}
	if len(allIDs) != 6 {
		t.Errorf("expected 6 total seeded users across pages, got %d", len(allIDs))
	}
}

func TestOktaAPIGroupsAppsAndLogs(t *testing.T) {
	s, ts := newTestServer(t)
	s.registerOktaAPI()
	auth := "SSWS test-token"

	// Create group
	resp, raw := oktaReq(t, ts, "POST", "/t/okta/api/v1/groups", auth, map[string]any{
		"profile": map[string]any{
			"name":        "Security",
			"description": "Security team",
		},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("create group failed: %d %s", resp.StatusCode, raw)
	}
	var grp map[string]any
	json.Unmarshal(raw, &grp)
	gid := str(grp["id"])

	// Get Alice's ID
	_, raw = oktaReq(t, ts, "GET", "/t/okta/api/v1/users/alice@acme.example", auth, nil)
	var alice map[string]any
	json.Unmarshal(raw, &alice)
	aliceID := str(alice["id"])

	// Add Alice to Security group
	resp, _ = oktaReq(t, ts, "PUT", "/t/okta/api/v1/groups/"+gid+"/users/"+aliceID, auth, nil)
	if resp.StatusCode != 204 {
		t.Fatalf("add group member failed: %d", resp.StatusCode)
	}

	// List users in group
	_, raw = oktaReq(t, ts, "GET", "/t/okta/api/v1/groups/"+gid+"/users", auth, nil)
	var members []map[string]any
	json.Unmarshal(raw, &members)
	if len(members) != 1 || str(members[0]["id"]) != aliceID {
		t.Fatalf("expected Alice in group, got %v", members)
	}

	// List groups for Alice
	_, raw = oktaReq(t, ts, "GET", "/t/okta/api/v1/users/"+aliceID+"/groups", auth, nil)
	var uGroups []map[string]any
	json.Unmarshal(raw, &uGroups)
	foundSec := false
	for _, g := range uGroups {
		if str(g["id"]) == gid {
			foundSec = true
		}
	}
	if !foundSec {
		t.Errorf("Security group not in Alice's groups")
	}

	// Remove Alice from Security group and delete group
	resp, _ = oktaReq(t, ts, "DELETE", "/t/okta/api/v1/groups/"+gid+"/users/"+aliceID, auth, nil)
	if resp.StatusCode != 204 {
		t.Fatalf("remove group member failed: %d", resp.StatusCode)
	}
	resp, _ = oktaReq(t, ts, "DELETE", "/t/okta/api/v1/groups/"+gid, auth, nil)
	if resp.StatusCode != 204 {
		t.Fatalf("delete group failed: %d", resp.StatusCode)
	}

	// Apps API
	resp, raw = oktaReq(t, ts, "GET", "/t/okta/api/v1/apps", auth, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("list apps failed: %d", resp.StatusCode)
	}
	var apps []map[string]any
	json.Unmarshal(raw, &apps)
	if len(apps) < 2 {
		t.Errorf("expected at least 2 apps, got %d", len(apps))
	}

	// System Log API
	resp, raw = oktaReq(t, ts, "GET", "/t/okta/api/v1/logs", auth, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("list logs failed: %d", resp.StatusCode)
	}
	var logs []map[string]any
	json.Unmarshal(raw, &logs)
	if len(logs) == 0 {
		t.Errorf("expected non-empty system logs")
	}

	// Fault simulation (503 outage)
	call(t, ts, "PATCH", "/api/tenants/okta/simulations", map[string]any{"httpStatus": 503, "once": true})
	resp, _ = oktaReq(t, ts, "GET", "/t/okta/api/v1/users", auth, nil)
	if resp.StatusCode != 503 {
		t.Errorf("expected 503 outage simulation, got %d", resp.StatusCode)
	}
	resp, _ = oktaReq(t, ts, "GET", "/t/okta/api/v1/users", auth, nil)
	if resp.StatusCode != 200 {
		t.Errorf("expected 200 after once outage cleared, got %d", resp.StatusCode)
	}
}
