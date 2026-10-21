// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func TestProvisionIdempotencyReplaysAndSerializesConcurrentRequests(t *testing.T) {
	h := newTestHandler(t, false)
	const customerID = "cust_idempotent"
	const nodeID = "node_idempotent"
	const appName = "idempotent-app"
	if err := h.db.RegisterNode(nodeID, "worker-idempotent", "10.0.0.20", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register worker: %v", err)
	}
	if err := h.db.UpdateNodeHeartbeat(nodeID, &admiral.HeartbeatRequest{
		NodeID: nodeID, DiskTotal: 100 << 30, DiskUsed: 1 << 30, RAMTotal: 16 << 30, RAMUsed: 1 << 30,
	}); err != nil {
		t.Fatalf("set worker heartbeat: %v", err)
	}
	if err := h.recomputeNodePolicy(nodeID); err != nil {
		t.Fatalf("set worker policy: %v", err)
	}
	appYAML := strings.Replace(minimalAppYAML(appName), "    port: 80\n", "    port: 80\n    setup_command: echo ready\n", 1)
	if err := h.db.SaveAppDefinition(appName, "Idempotent Test App", "provision idempotency test", appYAML, []database.AppTier{
		{AppName: appName, Name: "small", CPU: 1, Memory: "256M", Storage: "1G", PriceMonthly: 1},
	}, "improvement"); err != nil {
		t.Fatalf("save test app: %v", err)
	}
	t.Cleanup(func() {
		_, _ = h.db.Exec("DELETE FROM customer_apps WHERE customer_id = $1", customerID)
		_, _ = h.db.Exec("DELETE FROM provision_requests WHERE customer_id = $1", customerID)
		_, _ = h.db.Exec("DELETE FROM app_definitions WHERE name = $1", appName)
		_, _ = h.db.Exec("DELETE FROM nodes WHERE id = $1", nodeID)
	})

	request := func(key, logicalInstanceID string) (*httptest.ResponseRecorder, admiral.ProvisionResponse) {
		t.Helper()
		body, err := json.Marshal(admiral.ProvisionRequest{
			AppDefinitionName: appName, TierName: "small", CustomerID: customerID,
			LogicalInstanceID: logicalInstanceID,
		})
		if err != nil {
			t.Fatalf("marshal provision request: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/customer-apps", bytes.NewReader(body))
		req.Header.Set("X-Admiral-Customer-ID", customerID)
		req.Header.Set("Idempotency-Key", key)
		rec := httptest.NewRecorder()
		h.HandleCustomerApps(rec, req)
		var response admiral.ProvisionResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode provision response %q: %v", rec.Body.String(), err)
		}
		return rec, response
	}

	first, firstResponse := request("stable-key-001", "")
	if first.Code != http.StatusAccepted || firstResponse.InstanceID == "" || firstResponse.OperationID == "" {
		t.Fatalf("first provision failed: status=%d body=%s", first.Code, first.Body.String())
	}
	replay, replayResponse := request("stable-key-001", "")
	if replay.Code != http.StatusAccepted || replay.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("expected accepted replay, got status=%d headers=%v body=%s", replay.Code, replay.Header(), replay.Body.String())
	}
	if replayResponse.InstanceID != firstResponse.InstanceID || replayResponse.OperationID != firstResponse.OperationID {
		t.Fatalf("replay changed operation identity: first=%+v replay=%+v", firstResponse, replayResponse)
	}
	if got := h.publisher.(*mockPublisher).taskCount(); got != 1 {
		t.Fatalf("replay published another task: got %d tasks", got)
	}

	changedRequest, _ := request("stable-key-001", "different-logical-instance")
	if changedRequest.Code != http.StatusConflict {
		t.Fatalf("expected 409 when reusing a key with a different payload, got %d: %s", changedRequest.Code, changedRequest.Body.String())
	}
	intentionalSecond, secondResponse := request("stable-key-002", "")
	if intentionalSecond.Code != http.StatusAccepted || secondResponse.InstanceID == firstResponse.InstanceID {
		t.Fatalf("a distinct key should create an intentional second instance, status=%d body=%s", intentionalSecond.Code, intentionalSecond.Body.String())
	}

	gatedPublisher := &mockPublisher{entered: make(chan struct{}), release: make(chan struct{})}
	h.publisher = gatedPublisher
	firstDone := make(chan struct {
		recorder *httptest.ResponseRecorder
		response admiral.ProvisionResponse
	}, 1)
	go func() {
		rec, response := request("concurrent-key-001", "")
		firstDone <- struct {
			recorder *httptest.ResponseRecorder
			response admiral.ProvisionResponse
		}{recorder: rec, response: response}
	}()
	<-gatedPublisher.entered
	concurrentReplay, concurrentResponse := request("concurrent-key-001", "")
	if concurrentReplay.Code != http.StatusAccepted || concurrentResponse.Status != "processing" {
		t.Fatalf("concurrent replay should return the in-progress operation, got %d: %s", concurrentReplay.Code, concurrentReplay.Body.String())
	}
	close(gatedPublisher.release)
	firstResult := <-firstDone
	if firstResult.recorder.Code != http.StatusAccepted {
		t.Fatalf("first concurrent request failed: %d %s", firstResult.recorder.Code, firstResult.recorder.Body.String())
	}
	if firstResult.response.InstanceID != concurrentResponse.InstanceID || firstResult.response.OperationID != concurrentResponse.OperationID {
		t.Fatalf("concurrent request did not share stable IDs: first=%+v replay=%+v", firstResult.response, concurrentResponse)
	}
	if got := gatedPublisher.taskCount(); got != 1 {
		t.Fatalf("concurrent replay published %d tasks, want one", got)
	}

	var instances, operations int
	if err := h.db.QueryRow("SELECT COUNT(*) FROM customer_apps WHERE customer_id=$1", customerID).Scan(&instances); err != nil {
		t.Fatalf("count instances: %v", err)
	}
	if err := h.db.QueryRow("SELECT COUNT(*) FROM operations WHERE instance_id IN (SELECT id FROM customer_apps WHERE customer_id=$1)", customerID).Scan(&operations); err != nil {
		t.Fatalf("count operations: %v", err)
	}
	if instances != 3 || operations != 3 {
		t.Fatalf("expected three intentional provisions and operations, got instances=%d operations=%d", instances, operations)
	}
	var committedRAM, committedDisk int64
	if err := h.db.QueryRow("SELECT committed_ram_bytes, committed_disk_bytes FROM nodes WHERE id=$1", nodeID).Scan(&committedRAM, &committedDisk); err != nil {
		t.Fatalf("read node capacity: %v", err)
	}
	if committedRAM != 3*(256<<20) || committedDisk != 3*(1<<30) {
		t.Fatalf("capacity was reserved more than once for a replay: RAM=%d disk=%d", committedRAM, committedDisk)
	}
	if got := gatedPublisher.taskCount(); got != 1 {
		t.Fatalf("expected one task for concurrent request, got %d", got)
	}

	var committedRAMBefore, committedDiskBefore int64
	if err := h.db.QueryRow("SELECT committed_ram_bytes, committed_disk_bytes FROM nodes WHERE id=$1", nodeID).Scan(&committedRAMBefore, &committedDiskBefore); err != nil {
		t.Fatalf("read node capacity before publication failure: %v", err)
	}
	h.publisher = &mockPublisher{publishErr: errors.New("queue unavailable")}
	failedPublish, _ := request("stable-key-publish-failure", "")
	if failedPublish.Code != http.StatusInternalServerError {
		t.Fatalf("failed task publication must return 500, got status=%d body=%s", failedPublish.Code, failedPublish.Body.String())
	}
	replayedFailure, _ := request("stable-key-publish-failure", "")
	if replayedFailure.Code != http.StatusInternalServerError || replayedFailure.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("failed publication replay must preserve the original failure, got status=%d headers=%v body=%s", replayedFailure.Code, replayedFailure.Header(), replayedFailure.Body.String())
	}
	keyHash, err := provisionIdempotencyKeyHash("stable-key-publish-failure")
	if err != nil {
		t.Fatalf("hash publication failure key: %v", err)
	}
	failedRequest, err := h.db.GetProvisionRequest(customerID, keyHash)
	if err != nil || failedRequest == nil {
		t.Fatalf("read failed provision request: record=%+v err=%v", failedRequest, err)
	}
	failedInstance, err := h.db.GetCustomerApp(failedRequest.InstanceID)
	if err != nil {
		t.Fatalf("read failed provision instance: %v", err)
	}
	if failedInstance == nil || failedInstance.TechnicalStatus != "failed" {
		t.Fatalf("failed publication must not leave setup instance initializing: got %+v", failedInstance)
	}
	var committedRAMAfter, committedDiskAfter int64
	if err := h.db.QueryRow("SELECT committed_ram_bytes, committed_disk_bytes FROM nodes WHERE id=$1", nodeID).Scan(&committedRAMAfter, &committedDiskAfter); err != nil {
		t.Fatalf("read node capacity after publication failure: %v", err)
	}
	if committedRAMAfter != committedRAMBefore || committedDiskAfter != committedDiskBefore {
		t.Fatalf("failed publication leaked node capacity: before=(%d,%d), after=(%d,%d)", committedRAMBefore, committedDiskBefore, committedRAMAfter, committedDiskAfter)
	}
}
