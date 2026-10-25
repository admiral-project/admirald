// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/queue"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

type queuedTaskClaim struct {
	task      *admiral.FleetTask
	commandID string
}

type terminalTaskClaimPublisher struct {
	*mockPublisher
	claims            []queuedTaskClaim
	discardedCommands []string
	cancelledTasks    []string
	acknowledgedTasks []string
}

func (p *terminalTaskClaimPublisher) ClaimTask(string) (*admiral.FleetTask, string, int, int, error) {
	if len(p.claims) == 0 {
		return nil, "", 0, 0, queue.ErrNoCommandAvailable
	}
	claim := p.claims[0]
	p.claims = p.claims[1:]
	return claim.task, claim.commandID, 1, 5, nil
}

func (p *terminalTaskClaimPublisher) CancelCommandForNode(commandID, _, _ string) error {
	p.discardedCommands = append(p.discardedCommands, commandID)
	return nil
}

func (p *terminalTaskClaimPublisher) CancelTaskForNode(taskPublicID, _, _ string) error {
	p.cancelledTasks = append(p.cancelledTasks, taskPublicID)
	return nil
}

func (p *terminalTaskClaimPublisher) AcknowledgeTaskForNode(taskPublicID, _ string) error {
	p.acknowledgedTasks = append(p.acknowledgedTasks, taskPublicID)
	return nil
}

func TestHandleTaskClaimDiscardsIneligibleTasksBeforeDispatch(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_002", "cust_001", "testapp", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create deprovisioned instance: %v", err)
	}
	if err := h.db.UpdateCustomerAppStatus("inst_002", "cancelled", "deprovisioned"); err != nil {
		t.Fatalf("mark instance deprovisioned: %v", err)
	}

	operations := []struct {
		id, instanceID, status, taskID string
	}{
		{"op_failed", "inst_001", "failed", "task_failed"},
		{"op_cancelled", "inst_001", "cancelled", "task_cancelled"},
		{"op_succeeded", "inst_001", "succeeded", "task_succeeded"},
		{"op_replaced", "inst_001", "running", "task_current"},
		{"op_deprovisioned", "inst_002", "running", "task_deprovisioned"},
		{"op_missing_task", "inst_001", "running", ""},
		{"op_live", "inst_001", "running", "task_live"},
	}
	for _, op := range operations {
		if err := h.db.CreateOperation(op.id, op.instanceID, "node_001", string(admiral.ActionProvisionApp), op.status, "test"); err != nil {
			t.Fatalf("create operation %s: %v", op.id, err)
		}
		if err := h.db.UpdateOperationTaskID(op.id, op.taskID); err != nil {
			t.Fatalf("set task ID on operation %s: %v", op.id, err)
		}
	}

	publisher := &terminalTaskClaimPublisher{mockPublisher: &mockPublisher{}, claims: []queuedTaskClaim{
		{commandID: "cmd_failed", task: claimTask("op_failed", "task_failed")},
		{commandID: "cmd_cancelled", task: claimTask("op_cancelled", "task_cancelled")},
		{commandID: "cmd_succeeded", task: claimTask("op_succeeded", "task_succeeded")},
		{commandID: "cmd_missing", task: claimTask("op_missing", "task_missing")},
		{commandID: "cmd_replaced", task: claimTask("op_replaced", "task_old")},
		{commandID: "cmd_deprovisioned", task: claimTaskForInstance("op_deprovisioned", "task_deprovisioned", "inst_002")},
		{commandID: "cmd_missing_task", task: claimTask("op_missing_task", "task_without_operation_id")},
		{commandID: "cmd_live", task: claimTask("op_live", "task_live")},
	}}
	h.publisher = publisher

	body, _ := json.Marshal(map[string]string{"node_id": "node_001"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/tasks/claim", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), contextKeyNodeID, "node_001"))
	rec := httptest.NewRecorder()
	h.HandleTaskClaim(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("claim status = %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var response struct {
		Task admiral.FleetTask `json:"task"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode claim response: %v", err)
	}
	if response.Task.TaskID != "task_live" {
		t.Fatalf("dispatched task %q, want only live task", response.Task.TaskID)
	}
	wantDiscarded := []string{"cmd_failed", "cmd_cancelled", "cmd_succeeded", "cmd_missing", "cmd_replaced", "cmd_deprovisioned", "cmd_missing_task"}
	if !reflect.DeepEqual(publisher.discardedCommands, wantDiscarded) {
		t.Fatalf("discarded commands = %v, want %v", publisher.discardedCommands, wantDiscarded)
	}
}

func TestTerminalFleetCallbackSettlesQueueCommand(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	for _, op := range []struct{ id, status, taskID string }{
		{"op_done", "succeeded", "task_done"},
		{"op_failed", "failed", "task_late"},
	} {
		if err := h.db.CreateOperation(op.id, "inst_001", "node_001", string(admiral.ActionProvisionApp), op.status, "test"); err != nil {
			t.Fatalf("create operation %s: %v", op.id, err)
		}
	}
	publisher := &terminalTaskClaimPublisher{mockPublisher: &mockPublisher{}}
	h.publisher = publisher

	for _, callback := range []admiral.TaskResult{
		{TaskID: "task_done", OperationID: "op_done", NodeID: "node_001", Success: false, Error: "late duplicate"},
		{TaskID: "task_late", OperationID: "op_failed", NodeID: "node_001", Success: false, Error: "late retry"},
	} {
		body, _ := json.Marshal(callback)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/callback", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		h.HandleFleetCallback(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("callback for %s status = %d body=%s", callback.OperationID, rec.Code, rec.Body.String())
		}
	}
	if !reflect.DeepEqual(publisher.acknowledgedTasks, []string{"task_done"}) {
		t.Fatalf("acknowledged tasks = %v, want [task_done]", publisher.acknowledgedTasks)
	}
	if !reflect.DeepEqual(publisher.cancelledTasks, []string{"task_late"}) {
		t.Fatalf("cancelled tasks = %v, want [task_late]", publisher.cancelledTasks)
	}
	for _, opID := range []string{"op_done", "op_failed"} {
		op, err := h.db.GetOperation(opID)
		if err != nil {
			t.Fatalf("get operation %s: %v", opID, err)
		}
		want := "succeeded"
		if opID == "op_failed" {
			want = "failed"
		}
		if op.Status != want {
			t.Fatalf("terminal operation %s changed to %q, want %q", opID, op.Status, want)
		}
	}
}

func claimTask(operationID, taskID string) *admiral.FleetTask {
	return claimTaskForInstance(operationID, taskID, "inst_001")
}

func claimTaskForInstance(operationID, taskID, instanceID string) *admiral.FleetTask {
	return &admiral.FleetTask{
		TaskID:      taskID,
		OperationID: operationID,
		NodeID:      "node_001",
		InstanceID:  instanceID,
		Action:      admiral.ActionProvisionApp,
	}
}
