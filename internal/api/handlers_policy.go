package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func isMetricsFresh(lastMetricsAt *time.Time) bool {
	if lastMetricsAt == nil {
		return false
	}
	return time.Since(lastMetricsAt.UTC()) <= time.Duration(database.MetricsStaleAfterSec)*time.Second
}

func hasValidNodeMetrics(node database.Node) bool {
	if node.RAMTotal <= 0 || node.DiskTotal <= 0 {
		return false
	}
	if node.RAMUsed < 0 || node.DiskUsed < 0 {
		return false
	}
	if node.RAMUsed > node.RAMTotal || node.DiskUsed > node.DiskTotal {
		return false
	}
	return true
}

func appendUniqueReason(reasons []string, reason string) []string {
	if reason == "" {
		return reasons
	}
	for _, existing := range reasons {
		if existing == reason {
			return reasons
		}
	}
	return append(reasons, reason)
}

func normalizeReasons(reasons []string) []string {
	if len(reasons) == 0 {
		return nil
	}
	sort.Strings(reasons)
	out := reasons[:0]
	for _, reason := range reasons {
		if len(out) == 0 || out[len(out)-1] != reason {
			out = append(out, reason)
		}
	}
	return out
}

func joinReasons(reasons []string) string {
	reasons = normalizeReasons(reasons)
	if len(reasons) == 0 {
		return ""
	}
	return strings.Join(reasons, ",")
}

func (h *APIHandlers) recomputeNodePolicy(nodeID string) error {
	node, err := h.db.GetNode(nodeID)
	if err != nil {
		return fmt.Errorf("get node %q for policy recompute: %w", nodeID, err)
	}
	if node == nil {
		return fmt.Errorf("node %q not found for policy recompute", nodeID)
	}

	if node.NodeRole == "portal" {
		return h.recomputePortalNodePolicy(node)
	}

	ramCommitLimit := database.CalculateRAMCommitLimit(node.RAMTotal)
	diskCommitLimit := database.CalculateDiskCommitLimit(node.DiskTotal)
	if err := h.db.UpdateNodeCommitLimits(nodeID, ramCommitLimit, diskCommitLimit); err != nil {
		return fmt.Errorf("update commit limits for node %q: %w", nodeID, err)
	}

	metricsFresh := isMetricsFresh(node.LastMetricsAt)
	metricsValid := hasValidNodeMetrics(*node) && ramCommitLimit > 0 && diskCommitLimit > 0

	healthReasons := []string{}
	availabilityReasons := []string{}

	if node.Status != "active" {
		healthReasons = appendUniqueReason(healthReasons, "fleet_offline")
		availabilityReasons = appendUniqueReason(availabilityReasons, "fleet_offline")
	}
	if node.ManualDisabled {
		healthReasons = appendUniqueReason(healthReasons, "manual_disabled")
		availabilityReasons = appendUniqueReason(availabilityReasons, "manual_disabled")
	}
	if !metricsFresh {
		healthReasons = appendUniqueReason(healthReasons, "metrics_stale")
		availabilityReasons = appendUniqueReason(availabilityReasons, "metrics_stale")
	}
	if !metricsValid {
		healthReasons = appendUniqueReason(healthReasons, "invalid_metrics")
		availabilityReasons = appendUniqueReason(availabilityReasons, "invalid_metrics")
	}
	if metricsValid {
		ramRatio := float64(node.RAMUsed) / float64(node.RAMTotal)
		if ramRatio >= database.RAMHealthCriticalRatio {
			healthReasons = appendUniqueReason(healthReasons, "ram_usage_critical")
			availabilityReasons = appendUniqueReason(availabilityReasons, "ram_usage_critical")
		}
		diskRatio := float64(node.DiskUsed) / float64(node.DiskTotal)
		if diskRatio >= database.DiskHealthCriticalRatio {
			healthReasons = appendUniqueReason(healthReasons, "disk_usage_critical")
			availabilityReasons = appendUniqueReason(availabilityReasons, "disk_usage_critical")
		}
	}
	if ramCommitLimit <= 0 || node.CommittedRAM >= ramCommitLimit {
		availabilityReasons = appendUniqueReason(availabilityReasons, "insufficient_ram_commit_capacity")
	}
	if diskCommitLimit <= 0 || node.CommittedDisk >= diskCommitLimit {
		availabilityReasons = appendUniqueReason(availabilityReasons, "insufficient_disk_commit_capacity")
	}

	healthStatus := "healthy"
	if len(healthReasons) > 0 {
		healthStatus = "unhealthy"
	}
	available := len(availabilityReasons) == 0

	if err := h.db.UpdateNodeHealth(nodeID, healthStatus, joinReasons(healthReasons), available, joinReasons(availabilityReasons)); err != nil {
		return fmt.Errorf("update node %q health: %w", nodeID, err)
	}
	newHealthReasons := joinReasons(healthReasons)
	newAvailabilityReasons := joinReasons(availabilityReasons)
	if node.HealthStatus != healthStatus || node.HealthReasonCodes != newHealthReasons {
		h.auditEvent("node_health_changed", map[string]interface{}{
			"node_id":        nodeID,
			"actor_type":     "system",
			"actor_id":       "admirald",
			"previous_value": node.HealthStatus,
			"new_value":      healthStatus,
			"reason_codes":   newHealthReasons,
		})
	}
	if node.AvailableForProvisioning != available || node.UnavailableReasonCodes != newAvailabilityReasons {
		h.auditEvent("node_provisioning_availability_changed", map[string]interface{}{
			"node_id":        nodeID,
			"actor_type":     "system",
			"actor_id":       "admirald",
			"previous_value": node.AvailableForProvisioning,
			"new_value":      available,
			"reason_codes":   newAvailabilityReasons,
		})
	}
	return nil
}

func (h *APIHandlers) evaluateNodeForTier(node database.Node, requestedRAM, requestedDisk int64) admiral.NodeProvisioningEvaluation {
	evaluation := admiral.NodeProvisioningEvaluation{NodeID: node.ID}
	reasons := []string{}

	if node.NodeRole == "admin" || node.NodeRole == "portal" {
		reasons = appendUniqueReason(reasons, "not_a_worker_node")
	}
	if node.Status != "active" || node.HealthStatus != "healthy" {
		reasons = appendUniqueReason(reasons, "node_unhealthy")
	}
	if node.ManualDisabled {
		reasons = appendUniqueReason(reasons, "manual_disabled")
	}
	if !isMetricsFresh(node.LastMetricsAt) {
		reasons = appendUniqueReason(reasons, "metrics_stale")
	}
	if !hasValidNodeMetrics(node) {
		reasons = appendUniqueReason(reasons, "invalid_metrics")
	}

	ramCommitLimit := node.RAMCommitLimit
	if ramCommitLimit <= 0 {
		ramCommitLimit = database.CalculateRAMCommitLimit(node.RAMTotal)
	}
	diskCommitLimit := node.DiskCommitLimit
	if diskCommitLimit <= 0 {
		diskCommitLimit = database.CalculateDiskCommitLimit(node.DiskTotal)
	}

	if ramCommitLimit <= 0 || node.CommittedRAM+requestedRAM > ramCommitLimit {
		reasons = appendUniqueReason(reasons, "insufficient_ram_commit_capacity")
	}
	if diskCommitLimit <= 0 || node.CommittedDisk+requestedDisk > diskCommitLimit {
		reasons = appendUniqueReason(reasons, "insufficient_disk_commit_capacity")
	}

	reasons = normalizeReasons(reasons)
	evaluation.RejectionReasons = reasons
	evaluation.Eligible = len(reasons) == 0
	if evaluation.Eligible {
		evaluation.RemainingRAMAfterAllocationBytes = ramCommitLimit - (node.CommittedRAM + requestedRAM)
		evaluation.RemainingDiskAfterAllocationBytes = diskCommitLimit - (node.CommittedDisk + requestedDisk)
	}
	return evaluation
}

func (h *APIHandlers) selectNodeForTier(tier database.AppTier, requestedNodeID string) (nodeSelectionResult, error) {
	nodes, err := h.db.GetNodes()
	if err != nil {
		return nodeSelectionResult{}, err
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})

	requestedRAM := database.ParseSizeBytes(tier.Memory)
	requestedDisk := database.ParseSizeBytes(tier.Storage)
	if requestedRAM <= 0 || requestedDisk <= 0 {
		return nodeSelectionResult{}, fmt.Errorf("tier %q has invalid resource definition", tier.Name)
	}

	result := nodeSelectionResult{}
	for _, node := range nodes {
		if requestedNodeID != "" && node.ID != requestedNodeID {
			continue
		}
		evaluation := h.evaluateNodeForTier(node, requestedRAM, requestedDisk)
		result.Evaluations = append(result.Evaluations, evaluation)
		if !evaluation.Eligible {
			continue
		}
		if result.NodeID == "" {
			result.NodeID = node.ID
			continue
		}
		best := result.Evaluations[0]
		for _, candidate := range result.Evaluations {
			if candidate.NodeID == result.NodeID {
				best = candidate
				break
			}
		}
		if evaluation.RemainingRAMAfterAllocationBytes > best.RemainingRAMAfterAllocationBytes ||
			(evaluation.RemainingRAMAfterAllocationBytes == best.RemainingRAMAfterAllocationBytes && evaluation.RemainingDiskAfterAllocationBytes > best.RemainingDiskAfterAllocationBytes) ||
			(evaluation.RemainingRAMAfterAllocationBytes == best.RemainingRAMAfterAllocationBytes && evaluation.RemainingDiskAfterAllocationBytes == best.RemainingDiskAfterAllocationBytes && node.ID < result.NodeID) {
			result.NodeID = node.ID
		}
	}
	return result, nil
}

func policyRejectedAction(action admiral.TaskAction) admiral.TaskAction {
	switch action {
	case admiral.ActionResizeApp:
		return admiral.ActionResizePolicyRejected
	default:
		return admiral.ActionProvisionPolicyRejected
	}
}

func (h *APIHandlers) refreshNodeEvaluationsForTier(tier database.AppTier, requestedNodeID string) []admiral.NodeProvisioningEvaluation {
	selection, err := h.selectNodeForTier(tier, requestedNodeID)
	if err != nil {
		h.log.Error("Refresh node evaluations failed", err, map[string]interface{}{"requested_node_id": requestedNodeID, "tier": tier.Name})
		return nil
	}
	return selection.Evaluations
}

func (h *APIHandlers) persistRejectedTask(operationID, instanceID, nodeID string, taskAction admiral.TaskAction, tier database.AppTier, detail blockedProvisioningAuditDetail) (string, error) {
	if h.publisher == nil {
		return "", nil
	}
	payload, err := json.Marshal(detail)
	if err != nil {
		return "", fmt.Errorf("marshal rejected task payload: %w", err)
	}
	task := &admiral.FleetTask{
		TaskID:      generateID("task"),
		OperationID: operationID,
		NodeID:      nodeID,
		Action:      taskAction,
		InstanceID:  instanceID,
		Tier: admiral.TierInfo{
			Name:        tier.Name,
			CPU:         tier.CPU,
			Memory:      tier.Memory,
			Storage:     tier.Storage,
			Environment: tier.Environment,
		},
		App: admiral.AppInfo{Name: detail.RequestedAppDefinition, Version: "policy-rejected"},
	}
	if err := h.db.UpdateOperationTaskID(operationID, task.TaskID); err != nil {
		return "", fmt.Errorf("persist rejected task id on operation: %w", err)
	}
	if err := h.publisher.PublishRejectedTask(task, detail.Detail, string(payload)); err != nil {
		return "", fmt.Errorf("persist rejected queue task: %w", err)
	}
	return task.TaskID, nil
}

func (h *APIHandlers) auditCapacityEvent(eventType, nodeID, instanceID, operationID string, action admiral.TaskAction, ramBytes, diskBytes int64) {
	h.auditEvent(eventType, map[string]interface{}{
		"node_id":        nodeID,
		"related_app_id": instanceID,
		"operation_id":   operationID,
		"action":         string(action),
		"ram_bytes":      ramBytes,
		"disk_bytes":     diskBytes,
		"actor_type":     "system",
		"actor_id":       "admirald",
	})
}

func (h *APIHandlers) recordBlockedWorkloadAttempt(w http.ResponseWriter, r *http.Request, action admiral.TaskAction, instanceID, appDefinitionName, customerID, requestedNodeID string, tier database.AppTier, evaluations []admiral.NodeProvisioningEvaluation) error {
	operationID := generateID("op")
	operator := operatorFromRequest(r)
	if err := h.db.CreateOperation(operationID, instanceID, requestedNodeID, string(action), "failed", operator); err != nil {
		return fmt.Errorf("create blocked workload operation: %w", err)
	}

	detail := blockedProvisioningAuditDetail{
		Code:                   provisioningBlockedCode,
		Message:                provisioningBlockedMessage,
		Detail:                 provisioningBlockedMessage + " La politica de capacidad impide asignar mas workloads al nodo evaluado.",
		Action:                 string(action),
		RequestedAppDefinition: appDefinitionName,
		RequestedTier:          tier.Name,
		RequestedNodeID:        requestedNodeID,
		CustomerID:             customerID,
		Operator:               operator,
		NodeEvaluations:        evaluations,
	}
	payload, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("marshal blocked workload detail: %w", err)
	}
	if err := h.db.UpdateOperation(operationID, "failed", string(payload)); err != nil {
		return fmt.Errorf("update blocked workload operation: %w", err)
	}
	taskID, err := h.persistRejectedTask(operationID, instanceID, requestedNodeID, policyRejectedAction(action), tier, detail)
	if err != nil {
		return err
	}
	h.auditEvent("node_provisioning_rejected_no_capacity", map[string]interface{}{
		"node_id":          requestedNodeID,
		"operation_id":     operationID,
		"task_id":          taskID,
		"related_app_id":   instanceID,
		"related_tier_id":  tier.Name,
		"app_definition":   appDefinitionName,
		"customer_id":      customerID,
		"reason_codes":     provisioningBlockedCode,
		"node_evaluations": evaluations,
		"actor_type":       "operator",
		"actor_id":         operator,
	})

	writeJSON(w, http.StatusServiceUnavailable, admiral.ProvisioningRejectedResponse{
		Code:            provisioningBlockedCode,
		Message:         provisioningBlockedMessage,
		Error:           provisioningBlockedMessage,
		Detail:          detail.Detail,
		OperationID:     operationID,
		TaskID:          taskID,
		RequestedNodeID: requestedNodeID,
		NodeEvaluations: evaluations,
	})
	return nil
}

func (h *APIHandlers) recomputePortalNodePolicy(node *database.Node) error {
	healthReasons := []string{}
	availabilityReasons := []string{}

	if node.Status != "active" {
		healthReasons = appendUniqueReason(healthReasons, "portal_offline")
	}
	if node.ManualDisabled {
		healthReasons = appendUniqueReason(healthReasons, "manual_disabled")
		availabilityReasons = appendUniqueReason(availabilityReasons, "manual_disabled")
	}

	healthStatus := "healthy"
	if len(healthReasons) > 0 {
		healthStatus = "unhealthy"
	}
	available := len(availabilityReasons) == 0

	if err := h.db.UpdateNodeHealth(node.ID, healthStatus, joinReasons(healthReasons), available, joinReasons(availabilityReasons)); err != nil {
		return fmt.Errorf("update portal node %q health: %w", node.ID, err)
	}
	newHealthReasons := joinReasons(healthReasons)
	newAvailabilityReasons := joinReasons(availabilityReasons)
	if node.HealthStatus != healthStatus || node.HealthReasonCodes != newHealthReasons {
		h.auditEvent("node_health_changed", map[string]interface{}{
			"node_id":        node.ID,
			"actor_type":     "system",
			"actor_id":       "admirald",
			"previous_value": node.HealthStatus,
			"new_value":      healthStatus,
			"reason_codes":   newHealthReasons,
		})
	}
	if node.AvailableForProvisioning != available || node.UnavailableReasonCodes != newAvailabilityReasons {
		h.auditEvent("node_provisioning_availability_changed", map[string]interface{}{
			"node_id":        node.ID,
			"actor_type":     "system",
			"actor_id":       "admirald",
			"previous_value": node.AvailableForProvisioning,
			"new_value":      available,
			"reason_codes":   newAvailabilityReasons,
		})
	}
	return nil
}
