package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// write_target_model must be default-bound to the planner only: worker and main
// agent keep writing observations through record_fact, never shared guidance.
func TestTargetModelToolIsPlannerOnly(t *testing.T) {
	has := func(tools []actool.CoreTool, name string) bool {
		for _, tool := range tools {
			if tool.Name() == name {
				return true
			}
		}
		return false
	}
	ts := NewToolSet(nil, "")
	if !has(ts.PlannerTools(), "write_target_model") {
		t.Fatal("PlannerTools lost write_target_model")
	}
	if has(ts.WorkerTools(), "write_target_model") {
		t.Fatal("WorkerTools must not expose write_target_model")
	}
	if has(ts.MainAgentTools(), "write_target_model") {
		t.Fatal("MainAgentTools must not expose write_target_model")
	}
	for _, seed := range BuiltinToolSeeds() {
		if seed.Key != "write_target_model" {
			continue
		}
		if len(seed.Agents) != 1 || seed.Agents[0] != "planner" {
			t.Fatalf("seed agents = %v, want [planner]", seed.Agents)
		}
		return
	}
	t.Fatal("write_target_model missing from BuiltinToolSeeds")
}

// Without a task-scoped store the tool must answer with a tool error (same
// refusal contract as every other domain write tool), never panic or write.
func TestTargetModelToolRefusesWithoutTaskContext(t *testing.T) {
	ts := NewToolSet(nil, "worker-1")
	res, err := ts.writeTargetModel().Call(context.Background(),
		json.RawMessage(`{"summary":"m","model":{"group_key":"g"},"asset_ids":[1]}`), nil)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("want refusal, got %q", res.Flatten())
	}
}

// Worker injection only includes models whose anchors intersect the intent assets.
func TestTargetModelContextFiltersAssets(t *testing.T) {
	items := []map[string]any{
		{"id": int64(1), "asset_ids": []int64{10}, "group": "a", "summary": "one"},
		{"id": int64(2), "asset_ids": []any{float64(20)}, "group": "b", "summary": "two"},
	}
	got := selectTargetModels(items, []int64{20})
	if !strings.Contains(got, `"id":2`) {
		t.Fatalf("expected model 2 in %q", got)
	}
	if strings.Contains(got, `"id":1`) {
		t.Fatalf("unexpected model 1 in %q", got)
	}
}

func TestTargetModelContextNoMatch(t *testing.T) {
	items := []map[string]any{{"id": int64(1), "asset_ids": []int64{10}}}
	if got := selectTargetModels(items, []int64{20}); got != "当前意图没有匹配的目标模型。" {
		t.Fatalf("got %q", got)
	}
	if got := selectTargetModels(nil, nil); got != "当前没有可用目标模型。" {
		t.Fatalf("got %q", got)
	}
}

// Model index fields are collapsed to one line so a target-derived summary
// cannot add prompt structure to the worker system message.
func TestTargetModelContextIsSingleLine(t *testing.T) {
	items := []map[string]any{{
		"id": int64(1), "asset_ids": []int64{10},
		"group": "g\nh", "summary": "line one\nline two",
	}}
	got := selectTargetModels(items, []int64{10})
	if !strings.Contains(got, `"group":"g h"`) {
		t.Fatalf("group not collapsed: %q", got)
	}
	if !strings.Contains(got, `"summary":"line one line two"`) {
		t.Fatalf("summary not collapsed: %q", got)
	}
}

// Object-shaped fields are a valid, information-rich form (role→description,
// unknown→question); counts must not report them as empty.
func TestTargetModelFieldCountAcceptsObjects(t *testing.T) {
	cases := []struct {
		name string
		v    any
		want int
	}{
		{"array", []any{"a", "b"}, 2},
		{"object", map[string]any{"a": "x", "b": "y"}, 2},
		{"empty array", []any{}, 0},
		{"scalar", "text", 0},
		{"nil", nil, 0},
	}
	for _, c := range cases {
		if got := targetModelFieldCount(c.v); got != c.want {
			t.Fatalf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

// Oversized matched models are compressed to an id/group/summary index; the
// full payload is never injected into the system prompt.
func TestTargetModelContextSizeCeiling(t *testing.T) {
	big := strings.Repeat("x", 9000)
	items := []map[string]any{
		{"id": int64(1), "asset_ids": []int64{10}, "group": "g", "summary": big},
		{"id": int64(2), "asset_ids": []int64{10}, "group": "g2", "summary": big},
	}
	got := selectTargetModels(items, []int64{10})
	if !strings.Contains(got, "node_detail(id)") {
		t.Fatalf("expected index pointer, got %d bytes", len(got))
	}
	if len(got) > 4096 {
		t.Fatalf("index too large: %d bytes", len(got))
	}
	if strings.Contains(got, strings.Repeat("x", 200)) {
		t.Fatalf("full summary leaked into index: %q", got)
	}
}

// Role and task guards are distinct: with a real store, a worker ToolSet must be
// refused by the role guard, and a planner without taskID by the task guard.
func TestTargetModelToolGuardsWithStore(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	task, err := d.CreateTaskWithOptions("tmdl-guard", "guard", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets(type, domain, root_domain) VALUES ('root_domain','tmdl-guard.example','tmdl-guard.example') RETURNING id`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM assets WHERE id=$1`, assetID)
	if _, err := d.Exec(`INSERT INTO task_scope(task_id, kind, domain) VALUES ($1,'root_domain','tmdl-guard.example')`, task.ID); err != nil {
		t.Fatal(err)
	}
	input := json.RawMessage(`{"summary":"m","model":{"group_key":"g"},"asset_ids":[` + fmt.Sprintf("%d", assetID) + `]}`)

	workerTS := NewToolSet(d.Exploration(task.ExplorationID), "worker-1")
	workerTS.SetTaskID(task.ID)
	res, err := workerTS.writeTargetModel().Call(context.Background(), input, nil)
	if err != nil || !res.IsError || !strings.Contains(res.Flatten(), "仅 planner") {
		t.Fatalf("worker guard: err=%v res=%q", err, res.Flatten())
	}

	noTaskTS := NewToolSet(d.Exploration(task.ExplorationID), "planner")
	res, err = noTaskTS.writeTargetModel().Call(context.Background(), input, nil)
	if err != nil || !res.IsError || !strings.Contains(res.Flatten(), "taskID") {
		t.Fatalf("task guard: err=%v res=%q", err, res.Flatten())
	}

	plannerTS := NewToolSet(d.Exploration(task.ExplorationID), "planner")
	plannerTS.SetTaskID(task.ID)
	res, err = plannerTS.writeTargetModel().Call(context.Background(), input, nil)
	if err != nil || res.IsError {
		t.Fatalf("planner path failed: err=%v res=%q", err, res.Flatten())
	}
}

// End-to-end wiring: planner writes a model, the overview slot exposes it, and
// the worker's asset-filtered context includes it.
func TestTargetModelAppearsInOverviewAndWorkerContext(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	task, err := d.CreateTaskWithOptions("tmdl-e2e", "e2e", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets(type, domain, root_domain) VALUES ('root_domain','tmdl-e2e.example','tmdl-e2e.example') RETURNING id`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM assets WHERE id=$1`, assetID)
	if _, err := d.Exec(`INSERT INTO task_scope(task_id, kind, domain) VALUES ($1,'root_domain','tmdl-e2e.example')`, task.ID); err != nil {
		t.Fatal(err)
	}

	store := d.Exploration(task.ExplorationID)
	planner := NewToolSet(store, "planner")
	planner.SetTaskID(task.ID)
	input := json.RawMessage(`{"summary":"e2e model","model":{"group_key":"tmdl-e2e.example","roles":{"user":"normal user","admin":"privileged"}},"asset_ids":[` + fmt.Sprintf("%d", assetID) + `]}`)
	if res, err := planner.writeTargetModel().Call(context.Background(), input, nil); err != nil || res.IsError {
		t.Fatalf("write failed: err=%v res=%q", err, res.Flatten())
	}
	active, err := store.ListActiveTargetModels(10)
	if err != nil || len(active) != 1 {
		t.Fatalf("active models after v1 = %d err=%v", len(active), err)
	}
	v1ID := active[0].ID
	input2 := json.RawMessage(`{"summary":"e2e model v2","model":{"group_key":"tmdl-e2e.example","roles":{"user":"normal user","admin":"privileged"}},"asset_ids":[` + fmt.Sprintf("%d", assetID) + `]}`)
	if res, err := planner.writeTargetModel().Call(context.Background(), input2, nil); err != nil || res.IsError {
		t.Fatalf("second write failed: err=%v res=%q", err, res.Flatten())
	}

	overview := planner.graphOverviewData()
	items, ok := overview["target_models"].([]map[string]any)
	if !ok || len(items) != 1 {
		t.Fatalf("overview slot = %#v", overview["target_models"])
	}
	if items[0]["group_key"] != "tmdl-e2e.example" {
		t.Fatalf("overview group_key = %v", items[0]["group_key"])
	}
	if items[0]["roles_count"] != 2 {
		t.Fatalf("object roles_count = %v, want 2", items[0]["roles_count"])
	}
	if got, ok := items[0]["supersedes"].(float64); !ok || int64(got) != v1ID {
		t.Fatalf("overview supersedes = %#v, want %d", items[0]["supersedes"], v1ID)
	}

	worker := NewToolSet(store, "worker-1")
	worker.SetTaskID(task.ID)
	ctx := worker.targetModelContextForAssets([]int64{assetID})
	if !strings.Contains(ctx, "tmdl-e2e.example") {
		t.Fatalf("worker context missing model: %q", ctx)
	}
	if !strings.Contains(ctx, "node_detail(id)") {
		t.Fatalf("worker context must point at node_detail: %q", ctx)
	}
	if !strings.Contains(ctx, fmt.Sprintf(`"supersedes":%d`, v1ID)) {
		t.Fatalf("worker context missing supersedes pointer: %q", ctx)
	}
	if strings.Contains(ctx, `"roles"`) || strings.Contains(ctx, `"user"`) {
		t.Fatalf("full model payload leaked into system context: %q", ctx)
	}
	if ctx := worker.targetModelContextForAssets([]int64{assetID + 999999}); strings.Contains(ctx, "tmdl-e2e.example") {
		t.Fatalf("worker context leaked model to unrelated asset: %q", ctx)
	}
}
