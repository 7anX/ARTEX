package db

import (
	"context"
	"encoding/json"
	"reflect"
	"sync"
	"testing"
)

func TestTargetModelVersioningAndSupersede(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("target-model-test", "业务逻辑测试")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) // cascades nodes/edges/anchors
	es := d.Exploration(expID)

	// Anchors reference the global assets table; create throwaway assets.
	var a1, a2, a3 int64
	if err := d.QueryRow(`INSERT INTO assets(type, domain) VALUES ('root_domain','tmdl-one.example') RETURNING id`).Scan(&a1); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`INSERT INTO assets(type, domain) VALUES ('root_domain','tmdl-two.example') RETURNING id`).Scan(&a2); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`INSERT INTO assets(type, domain) VALUES ('root_domain','tmdl-three.example') RETURNING id`).Scan(&a3); err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM assets WHERE id IN ($1,$2,$3)`, a1, a2, a3)

	// Evidence must be a fact of this exploration.
	factID, err := es.AddNode(KindFact, map[string]any{"summary": "observed login flow"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mk := func(group string, assets []int64, evidence []int64) (*TargetModelWriteResult, error) {
		return es.AddTargetModel(ctx, TargetModelInput{
			Payload: map[string]any{
				"summary": "model " + group,
				"model": map[string]any{
					"group_key": group,
					"roles":     []any{"user", "admin"},
					"unknowns":  []any{"audit flow"},
				},
			},
			AssetIDs:    assets,
			EvidenceIDs: evidence,
			Origin:      "planner",
		})
	}

	v1, err := mk("app.example.com", []int64{a1, a2}, []int64{factID})
	if err != nil {
		t.Fatal(err)
	}
	if v1.Version != 1 || len(v1.SupersededIDs) != 0 {
		t.Fatalf("v1 = %+v", v1)
	}
	v2, err := mk("app.example.com", []int64{a1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v2.Version != 2 {
		t.Fatalf("v2 version = %d, want 2", v2.Version)
	}
	if len(v2.SupersededIDs) != 1 || v2.SupersededIDs[0] != v1.NodeID {
		t.Fatalf("v2 superseded = %v, want [%d]", v2.SupersededIDs, v1.NodeID)
	}
	old, err := es.GetNode(v1.NodeID)
	if err != nil || old == nil || old.State != StateTargetModelSuperseded {
		t.Fatalf("v1 state = %+v err=%v, want superseded", old, err)
	}
	var p1 map[string]any
	if err := json.Unmarshal(old.Payload, &p1); err != nil {
		t.Fatal(err)
	}
	ids1, _ := p1["evidence_ids"].([]any)
	if len(ids1) != 1 || int64(ids1[0].(float64)) != factID {
		t.Fatalf("v1 payload evidence_ids = %#v, want [%d]", p1["evidence_ids"], factID)
	}
	m1, _ := p1["model"].(map[string]any)
	if _, ok := m1["supersedes"]; ok {
		t.Fatalf("v1 must not carry supersedes: %#v", m1["supersedes"])
	}
	// A revision without evidence keeps an explicit empty list, so consumers
	// never have to distinguish "none" from "field missing".
	v2node, err := es.GetNode(v2.NodeID)
	if err != nil || v2node == nil {
		t.Fatalf("v2 node = %+v err=%v", v2node, err)
	}
	var p2 map[string]any
	if err := json.Unmarshal(v2node.Payload, &p2); err != nil {
		t.Fatal(err)
	}
	if ids2, ok := p2["evidence_ids"].([]any); !ok || len(ids2) != 0 {
		t.Fatalf("v2 payload evidence_ids = %#v, want []", p2["evidence_ids"])
	}
	m2, _ := p2["model"].(map[string]any)
	if got, ok := m2["supersedes"].(float64); !ok || int64(got) != v1.NodeID {
		t.Fatalf("v2 supersedes = %#v, want %d", m2["supersedes"], v1.NodeID)
	}
	if got, ok := m2["supersedes_version"].(float64); !ok || int(got) != 1 {
		t.Fatalf("v2 supersedes_version = %#v, want 1", m2["supersedes_version"])
	}
	// A different group must not supersede the first group's active version.
	v3, err := mk("api.example.com", []int64{a3}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v3.Version != 1 || len(v3.SupersededIDs) != 0 {
		t.Fatalf("v3 = %+v", v3)
	}

	active, err := es.ListActiveTargetModels(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 {
		t.Fatalf("active models = %d, want 2 (one per group)", len(active))
	}
	seen := map[string]int64{}
	anchors, err := es.NodeAssets([]int64{v1.NodeID, v2.NodeID})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range active {
		var p map[string]any
		if err := json.Unmarshal(n.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if m, ok := p["model"].(map[string]any); ok {
			if g, ok := m["group_key"].(string); ok {
				seen[g] = n.ID
			}
		}
	}
	if seen["app.example.com"] != v2.NodeID {
		t.Fatalf("app group active = %d, want v2 %d", seen["app.example.com"], v2.NodeID)
	}
	if got := anchors[v1.NodeID]; len(got) != 2 {
		t.Fatalf("v1 anchors = %v, want two", got)
	}
}

func TestTargetModelRejectsForeignEvidence(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("target-model-evidence", "证据校验")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	intentID, err := es.AddIntent(map[string]any{"summary": "x"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets(type, domain) VALUES ('root_domain','tmdl-evidence.example') RETURNING id`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM assets WHERE id=$1`, assetID)
	_, err = es.AddTargetModel(context.Background(), TargetModelInput{
		Payload:     map[string]any{"summary": "m", "model": map[string]any{"group_key": "g"}},
		AssetIDs:    []int64{assetID},
		EvidenceIDs: []int64{intentID}, // intent is not fact/finding
	})
	if err == nil {
		t.Fatal("expected rejection of intent as evidence")
	}
}

// Concurrent writers on the same group must serialize on the exploration row:
// versions are unique and contiguous, and exactly one version stays active.
func TestTargetModelConcurrentVersioning(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("target-model-concurrent", "并发版本")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets(type, domain) VALUES ('root_domain','tmdl-concurrent.example') RETURNING id`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM assets WHERE id=$1`, assetID)

	const writers = 8
	versions := make(chan int, writers)
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := es.AddTargetModel(context.Background(), TargetModelInput{
				Payload:  map[string]any{"summary": "concurrent", "model": map[string]any{"group_key": "cg"}},
				AssetIDs: []int64{assetID},
			})
			if err != nil {
				errs <- err
				return
			}
			versions <- res.Version
		}()
	}
	wg.Wait()
	close(versions)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent write failed: %v", err)
	}
	seen := map[int]bool{}
	for v := range versions {
		if seen[v] {
			t.Fatalf("duplicate version %d", v)
		}
		seen[v] = true
	}
	for v := 1; v <= writers; v++ {
		if !seen[v] {
			t.Fatalf("missing version %d (got %v)", v, seen)
		}
	}
	active, err := es.ListActiveTargetModels(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 {
		t.Fatalf("active versions = %d, want 1", len(active))
	}
}

// Cancelling an intent cascades through exclusive derived_from descendants; a
// target model that cites a cancelled intent's fact must survive (it is a
// permanent task-level slot, not intent output).
func TestTargetModelSurvivesIntentCancel(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("target-model-cancel", "取消意图")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets(type, domain) VALUES ('root_domain','tmdl-cancel.example') RETURNING id`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM assets WHERE id=$1`, assetID)

	intentID, err := es.AddIntent(map[string]any{"summary": "probe"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	factID, err := es.AddNode(KindFact, map[string]any{"summary": "observed"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := es.Link(intentID, RelYields, factID); err != nil {
		t.Fatal(err)
	}
	res, err := es.AddTargetModel(context.Background(), TargetModelInput{
		Payload:     map[string]any{"summary": "m", "model": map[string]any{"group_key": "cg"}},
		AssetIDs:    []int64{assetID},
		EvidenceIDs: []int64{factID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := es.CancelIntent(intentID); err != nil {
		t.Fatal(err)
	}
	node, err := es.GetNode(res.NodeID)
	if err != nil || node == nil {
		t.Fatalf("target model deleted with cancelled intent: node=%v err=%v", node, err)
	}
	if node.State != StateTargetModelActive {
		t.Fatalf("state = %q, want active", node.State)
	}
	// The live derived_from edge cascades with the deleted fact; the payload
	// copy is what keeps the provenance auditable after the hard delete.
	var p map[string]any
	if err := json.Unmarshal(node.Payload, &p); err != nil {
		t.Fatal(err)
	}
	ids, _ := p["evidence_ids"].([]any)
	if len(ids) != 1 || int64(ids[0].(float64)) != factID {
		t.Fatalf("payload evidence_ids = %#v, want [%d]", p["evidence_ids"], factID)
	}
	var edgeCount int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_edges
		WHERE exploration_id=$1 AND src_id=$2 AND rel=$3 AND dst_id=$4`,
		expID, factID, RelDerivedFrom, res.NodeID).Scan(&edgeCount); err != nil {
		t.Fatal(err)
	}
	if edgeCount != 0 {
		t.Fatalf("derived_from edge survived the hard delete (count=%d)", edgeCount)
	}
}

// Scope-only assets (task_scope membership, no per-asset link) must be accepted:
// UI/agent scope edits write task_scope without touching assets.task_ids.
func TestTargetModelAssetScopeAndOwnership(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	task, err := d.CreateTaskWithOptions("tmdl-scope", "scope check", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID) // cascades the exploration
	es := d.Exploration(task.ExplorationID)

	var inScope, outOfScope int64
	if err := d.QueryRow(`INSERT INTO assets(type, domain, root_domain) VALUES ('root_domain','tmdl-in-scope.example','tmdl-in-scope.example') RETURNING id`).Scan(&inScope); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`INSERT INTO assets(type, domain) VALUES ('root_domain','tmdl-out-scope.example') RETURNING id`).Scan(&outOfScope); err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM assets WHERE id IN ($1,$2)`, inScope, outOfScope)
	if _, err := d.Exec(`INSERT INTO task_scope(task_id, kind, domain) VALUES ($1,'root_domain','tmdl-in-scope.example')`, task.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := es.AddTargetModel(context.Background(), TargetModelInput{
		Payload:  map[string]any{"summary": "m", "model": map[string]any{"group_key": "g"}},
		TaskID:   task.ID,
		AssetIDs: []int64{inScope},
	}); err != nil {
		t.Fatalf("scope-only asset rejected: %v", err)
	}
	if _, err := es.AddTargetModel(context.Background(), TargetModelInput{
		Payload:  map[string]any{"summary": "m2", "model": map[string]any{"group_key": "g2"}},
		TaskID:   task.ID,
		AssetIDs: []int64{outOfScope},
	}); err == nil {
		t.Fatal("out-of-scope asset accepted")
	}
}

// A failed evidence check must roll back the node, anchors and edges.
func TestTargetModelRollbackOnInvalidEvidence(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("target-model-rollback", "rollback")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets(type, domain) VALUES ('root_domain','tmdl-rollback.example') RETURNING id`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM assets WHERE id=$1`, assetID)
	intentID, err := es.AddIntent(map[string]any{"summary": "not evidence"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := es.AddTargetModel(context.Background(), TargetModelInput{
		Payload:     map[string]any{"summary": "m", "model": map[string]any{"group_key": "g"}},
		AssetIDs:    []int64{assetID},
		EvidenceIDs: []int64{intentID},
	}); err == nil {
		t.Fatal("expected rejection")
	}
	var nodes, anchors, edges int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1 AND kind='target_model'`, expID).Scan(&nodes); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM exploration_anchors ea JOIN exploration_nodes n ON n.id=ea.node_id WHERE n.exploration_id=$1 AND n.kind='target_model'`, expID).Scan(&anchors); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM exploration_edges e JOIN exploration_nodes n ON n.id=e.dst_id WHERE e.exploration_id=$1 AND n.kind='target_model'`, expID).Scan(&edges); err != nil {
		t.Fatal(err)
	}
	if nodes != 0 || anchors != 0 || edges != 0 {
		t.Fatalf("torn write: nodes=%d anchors=%d edges=%d", nodes, anchors, edges)
	}
}

// Simulate an install whose constraints predate target_model, then verify the
// startup schema replay widens them (the DO-block migration branch).
func TestSchemaUpgradeAddsTargetModelConstraint(t *testing.T) {
	dsn := testDSN(t)
	d, err := Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	expID, err := d.CreateExploration("target-model-migrate", "migration")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := d.Exec(`ALTER TABLE exploration_nodes DROP CONSTRAINT ck_node_kind`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`ALTER TABLE exploration_nodes ADD CONSTRAINT ck_node_kind CHECK (kind IN ('begin','goal','intent','fact','finding','hint','digest'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`ALTER TABLE exploration_nodes DROP CONSTRAINT ck_node_state`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`ALTER TABLE exploration_nodes ADD CONSTRAINT ck_node_state CHECK (
        (kind='begin' AND state IN ('open')) OR
        (kind='intent' AND state IN ('open','running','paused','done','blocked','exhausted','stopped','deleted')) OR
        (kind='goal' AND state IN ('open','met','abandoned')) OR
        (kind='fact' AND state IN ('confirmed','dismissed','origin')) OR
        (kind='finding' AND state IN ('confirmed','dismissed')) OR
        (kind='hint' AND state IN ('active','consumed')) OR
        (kind='digest' AND state IN ('active','superseded')))`); err != nil {
		t.Fatal(err)
	}
	d.Close()

	d2, err := Open(dsn) // replay schema.sql → DO blocks must widen both constraints
	if err != nil {
		t.Fatalf("schema replay failed: %v", err)
	}
	defer d2.Close()
	defer func() { _, _ = d2.Exec(`DELETE FROM explorations WHERE id=$1`, expID) }()
	es := d2.Exploration(expID)
	id, err := es.AddNode(KindTargetModel, map[string]any{"summary": "m"}, 8, StateTargetModelActive, "planner", nil)
	if err != nil {
		t.Fatalf("target_model insert rejected after upgrade: %v", err)
	}
	if err := es.SetNodeState(id, StateTargetModelSuperseded); err != nil {
		t.Fatalf("superseded state rejected after upgrade: %v", err)
	}
}

// Pre-fix target_model rows have no payload.evidence_ids and no version
// lineage. Replaying schema.sql must backfill evidence_ids from the live
// derived_from edges and supersedes from the previous version, so a later hard
// delete or a "same as previous" detail remains resolvable.
func TestSchemaBackfillsTargetModelEvidence(t *testing.T) {
	dsn := testDSN(t)
	d, err := Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	expID, err := d.CreateExploration("target-model-backfill", "backfill")
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	es := d.Exploration(expID)
	factID, err := es.AddNode(KindFact, map[string]any{"summary": "observed"}, 5, "confirmed", "worker", nil)
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	modelID, err := es.AddNode(KindTargetModel, map[string]any{
		"summary": "legacy model",
		"model":   map[string]any{"group_key": "legacy.example", "version": 1},
	}, 8, StateTargetModelActive, "planner", nil)
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	model2ID, err := es.AddNode(KindTargetModel, map[string]any{
		"summary": "legacy model v2",
		"model":   map[string]any{"group_key": "legacy.example", "version": 2},
	}, 8, StateTargetModelActive, "planner", nil)
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	if err := es.Link(factID, RelDerivedFrom, modelID); err != nil {
		d.Close()
		t.Fatal(err)
	}
	d.Close()

	d2, err := Open(dsn) // replay schema.sql → evidence_ids + supersedes backfill
	if err != nil {
		t.Fatalf("schema replay failed: %v", err)
	}
	defer d2.Close()
	defer func() { _, _ = d2.Exec(`DELETE FROM explorations WHERE id=$1`, expID) }()

	node, err := d2.Exploration(expID).GetNode(modelID)
	if err != nil || node == nil {
		t.Fatalf("legacy model = %+v err=%v", node, err)
	}
	var p map[string]any
	if err := json.Unmarshal(node.Payload, &p); err != nil {
		t.Fatal(err)
	}
	ids, _ := p["evidence_ids"].([]any)
	if len(ids) != 1 || int64(ids[0].(float64)) != factID {
		t.Fatalf("backfilled evidence_ids = %#v, want [%d]", p["evidence_ids"], factID)
	}

	node2, err := d2.Exploration(expID).GetNode(model2ID)
	if err != nil || node2 == nil {
		t.Fatalf("legacy model v2 = %+v err=%v", node2, err)
	}
	var p2 map[string]any
	if err := json.Unmarshal(node2.Payload, &p2); err != nil {
		t.Fatal(err)
	}
	m2, _ := p2["model"].(map[string]any)
	if got, ok := m2["supersedes"].(float64); !ok || int64(got) != modelID {
		t.Fatalf("backfilled supersedes = %#v, want %d", m2["supersedes"], modelID)
	}
	if got, ok := m2["supersedes_version"].(float64); !ok || int(got) != 1 {
		t.Fatalf("backfilled supersedes_version = %#v, want 1", m2["supersedes_version"])
	}
}

// Explicit association (assets.task_ids / task_asset_links) without task_scope
// must also pass the ownership gate.
func TestTargetModelLinkedAssetAccepted(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	task, err := d.CreateTaskWithOptions("tmdl-linked", "linked", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	es := d.Exploration(task.ExplorationID)

	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets(type, domain, task_ids) VALUES ('root_domain','tmdl-linked.example', ARRAY[$1]::bigint[]) RETURNING id`, task.ID).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM assets WHERE id=$1`, assetID)

	if _, err := es.AddTargetModel(context.Background(), TargetModelInput{
		Payload:  map[string]any{"summary": "m", "model": map[string]any{"group_key": "g"}},
		TaskID:   task.ID,
		AssetIDs: []int64{assetID},
	}); err != nil {
		t.Fatalf("linked asset rejected: %v", err)
	}
}

// Evidence must belong to the same exploration.
func TestTargetModelRejectsCrossExplorationEvidence(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expA, err := d.CreateExploration("tmdl-ev-a", "a")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expA)
	expB, err := d.CreateExploration("tmdl-ev-b", "b")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expB)
	esA := d.Exploration(expA)
	esB := d.Exploration(expB)

	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets(type, domain) VALUES ('root_domain','tmdl-cross.example') RETURNING id`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM assets WHERE id=$1`, assetID)
	foreignFact, err := esB.AddNode(KindFact, map[string]any{"summary": "foreign"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := esA.AddTargetModel(context.Background(), TargetModelInput{
		Payload:     map[string]any{"summary": "m", "model": map[string]any{"group_key": "g"}},
		AssetIDs:    []int64{assetID},
		EvidenceIDs: []int64{foreignFact},
	}); err == nil {
		t.Fatal("cross-exploration evidence accepted")
	}
}

// A compact revision (structured fields omitted) must leave the active model as
// a complete snapshot: the server inherits omitted fields from the previous
// active revision, following its supersedes chain for legacy compact rows, while
// an explicit [] / {} still clears.
func TestTargetModelRevisionMaterializesFields(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("target-model-materialize", "模型物化")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets(type, domain) VALUES ('root_domain','tmdl-materialize.example') RETURNING id`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM assets WHERE id=$1`, assetID)

	ctx := context.Background()
	write := func(group, summary string, model map[string]any) *TargetModelWriteResult {
		model["group_key"] = group
		res, err := es.AddTargetModel(ctx, TargetModelInput{
			Payload:  map[string]any{"summary": summary, "model": model},
			AssetIDs: []int64{assetID},
		})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	readModel := func(nodeID int64) map[string]any {
		n, err := es.GetNode(nodeID)
		if err != nil || n == nil {
			t.Fatalf("node %d = %+v err=%v", nodeID, n, err)
		}
		var p map[string]any
		if err := json.Unmarshal(n.Payload, &p); err != nil {
			t.Fatal(err)
		}
		m, _ := p["model"].(map[string]any)
		return m
	}

	roles := []any{"user", "admin"}
	objects := map[string]any{"account": "用户账户"}
	flows := []any{"login"}
	trust := []any{"gateway"}
	assumptions := []any{"session is bound"}
	invariants := []any{"tenant isolation"}
	v1 := write("mat.example.com", "v1", map[string]any{
		"roles": roles, "objects": objects, "flows": flows,
		"trust_boundaries": trust, "assumptions": assumptions, "invariants": invariants,
		"unknowns": []any{"audit"},
	})
	_ = v1
	v2 := write("mat.example.com", "v2 compact", map[string]any{"unknowns": []any{"audit", "export"}})
	m2 := readModel(v2.NodeID)
	wantInherited := map[string]any{
		"roles": roles, "objects": objects, "flows": flows,
		"trust_boundaries": trust, "assumptions": assumptions, "invariants": invariants,
	}
	for key, want := range wantInherited {
		if !reflect.DeepEqual(m2[key], want) {
			t.Fatalf("%s not inherited: %#v", key, m2[key])
		}
	}
	if !reflect.DeepEqual(m2["unknowns"], []any{"audit", "export"}) {
		t.Fatalf("new unknowns lost: %#v", m2["unknowns"])
	}

	v3 := write("mat.example.com", "v3 clears roles", map[string]any{"roles": []any{}, "unknowns": []any{"audit"}})
	m3 := readModel(v3.NodeID)
	if !reflect.DeepEqual(m3["roles"], []any{}) {
		t.Fatalf("explicit empty roles must stay empty: %#v", m3["roles"])
	}
	if !reflect.DeepEqual(m3["objects"], objects) {
		t.Fatalf("omitted objects not inherited: %#v", m3["objects"])
	}

	// Legacy compact active row: it only has unknowns + supersedes v1. A new
	// revision that omits roles must resolve through this row to v1.
	v1b := write("chain.example.com", "chain v1", map[string]any{"roles": []any{"viewer"}, "unknowns": []any{}})
	compact := map[string]any{"summary": "legacy compact", "model": map[string]any{
		"group_key": "chain.example.com", "version": 2, "status": "active",
		"unknowns": []any{"legacy"}, "supersedes": v1b.NodeID, "supersedes_version": 1,
	}}
	raw, err := json.Marshal(compact)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin)
VALUES ($1,'target_model',$2,8,'active','planner') RETURNING id`, expID, string(raw)).Scan(new(int64)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE exploration_nodes
SET state='superseded', payload=jsonb_set(payload,'{model,status}','"superseded"')
WHERE id=$1`, v1b.NodeID); err != nil {
		t.Fatal(err)
	}
	v3b := write("chain.example.com", "chain v3", map[string]any{"unknowns": []any{"legacy", "next"}})
	m3b := readModel(v3b.NodeID)
	if !reflect.DeepEqual(m3b["roles"], []any{"viewer"}) {
		t.Fatalf("roles not resolved through compact chain: %#v", m3b["roles"])
	}
}

// The graph projection drops superseded target-model revisions in SQL and only
// returns edges whose endpoints survived; full history remains available via
// Nodes/播报板.
func TestNodesCurrentExcludesSupersededTargetModels(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("target-model-graph", "图投影")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets(type, domain) VALUES ('root_domain','tmdl-graph.example') RETURNING id`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM assets WHERE id=$1`, assetID)

	factID, err := es.AddNode(KindFact, map[string]any{"summary": "observed"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mk := func(summary string) *TargetModelWriteResult {
		res, err := es.AddTargetModel(ctx, TargetModelInput{
			Payload:     map[string]any{"summary": summary, "model": map[string]any{"group_key": "graph.example.com"}},
			AssetIDs:    []int64{assetID},
			EvidenceIDs: []int64{factID},
		})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	v1 := mk("v1")
	v2 := mk("v2")

	all, err := es.Nodes(2000)
	if err != nil {
		t.Fatal(err)
	}
	allIDs := map[int64]bool{}
	for _, n := range all {
		allIDs[n.ID] = true
	}
	if !allIDs[v1.NodeID] || !allIDs[v2.NodeID] {
		t.Fatal("full history must keep both versions")
	}

	current, err := es.NodesCurrent(2000)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]int64, 0, len(current))
	cur := map[int64]bool{}
	for _, n := range current {
		ids = append(ids, n.ID)
		cur[n.ID] = true
	}
	if cur[v1.NodeID] {
		t.Fatal("superseded model leaked into current graph")
	}
	if !cur[v2.NodeID] || !cur[factID] {
		t.Fatal("active model or fact missing from current graph")
	}

	edges, err := es.EdgesAmong(ids, 5000)
	if err != nil {
		t.Fatal(err)
	}
	toActive := false
	for _, e := range edges {
		if e.From == v1.NodeID || e.To == v1.NodeID {
			t.Fatalf("edge to superseded model returned: %+v", e)
		}
		if e.From == factID && e.To == v2.NodeID && e.Rel == RelDerivedFrom {
			toActive = true
		}
	}
	if !toActive {
		t.Fatal("edge fact->active model missing")
	}
	lineage, err := es.EdgesForLineage(5000)
	if err != nil {
		t.Fatal(err)
	}
	if len(lineage) != 0 {
		t.Fatalf("lineage returned target-model edges: %+v", lineage)
	}
}
