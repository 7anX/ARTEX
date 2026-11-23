package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// TargetModelInput is the storage-level contract for a task-local target model.
// Asset scope is represented by exploration_anchors; payload must not embed asset ids.
// EvidenceIDs are used for derived_from edges and are also frozen into
// payload.evidence_ids, because edges cascade when an evidence node is deleted
// while the model node itself is protected.
type TargetModelInput struct {
	Payload     map[string]any
	TaskID      int64
	AssetIDs    []int64
	EvidenceIDs []int64
	Origin      string
}

// TargetModelWriteResult describes the newly active model and versions it superseded.
type TargetModelWriteResult struct {
	NodeID        int64   `json:"id"`
	GroupKey      string  `json:"group_key"`
	Version       int     `json:"version"`
	SupersededIDs []int64 `json:"superseded_ids,omitempty"`
}

// AddTargetModel writes a target_model node, anchors, evidence edges and
// supersedes prior active versions atomically. The exploration row is locked
// while the per-group version is allocated, avoiding MAX+1 races.
func (s *ExplorationStore) AddTargetModel(ctx context.Context, in TargetModelInput) (*TargetModelWriteResult, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("target_model 需要任务上下文")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	groupKey := targetModelGroupKey(in.Payload)
	if groupKey == "" {
		return nil, fmt.Errorf("target_model.model.group_key 不能为空")
	}
	if len(in.AssetIDs) == 0 {
		return nil, fmt.Errorf("target_model 至少需要一个资产锚点")
	}

	raw, err := json.Marshal(in.Payload)
	if err != nil {
		return nil, fmt.Errorf("target_model payload 无法序列化: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Lock the exploration parent as the per-exploration serialization point.
	var exists int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM explorations WHERE id=$1 FOR UPDATE`, s.expID).Scan(&exists); err != nil {
		return nil, err
	}

	var version int
	if err := tx.QueryRowContext(ctx, `
SELECT COALESCE(MAX((payload->'model'->>'version')::int), 0) + 1
FROM exploration_nodes
WHERE exploration_id=$1 AND kind=$2
  AND payload->'model'->>'group_key'=$3`, s.expID, KindTargetModel, groupKey).Scan(&version); err != nil {
		return nil, err
	}
	model, ok := in.Payload["model"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("target_model.model 必须是对象")
	}
	// Record the version this revision supersedes. A compact revision often
	// says "same as previous" in detail while omitting structured fields, so
	// the pointer is what makes that reference resolvable via node_detail.
	var prevID int64
	var prevVersion int
	var prevPayloadRaw []byte
	err = tx.QueryRowContext(ctx, `
SELECT id, COALESCE((payload->'model'->>'version')::int, 0), payload
FROM exploration_nodes
WHERE exploration_id=$1 AND kind=$2 AND state=$3
  AND payload->'model'->>'group_key'=$4
ORDER BY (payload->'model'->>'version')::int DESC, id DESC
LIMIT 1`, s.expID, KindTargetModel, StateTargetModelActive, groupKey).Scan(&prevID, &prevVersion, &prevPayloadRaw)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if prevPayloadRaw != nil {
		var prevPayload map[string]any
		if json.Unmarshal(prevPayloadRaw, &prevPayload) == nil {
			if err := materializeTargetModelFields(ctx, tx, s.expID, model, prevPayload); err != nil {
				return nil, err
			}
		}
	}
	delete(model, "supersedes")
	delete(model, "supersedes_version")
	if prevID > 0 {
		model["supersedes"] = prevID
		model["supersedes_version"] = prevVersion
	}
	model["version"] = version
	model["group_key"] = groupKey
	model["status"] = StateTargetModelActive
	in.Payload["model"] = model
	// Freeze the evidence ids in the payload as well as the derived_from edges.
	// Edges are the live graph view and cascade away when an evidence node is
	// hard-deleted with its intent; the payload keeps the provenance immutable.
	in.Payload["evidence_ids"] = uniquePositiveIDs(in.EvidenceIDs)
	raw, err = json.Marshal(in.Payload)
	if err != nil {
		return nil, fmt.Errorf("target_model payload 无法序列化: %w", err)
	}
	// The tool layer checks before version/status/evidence_ids are added; re-check
	// the final stored form so the 16KB contract holds end to end.
	if len(raw) > 16*1024 {
		return nil, fmt.Errorf("target_model payload 超过 16KB")
	}

	var nodeID int64
	origin := in.Origin
	if origin == "" {
		origin = "planner"
	}
	if err := tx.QueryRowContext(ctx, `
INSERT INTO exploration_nodes(exploration_id, kind, payload, priority, state, origin)
VALUES ($1,$2,$3,8,$4,$5) RETURNING id`, s.expID, KindTargetModel, string(raw), StateTargetModelActive, origin).Scan(&nodeID); err != nil {
		return nil, err
	}
	for _, assetID := range uniquePositiveIDs(in.AssetIDs) {
		if in.TaskID > 0 {
			ok, err := targetModelAssetAllowed(ctx, tx, in.TaskID, assetID)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, fmt.Errorf("asset_id %d 不在当前任务授权范围内（未关联该任务，也不在任务/来源任务 scope 中）", assetID)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO exploration_anchors(node_id,asset_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, nodeID, assetID); err != nil {
			return nil, err
		}
	}
	for _, evidenceID := range uniquePositiveIDs(in.EvidenceIDs) {
		var kind string
		if err := tx.QueryRowContext(ctx, `SELECT kind FROM exploration_nodes WHERE id=$1 AND exploration_id=$2`, evidenceID, s.expID).Scan(&kind); err != nil {
			return nil, fmt.Errorf("evidence_id %d 必须是本任务的 fact/finding: %w", evidenceID, err)
		}
		if kind != KindFact && kind != KindFinding {
			return nil, fmt.Errorf("evidence_id %d 是 %q，必须是 fact/finding", evidenceID, kind)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id)
VALUES ($1,$2,$3,$4) ON CONFLICT (exploration_id,src_id,rel,dst_id) DO NOTHING`, s.expID, evidenceID, RelDerivedFrom, nodeID); err != nil {
			return nil, err
		}
	}

	rows, err := tx.QueryContext(ctx, `
SELECT id FROM exploration_nodes
WHERE exploration_id=$1 AND kind=$2 AND state=$3
  AND id<>$4 AND payload->'model'->>'group_key'=$5
ORDER BY id`, s.expID, KindTargetModel, StateTargetModelActive, nodeID, groupKey)
	if err != nil {
		return nil, err
	}
	var superseded []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		superseded = append(superseded, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for _, id := range superseded {
		if _, err := tx.ExecContext(ctx, `
UPDATE exploration_nodes
SET state=$1,
    payload=jsonb_set(payload, '{model,status}', to_jsonb($2::text)),
    updated_at=now(),
    content_version=content_version+1
WHERE id=$3 AND exploration_id=$4`,
			StateTargetModelSuperseded, StateTargetModelSuperseded, id, s.expID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &TargetModelWriteResult{NodeID: nodeID, GroupKey: groupKey, Version: version, SupersededIDs: superseded}, nil
}

// targetModelStructuredFields are the model fields a compact revision may omit.
var targetModelStructuredFields = []string{
	"roles", "objects", "flows", "trust_boundaries",
	"assumptions", "invariants", "unknowns",
}

// materializeTargetModelFields fills fields omitted by a compact revision from
// the previous active revision. Earlier actives may themselves be compact, so it
// follows their supersedes chain until every field is found or the chain ends.
// Explicit JSON null counts as omitted; an explicit [] / {} is an intentional
// clear and is preserved.
func materializeTargetModelFields(ctx context.Context, tx *sql.Tx, expID int64, model map[string]any, prevPayload map[string]any) error {
	missing := make(map[string]struct{}, len(targetModelStructuredFields))
	for _, k := range targetModelStructuredFields {
		if v, ok := model[k]; !ok || v == nil {
			missing[k] = struct{}{}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	payload := prevPayload
	for depth := 0; depth < 128 && len(missing) > 0; depth++ {
		pm, _ := payload["model"].(map[string]any)
		if pm == nil {
			return nil
		}
		for k := range missing {
			if v, ok := pm[k]; ok && v != nil {
				model[k] = v
				delete(missing, k)
			}
		}
		if len(missing) == 0 {
			return nil
		}
		nextID, ok := jsonInt64(pm["supersedes"])
		if !ok || nextID <= 0 {
			return nil
		}
		var raw []byte
		err := tx.QueryRowContext(ctx, `SELECT payload FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind=$3`, nextID, expID, KindTargetModel).Scan(&raw)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		var nextPayload map[string]any
		if json.Unmarshal(raw, &nextPayload) != nil {
			return nil
		}
		payload = nextPayload
	}
	return nil
}

// ListActiveTargetModels returns the newest active target model of each group,
// newest group first. Dedup happens in SQL (DISTINCT ON group_key) so a deep
// history of superseded versions can never push an older group out of the window.
func (s *ExplorationStore) ListActiveTargetModels(limit int) ([]*Node, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.Query(`
SELECT id, kind, payload, priority, state, origin, owner, blocked_reason, delete_reason, created_at
FROM (
  SELECT DISTINCT ON (payload->'model'->>'group_key')
         id, kind, payload, priority, state,
         COALESCE(origin,'')         AS origin,
         COALESCE(owner,'')          AS owner,
         COALESCE(blocked_reason,'') AS blocked_reason,
         COALESCE(delete_reason,'')  AS delete_reason,
         created_at
  FROM exploration_nodes
  WHERE exploration_id=$1 AND kind=$2 AND state=$3
  ORDER BY payload->'model'->>'group_key',
           (payload->'model'->>'version')::int DESC, id DESC
) latest
ORDER BY id DESC LIMIT $4`, s.expID, KindTargetModel, StateTargetModelActive, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

// ListActiveTargetModelsForAssets returns the newest active model per group among
// models anchored to any of assetIDs — filtering happens in SQL so a long tail of
// unrelated groups can never hide the one a worker actually needs.
func (s *ExplorationStore) ListActiveTargetModelsForAssets(assetIDs []int64, limit int) ([]*Node, error) {
	ids := uniquePositiveIDs(assetIDs)
	if len(ids) == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(`
SELECT id, kind, payload, priority, state, origin, owner, blocked_reason, delete_reason, created_at
FROM (
  SELECT DISTINCT ON (payload->'model'->>'group_key')
         id, kind, payload, priority, state,
         COALESCE(origin,'')         AS origin,
         COALESCE(owner,'')          AS owner,
         COALESCE(blocked_reason,'') AS blocked_reason,
         COALESCE(delete_reason,'')  AS delete_reason,
         created_at
  FROM exploration_nodes n
  WHERE n.exploration_id=$1 AND n.kind=$2 AND n.state=$3
    AND EXISTS (SELECT 1 FROM exploration_anchors ea
                WHERE ea.node_id=n.id AND ea.asset_id = ANY($4))
  ORDER BY payload->'model'->>'group_key',
           (payload->'model'->>'version')::int DESC, id DESC
) latest
ORDER BY id DESC LIMIT $5`, s.expID, KindTargetModel, StateTargetModelActive, ids, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

func targetModelGroupKey(payload map[string]any) string {
	model, ok := payload["model"].(map[string]any)
	if !ok {
		return ""
	}
	key, _ := model["group_key"].(string)
	return strings.TrimSpace(key)
}

func uniquePositiveIDs(ids []int64) []int64 {
	seen := make(map[int64]struct{}, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id > 0 {
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				out = append(out, id)
			}
		}
	}
	return out
}

// targetModelAssetAllowed accepts an asset when it belongs to the task either
// through explicit association (assets.task_ids / task_asset_links) or through
// the task's (or a direct source task's) declared scope — the same boundary
// add_intent/list_assets use. Scope-only assets are common: UI/agent scope edits
// write task_scope without touching per-asset associations.
func targetModelAssetAllowed(ctx context.Context, tx *sql.Tx, taskID, assetID int64) (bool, error) {
	var ok bool
	err := tx.QueryRowContext(ctx, `
WITH `+scopeTargetCTE+`,
in_scope AS (SELECT 1 FROM target WHERE id=$2),
linked AS (
  SELECT 1 FROM assets a WHERE a.id=$2 AND $1 = ANY(a.task_ids)
  UNION ALL
  SELECT 1 FROM task_asset_links l WHERE l.task_id=$1 AND l.asset_id=$2
)
SELECT EXISTS(SELECT 1 FROM in_scope) OR EXISTS(SELECT 1 FROM linked)`, taskID, assetID).Scan(&ok)
	return ok, err
}
