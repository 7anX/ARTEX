package agent

import _ "embed"

// The built-in editable prompt bodies live in prompts/*.md so long
// operator-maintained text stays reviewable and can contain backticks.
//
// plannerDefaultTmpl is the built-in editable body (段 [A]) seeded into
// agent_prompts; the artifact-spec tail is code-owned.
//
//go:embed prompts/planner.md
var plannerDefaultTmpl string

// workerDefaultTmpl is the built-in editable body (段 [A]); the traffic-tool
// block and artifact-spec tail are code-owned.
//
//go:embed prompts/worker.md
var workerDefaultTmpl string
