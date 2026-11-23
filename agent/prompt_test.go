package agent

import (
	"strings"
	"testing"
)

// The built-in planner/worker bodies are embedded from prompts/*.md; they must
// load, render {{.Goal}}, and keep the operator safety sections.
func TestBuiltinPromptsEmbedAndRender(t *testing.T) {
	prev := PromptOverride
	PromptOverride = nil
	t.Cleanup(func() { PromptOverride = prev })

	seeds := BuiltinPromptSeeds()
	planner := seeds["planner"]
	if !strings.Contains(planner, "任务即授权") || !strings.Contains(planner, "目标模型（target_models）") {
		t.Fatalf("planner seed missing operator sections")
	}
	if !strings.Contains(planner, "只有目标模型发生材料性变化时才写新版本") || !strings.Contains(planner, "心跳") {
		t.Fatalf("planner seed missing target-model write gating")
	}
	rendered := renderSystem("planner", planner, PlannerVars{Goal: "TARGET-X"})
	if !strings.Contains(rendered, "TARGET-X") || strings.Contains(rendered, "{{") {
		t.Fatalf("planner seed did not render cleanly")
	}

	worker := seeds["worker"]
	if !strings.Contains(worker, "总则") || !strings.Contains(worker, "目标模型是背景") {
		t.Fatalf("worker seed missing operator sections")
	}
	rendered = renderSystem("worker", worker, WorkerVars{})
	if strings.Contains(rendered, "{{") {
		t.Fatalf("worker seed did not render cleanly")
	}
}

func TestReporterPromptEmbedded(t *testing.T) {
	p := ReporterDefaultPrompt
	for _, want := range []string{"## 1、漏洞详情", "## 2、漏洞证明", "## 3、修复方案", "update_finding_report", "get_finding_traffic", "evidence_version", "<上一步获取的id>", "不要强制附 curl", "整段复制即可执行"} {
		if !strings.Contains(p, want) {
			t.Fatalf("reporter prompt missing %q", want)
		}
	}
	if strings.Contains(p, "{{") {
		t.Fatalf("reporter prompt must not contain Go-template placeholders")
	}
	for _, bad := range []string{"### 2.1", "### 2.2", "### 2.3"} {
		if strings.Contains(p, bad) {
			t.Fatalf("reporter prompt must keep section 2 as one block, found %q", bad)
		}
	}
}

func TestRenderSystemOverrideAndFallback(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })

	// no override → built-in default
	PromptOverride = nil
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "g"}); got != "DEFAULT" {
		t.Fatalf("no override should give default, got %q", got)
	}

	// override → rendered with vars
	PromptOverride = func(k string) (string, bool) {
		if k == "planner" {
			return "目标:{{.Goal}} 范围:{{.Scope}}", true
		}
		return "", false
	}
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "拿下X", Scope: "*.x.com"}); got != "目标:拿下X 范围:*.x.com" {
		t.Fatalf("override render: %q", got)
	}

	// override referencing a non-catalog var → execution error → fallback to default
	PromptOverride = func(k string) (string, bool) { return "{{.NotInCatalog}}", true }
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "x"}); got != "DEFAULT" {
		t.Fatalf("bad var should fall back to default, got %q", got)
	}

	// full plannerSystem path: DB body [A] is honored, then the code-owned tail
	// [C] (中间产物输出规约) is ALWAYS appended — editing the body can't drop it.
	PromptOverride = func(k string) (string, bool) { return "PLANNER {{.Goal}}", true }
	got := plannerSystem("拿下X", "/data", "/data")
	if !strings.HasPrefix(got, "PLANNER 拿下X") {
		t.Fatalf("plannerSystem body not honored: %q", got)
	}
	if !strings.Contains(got, "中间产物输出规约") || !strings.Contains(got, "/data") {
		t.Fatalf("plannerSystem missing code-owned artifact tail: %q", got)
	}

	// worker dual-text via {{if .ProxyAddr}} in a user template, plus the code tail:
	// [B] trafficTool present only when RECORDING (caCert set — the MITM is on, so
	// the traffic_* tools exist), [C] artifact spec always present. The trafficTool
	// block is gated on the CA (arg 2), NOT on ProxyAddr — a global egress proxy
	// with capture off routes traffic but records nothing.
	PromptOverride = func(k string) (string, bool) {
		return "{{if .ProxyAddr}}走代理 {{.ProxyAddr}}{{else}}手动{{end}}", true
	}
	recording := workerSystem("127.0.0.1:8080", "/ca.pem", "/data", "/data")
	if !strings.HasPrefix(recording, "走代理 127.0.0.1:8080") {
		t.Fatalf("worker proxy branch body: %q", recording)
	}
	if !strings.Contains(recording, "traffic_search") {
		t.Fatalf("worker while recording should inject trafficTool: %q", recording)
	}
	if strings.Contains(recording, "traffic_refs") {
		t.Fatalf("worker bypassed shared optional evidence policy: %q", recording)
	}
	if !strings.Contains(recording, "中间产物输出规约") {
		t.Fatalf("worker missing artifact tail: %q", recording)
	}
	// Egress proxy set but capture OFF (no CA): the ProxyAddr template branch still
	// renders, but the trafficTool block must NOT — those tools are not registered.
	egressOnly := workerSystem("127.0.0.1:8080", "", "/data", "/data")
	if !strings.HasPrefix(egressOnly, "走代理 127.0.0.1:8080") {
		t.Fatalf("worker egress-only branch body: %q", egressOnly)
	}
	if strings.Contains(egressOnly, "traffic_search") {
		t.Fatalf("worker without recording must NOT inject trafficTool: %q", egressOnly)
	}
	noProxy := workerSystem("", "", "/data", "/data")
	if !strings.HasPrefix(noProxy, "手动") {
		t.Fatalf("worker no-proxy branch body: %q", noProxy)
	}
	if strings.Contains(noProxy, "traffic_search") {
		t.Fatalf("worker without proxy must NOT inject trafficTool: %q", noProxy)
	}
}
