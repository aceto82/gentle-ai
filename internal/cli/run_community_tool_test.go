package cli

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gentleman-programming/gentle-ai/internal/components/communitytool"
	"github.com/gentleman-programming/gentle-ai/internal/model"
	"github.com/gentleman-programming/gentle-ai/internal/planner"
	"github.com/gentleman-programming/gentle-ai/internal/system"
)

func TestInstallRuntimeStagePlanAddsCommunityToolStepsInSelectionOrder(t *testing.T) {
	runtime := &installRuntime{
		homeDir:      t.TempDir(),
		workspaceDir: "/work/project",
		selection: model.Selection{
			CommunityTools: []model.CommunityToolID{model.CommunityToolCodeGraph},
		},
		resolved: planner.ResolvedPlan{},
		profile:  system.PlatformProfile{},
		state:    &runtimeState{},
	}

	plan := runtime.stagePlan()
	var got []string
	for _, step := range plan.Apply {
		got = append(got, step.ID())
	}
	want := []string{"apply:rollback-restore", "community-tool:codegraph"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("apply step IDs = %#v, want %#v", got, want)
	}
}

func TestInstallRuntimeStagePlanDeselectionCleansOwnedPiIntegration(t *testing.T) {
	home := t.TempDir()
	writePiInstallFixture(t, home)
	if _, err := communitytool.ReconcilePiCodeGraph(communitytool.PiCodeGraphOptions{
		HomeDir:  home,
		Selected: true,
		EffectiveMCPProbe: func(string) (communitytool.PiCodeGraphMCPProbeResult, error) {
			return communitytool.PiCodeGraphMCPProbeResult{
				AdapterAvailable: true,
				Initialized:      true,
				Tools: []communitytool.PiCodeGraphMCPTool{{
					Name: "codegraph_explore",
					InputSchema: map[string]any{
						"type": "object",
						"properties": map[string]any{
							"query":       map[string]any{"type": "string"},
							"maxFiles":    map[string]any{"type": "number"},
							"projectPath": map[string]any{"type": "string"},
						},
						"required": []any{"query"},
					},
				}},
			}, nil
		},
	}); err != nil {
		t.Fatal(err)
	}

	runtime := &installRuntime{
		homeDir:      home,
		workspaceDir: filepath.Join(home, "project"),
		selection:    model.Selection{Agents: []model.AgentID{model.AgentPi}},
		resolved:     planner.ResolvedPlan{Agents: []model.AgentID{model.AgentPi}},
		profile:      system.PlatformProfile{},
		state:        &runtimeState{},
	}
	plan := runtime.stagePlan()
	step := plan.Apply[len(plan.Apply)-1]
	if step.ID() != "community-tool:pi-codegraph-deselect" {
		t.Fatalf("last apply step = %q, want Pi deselection cleanup", step.ID())
	}
	if err := step.Run(); err != nil {
		t.Fatalf("deselection pipeline step error = %v", err)
	}
	if runtime.state.piCodeGraph == nil || !runtime.state.piCodeGraph.Changed {
		t.Fatalf("pipeline Pi result = %#v, want reported cleanup", runtime.state.piCodeGraph)
	}
	if _, err := os.Stat(filepath.Join(home, ".gentle-ai", "pi-codegraph.json")); !os.IsNotExist(err) {
		t.Fatalf("manifest remains after pipeline deselection: %v", err)
	}
}

func TestBackupTargetsSnapshotPiManifestOverlayDuringDeselection(t *testing.T) {
	home := t.TempDir()
	overlay := filepath.Join(home, ".pi", "agent", "subagents", "package.md")
	manifest := filepath.Join(home, ".gentle-ai", "pi-codegraph.json")
	writePiInstallFixture(t, home)
	if err := os.MkdirAll(filepath.Dir(manifest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte(`{"children":{"`+overlay+`":{"after":"managed","afterHash":"hash","overlay":true}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	targets := backupTargets(home, "", ScopeGlobal, model.Selection{}, planner.ResolvedPlan{Agents: []model.AgentID{model.AgentPi}})
	if !slices.Contains(targets, manifest) || !slices.Contains(targets, overlay) {
		t.Fatalf("backup targets = %v, want manifest and discovered overlay during deselection", targets)
	}
}

func TestCodeGraphGuidanceMarkdownForSDDOnlyWhenSelectedOrConfigured(t *testing.T) {
	tests := []struct {
		name      string
		setupHome func(t *testing.T, home string)
		lookPath  func(string) (string, error)
		selected  []model.CommunityToolID
		want      bool
	}{
		{
			name:     "CLI missing and no selection",
			lookPath: func(string) (string, error) { return "", errors.New("not found") },
		},
		{
			name:     "CLI available but not configured",
			lookPath: func(string) (string, error) { return "/bin/codegraph", nil },
		},
		{
			name:     "selected CodeGraph",
			lookPath: func(string) (string, error) { return "", errors.New("not found") },
			selected: []model.CommunityToolID{model.CommunityToolCodeGraph},
			want:     true,
		},
		{
			name: "configured guidance marker",
			setupHome: func(t *testing.T, home string) {
				mustWriteFile(t, filepath.Join(home, ".claude", "CLAUDE.md"), []byte(strings.Join([]string{
					"existing Claude guidance",
					"<!-- gentle-ai:codegraph-guidance -->",
					"CodeGraph guidance with `codegraph init <project-root>`",
					"<!-- /gentle-ai:codegraph-guidance -->",
				}, "\n")))
			},
			lookPath: func(string) (string, error) { return "/bin/codegraph", nil },
			want:     true,
		},
		{
			name: "configured MCP marker",
			setupHome: func(t *testing.T, home string) {
				mustWriteFile(t, filepath.Join(home, ".codex", "config.toml"), []byte(strings.Join([]string{
					`[mcp_servers.codegraph]`,
					`command = "codegraph"`,
				}, "\n")))
			},
			lookPath: func(string) (string, error) { return "/bin/codegraph", nil },
			want:     true,
		},
		{
			name: "legacy marker with CLI available",
			setupHome: func(t *testing.T, home string) {
				mustWriteFile(t, filepath.Join(home, ".config", "opencode", "opencode.json"), []byte(`{}`))
				mustWriteFile(t, filepath.Join(home, ".config", "opencode", "AGENTS.md"), []byte(strings.Join([]string{
					"custom notes",
					"<!-- CODEGRAPH_START -->",
					"old CodeGraph instructions",
					"<!-- CODEGRAPH_END -->",
				}, "\n")))
			},
			lookPath: func(string) (string, error) { return "/bin/codegraph", nil },
			want:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			previousLookPath := cmdLookPath
			t.Cleanup(func() { cmdLookPath = previousLookPath })
			cmdLookPath = tc.lookPath

			home := t.TempDir()
			if tc.setupHome != nil {
				tc.setupHome(t, home)
			}

			got := codeGraphGuidanceMarkdownForSDD(home, tc.selected)
			if !tc.want {
				if got != "" {
					t.Fatalf("guidance = %q, want empty", got)
				}
				return
			}
			if !strings.Contains(got, "codegraph init <project-root>") {
				t.Fatalf("CodeGraph guidance missing search-order rule:\n%s", got)
			}
		})
	}
}

func TestComponentApplyStepInjectsCodeGraphGuidanceWhenCodeGraphSelected(t *testing.T) {
	home := t.TempDir()
	withCodeGraphLookPath(t, func(string) (string, error) { return "", errors.New("not found") })

	step := componentApplyStep{
		id:           "apply:sdd",
		component:    model.ComponentSDD,
		homeDir:      home,
		workspaceDir: "/work/project",
		scope:        ScopeGlobal,
		agents:       []model.AgentID{model.AgentOpenCode},
		selection: model.Selection{
			CommunityTools: []model.CommunityToolID{model.CommunityToolCodeGraph},
			SDDMode:        model.SDDModeMulti,
		},
	}
	if err := step.Run(); err != nil {
		t.Fatalf("componentApplyStep.Run() error = %v", err)
	}

	assertOpenCodeSharedPromptCodeGraphGuidance(t, home, true)
}

func TestComponentApplyStepInjectsCodeGraphGuidanceWhenCodeGraphConfigured(t *testing.T) {
	home := t.TempDir()
	withCodeGraphLookPath(t, func(string) (string, error) { return "/bin/codegraph", nil })
	mustWriteFile(t, filepath.Join(home, ".codex", "config.toml"), []byte(strings.Join([]string{
		`[mcp_servers.codegraph]`,
		`command = "codegraph"`,
	}, "\n")))
	mustWriteFile(t, filepath.Join(home, ".codex", "AGENTS.md"), []byte(strings.Join([]string{
		"existing Codex guidance",
		"<!-- gentle-ai:codegraph-guidance -->",
		"CodeGraph guidance with `codegraph init <project-root>`",
		"<!-- /gentle-ai:codegraph-guidance -->",
	}, "\n")))

	step := componentApplyStep{
		id:           "apply:sdd",
		component:    model.ComponentSDD,
		homeDir:      home,
		workspaceDir: "/work/project",
		scope:        ScopeGlobal,
		agents:       []model.AgentID{model.AgentOpenCode},
		selection:    model.Selection{SDDMode: model.SDDModeMulti},
	}
	if err := step.Run(); err != nil {
		t.Fatalf("componentApplyStep.Run() error = %v", err)
	}

	assertOpenCodeSharedPromptCodeGraphGuidance(t, home, true)
}

func TestComponentApplyStepOmitsCodeGraphGuidanceWhenOnlyCLIAvailable(t *testing.T) {
	home := t.TempDir()
	withCodeGraphLookPath(t, func(string) (string, error) { return "/bin/codegraph", nil })

	step := componentApplyStep{
		id:           "apply:sdd",
		component:    model.ComponentSDD,
		homeDir:      home,
		workspaceDir: "/work/project",
		scope:        ScopeGlobal,
		agents:       []model.AgentID{model.AgentOpenCode},
		selection:    model.Selection{SDDMode: model.SDDModeMulti},
	}
	if err := step.Run(); err != nil {
		t.Fatalf("componentApplyStep.Run() error = %v", err)
	}

	assertOpenCodeSharedPromptCodeGraphGuidance(t, home, false)
}

func TestComponentSyncStepInjectsCodeGraphGuidanceFromLegacyMarker(t *testing.T) {
	home := t.TempDir()
	withCodeGraphLookPath(t, func(string) (string, error) { return "/bin/codegraph", nil })
	mustWriteFile(t, filepath.Join(home, ".config", "opencode", "opencode.json"), []byte(`{}`))
	mustWriteFile(t, filepath.Join(home, ".config", "opencode", "AGENTS.md"), []byte(strings.Join([]string{
		"custom notes",
		"<!-- CODEGRAPH_START -->",
		"old CodeGraph instructions",
		"<!-- CODEGRAPH_END -->",
	}, "\n")))

	var changed []string
	step := componentSyncStep{
		id:           "sync:sdd",
		component:    model.ComponentSDD,
		homeDir:      home,
		workspaceDir: "/work/project",
		agents:       []model.AgentID{model.AgentOpenCode},
		selection:    model.Selection{SDDMode: model.SDDModeMulti},
		changedFiles: &changed,
	}
	if err := step.Run(); err != nil {
		t.Fatalf("componentSyncStep.Run() error = %v", err)
	}

	assertOpenCodeSharedPromptCodeGraphGuidance(t, home, true)
}

func TestCommunityToolInstallStepUsesInjectableInstaller(t *testing.T) {
	previousInstall := installCommunityToolWithHome
	previousRunCommand := runCommand
	t.Cleanup(func() {
		installCommunityToolWithHome = previousInstall
		runCommand = previousRunCommand
	})

	runCommand = func(string, ...string) error {
		t.Fatal("communityToolInstallStep should not call real command runner when installer is injected")
		return nil
	}

	var gotTool model.CommunityToolID
	var gotWorkspace string
	var runner communitytool.Runner
	installCommunityToolWithHome = func(tool model.CommunityToolID, workspaceDir string, _ string, r communitytool.Runner, _ communitytool.Detector) (communitytool.Result, error) {
		gotTool = tool
		gotWorkspace = workspaceDir
		runner = r
		return communitytool.Result{Tool: tool}, nil
	}

	step := communityToolInstallStep{id: "community-tool:codegraph", tool: model.CommunityToolCodeGraph, workspaceDir: "/work/project"}
	if err := step.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if gotTool != model.CommunityToolCodeGraph || gotWorkspace != "/work/project" || runner == nil {
		t.Fatalf("installer args = (%q, %q, %#v), want CodeGraph, workspace, runner", gotTool, gotWorkspace, runner)
	}
}

func TestCommunityToolInstallStepPassesRuntimeHomeToPiReconciler(t *testing.T) {
	previous := installCommunityToolWithHome
	t.Cleanup(func() { installCommunityToolWithHome = previous })
	var gotHome string
	installCommunityToolWithHome = func(_ model.CommunityToolID, _ string, home string, _ communitytool.Runner, _ communitytool.Detector) (communitytool.Result, error) {
		gotHome = home
		return communitytool.Result{Tool: model.CommunityToolCodeGraph}, nil
	}
	step := communityToolInstallStep{id: "community-tool:codegraph", tool: model.CommunityToolCodeGraph, workspaceDir: "/work/project", homeDir: "/tmp/pi-home"}
	if err := step.Run(); err != nil {
		t.Fatal(err)
	}
	if gotHome != "/tmp/pi-home" {
		t.Fatalf("home = %q, want runtime home", gotHome)
	}
}

func TestSyncPlanAlwaysIncludesPiCodeGraphReconciliationAfterComponents(t *testing.T) {
	home := t.TempDir()
	runtime, err := newSyncRuntime(home, model.Selection{Agents: []model.AgentID{model.AgentPi}})
	if err != nil {
		t.Fatal(err)
	}
	plan := runtime.stagePlan()
	if len(plan.Apply) == 0 || plan.Apply[len(plan.Apply)-1].ID() != "sync:community-tool:pi-codegraph" {
		t.Fatalf("sync apply steps do not end in Pi reconciliation")
	}
}

func withCodeGraphLookPath(t *testing.T, lookPath func(string) (string, error)) {
	t.Helper()
	previousLookPath := cmdLookPath
	t.Cleanup(func() { cmdLookPath = previousLookPath })
	cmdLookPath = func(name string) (string, error) {
		if name != "codegraph" {
			return "", errors.New("not found")
		}
		return lookPath(name)
	}
}

func assertOpenCodeSharedPromptCodeGraphGuidance(t *testing.T, home string, want bool) {
	t.Helper()
	promptPath := filepath.Join(home, ".config", "opencode", "prompts", "sdd", "sdd-apply.md")
	content, err := os.ReadFile(promptPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", promptPath, err)
	}
	text := string(content)
	hasGuidance := strings.Contains(text, "<!-- gentle-ai:codegraph-guidance -->") && strings.Contains(text, "codegraph init <project-root>")
	if hasGuidance != want {
		t.Fatalf("CodeGraph guidance present = %v, want %v in %s", hasGuidance, want, promptPath)
	}
}

func writePiInstallFixture(t *testing.T, home string) {
	t.Helper()
	mustWriteFile(t, filepath.Join(home, ".pi", "agent", "settings.json"), []byte(`{}`))
	mustWriteFile(t, filepath.Join(home, ".pi", "agent", "subagents", "worker.md"), []byte("---\ntools: bash\n---\nwork\n"))
}
