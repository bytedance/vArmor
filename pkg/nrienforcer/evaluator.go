package nrienforcer

import (
	"context"
	_ "embed"
	"fmt"
	"sync"
	"time"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	"github.com/containerd/nri/pkg/api"
	"github.com/open-policy-agent/opa/rego"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	BuiltinProfileName = "varmor-builtin"
)

// Options defines the options for NRI enforcer.
type Options struct {
	// Timeout specifies the maximum time in millisecond for policy evaluation
	Timeout int
	// AuditViolations determines whether to log the actions that violate the mandatory access control rules.
	AuditViolations bool
	// AllowViolations determines whether to allow the actions that are against mandatory access control rules.
	AllowViolations bool
	// FailurePolicy defines the action to take when the policy evaluation fails or an error occurs.
	// "Audit": log the error and allow the action (default)
	// "Fail": log the error and block the action
	// "Ignore": allow the action and do not log the error
	FailurePolicy string
}

// PolicyMatchInfo stores the matching information for a policy
type PolicyMatchInfo struct {
	Namespace      string
	Target         varmor.Target
	IsClusterScope bool
}

//go:embed policies/builtin.rego
var builtinPolicy string

type Evaluator struct {
	// queries stores the prepared queries for each policy, keyed by profile name
	queries map[string]rego.PreparedEvalQuery
	// options stores the NriOptions for each policy, keyed by profile name
	options map[string]Options
	// matchInfos stores the matching information for each policy, keyed by profile name
	matchInfos map[string]PolicyMatchInfo
	mu         sync.RWMutex
}

// NewEvaluator creates a new OPA evaluator.
func NewEvaluator(ctx context.Context) (*Evaluator, error) {
	e := &Evaluator{
		queries:    make(map[string]rego.PreparedEvalQuery),
		options:    make(map[string]Options),
		matchInfos: make(map[string]PolicyMatchInfo),
	}
	return e, nil
}

// UpdatePolicy updates or adds a policy for a specific profile.
func (e *Evaluator) UpdatePolicy(ctx context.Context, profileName string, builtinRules string, rawRules string, options Options, matchInfo PolicyMatchInfo) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// If both builtin and raw rules are empty, just save the options and match info.
	// However, without a policy query, Evaluate() won't do anything for this profile.
	if builtinRules == "" && rawRules == "" {
		delete(e.queries, profileName)
		e.options[profileName] = options
		e.matchInfos[profileName] = matchInfo
		return nil
	}

	// Create a Rego object.
	// We query the whole package "data.nri.authz" to get all rules (deny, audit_deny, audit_allow).
	// We load builtin.rego, builtin rules (if any), and raw rules (if any) as separate modules.
	var opts []func(*rego.Rego)
	opts = append(opts, rego.Query("data.nri.authz"))
	opts = append(opts, rego.Module("builtin.rego", builtinPolicy))

	if builtinRules != "" {
		opts = append(opts, rego.Module("builtin-user.rego", builtinRules))
	}
	if rawRules != "" {
		opts = append(opts, rego.Module("user.rego", rawRules))
	}

	r := rego.New(opts...)

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("failed to prepare rego query for profile %s: %w", profileName, err)
	}

	e.queries[profileName] = query
	e.options[profileName] = options
	e.matchInfos[profileName] = matchInfo
	return nil
}

// DeletePolicy removes a policy for a specific profile.
func (e *Evaluator) DeletePolicy(profileName string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.queries, profileName)
	delete(e.options, profileName)
	delete(e.matchInfos, profileName)
}

// matchesPolicy checks if a policy matches the given pod based on:
// 1. Namespace match (for non-cluster-scope policies)
// 2. Label selector match (if target.selector is specified)
// Empty target means matches everything
func (e *Evaluator) matchesPolicy(policyNamespace string, target varmor.Target, isClusterScope bool, pod *api.PodSandbox) bool {
	// 1. Check namespace match if not cluster scope
	if !isClusterScope && policyNamespace != "" && pod.Namespace != policyNamespace {
		return false
	}

	// 2. If no selector specified, match all
	if target.Selector == nil {
		return true
	}

	// 3. Convert LabelSelector to Selector
	selector, err := metav1.LabelSelectorAsSelector(target.Selector)
	if err != nil {
		return false
	}

	// 4. Match pod labels
	return selector.Matches(labels.Set(pod.Labels))
}

// EvalResult contains the result of a policy evaluation
type EvalResult struct {
	ProfileName        string
	DenyMessages       []string // Only Block
	AuditDenyMessages  []string // Block + Alert
	AuditAllowMessages []string // Allow + Alert
	Options            Options
	Error              error
}

// Evaluate evaluates the input against all matching policies.
// It first applies VarmorPolicy (namespace-scoped) in matching order, then VarmorClusterPolicy (cluster-scoped).
// It returns a list of evaluation results for each policy that produced violations, audit messages, or errors.
func (e *Evaluator) Evaluate(ctx context.Context, input interface{}, pod *api.PodSandbox) ([]EvalResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var results []EvalResult

	// First pass: collect matching policies and separate by scope
	var varmorPolicyProfiles []string
	var varmorClusterPolicyProfiles []string

	for profileName, matchInfo := range e.matchInfos {
		if e.matchesPolicy(matchInfo.Namespace, matchInfo.Target, matchInfo.IsClusterScope, pod) {
			if matchInfo.IsClusterScope {
				varmorClusterPolicyProfiles = append(varmorClusterPolicyProfiles, profileName)
			} else {
				varmorPolicyProfiles = append(varmorPolicyProfiles, profileName)
			}
		}
	}

	// Evaluate in order: VarmorPolicy first, then VarmorClusterPolicy
	evaluateProfiles := func(profiles []string) {
		for _, profileName := range profiles {
			options := e.options[profileName]
			query, ok := e.queries[profileName]
			if !ok {
				continue
			}

			userRes, err := e.evaluateUserPolicy(ctx, query, options, input)
			if err != nil {
				results = append(results, EvalResult{
					ProfileName: profileName,
					Options:     options,
					Error:       err,
				})
				continue
			}

			if len(userRes.DenyMessages) > 0 || len(userRes.AuditDenyMessages) > 0 || len(userRes.AuditAllowMessages) > 0 {
				userRes.ProfileName = profileName
				userRes.Options = options
				results = append(results, userRes)
			}
		}
	}

	evaluateProfiles(varmorPolicyProfiles)
	evaluateProfiles(varmorClusterPolicyProfiles)

	return results, nil
}

func (e *Evaluator) evaluateUserPolicy(ctx context.Context, query rego.PreparedEvalQuery, options Options, input interface{}) (EvalResult, error) {
	var result EvalResult
	var evalCtx context.Context
	var cancel context.CancelFunc

	if options.Timeout > 0 {
		evalCtx, cancel = context.WithTimeout(ctx, time.Duration(options.Timeout)*time.Millisecond)
	} else {
		evalCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
	}
	defer cancel()

	rs, err := query.Eval(evalCtx, rego.EvalInput(input))
	if err != nil {
		return result, fmt.Errorf("failed to evaluate policy: %w", err)
	}

	if len(rs) > 0 {
		e.parseRegoResult(rs, &result)
	}
	return result, nil
}

func (e *Evaluator) parseRegoResult(rs rego.ResultSet, result *EvalResult) {
	// rs[0].Expressions[0].Value should be map[string]interface{}
	// representing the package "data.nri.authz"
	// Keys: "deny", "audit_deny", "audit_allow" (if defined)
	// Values: []interface{} (sets of decisions)

	for _, res := range rs {
		for _, expr := range res.Expressions {
			pkgMap, ok := expr.Value.(map[string]interface{})
			if !ok {
				continue
			}

			// Helper to process a rule's output list
			processRule := func(ruleName string, targetList *[]string) {
				if val, ok := pkgMap[ruleName]; ok {
					if decisions, ok := val.([]interface{}); ok {
						for _, d := range decisions {
							if m, ok := d.(map[string]interface{}); ok {
								if msg, ok := m["message"].(string); ok && msg != "" {
									*targetList = append(*targetList, msg)
								}
							} else if s, ok := d.(string); ok && s != "" {
								*targetList = append(*targetList, s)
							}
						}
					}
				}
			}

			processRule("deny", &result.DenyMessages)
			processRule("audit_deny", &result.AuditDenyMessages)
			processRule("audit_allow", &result.AuditAllowMessages)
		}
	}
}
