// Package policy implements the GHOSTWIRE policy engine for access control.
package policy

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
)

// Effect is the result of a policy evaluation
type Effect uint8

const (
	EffectDeny Effect = iota
	EffectAllow
)

func (e Effect) String() string {
	if e == EffectAllow {
		return "allow"
	}
	return "deny"
}

// Rule represents a single access control rule
type Rule struct {
	// Name is a unique identifier for the rule
	Name string `yaml:"name"`

	// Description explains what this rule does
	Description string `yaml:"description,omitempty"`

	// Priority determines evaluation order (higher = evaluated first)
	Priority int `yaml:"priority"`

	// Subjects defines who this rule applies to
	Subjects SubjectSpec `yaml:"subjects"`

	// Resources defines what this rule controls access to
	Resources ResourceSpec `yaml:"resources"`

	// Condition is an optional CEL expression for dynamic evaluation
	Condition string `yaml:"condition,omitempty"`

	// Effect is allow or deny
	Effect Effect `yaml:"effect"`

	// compiled CEL program (internal)
	program cel.Program
}

// SubjectSpec defines the entities a rule applies to
type SubjectSpec struct {
	// Roles that this rule applies to (OR'd)
	Roles []string `yaml:"roles,omitempty"`

	// NodeIDs that this rule applies to (OR'd)
	NodeIDs []string `yaml:"node_ids,omitempty"`

	// Compartments that this rule applies to (OR'd)
	Compartments []string `yaml:"compartments,omitempty"`
}

// ResourceSpec defines what resources a rule controls
type ResourceSpec struct {
	// Nodes that can be accessed (wildcards allowed)
	Nodes []string `yaml:"nodes,omitempty"`

	// Ports that can be accessed
	Ports []PortRange `yaml:"ports,omitempty"`

	// Networks (CIDR) that can be accessed
	Networks []string `yaml:"networks,omitempty"`

	// Protocols allowed (tcp, udp, icmp, *)
	Protocols []string `yaml:"protocols,omitempty"`

	// Direction: ingress, egress, or both
	Direction string `yaml:"direction,omitempty"`
}

// PortRange represents a range of ports
type PortRange struct {
	Start uint16 `yaml:"start"`
	End   uint16 `yaml:"end,omitempty"` // If 0, same as Start
}

// Contains checks if a port is in the range
func (pr PortRange) Contains(port uint16) bool {
	end := pr.End
	if end == 0 {
		end = pr.Start
	}
	return port >= pr.Start && port <= end
}

// PolicySet is a collection of rules
type PolicySet struct {
	Version     int     `yaml:"version"`
	Name        string  `yaml:"name"`
	Description string  `yaml:"description,omitempty"`
	Rules       []*Rule `yaml:"rules"`
}

// Request represents an access control request
type Request struct {
	// Source information
	SourceNodeID      string
	SourceRoles       []string
	SourceCompartment string
	SourceIP          netip.Addr

	// Destination information
	DestNodeID      string
	DestRoles       []string
	DestCompartment string
	DestIP          netip.Addr
	DestPort        uint16

	// Connection information
	Protocol  string // tcp, udp, icmp
	Direction string // ingress, egress

	// Additional context
	Metadata map[string]string
}

// Decision is the result of policy evaluation
type Decision struct {
	Effect Effect
	Rule   *Rule
	Reason string
}

// Engine evaluates access control policies
type Engine struct {
	mu       sync.RWMutex
	policies *PolicySet
	celEnv   *cel.Env
	compiled map[string]cel.Program
}

// NewEngine creates a new policy engine
func NewEngine() (*Engine, error) {
	// Create CEL environment with custom declarations
	env, err := cel.NewEnv(
		cel.Declarations(
			decls.NewVar("source_node_id", decls.String),
			decls.NewVar("source_roles", decls.NewListType(decls.String)),
			decls.NewVar("source_compartment", decls.String),
			decls.NewVar("source_ip", decls.String),
			decls.NewVar("dest_node_id", decls.String),
			decls.NewVar("dest_roles", decls.NewListType(decls.String)),
			decls.NewVar("dest_compartment", decls.String),
			decls.NewVar("dest_ip", decls.String),
			decls.NewVar("dest_port", decls.Int),
			decls.NewVar("protocol", decls.String),
			decls.NewVar("direction", decls.String),
			decls.NewVar("metadata", decls.NewMapType(decls.String, decls.String)),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}

	return &Engine{
		celEnv:   env,
		compiled: make(map[string]cel.Program),
	}, nil
}

// LoadPolicies loads and compiles a policy set
func (e *Engine) LoadPolicies(ps *PolicySet) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Compile any CEL conditions
	for _, rule := range ps.Rules {
		if rule.Condition != "" {
			ast, issues := e.celEnv.Compile(rule.Condition)
			if issues != nil && issues.Err() != nil {
				return fmt.Errorf("compile condition for rule %s: %w", rule.Name, issues.Err())
			}
			prg, err := e.celEnv.Program(ast)
			if err != nil {
				return fmt.Errorf("program condition for rule %s: %w", rule.Name, err)
			}
			rule.program = prg
			e.compiled[rule.Name] = prg
		}
	}

	// Sort rules by priority (descending)
	sortRules(ps.Rules)

	e.policies = ps
	return nil
}

// Evaluate checks a request against loaded policies
func (e *Engine) Evaluate(req *Request) *Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.policies == nil || len(e.policies.Rules) == 0 {
		// Default deny if no policies
		return &Decision{
			Effect: EffectDeny,
			Reason: "no policies loaded",
		}
	}

	for _, rule := range e.policies.Rules {
		if e.ruleMatches(rule, req) {
			return &Decision{
				Effect: rule.Effect,
				Rule:   rule,
				Reason: fmt.Sprintf("matched rule: %s", rule.Name),
			}
		}
	}

	// Default deny
	return &Decision{
		Effect: EffectDeny,
		Reason: "no matching rule (default deny)",
	}
}

// ruleMatches checks if a rule applies to a request
func (e *Engine) ruleMatches(rule *Rule, req *Request) bool {
	// Check subjects
	if !e.subjectsMatch(&rule.Subjects, req) {
		return false
	}

	// Check resources
	if !e.resourcesMatch(&rule.Resources, req) {
		return false
	}

	// Check CEL condition if present
	if rule.program != nil {
		if !e.evaluateCondition(rule, req) {
			return false
		}
	}

	return true
}

func (e *Engine) subjectsMatch(spec *SubjectSpec, req *Request) bool {
	// If no subjects specified, matches all
	if len(spec.Roles) == 0 && len(spec.NodeIDs) == 0 && len(spec.Compartments) == 0 {
		return true
	}

	// Check roles (OR)
	if len(spec.Roles) > 0 {
		matched := false
		for _, role := range spec.Roles {
			if role == "*" {
				matched = true
				break
			}
			for _, srcRole := range req.SourceRoles {
				if role == srcRole {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check node IDs (OR)
	if len(spec.NodeIDs) > 0 {
		matched := false
		for _, nodeID := range spec.NodeIDs {
			if nodeID == "*" || nodeID == req.SourceNodeID {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check compartments (OR)
	if len(spec.Compartments) > 0 {
		matched := false
		for _, comp := range spec.Compartments {
			if comp == "*" || comp == req.SourceCompartment {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

func (e *Engine) resourcesMatch(spec *ResourceSpec, req *Request) bool {
	// Check direction
	if spec.Direction != "" && spec.Direction != "both" {
		if spec.Direction != req.Direction {
			return false
		}
	}

	// Check protocols
	if len(spec.Protocols) > 0 {
		matched := false
		for _, proto := range spec.Protocols {
			if proto == "*" || proto == req.Protocol {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check nodes
	if len(spec.Nodes) > 0 {
		matched := false
		for _, node := range spec.Nodes {
			if node == "*" || node == req.DestNodeID {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check ports
	if len(spec.Ports) > 0 {
		matched := false
		for _, pr := range spec.Ports {
			if pr.Contains(req.DestPort) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check networks
	if len(spec.Networks) > 0 {
		matched := false
		for _, network := range spec.Networks {
			if network == "*" {
				matched = true
				break
			}
			prefix, err := netip.ParsePrefix(network)
			if err == nil && prefix.Contains(req.DestIP) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

func (e *Engine) evaluateCondition(rule *Rule, req *Request) bool {
	vars := map[string]interface{}{
		"source_node_id":     req.SourceNodeID,
		"source_roles":       req.SourceRoles,
		"source_compartment": req.SourceCompartment,
		"source_ip":          req.SourceIP.String(),
		"dest_node_id":       req.DestNodeID,
		"dest_roles":         req.DestRoles,
		"dest_compartment":   req.DestCompartment,
		"dest_ip":            req.DestIP.String(),
		"dest_port":          int64(req.DestPort),
		"protocol":           req.Protocol,
		"direction":          req.Direction,
		"metadata":           req.Metadata,
	}

	out, _, err := rule.program.Eval(vars)
	if err != nil {
		return false
	}

	result, ok := out.Value().(bool)
	return ok && result
}

// sortRules sorts rules by priority (descending)
func sortRules(rules []*Rule) {
	for i := 0; i < len(rules)-1; i++ {
		for j := i + 1; j < len(rules); j++ {
			if rules[j].Priority > rules[i].Priority {
				rules[i], rules[j] = rules[j], rules[i]
			}
		}
	}
}

// DefaultPolicies returns a basic default-deny policy set
func DefaultPolicies() *PolicySet {
	return &PolicySet{
		Version:     1,
		Name:        "default",
		Description: "Default GHOSTWIRE policies",
		Rules: []*Rule{
			{
				Name:        "admin-full-access",
				Description: "Admin nodes have unrestricted mesh access",
				Priority:    100,
				Subjects: SubjectSpec{
					Roles: []string{"admin"},
				},
				Resources: ResourceSpec{
					Nodes:     []string{"*"},
					Protocols: []string{"*"},
				},
				Effect: EffectAllow,
			},
			{
				Name:        "relay-forward",
				Description: "Relay nodes can forward traffic",
				Priority:    90,
				Subjects: SubjectSpec{
					Roles: []string{"relay"},
				},
				Resources: ResourceSpec{
					Nodes:     []string{"*"},
					Protocols: []string{"*"},
				},
				Effect: EffectAllow,
			},
			{
				Name:        "operator-mesh-access",
				Description: "Operators can reach other operators and relays",
				Priority:    50,
				Subjects: SubjectSpec{
					Roles: []string{"operator"},
				},
				Resources: ResourceSpec{
					Nodes:     []string{"*"},
					Protocols: []string{"tcp", "udp"},
				},
				Condition: `dest_roles.exists(r, r == "operator" || r == "relay" || r == "admin")`,
				Effect:    EffectAllow,
			},
			{
				Name:        "sensor-egress-only",
				Description: "Sensors can only send to collectors",
				Priority:    40,
				Subjects: SubjectSpec{
					Roles: []string{"sensor"},
				},
				Resources: ResourceSpec{
					Direction: "egress",
					Protocols: []string{"tcp", "udp"},
				},
				Condition: `dest_roles.exists(r, r == "collector" || r == "admin")`,
				Effect:    EffectAllow,
			},
			{
				Name:        "default-deny",
				Description: "Deny everything not explicitly allowed",
				Priority:    0,
				Subjects: SubjectSpec{
					Roles: []string{"*"},
				},
				Resources: ResourceSpec{
					Nodes: []string{"*"},
				},
				Effect: EffectDeny,
			},
		},
	}
}
