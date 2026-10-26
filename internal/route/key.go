package route

import "strconv"

// RuleKeys returns one stable statistics key per rule of the validated (and
// therefore normalized) options, plus the key of final. A key is derived from
// the rule's condition and outcome, never from its position, so statistics
// survive reordering; identical rules get "#2", "#3" ... suffixes in order.
func RuleKeys(o Options) (rules []string, final string) {
	seen := map[string]int{}
	rules = make([]string, len(o.Rules))
	for i, r := range o.Rules {
		k := condString(&r) + "->" + ruleTarget(r.Action, r.Outbound)
		seen[k]++
		if n := seen[k]; n > 1 {
			k += "#" + strconv.Itoa(n)
		}
		rules[i] = k
	}
	f := o.Final
	if f == "" {
		f = "direct"
	}
	return rules, "final->" + f
}

func ruleTarget(action, out string) string {
	switch {
	case action == "direct" || out == "direct":
		return "direct"
	case action == "reject" || out == "reject":
		return "reject"
	}
	return out
}
