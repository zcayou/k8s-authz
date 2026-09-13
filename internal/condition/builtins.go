package condition

import (
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/zcayou/k8s-authz/internal/model"
)

// defaultBuiltins are the pure builtins whose cost a condition's inputs
// bound. Network, runtime, randomness, print and trace, rego.*, certificates
// and keys, JWT, providers, GraphQL, graph and JSON-schema builtins are left
// out, and so is every builtin a constant can make run for unbounded time
// without observing cancellation: numbers.range, numbers.range_step,
// net.cidr_expand, bits.lsh and strings.render_template.
var defaultBuiltins = model.NewBuiltinSet([]string{
	"abs", "ceil", "concat", "contains", "count", "endswith", "floor", "format_int",
	"indexof", "indexof_n", "intersection", "is_array", "is_boolean", "is_null",
	"is_number", "is_object", "is_set", "is_string", "lower", "max", "min", "product",
	"replace", "round", "sort", "split", "sprintf", "startswith", "substring", "sum",
	"to_number", "trim", "trim_left", "trim_prefix", "trim_right", "trim_space",
	"trim_suffix", "type_name", "union", "upper", "walk",
	"array.concat", "array.flatten", "array.reverse", "array.slice",
	"object.filter", "object.get", "object.keys", "object.remove", "object.subset",
	"object.union", "object.union_n",
	"strings.any_prefix_match", "strings.any_suffix_match", "strings.count",
	"strings.replace_n", "strings.reverse", "strings.split_n",
	"regex.find_all_string_submatch_n", "regex.find_n", "regex.globs_match",
	"regex.is_valid", "regex.match", "regex.replace", "regex.split", "regex.template_match",
	"glob.match", "glob.quote_meta",
	"base64.decode", "base64.encode", "base64.is_valid", "base64url.decode",
	"base64url.encode", "base64url.encode_no_pad", "hex.decode", "hex.encode",
	"urlquery.decode", "urlquery.decode_object", "urlquery.encode", "urlquery.encode_object",
	"json.filter", "json.is_valid", "json.marshal", "json.marshal_with_options",
	"json.patch", "json.remove", "json.unmarshal", "yaml.is_valid", "yaml.marshal",
	"yaml.unmarshal",
	"crypto.hmac.equal", "crypto.hmac.md5", "crypto.hmac.sha1", "crypto.hmac.sha256",
	"crypto.hmac.sha512", "crypto.md5", "crypto.sha1", "crypto.sha256",
	"semver.compare", "semver.is_valid", "units.parse", "units.parse_bytes",
	"uri.is_valid", "uri.parse", "uuid.parse",
	"time.add_date", "time.clock", "time.date", "time.diff", "time.format", "time.now_ns",
	"time.parse_duration_ns", "time.parse_ns", "time.parse_rfc3339_ns", "time.weekday",
	"net.cidr_contains", "net.cidr_contains_matches", "net.cidr_intersects",
	"net.cidr_is_valid", "net.cidr_merge",
	"bits.and", "bits.negate", "bits.or", "bits.rsh", "bits.xor",
})

// DefaultBuiltins returns the builtins a source allows when it lists none.
func DefaultBuiltins() model.BuiltinSet {
	return defaultBuiltins
}

// Defined reports whether name is a builtin of the linked OPA release
// that an allowlist can name: defined, not an operator, not internal.
func Defined(name string) bool {
	if name == ast.Print.Name {
		return true
	}
	builtin, ok := ast.BuiltinMap[name]
	return ok && builtin.Infix == "" && !builtin.Deprecated && !strings.HasPrefix(name, "internal.")
}
