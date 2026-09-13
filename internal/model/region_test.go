package model_test

import (
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("Permission regions", func() {
	It("preserves exact, complement and nested prefix membership", func() {
		sets := []model.Region{model.EmptyRegion(), model.AnyRegion(), model.Values("", "a", "abc"), model.Prefix("a"), model.Prefix("ab").Complement(), model.Prefix("a").Subtract(model.Prefix("ab")).Union(model.Values("abc"))}
		values := []string{"", "a", "ab", "abc", "abcd", "ac", "b", "\x00", "é"}
		for _, a := range sets {
			for _, b := range sets {
				union, intersection, difference := a.Union(b), a.Intersect(b), a.Subtract(b)
				Expect(utils.ValidateRegion(union)).To(Succeed())
				Expect(utils.ValidateRegion(intersection)).To(Succeed())
				Expect(utils.ValidateRegion(difference)).To(Succeed())
				for _, value := range values {
					Expect(union.Contains(value)).To(Equal(a.Contains(value) || b.Contains(value)))
					Expect(intersection.Contains(value)).To(Equal(a.Contains(value) && b.Contains(value)))
					Expect(difference.Contains(value)).To(Equal(a.Contains(value) && !b.Contains(value)))
				}
			}
		}
	})
	It("detects empty prefix differences without inventing a witness", func() {
		Expect(model.Prefix("a").Subtract(model.Prefix("a")).Empty()).To(BeTrue())
		region := model.Prefix("a").Subtract(model.Values("a"))
		for value := range 256 {
			region = region.Subtract(model.Prefix("a" + string([]byte{byte(value)})))
		}
		Expect(region.Empty()).To(BeTrue())
	})
	It("handles long included boundaries and exact holes without walking each byte", func() {
		boundary := strings.Repeat("a", 64*1024)
		Expect(model.Values(boundary).Empty()).To(BeFalse())
		Expect(model.Prefix(boundary).Subtract(model.Values(boundary)).Empty()).To(BeFalse())
		Expect(model.Prefix(boundary).Subtract(model.Prefix(boundary)).Empty()).To(BeTrue())
	})
})

// universe holds every string over {a, b, c} of at most three bytes. Fuzzed
// regions draw their boundaries from strings over {a, b} of at most two bytes,
// so each nonempty region has a member here: a boundary itself, or a boundary
// followed by c.
var universe = func() []string {
	result := []string{""}
	for length := 1; length <= 3; length++ {
		for _, prefix := range result {
			if len(prefix) != length-1 {
				continue
			}
			for _, next := range "abc" {
				result = append(result, prefix+string(next))
			}
		}
	}
	return result
}()

// boundary reads a boundary over {a, b} of at most two bytes from data.
func boundary(data []byte) (string, []byte) {
	if len(data) == 0 {
		return "", nil
	}
	value := []string{"", "a", "b", "aa", "ab", "ba", "bb"}[int(data[0])%7]
	return value, data[1:]
}

// FuzzRegionAlgebra checks the region algebra against a finite-set oracle:
// each region is built from the same operations as a membership predicate.
func FuzzRegionAlgebra(f *testing.F) {
	f.Add([]byte{0, 1, 1, 3, 2, 4, 5, 6, 7})
	f.Add([]byte{1, 4, 3, 2, 5, 0, 6, 1, 7, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		type operand struct {
			region model.Region
			member func(string) bool
		}
		stack := []operand{{model.EmptyRegion(), func(string) bool { return false }}}
		for len(data) > 0 {
			op := data[0] % 8
			data = data[1:]
			var value string
			top := stack[len(stack)-1]
			switch op {
			case 0:
				value, data = boundary(data)
				stack = append(stack, operand{model.Values(value), func(s string) bool { return s == value }})
			case 1:
				value, data = boundary(data)
				stack = append(stack, operand{model.Prefix(value), func(s string) bool { return strings.HasPrefix(s, value) }})
			case 2:
				stack[len(stack)-1] = operand{top.region.Complement(), func(s string) bool { return !top.member(s) }}
			case 3, 4, 5:
				if len(stack) < 2 {
					continue
				}
				left := stack[len(stack)-2]
				stack = stack[:len(stack)-2]
				switch op {
				case 3:
					stack = append(stack, operand{left.region.Union(top.region), func(s string) bool { return left.member(s) || top.member(s) }})
				case 4:
					stack = append(stack, operand{left.region.Intersect(top.region), func(s string) bool { return left.member(s) && top.member(s) }})
				default:
					stack = append(stack, operand{left.region.Subtract(top.region), func(s string) bool { return left.member(s) && !top.member(s) }})
				}
			default:
				stack = append(stack, operand{model.AnyRegion(), func(string) bool { return true }})
			}
		}
		for _, item := range stack {
			if err := utils.ValidateRegion(item.region); err != nil {
				t.Fatalf("region %+v isn't normalized: %v", item.region, err)
			}
			empty := true
			for _, value := range universe {
				if item.region.Contains(value) != item.member(value) {
					t.Fatalf("region %+v: Contains(%q) = %v", item.region, value, !item.member(value))
				}
				empty = empty && !item.member(value)
			}
			if item.region.Empty() != empty {
				t.Fatalf("region %+v: Empty() = %v", item.region, !empty)
			}
		}
	})
}

// FuzzRegionNormalize checks that normalizing an arbitrary region keeps its
// membership and yields a form ValidateRegion accepts.
func FuzzRegionNormalize(f *testing.F) {
	f.Add(true, []byte{1, 1, 3, 0, 2, 1})
	f.Add(false, []byte{0, 1, 4, 0, 4, 1, 6, 0})
	f.Fuzz(func(t *testing.T, fallback bool, data []byte) {
		region := model.Region{Default: fallback}
		prefixes, values := map[string]bool{}, map[string]bool{}
		for len(data) > 1 {
			kind, include := data[0]%2, data[1]%2 == 0
			var value string
			value, data = boundary(data[1:])
			if kind == 0 && !prefixes[value] {
				prefixes[value] = true
				region.Prefixes = append(region.Prefixes, model.Override{Value: value, Include: include})
			} else if kind == 1 && !values[value] {
				values[value] = true
				region.Values = append(region.Values, model.Override{Value: value, Include: include})
			}
		}
		member := func(value string) bool {
			for _, rule := range region.Values {
				if rule.Value == value {
					return rule.Include
				}
			}
			result, longest := region.Default, -1
			for _, rule := range region.Prefixes {
				if len(rule.Value) > longest && strings.HasPrefix(value, rule.Value) {
					result, longest = rule.Include, len(rule.Value)
				}
			}
			return result
		}
		normalized := region.Normalize()
		if err := utils.ValidateRegion(normalized); err != nil {
			t.Fatalf("normalized region %+v is rejected: %v", normalized, err)
		}
		for _, value := range universe {
			if normalized.Contains(value) != member(value) {
				t.Fatalf("normalizing %+v changed membership of %q", region, value)
			}
		}
	})
}
