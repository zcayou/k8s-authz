package model_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("Ordered permission diagrams", func() {
	It("bulk unions preserve the canonical diagram and correlated operation semantics", func() {
		cubes := make([]model.Cube, 0, 257)
		for index := range 257 {
			cubes = append(cubes, model.Cube{
				model.APIGroup:          model.Values(string(rune('a' + index%5))),
				model.Resource:          model.Values(string(rune('a' + index%17))),
				model.Verb:              model.Values(string(rune('a' + index%7))),
				model.AffectedNamespace: model.Values(model.Atom(string(rune('a' + index%11)))),
			})
		}
		build := func(bulk bool) model.Diagram {
			arena := model.NewArena(100_000)
			roots := make([]model.NodeID, 0, len(cubes))
			root := model.NodeID(0)
			for _, cube := range cubes {
				next, err := arena.Cube(cube)
				Expect(err).NotTo(HaveOccurred())
				if bulk {
					roots = append(roots, next)
					continue
				}
				root, err = arena.Union(root, next)
				Expect(err).NotTo(HaveOccurred())
			}
			if bulk {
				var err error
				root, err = arena.UnionAll(roots)
				Expect(err).NotTo(HaveOccurred())
			}
			return arena.Snapshot(root)
		}
		sequential, bulk := build(false), build(true)
		Expect(bulk).To(Equal(sequential))
		Expect(utils.ValidateDiagram(bulk, 100_000)).To(Succeed())
		for group := range 5 {
			for resource := range 17 {
				for verb := range 7 {
					for namespace := range 11 {
						point := map[string]string{
							model.APIGroup:          string(rune('a' + group)),
							model.Resource:          string(rune('a' + resource)),
							model.Verb:              string(rune('a' + verb)),
							model.AffectedNamespace: model.Atom(string(rune('a' + namespace))),
						}
						expected := false
						for index := range 257 {
							if index%5 == group && index%17 == resource && index%7 == verb && index%11 == namespace {
								expected = true
								break
							}
						}
						Expect(covered(bulk, point)).To(Equal(expected))
					}
				}
			}
		}
	})
	It("rejects an unknown node in a bulk union, a label or an import", func() {
		_, err := model.NewArena(16).UnionAll([]model.NodeID{1, 16})
		Expect(err).To(MatchError("unknown diagram node"))
		_, err = model.NewArena(16).Label(16, "label")
		Expect(err).To(MatchError("unknown diagram node"))
		dangling := model.Diagram{Nodes: []model.Node{{Dimension: model.Verb, Edges: []model.Edge{{Region: model.AnyRegion(), Next: 7}}}}}
		_, err = model.NewArena(16).Import(dangling)
		Expect(err).To(MatchError("unknown diagram node"))
		_, err = model.NewArena(16).Import(model.Diagram{Root: 3, Nodes: []model.Node{{}}})
		Expect(err).To(MatchError("unknown diagram node"))
	})
	It("keeps independent verbs and namespaces correlated", func() {
		arena := model.NewArena(1000)
		one, err := arena.Cube(map[string]model.Region{model.Verb: model.Values("get"), model.AffectedNamespace: model.Values(model.Atom("one"))})
		Expect(err).NotTo(HaveOccurred())
		two, err := arena.Cube(map[string]model.Region{model.Verb: model.Values("update"), model.AffectedNamespace: model.Values(model.Atom("two"))})
		Expect(err).NotTo(HaveOccurred())
		root, err := arena.Union(one, two)
		Expect(err).NotTo(HaveOccurred())
		diagram := arena.Snapshot(root)
		Expect(utils.ValidateDiagram(diagram, 1000)).To(Succeed())
		for _, verb := range []string{"get", "update", "delete"} {
			for _, namespace := range []string{"one", "two", "three"} {
				point := map[string]string{model.Verb: verb, model.AffectedNamespace: model.Atom(namespace)}
				Expect(covered(diagram, point)).To(Equal(verb == "get" && namespace == "one" || verb == "update" && namespace == "two"))
			}
		}
	})
	It("keeps the namespace-less witness out of named namespaces and retains namespace exclusions", func() {
		arena := model.NewArena(1000)
		named, err := arena.Cube(map[string]model.Region{model.AffectedNamespace: model.NamedNamespaces()})
		Expect(err).NotTo(HaveOccurred())
		witness := map[string]string{model.IngressNamespace: model.Atom(""), model.AffectedNamespace: utils.NamespaceWitness}
		system := map[string]string{model.IngressNamespace: model.Atom(""), model.AffectedNamespace: model.Atom("kube-system")}
		Expect(covered(arena.Snapshot(named), witness)).To(BeFalse())
		Expect(covered(arena.Snapshot(named), system)).To(BeTrue())
		excluded, err := arena.Cube(map[string]model.Region{model.AffectedNamespace: model.Values(model.Atom("kube-system"))})
		Expect(err).NotTo(HaveOccurred())
		without, err := arena.Subtract(1, excluded)
		Expect(err).NotTo(HaveOccurred())
		Expect(covered(arena.Snapshot(without), system)).To(BeFalse())
		Expect(covered(arena.Snapshot(without), witness)).To(BeTrue())
	})
	It("matches an independent finite oracle through repeated algebra", func() {
		random := rand.New(rand.NewPCG(19, 71))
		arena := model.NewArena(100000)
		root := model.NodeID(0)
		oracle := [5][5]bool{}
		for range 100 {
			x, y := random.IntN(5), random.IntN(5)
			rule, err := arena.Cube(map[string]model.Region{model.APIGroup: model.Values(string(rune('a' + x))), model.Verb: model.Values(string(rune('a' + y)))})
			Expect(err).NotTo(HaveOccurred())
			if random.IntN(2) == 0 {
				root, err = arena.Union(root, rule)
				oracle[x][y] = true
			} else {
				root, err = arena.Subtract(root, rule)
				oracle[x][y] = false
			}
			Expect(err).NotTo(HaveOccurred())
			diagram := arena.Snapshot(root)
			Expect(utils.ValidateDiagram(diagram, 100000)).To(Succeed())
			for row := range 5 {
				for column := range 5 {
					point := map[string]string{model.APIGroup: string(rune('a' + row)), model.Verb: string(rune('a' + column))}
					Expect(covered(diagram, point)).To(Equal(oracle[row][column]))
				}
			}
			encoded, err := json.Marshal(diagram)
			Expect(err).NotTo(HaveOccurred())
			var decoded model.Diagram
			Expect(json.Unmarshal(encoded, &decoded)).To(Succeed())
			Expect(utils.ValidateDiagram(decoded, 100000)).To(Succeed())
		}
	})
})

const (
	diagramSeedOne = uint64(0x618f_930c_a2d4_7e11)
	diagramSeedTwo = uint64(0xde70_14ab_5f28_09c3)
)

var _ = Describe("Generated diagram bounds", func() {
	It("preserves point membership of labeled rules and enforces the arena's node cap", func() {
		AddReportEntry("seed", fmt.Sprintf("%#x/%#x", diagramSeedOne, diagramSeedTwo))
		random := rand.New(rand.NewPCG(diagramSeedOne, diagramSeedTwo))
		order := random.Perm(128)

		arena := model.NewArena(50_000)
		roots := make([]model.NodeID, 0, len(order))
		for _, value := range order {
			root, err := arena.Cube(model.Cube{
				model.APIGroup: model.Values("apps"),
				model.Resource: model.Values(fmt.Sprintf("resource-%03d", value)),
				model.Verb:     model.Values("get"),
			})
			Expect(err).NotTo(HaveOccurred())
			root, err = arena.Label(root, fmt.Sprintf("permission-%03d", value))
			Expect(err).NotTo(HaveOccurred())
			roots = append(roots, root)
		}
		root, err := arena.UnionAll(roots)
		Expect(err).NotTo(HaveOccurred())
		diagram := arena.Snapshot(root)
		Expect(utils.ValidateDiagram(diagram, 50_000)).To(Succeed())

		selected := order[random.IntN(len(order))]
		Expect(terminals(diagram, map[string]string{
			model.APIGroup: "apps",
			model.Resource: fmt.Sprintf("resource-%03d", selected),
			model.Verb:     "get",
		})).To(Equal([]string{fmt.Sprintf("permission-%03d", selected)}))

		limited := model.NewArena(2)
		_, err = limited.Cube(model.Cube{model.Verb: model.Values("get")})
		Expect(errors.Is(err, model.ErrLimit)).To(BeTrue())
	})
})
