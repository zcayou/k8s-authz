package authz.program.kubernetes

normalize(review) := normalized if {
	valid_request(review)
	normalized := normalized_request(review)
} else := {"valid": false, "error": "invalid SubjectAccessReview"}

normalized_request(review) := {
	"valid": true,
	"principal": normalized_principal(review.spec),
	"query": normalized_query(review.spec),
	"conditionInput": condition_input(review.spec),
}

valid_request(review) if {
	is_object(review)
	review.apiVersion == "authorization.k8s.io/v1"
	review.kind == "SubjectAccessReview"
	spec_valid(field(review, "spec", {}))
}

spec_valid(spec) if {
	is_object(spec)
	principal_valid(spec)
	exactly_one_operation(spec)
	operation_valid(spec)
}

principal_valid(spec) if {
	is_string(field(spec, "user", ""))
	is_string(field(spec, "uid", ""))
	all_strings(field(spec, "groups", []))
	extra := field(spec, "extra", {})
	is_object(extra)
	every key, _ in extra {
		all_strings(field(extra, key, []))
	}
}

exactly_one_operation(spec) if {
	present(spec, "resourceAttributes")
	not present(spec, "nonResourceAttributes")
}

exactly_one_operation(spec) if {
	present(spec, "nonResourceAttributes")
	not present(spec, "resourceAttributes")
}

operation_valid(spec) if {
	present(spec, "resourceAttributes")
	resource_attributes_valid(spec.resourceAttributes)
}

operation_valid(spec) if {
	present(spec, "nonResourceAttributes")
	non_resource_attributes_valid(spec.nonResourceAttributes)
}

# resource_attributes_valid refuses a NUL in the resource or subresource,
# which resource_region joins with one.
resource_attributes_valid(attributes) if {
	is_object(attributes)
	every key in resource_attribute_strings {
		is_string(field(attributes, key, ""))
	}
	not contains(field(attributes, "resource", ""), "\u0000")
	not contains(field(attributes, "subresource", ""), "\u0000")
	selector_valid(field(attributes, "fieldSelector", {}))
	selector_valid(field(attributes, "labelSelector", {}))
}

non_resource_attributes_valid(attributes) if {
	is_object(attributes)
	is_string(field(attributes, "path", ""))
	is_string(field(attributes, "verb", ""))
}

selector_valid(selector) if {
	is_object(selector)
	is_string(field(selector, "rawSelector", ""))
	requirements := field(selector, "requirements", [])
	is_array(requirements)
	every requirement in requirements {
		requirement_valid(requirement)
	}
	selector_encoding_compatible(selector)
}

requirement_valid(requirement) if {
	is_object(requirement)
	is_string(field(requirement, "key", ""))
	is_string(field(requirement, "operator", ""))
	all_strings(field(requirement, "values", []))
}

selector_encoding_compatible(selector) if {
	field(selector, "rawSelector", "") == ""
}

selector_encoding_compatible(selector) if {
	count(field(selector, "requirements", [])) == 0
}

normalized_principal(spec) := {
	"user": field(spec, "user", ""),
	"groups": sort({group | some group in field(spec, "groups", [])}),
	"uid": field(spec, "uid", ""),
	"extra": normalized_extra(spec),
}

normalized_extra(spec) := null if {
	not present(spec, "extra")
} else := {key: sort({value | some value in field(spec.extra, key, [])}) |
	some key, _ in spec.extra
}

resource_attribute_strings := ["namespace", "verb", "group", "version", "resource", "subresource", "name"]

# condition_input is a condition's input: the normalized principal, with extra
# an object, and the request's attributes with every absent field defaulted.
condition_input(spec) := {"principal": condition_principal(spec), "request": condition_request(spec)}

condition_principal(spec) := object.union(normalized_principal(spec), {"extra": {}}) if {
	not present(spec, "extra")
} else := normalized_principal(spec)

condition_request(spec) := {"resourceAttributes": object.union(
	{key: field(spec.resourceAttributes, key, "") | some key in resource_attribute_strings},
	{key: field(spec.resourceAttributes, key, {}) | some key in ["fieldSelector", "labelSelector"]},
)} if {
	present(spec, "resourceAttributes")
} else := {"nonResourceAttributes": {key: field(spec.nonResourceAttributes, key, "") | some key in ["path", "verb"]}}

normalized_query(spec) := query if {
	present(spec, "resourceAttributes")
	query := normalized_resource_query(spec.resourceAttributes)
} else := query if {
	query := normalized_non_resource_query(spec.nonResourceAttributes)
}

# normalized_resource_query reads namespace "*" and subresource "*"
# literally, as RBAC matches them: kube-apiserver never sends either as
# a wildcard.
normalized_resource_query(attributes) := {"regions": shallow_union(
	shallow_union(
		{
			"00/category": exact_region("resource"),
			"01/apiGroup": ordinary_dimension(field(attributes, "group", ""), false),
			"02/apiVersion": ordinary_dimension(field(attributes, "version", ""), true),
			"03/resource": resource_region(field(attributes, "resource", ""), field(attributes, "subresource", "")),
			"04/verb": ordinary_dimension(field(attributes, "verb", ""), false),
			"07/name": name_region(field(attributes, "name", "")),
		},
		namespace_regions(field(attributes, "namespace", "")),
	),
	selector_regions(attributes),
)}

normalized_non_resource_query(attributes) := {
	"regions": {
		"00/category": exact_region("nonResource"),
		"04/verb": ordinary_dimension(field(attributes, "verb", ""), false),
		"10/url": url_region(field(attributes, "path", "")),
	},
}

ordinary_dimension(value, absent_unrestricted) := present_region if {
	value == "*"
} else := present_region if {
	value == ""
	absent_unrestricted
} else := exact_region(value)

resource_region(resource, subresource) := present_region if {
	resource == "*"
	subresource == ""
} else := prefix_region(atom(concat("", [subresource, "\u0000"]))) if {
	resource == "*"
} else := exact_encoded_region(atom(concat("", [subresource, "\u0000", resource])))

name_region(name) := present_region if {
	name == ""
} else := present_region if {
	name == "*"
} else := exact_region(name)

url_region(path) := present_region if {
	path == "*"
} else := exact_region(path)

namespace_regions(namespace) := {
	"05/ingressNamespace": exact_region(""),
	"06/affectedNamespace": empty_ingress_affected_region,
} if {
	namespace == ""
} else := {
	"05/ingressNamespace": exact_region(namespace),
	"06/affectedNamespace": exact_region(namespace),
}

selector_regions(attributes) := {} if {
	not collection_verb(field(attributes, "verb", ""))
} else := {} if {
	not selector_evidence_consistent(attributes)
} else := {dimension: selector_dimension_region(attributes, dimension) |
	some dimension in selector_dimensions(attributes)
}

# selector_evidence_consistent holds when no dimension's requirements
# contradict each other, so every selector region is nonempty.
selector_evidence_consistent(attributes) if {
	every dimension in selector_dimensions(attributes) {
		not selector_dimension_contradictory(attributes, dimension)
	}
}

selector_requirements(attributes) := array.concat(field_requirements(attributes), label_requirements(attributes))

field_requirements(attributes) := [normalized_field_requirement(requirement) |
	some requirement in field(field(attributes, "fieldSelector", {}), "requirements", [])
]

label_requirements(attributes) := [normalized_label_requirement(requirement) |
	some requirement in field(field(attributes, "labelSelector", {}), "requirements", [])
]

normalized_field_requirement(requirement) := {
	"dimension": field_dimension(field(requirement, "key", "")),
	"operator": field(requirement, "operator", ""),
	"values": field(requirement, "values", []),
}

normalized_label_requirement(requirement) := {
	"dimension": concat("", ["08/label/", field(requirement, "key", "")]),
	"operator": field(requirement, "operator", ""),
	"values": field(requirement, "values", []),
}

field_dimension(key) := "07/name" if {
	key == "metadata.name"
} else := concat("", ["09/field/", key])

selector_dimensions(attributes) := {requirement.dimension |
	some requirement in selector_requirements(attributes)
}

selector_dimension_contradictory(attributes, dimension) if {
	requirements := dimension_requirements(attributes, dimension)
	has_operator(requirements, "DoesNotExist")
	has_operator(requirements, "Exists")
}

selector_dimension_contradictory(attributes, dimension) if {
	requirements := dimension_requirements(attributes, dimension)
	has_operator(requirements, "DoesNotExist")
	has_operator(requirements, "In")
}

selector_dimension_contradictory(attributes, dimension) if {
	requirements := dimension_requirements(attributes, dimension)
	has_operator(requirements, "In")
	count(allowed_in_values(requirements)) == 0
}

selector_dimension_contradictory(attributes, "07/name") if {
	requirements := dimension_requirements(attributes, "07/name")
	has_operator(requirements, "DoesNotExist")
}

selector_dimension_contradictory(attributes, "07/name") if {
	name := field(attributes, "name", "")
	name != ""
	name != "*"
	requirements := dimension_requirements(attributes, "07/name")
	not requirements_accept_value(requirements, name)
}

dimension_requirements(attributes, dimension) := [requirement |
	some requirement in selector_requirements(attributes)
	requirement.dimension == dimension
]

has_operator(requirements, operator) if {
	some requirement in requirements
	requirement.operator == operator
}

allowed_in_values(requirements) := {value |
	some requirement in requirements
	requirement.operator == "In"
	some value in requirement.values
	every candidate in requirements {
		requirement_accepts(candidate, value)
	}
}

requirement_accepts(requirement, value) if {
	requirement.operator == "In"
	value in requirement.values
}

requirement_accepts(requirement, value) if {
	requirement.operator == "NotIn"
	not value in requirement.values
}

requirement_accepts(requirement, value) if {
	requirement.operator == "Exists"
	is_string(value)
}

requirements_accept_value(requirements, value) if {
	every requirement in requirements {
		requirement_accepts(requirement, value)
	}
}

selector_dimension_region(attributes, "07/name") := name_selector_region(attributes)

selector_dimension_region(attributes, dimension) := generic_selector_region(requirements) if {
	dimension != "07/name"
	requirements := dimension_requirements(attributes, dimension)
}

name_selector_region(attributes) := finite_encoded_region({atom(name)}) if {
	name := field(attributes, "name", "")
	name != ""
	name != "*"
} else := finite_region(allowed_in_values(dimension_requirements(attributes, "07/name"))) if {
	requirements := dimension_requirements(attributes, "07/name")
	has_operator(requirements, "In")
} else := present_except_region(not_in_values(dimension_requirements(attributes, "07/name")))

generic_selector_region(requirements) := finite_region(allowed_in_values(requirements)) if {
	has_operator(requirements, "In")
} else := exact_encoded_region("\u0000absent") if {
	has_operator(requirements, "DoesNotExist")
} else := complement_region(generic_exclusions(requirements))

not_in_values(requirements) := {value |
	some requirement in requirements
	requirement.operator == "NotIn"
	some value in requirement.values
}

generic_exclusions(requirements) := encoded if {
	not has_operator(requirements, "Exists")
	encoded := {atom(value) | some value in not_in_values(requirements)}
} else := exclusions if {
	has_operator(requirements, "Exists")
	encoded := {atom(value) | some value in not_in_values(requirements)}
	exclusions := encoded | {"\u0000absent"}
}

finite_region(values) := finite_encoded_region({atom(value) | some value in values})

finite_encoded_region(values) := {
	"default": false,
	"values": included_overrides(values),
}

complement_region(exclusions) := {"default": true} if {
	count(exclusions) == 0
} else := {
	"default": true,
	"values": excluded_overrides(exclusions),
}

present_except_region(exclusions) := present_region if {
	count(exclusions) == 0
} else := {
	"default": false,
	"prefixes": [{"value": "v:", "include": true}],
	"values": excluded_overrides({atom(value) | some value in exclusions}),
}

included_overrides(values) := [{"value": value, "include": true} | some value in sort(values)]

excluded_overrides(values) := [{"value": value, "include": false} | some value in sort(values)]

exact_region(value) := exact_encoded_region(atom(value))

exact_encoded_region(value) := {
	"default": false,
	"values": [{"value": value, "include": true}],
}

prefix_region(value) := {
	"default": false,
	"prefixes": [{"value": value, "include": true}],
}

present_region := prefix_region("v:")

empty_ingress_affected_region := {
	"default": false,
	"prefixes": [{"value": "v:", "include": true}],
	"values": [
		{"value": "\u0000namespace-witness", "include": true},
		{"value": "v:", "include": false},
	],
}

atom(value) := concat("", ["v:", value])

shallow_union(left, right) := {key: shallow_union_value(left, right, key) |
	some key in (object.keys(left) | object.keys(right))
}

shallow_union_value(left, right, key) := right[key] if {
	has_key(right, key)
} else := left[key]

collection_verb(verb) if {
	verb in {"deletecollection", "list", "watch"}
}

has_key(obj, key) if {
	_ := obj[key]
}

present(obj, key) if {
	obj[key] != null
}

# field reads an optional request field. kube-apiserver omits empty fields,
# and an explicit null means the same.
field(obj, key, absent) := value if {
	value := obj[key]
	value != null
} else := absent

all_strings(values) if {
	is_array(values)
	every value in values {
		is_string(value)
	}
}

decision(endpoint, review) := result if {
	normalized := normalize(review)
	normalized.valid
	result := data.authz.evaluator.decisions.evaluate(
		endpoint,
		normalized.principal,
		normalized.query,
		normalized.conditionInput,
	)
} else := data.authz.evaluator.decisions.evaluation_failure(endpoint, normalized.error) if {
	normalized := normalize(review)
	not normalized.valid
}

response(endpoint, review) := {
	"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
	"status": response_status(result),
} if {
	result := decision(endpoint, review)
}

response_status(result) := object.union(base, {"evaluationError": result.evaluationError}) if {
	result.evaluationError != ""
	base := response_status_base(result)
} else := response_status_base(result)

response_status_base(result) := {
	"allowed": result.result == "Allow",
	"denied": result.result == "Deny",
	"reason": sprintf("k8s-authz/v1 result=%s code=%s endpoint=%s authority=%s revision=%s", [
		result.result,
		result.code,
		urlquery.encode(result.endpoint),
		urlquery.encode(object.get(result, "authority", "")),
		result.revision,
	]),
}
