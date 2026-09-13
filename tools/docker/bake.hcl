# Vendored; do not edit — sync via base-image

variable "REGISTRY" {}
variable "TAGS" {
  type    = list(string)
  default = ["dev"]
}

target "_common" {
  context    = "."
  dockerfile = "Dockerfile"
  args       = { REGISTRY = REGISTRY }
  platforms  = ["linux/amd64", "linux/arm64"]
}

function "tags" {
  params = [name]
  result = [for t in TAGS : "${REGISTRY}/${name}:${t}"]
}

function "tags_suffix" {
  params = [name, suffix]
  result = [for t in TAGS : "${REGISTRY}/${name}:${t}${suffix}"]
}

function "vname" {
  params = [stage, version]
  result = "${stage}_${replace(version, ".", "_")}"
}

function "vnum" {
  params = [version]
  result = parseint(join("", [for c in split(".", trimprefix(version, "v")) : format("%09s", c)]), 10)
}

function "vprefix" {
  params = [version, level]
  result = join(".", slice(split(".", version), 0, lookup({ major = 1, minor = 2, patch = 3 }, level, 0)))
}

function "vtags" {
  params          = [name, version, stage]
  variadic_params = opts
  result = distinct([for t in concat([version], length(opts) == 0 ? [] :
      [for l in opts[0].levels : vprefix(version, l)
        if length([for w in opts[0].versions : w
          if vprefix(w, l) == vprefix(version, l) && vnum(w) > vnum(version)]) == 0]) :
    "${REGISTRY}/${name}:${t}${trimprefix(stage, element(split("/", name), length(split("/", name)) - 1))}"])
}
