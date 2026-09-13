{{/*
Image reference from an image dict, so an image can be rendered wherever it sits in
values — not just at .Values.image. Honours, in precedence order: override (used
verbatim), then repository with an optional :tag and an optional @digest (applied when
useDigest is set). defaultTag fills in an empty tag; pass .Chart.AppVersion for a
chart's primary image and omit it for sidecars that pin their own tag.

  image: {{ include "common.imageRef" (dict "image" .Values.node.registrar.image) }}
  image: {{ include "common.imageRef" (dict "image" .Values.image "defaultTag" .Chart.AppVersion) }}
*/}}
{{- define "common.imageRef" -}}
{{- $image := .image -}}
{{- if $image.override -}}
{{- $image.override -}}
{{- else -}}
{{- $ref := $image.repository -}}
{{- $tag := $image.tag | default .defaultTag | default "" -}}
{{- if ne $tag "" -}}
{{- $ref = printf "%s:%s" $ref $tag -}}
{{- end -}}
{{- if and ($image.useDigest | default false) $image.digest -}}
{{- $ref = printf "%s@%s" $ref $image.digest -}}
{{- end -}}
{{- $ref -}}
{{- end -}}
{{- end -}}

{{/*
A chart's primary image at .Values.image, with the tag defaulting to .Chart.AppVersion.
Shorthand for the common case; common.imageRef covers everything else.
*/}}
{{- define "common.image" -}}
{{- include "common.imageRef" (dict "image" .Values.image "defaultTag" .Chart.AppVersion) -}}
{{- end -}}

{{/*
Pod scheduling block (nodeSelector, affinity, tolerations,
topologySpreadConstraints). Emit at pod-spec level:
  {{- include "common.pod.scheduling" . | nindent 6 }}
Returns empty when none of the four values are set. The trim keeps the
leading newline out so a single nindent at the call site renders cleanly.
*/}}
{{- define "common.pod.scheduling" -}}
{{- include "common.pod.schedulingBlock" . | trim -}}
{{- end -}}

{{- define "common.pod.schedulingBlock" -}}
{{- with .Values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.topologySpreadConstraints }}
topologySpreadConstraints:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}
