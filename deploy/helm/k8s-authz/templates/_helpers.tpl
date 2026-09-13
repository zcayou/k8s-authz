{{- define "k8s-authz.serviceAccountSubject" -}}
- kind: ServiceAccount
  name: {{ include "common.serviceAccountName" . }}
  namespace: {{ .Release.Namespace }}
{{- end -}}
