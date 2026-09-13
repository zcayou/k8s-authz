{{/*
ClusterRoleBinding tying the chart's ServiceAccount to a ClusterRole of the
same fullname. The ClusterRole itself is chart-specific and stays per-chart.
Consume from a chart's clusterrolebinding.yaml:
  {{ include "common.clusterrolebinding" . }}
*/}}
{{- define "common.clusterrolebinding" -}}
{{- if .Values.rbac.create -}}
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {{ include "common.fullname" . }}
  labels:
    {{- include "common.labels" . | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {{ include "common.fullname" . }}
subjects:
  - kind: ServiceAccount
    name: {{ include "common.serviceAccountName" . }}
    namespace: {{ .Release.Namespace }}
{{- end }}
{{- end -}}
