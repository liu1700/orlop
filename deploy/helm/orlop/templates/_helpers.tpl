{{/* Expand the chart name. */}}
{{- define "orlop.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully-qualified app name (release-scoped). */}}
{{- define "orlop.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "orlop.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "orlop.labels" -}}
app.kubernetes.io/name: {{ include "orlop.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- with .Chart.AppVersion }}
app.kubernetes.io/version: {{ . | quote }}
{{- end }}
{{- end -}}

{{/* Control-plane object + Service name. */}}
{{- define "orlop.control.name" -}}
{{- printf "%s-control" (include "orlop.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Server object + Service name. This is deliberately serverFQDN itself (not a
release-scoped name): the server's self-provisioned cert SAN is serverFQDN, and
clients connect via the Service DNS name, so the two MUST be identical. Deriving
the Service name from serverFQDN makes fqdn_not_allowed impossible to hit.
*/}}
{{- define "orlop.server.name" -}}
{{- required "serverFQDN is required" .Values.serverFQDN | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* The Secret holding the shared token, enc key, and DB URL. */}}
{{- define "orlop.secretName" -}}
{{- if .Values.auth.existingSecret -}}
{{- .Values.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "orlop.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* In-cluster URL the server uses to reach the control plane for self-provisioning. */}}
{{- define "orlop.controlURL" -}}
{{- printf "http://%s:%d" (include "orlop.control.name" .) (int .Values.control.port) -}}
{{- end -}}

{{/* Resolved image refs (tag falls back to appVersion). */}}
{{- define "orlop.control.image" -}}
{{- printf "%s/%s:%s" .Values.image.registry .Values.image.control.repository (default .Chart.AppVersion .Values.image.control.tag) -}}
{{- end -}}
{{- define "orlop.server.image" -}}
{{- printf "%s/%s:%s" .Values.image.registry .Values.image.server.repository (default .Chart.AppVersion .Values.image.server.tag) -}}
{{- end -}}
