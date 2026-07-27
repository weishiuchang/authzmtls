{{/*
Standard chart naming helpers, kept separate so the other templates stay
focused on authzmtls-specific decisions.
*/}}

{{- define "authzmtls.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "authzmtls.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "authzmtls.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "authzmtls.labels" -}}
helm.sh/chart: {{ include "authzmtls.chart" . }}
{{ include "authzmtls.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "authzmtls.selectorLabels" -}}
app.kubernetes.io/name: {{ include "authzmtls.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "authzmtls.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "authzmtls.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Container port is derived from config.server.listen_addr, not a separate
field, so it can't drift from what the process actually binds.
*/}}
{{- define "authzmtls.containerPort" -}}
{{- .Values.config.server.listen_addr | splitList ":" | last -}}
{{- end -}}
