{{/* Common naming + label helpers. */}}

{{- define "pgauthz.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "pgauthz.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s" (include "pgauthz.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "pgauthz.labels" -}}
app.kubernetes.io/name: {{ include "pgauthz.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{/* CloudNativePG cluster name and its auto-generated Service names. */}}
{{- define "pgauthz.dbCluster" -}}{{ include "pgauthz.fullname" . }}-db{{- end -}}
{{- define "pgauthz.dbRW" -}}{{ include "pgauthz.dbCluster" . }}-rw{{- end -}}
{{- define "pgauthz.dbRO" -}}{{ include "pgauthz.dbCluster" . }}-ro{{- end -}}
{{- define "pgauthz.dbPoolerRO" -}}{{ include "pgauthz.dbCluster" . }}-pooler-ro{{- end -}}

{{/* Secret name holding the app passwords + OPA admin token. */}}
{{- define "pgauthz.secretName" -}}
{{- if .Values.secrets.existingSecret -}}{{ .Values.secrets.existingSecret }}{{- else -}}{{ include "pgauthz.fullname" . }}-secrets{{- end -}}
{{- end -}}

{{/* Resolve the reader's target Service host from postgrestReader.target. */}}
{{- define "pgauthz.readerHost" -}}
{{- if eq .Values.postgrestReader.target "rw" -}}{{ include "pgauthz.dbRW" . }}
{{- else if eq .Values.postgrestReader.target "ro" -}}{{ include "pgauthz.dbRO" . }}
{{- else -}}{{ include "pgauthz.dbPoolerRO" . }}
{{- end -}}
{{- end -}}

{{/* image "ref" helper: images.<key> -> repository:tag */}}
{{- define "pgauthz.image" -}}
{{- $img := . -}}{{ printf "%s:%s" $img.repository (toString $img.tag) }}
{{- end -}}
