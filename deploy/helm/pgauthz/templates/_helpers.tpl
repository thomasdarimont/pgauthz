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

{{/* Resolve the reader's target Service host from reader.target. */}}
{{- define "pgauthz.readerHost" -}}
{{- if eq .Values.reader.target "rw" -}}{{ include "pgauthz.dbRW" . }}
{{- else if eq .Values.reader.target "ro" -}}{{ include "pgauthz.dbRO" . }}
{{- else -}}{{ include "pgauthz.dbPoolerRO" . }}
{{- end -}}
{{- end -}}

{{/* image "ref" helper: images.<key> -> repository:tag */}}
{{- define "pgauthz.image" -}}
{{- $img := . -}}{{ printf "%s:%s" $img.repository (toString $img.tag) }}
{{- end -}}

{{/* Map an extraRoles access tier to the privilege role it should inherit. */}}
{{- define "pgauthz.accessRole" -}}
{{- $m := dict "read" "authz_reader" "readwrite" "authz_writer" "audit" "authz_auditor" "admin" "authz_admin" -}}
{{- $r := index $m . -}}
{{- if not $r -}}{{- fail (printf "extraRoles: access must be one of read|readwrite|audit|admin, got %q" .) -}}{{- end -}}
{{- $r -}}
{{- end -}}

{{/*
Volume name for a store's hook ConfigMap (ADR 0011). Sanitization alone
collides ("Foo" and "foo" → "foo") and can exceed the 63-char k8s name limit
("store-hooks-" + a 63-char store name). Deterministic mapping:
  store-hooks-<first 40 chars of lower/underscore-sanitized name>-<8-char sha256 of the raw name>
12 + 40 + 1 + 8 = 61 ≤ 63; the hash disambiguates case/truncation collisions.
The mount PATH keeps the exact store name — this mapping never reaches the
Rego namespace or the ABI.
*/}}
{{- define "pgauthz.storeHooksVolume" -}}
store-hooks-{{ printf "%.40s" (. | lower | replace "_" "-") }}-{{ sha256sum . | trunc 8 }}
{{- end }}
