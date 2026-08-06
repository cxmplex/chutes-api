{{- define "chutes.fullname" -}}
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
{{- end }}

{{- define "api.labels" -}}
app.kubernetes.io/name: api
{{- end }}

{{- define "socket.labels" -}}
app.kubernetes.io/name: socket
{{- end }}

{{- define "eventSocket.labels" -}}
app.kubernetes.io/name: event-socket
{{- end }}

{{- define "paymentWatcher.labels" -}}
app.kubernetes.io/name: payment-watcher
{{- end }}

{{- define "btTxTracker.labels" -}}
app.kubernetes.io/name: bt-tx-tracker
{{- end }}

{{- define "usageTracker.labels" -}}
app.kubernetes.io/name: usage-tracker
{{- end }}

{{- define "balanceRefresher.labels" -}}
app.kubernetes.io/name: balance-refresher
{{- end }}

{{- define "logProber.labels" -}}
app.kubernetes.io/name: log-prober
{{- end }}

{{- define "serverHealthProber.labels" -}}
app.kubernetes.io/name: server-health-prober
{{- end }}

{{- define "graval.labels" -}}
app.kubernetes.io/name: graval
{{- end }}

{{- define "gravaldb.labels" -}}
app.kubernetes.io/name: gravaldb
{{- end }}

{{- define "gravalWorker.labels" -}}
app.kubernetes.io/name: graval-worker
{{- end }}

{{- define "watchtower.labels" -}}
app.kubernetes.io/name: watchtower
{{- end }}

{{- define "cacher.labels" -}}
app.kubernetes.io/name: cacher
{{- end }}

{{- define "chuteAutoscaler.labels" -}}
app.kubernetes.io/name: chute-autoscaler
{{- end }}

{{- define "chuteAutoscalerDryrun.labels" -}}
app.kubernetes.io/name: chute-autoscaler-dryrun
{{- end }}

{{- define "autostaker.labels" -}}
app.kubernetes.io/name: autostaker
{{- end }}

{{- define "cpuScheduler.labels" -}}
app.kubernetes.io/name: cpu-scheduler
redis-access: "true"
db-access: "true"
{{- end }}

{{- define "gpuPlatformScheduler.labels" -}}
app.kubernetes.io/name: gpu-platform-scheduler
redis-access: "true"
db-access: "true"
{{- end }}

{{- define "forge.labels" -}}
app.kubernetes.io/name: forge
{{- end }}

{{- define "remoteForge.labels" -}}
app.kubernetes.io/name: remote-forge
redis-access: "true"
db-access: "true"
{{- end }}

{{- define "metasync.labels" -}}
app.kubernetes.io/name: metagraph-syncer
{{- end }}

{{- define "weightsetter.labels" -}}
app.kubernetes.io/name: weightsetter
{{- end }}

{{- define "cmRedis.labels" -}}
app.kubernetes.io/name: cm-redis
{{- end }}

{{- define "quotaRedis.labels" -}}
app.kubernetes.io/name: quota-redis
{{- end }}


{{- define "registry.labels" -}}
app.kubernetes.io/name: registry
{{- end }}

{{- define "registryProxy.labels" -}}
app.kubernetes.io/name: registry-proxy
{{- end }}

{{- define "attestationProxy.labels" -}}
app.kubernetes.io/name: attestation-proxy
{{- end }}

{{- define "claudeProxy.labels" -}}
app.kubernetes.io/name: claude-proxy
{{- end }}

{{- define "pgRouter.labels" -}}
app.kubernetes.io/name: pg-router
{{- end }}

{{- define "responsesProxy.labels" -}}
app.kubernetes.io/name: responses-proxy
{{- end }}

{{- define "connProber.labels" -}}
app.kubernetes.io/name: conn-prober
{{- end }}

{{- define "auditExporter.labels" -}}
app.kubernetes.io/name: audit-exporter
{{- end }}

{{- define "failedChuteCleanup.labels" -}}
app.kubernetes.io/name: failed-chute-cleanup
{{- end }}

{{/*
NetworkPolicy access label helpers.
Include chutes.dbAccess and/or chutes.redisAccess in the spec.selector.matchLabels
and spec.template.metadata.labels of any Deployment/CronJob that needs those policies.
*/}}
{{- define "chutes.dbAccess" -}}
db-access: "true"
{{- end }}

{{- define "chutes.redisAccess" -}}
redis-access: "true"
{{- end }}

{{/*
Client-IP boundary for every external ingress that routes directly to the API.
Cloudflare's header is trusted only when the ingress itself is source-restricted.
The proxy header configuration must be included in a location-scoped
configuration-snippet because generated ingress locations set proxy headers.
*/}}
{{- define "chutes.apiIngressClientIpValidation" -}}
{{- $ingress := .Values.ingress -}}
{{- if not (kindIs "map" $ingress) -}}
{{- fail "ingress must be a map" -}}
{{- end -}}
{{- $cloudflareClientIp := get $ingress "cloudflareClientIp" -}}
{{- if not (kindIs "map" $cloudflareClientIp) -}}
{{- fail "ingress.cloudflareClientIp must be a map" -}}
{{- end -}}
{{- range $key, $_ := $cloudflareClientIp -}}
{{- if ne $key "enabled" -}}
{{- fail (printf "ingress.cloudflareClientIp contains unsupported key %q" $key) -}}
{{- end -}}
{{- end -}}
{{- if not (hasKey $cloudflareClientIp "enabled") -}}
{{- fail "ingress.cloudflareClientIp.enabled is required" -}}
{{- end -}}
{{- if not (kindIs "bool" (get $cloudflareClientIp "enabled")) -}}
{{- fail "ingress.cloudflareClientIp.enabled must be a boolean" -}}
{{- end -}}
{{- end }}

{{- define "chutes.apiIngressClientIpConfiguration" -}}
{{- include "chutes.apiIngressClientIpValidation" . -}}
{{- if (get .Values.ingress.cloudflareClientIp "enabled") -}}
proxy_set_header X-Resolved-IP $http_cf_connecting_ip;
{{- else -}}
proxy_set_header X-Resolved-IP $remote_addr;
{{- end -}}
{{- end }}

{{- define "chutes.apiIngressClientIpAnnotations" -}}
{{- include "chutes.apiIngressClientIpValidation" . -}}
{{- if and (get .Values.ingress.cloudflareClientIp "enabled") (empty (trim .Values.ingress.whitelistSourceRange)) -}}
{{- fail "ingress.cloudflareClientIp.enabled requires a non-empty ingress.whitelistSourceRange" -}}
{{- end -}}
{{- with .Values.ingress.whitelistSourceRange }}
nginx.ingress.kubernetes.io/whitelist-source-range: {{ . | quote }}
{{- end }}
{{- end }}

{{- define "chutes.sensitiveEnv" -}}
- name: CLLMV_X25519_PRIVATE_KEY
  valueFrom:
    secretKeyRef:
      key: key
      name: cllmv-pkey
- name: PS_OP
  valueFrom:
    secretKeyRef:
      key: key
      name: inspecto
- name: HCAPTCHA_SITEKEY
  valueFrom:
   secretKeyRef:
     key: sitekey
     name: hcaptcha-config
- name: HCAPTCHA_SECRET
  valueFrom:
   secretKeyRef:
     key: secret
     name: hcaptcha-config
- name: CFSV_OP
  valueFrom:
   secretKeyRef:
     key: key
     name: cfsvop
- name: LAUNCH_CONFIG_KEY
  valueFrom:
    secretKeyRef:
      name: launch-config
      key: key
- name: CHUTEFS_TOKEN_KEY_ID
  valueFrom:
    secretKeyRef:
      name: chutefs-token-keys
      key: bootstrap-key-id
- name: CHUTEFS_TOKEN_KEYS_JSON
  valueFrom:
    secretKeyRef:
      name: chutefs-token-keys
      key: keyring-json
- name: CHUTEFS_TOKEN_REPLICA_ID
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
- name: CHUTEFS_TOKEN_REPLICA_COHORT
  value: {{ printf "%s-api" (include "chutes.fullname" .) | quote }}
- name: CHUTEFS_TOKEN_REQUIRED_ACK_COUNT
  value: {{ required "api.chutefsTokenRequiredAckCount is required" .Values.api.chutefsTokenRequiredAckCount | quote }}
- name: GPU_REGISTRATION_RECOVERY_KEY_ID
  valueFrom:
    secretKeyRef:
      name: gpu-registration-recovery-keys
      key: active-key-id
- name: GPU_REGISTRATION_RECOVERY_KEYS_JSON
  valueFrom:
    secretKeyRef:
      name: gpu-registration-recovery-keys
      key: keyring-json
- name: GPU_REGISTRATION_RECOVERY_REPLICA_ID
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
- name: GPU_REGISTRATION_RECOVERY_REPLICA_COHORT
  value: {{ printf "%s-api" (include "chutes.fullname" .) | quote }}
- name: GPU_REGISTRATION_RECOVERY_REQUIRED_ACK_COUNT
  value: {{ required "api.gpuRegistrationRecoveryRequiredAckCount is required" .Values.api.gpuRegistrationRecoveryRequiredAckCount | quote }}
- name: ENVDUMP_UNLOCK
  valueFrom:
    secretKeyRef:
      key: token
      name: envdump
- name: CODECHECK_KEY
  valueFrom:
    secretKeyRef:
      name: codecheck-key
      key: key
- name: IP_CHECK_SALT
  valueFrom:
    secretKeyRef:
      name: ip-check-salt
      key: salt
- name: VALIDATOR_SEED
  valueFrom:
    secretKeyRef:
      name: validator-credentials
      key: seed
- name: WALLET_KEY
  valueFrom:
    secretKeyRef:
      name: wallet-secret
      key: wallet-key
- name: PG_ENCRYPTION_KEY
  valueFrom:
    secretKeyRef:
      name: wallet-secret
      key: pg-key
{{- end }}

{{/*
Trusted client-IP headers require ingress isolation around the API. A non-empty chart trust list
is valid only when this chart renders a non-empty API ingress policy, or the deployment explicitly
acknowledges that an equivalent policy is managed outside this chart.
*/}}
{{- define "chutes.apiIsolationValidation" -}}
{{- $networkPolicies := .Values.networkPolicies -}}
{{- if not (kindIs "map" $networkPolicies) -}}
{{- fail "networkPolicies must be a map" -}}
{{- end -}}
{{- $apiPolicy := get $networkPolicies "api" -}}
{{- if not (kindIs "map" $apiPolicy) -}}
{{- fail "networkPolicies.api must be a map" -}}
{{- end -}}
{{- range $key, $_ := $apiPolicy -}}
{{- if not (or (eq $key "enabled") (eq $key "ingressPeers") (eq $key "externalPolicyAcknowledged")) -}}
{{- fail (printf "networkPolicies.api contains unsupported key %q" $key) -}}
{{- end -}}
{{- end -}}
{{- $networkPoliciesEnabled := get $networkPolicies "enabled" -}}
{{- if not (kindIs "bool" $networkPoliciesEnabled) -}}
{{- fail "networkPolicies.enabled must be a boolean" -}}
{{- end -}}
{{- $apiPolicyEnabled := get $apiPolicy "enabled" -}}
{{- if not (kindIs "bool" $apiPolicyEnabled) -}}
{{- fail "networkPolicies.api.enabled must be a boolean" -}}
{{- end -}}
{{- $externalPolicyAcknowledged := get $apiPolicy "externalPolicyAcknowledged" -}}
{{- if not (kindIs "bool" $externalPolicyAcknowledged) -}}
{{- fail "networkPolicies.api.externalPolicyAcknowledged must be a boolean" -}}
{{- end -}}
{{- $apiPeers := get $apiPolicy "ingressPeers" -}}
{{- if not (kindIs "slice" $apiPeers) -}}
{{- fail "networkPolicies.api.ingressPeers must be a list" -}}
{{- end -}}
{{- range $index, $peer := $apiPeers -}}
{{- if not (kindIs "map" $peer) -}}
{{- fail (printf "networkPolicies.api.ingressPeers[%d] must be a map" $index) -}}
{{- end -}}
{{- range $key, $_ := $peer -}}
{{- if not (or (eq $key "namespaceSelector") (eq $key "podSelector")) -}}
{{- fail (printf "networkPolicies.api.ingressPeers[%d] contains unsupported key %q" $index $key) -}}
{{- end -}}
{{- end -}}
{{- if not (and (hasKey $peer "namespaceSelector") (hasKey $peer "podSelector")) -}}
{{- fail (printf "networkPolicies.api.ingressPeers[%d] requires namespaceSelector and podSelector" $index) -}}
{{- end -}}
{{- range $selectorName := list "namespaceSelector" "podSelector" -}}
{{- $selector := get $peer $selectorName -}}
{{- if not (kindIs "map" $selector) -}}
{{- fail (printf "networkPolicies.api.ingressPeers[%d].%s must be a map" $index $selectorName) -}}
{{- end -}}
{{- range $key, $_ := $selector -}}
{{- if ne $key "matchLabels" -}}
{{- fail (printf "networkPolicies.api.ingressPeers[%d].%s contains unsupported key %q" $index $selectorName $key) -}}
{{- end -}}
{{- end -}}
{{- if not (hasKey $selector "matchLabels") -}}
{{- fail (printf "networkPolicies.api.ingressPeers[%d].%s requires matchLabels" $index $selectorName) -}}
{{- end -}}
{{- $matchLabels := get $selector "matchLabels" -}}
{{- if not (kindIs "map" $matchLabels) -}}
{{- fail (printf "networkPolicies.api.ingressPeers[%d].%s.matchLabels must be a map" $index $selectorName) -}}
{{- end -}}
{{- if empty $matchLabels -}}
{{- fail (printf "networkPolicies.api.ingressPeers[%d].%s.matchLabels must not be empty" $index $selectorName) -}}
{{- end -}}
{{- range $labelKey, $labelValue := $matchLabels -}}
{{- if not (kindIs "string" $labelKey) -}}
{{- fail (printf "networkPolicies.api.ingressPeers[%d].%s.matchLabels keys must be strings" $index $selectorName) -}}
{{- end -}}
{{- if empty (trim $labelKey) -}}
{{- fail (printf "networkPolicies.api.ingressPeers[%d].%s.matchLabels keys must not be empty" $index $selectorName) -}}
{{- end -}}
{{- if not (kindIs "string" $labelValue) -}}
{{- fail (printf "networkPolicies.api.ingressPeers[%d].%s.matchLabels[%q] must be a string" $index $selectorName $labelKey) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $trustedProxyCidrs := .Values.trustedProxyCidrs -}}
{{- if not (kindIs "string" $trustedProxyCidrs) -}}
{{- fail "trustedProxyCidrs must be a string" -}}
{{- end -}}
{{- $chartPolicyActive := and $networkPoliciesEnabled $apiPolicyEnabled (gt (len $apiPeers) 0) -}}
{{- if and (not (empty (trim $trustedProxyCidrs))) (not (or $chartPolicyActive $externalPolicyAcknowledged)) -}}
{{- fail "trustedProxyCidrs requires networkPolicies.enabled=true with networkPolicies.api.enabled=true and non-empty networkPolicies.api.ingressPeers, or networkPolicies.api.externalPolicyAcknowledged=true" -}}
{{- end -}}
{{- end }}

{{- define "chutes.commonEnv" -}}
{{- include "chutes.apiIsolationValidation" . -}}
- name: GRAVAL_URL
  value: https://graval.chutes.ai
- name: REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: redis-secret
      key: password
- name: REDIS_HOST
  value: {{ .Values.redis.host | quote }}
- name: REDIS_PORT
  value: {{ .Values.redis.port | quote }}
- name: TRUSTED_PROXY_CIDRS
  value: {{ .Values.trustedProxyCidrs | quote }}
{{- if .Values.redis.cacertSecret }}
- name: REDIS_CACERT
  value: "/etc/redis-cacert/cacert.pem"
{{- end }}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: postgres-secret
      key: password
- name: POSTGRESQL
  valueFrom:
    secretKeyRef:
      name: postgres-secret
      key: url
- name: POSTGRESQL_RO
  valueFrom:
    secretKeyRef:
      name: postgres-secret
      key: readonly_url
{{- if .Values.s3ProxyUrl }}
- name: S3_PROXY_URL
  value: {{ .Values.s3ProxyUrl | quote }}
{{- end }}
- name: AWS_ACCESS_KEY_ID
  valueFrom:
    secretKeyRef:
      name: {{ .Values.s3SecretName | default "s3-credentials" }}
      key: access-key-id
- name: AWS_SECRET_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.s3SecretName | default "s3-credentials" }}
      key: secret-access-key
- name: AWS_ENDPOINT_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.s3SecretName | default "s3-credentials" }}
      key: endpoint-url
- name: AWS_REGION
  valueFrom:
    secretKeyRef:
      name: {{ .Values.s3SecretName | default "s3-credentials" }}
      key: aws-region
- name: STORAGE_BUCKET
  valueFrom:
    secretKeyRef:
      name: {{ .Values.s3SecretName | default "s3-credentials" }}
      key: bucket
- name: REGISTRY_PASSWORD
  valueFrom:
    secretKeyRef:
      name: registry-secret
      key: password
- name: REGISTRY_INSECURE
  value: "true"
{{- end -}}

{{/*
Logging env for long-running services. LOG_FORMAT=json switches loguru to emit one
JSON object per line on stdout (see api/log.py configure_structured_logging); the node
Fluent Bit DaemonSet collects and enriches that stdout. Unset = human-readable stderr.
*/}}
{{- define "chutes.loggingEnv" -}}
- name: LOG_FORMAT
  value: {{ .Values.logFormat | default "json" | quote }}
{{- if .Values.logLevel }}
- name: LOG_LEVEL
  value: {{ .Values.logLevel | quote }}
{{- end }}
{{- end -}}

{{/*
Volume definition for the managed Redis TLS CA certificate.
Only emits when redis.cacertSecret is set.
*/}}
{{- define "chutes.redisCacertVolume" -}}
{{- if .Values.redis.cacertSecret }}
- name: redis-cacert
  secret:
    secretName: {{ .Values.redis.cacertSecret }}
    defaultMode: {{ .Values.redis.cacertMode | default 0444 }}
    items:
    - key: ca
      path: cacert.pem
{{- end }}
{{- end }}

{{/*
VolumeMount for the managed Redis TLS CA certificate.
Only emits when redis.cacertSecret is set.
*/}}
{{- define "chutes.redisCacertMount" -}}
{{- if .Values.redis.cacertSecret }}
- mountPath: /etc/redis-cacert
  name: redis-cacert
  readOnly: true
{{- end }}
{{- end }}

{{/*
Pod-level security context (seccompProfile).
*/}}
{{- define "chutes.podSecurityContext" -}}
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/*
Container-level security context (drops NET_RAW capability).
*/}}
{{- define "chutes.containerSecurityContext" -}}
capabilities:
  drop:
  - NET_RAW
{{- end }}

{{/*
Build a fully-qualified image reference.
Usage: {{ include "chutes.image" (list . .Values.api.image) | quote }}
Prepends .Values.imageRegistry (with trailing slash stripped) when set.
Public Docker Hub images (redis, etc.) are passed directly
via their own values keys without going through this helper.
*/}}
{{- define "chutes.image" -}}
{{- $root := index . 0 -}}
{{- $img  := index . 1 -}}
{{- $reg  := $root.Values.imageRegistry | default "" | trimSuffix "/" -}}
{{- if $reg -}}
{{- printf "%s/%s" $reg $img -}}
{{- else -}}
{{- $img -}}
{{- end -}}
{{- end }}

{{/*
Default node tolerations for amd64 architecture.
*/}}
{{- define "chutes.defaultTolerations" -}}
- effect: NoSchedule
  key: kubernetes.io/arch
  operator: Equal
  value: amd64
{{- end }}

{{/*
CronJob container resources. CronJobs in prod carry only an ephemeral-storage
limit (cpu/memory are requests-only); render that shape regardless of any
cpu/memory limits present in merged values.
*/}}
{{- define "chutes.cronjobResources" -}}
{{- $lim := .limits | default dict -}}
requests:
  {{- toYaml .requests | nindent 2 }}
limits:
  ephemeral-storage: {{ index $lim "ephemeral-storage" | default "1Gi" | quote }}
{{- end }}

{{/*
Minimal env block used by most CronJobs:
Redis connection + Validator SS58 + Postgres credentials.
*/}}
{{- define "chutes.cronjobEnv" -}}
- name: VALIDATOR_SS58
{{- if .ss58Literal }}
  value: {{ .ss58Literal | quote }}
{{- else }}
  valueFrom:
    secretKeyRef:
      name: validator-credentials
      key: ss58
{{- end }}
- name: REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: redis-secret
      key: password
- name: REDIS_HOST
  value: {{ .Values.redis.host | quote }}
- name: REDIS_PORT
  value: {{ .Values.redis.port | quote }}
{{- if .Values.redis.cacertSecret }}
- name: REDIS_CACERT
  value: "/etc/redis-cacert/cacert.pem"
{{- end }}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: postgres-secret
      key: password
- name: POSTGRESQL
  valueFrom:
    secretKeyRef:
      name: postgres-secret
      key: url
- name: POSTGRESQL_RO
  valueFrom:
    secretKeyRef:
      name: postgres-secret
      key: readonly_url
{{- end }}

{{/*
CronJob Job/pod retention. Resolution order: per-job override -> global .Values.cronjobDefaults -> hard default.
Call with: (dict "root" . "job" .Values.<jobKey>)
*/}}
{{- define "chutes.successfulJobsHistoryLimit" -}}
{{- $job := .job | default dict -}}
{{- $def := .root.Values.cronjobDefaults | default dict -}}
{{- $job.successfulJobsHistoryLimit | default $def.successfulJobsHistoryLimit | default 3 -}}
{{- end }}

{{- define "chutes.failedJobsHistoryLimit" -}}
{{- $job := .job | default dict -}}
{{- $def := .root.Values.cronjobDefaults | default dict -}}
{{- $job.failedJobsHistoryLimit | default $def.failedJobsHistoryLimit | default 3 -}}
{{- end }}

{{- define "chutes.ttlSecondsAfterFinished" -}}
{{- $job := .job | default dict -}}
{{- $def := .root.Values.cronjobDefaults | default dict -}}
{{- $job.ttlSecondsAfterFinished | default $def.ttlSecondsAfterFinished | default 3600 -}}
{{- end }}
