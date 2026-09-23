#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rendered="$(mktemp)"
trap 'rm -f -- "$rendered"' EXIT
kubectl kustomize "$root/overlays/live" >"$rendered"
test -s "$rendered"

ruby -ryaml - "$rendered" <<'RUBY'
documents = YAML.load_stream(File.read(ARGV.fetch(0)))
def resource(documents, kind, name)
  matches = documents.select { |item| item['kind'] == kind && item.dig('metadata', 'name') == name }
  raise "expected one #{kind}/#{name}, got #{matches.length}" unless matches.length == 1
  matches.first
end

statefulset = resource(documents, 'StatefulSet', 'ai-portal-mongodb-store')
raise 'old zero-replica StatefulSet must be pruned rather than updated across immutable claim templates' if documents.any? { |item| item['kind'] == 'StatefulSet' && item.dig('metadata', 'name') == 'ai-portal-mongodb' }
pod = statefulset.dig('spec', 'template', 'spec')
container = pod.fetch('containers').fetch(0)
raise 'MongoDB must run as a non-root user' unless pod.dig('securityContext', 'runAsNonRoot') == true
raise 'MongoDB must not mount a service account token' unless pod['automountServiceAccountToken'] == false
raise 'MongoDB must have a read-only root filesystem' unless container.dig('securityContext', 'readOnlyRootFilesystem') == true
raise 'MongoDB image must be pinned by digest' unless container['image'].match?(/\Amongo:8\.0\.32@sha256:[0-9a-f]{64}\z/)
raise 'MongoDB must not create an unbound PVC while scaled to zero' if documents.any? { |item| item['kind'] == 'PersistentVolumeClaim' && item.dig('metadata', 'name') == 'ai-portal-mongodb' }
claim = statefulset.dig('spec', 'volumeClaimTemplates', 0)
raise 'MongoDB must create its 5 GiB data PVC with its first pod' unless claim.dig('metadata', 'name') == 'data' && claim.dig('spec', 'accessModes') == ['ReadWriteOnce'] && claim.dig('spec', 'storageClassName') == 'local-path' && claim.dig('spec', 'resources', 'requests', 'storage') == '5Gi'
raise 'MongoDB must mount its generated claim' unless container.fetch('volumeMounts').any? { |mount| mount['name'] == 'data' && mount['mountPath'] == '/data/db' }
raise 'MongoDB must enable root authentication' unless container.fetch('env').any? { |item| item['name'] == 'MONGO_INITDB_ROOT_PASSWORD' && item.dig('valueFrom', 'secretKeyRef') == { 'name' => 'ai-portal-mongodb', 'key' => 'root-password' } }
raise 'MongoDB app credential must come from ESO Secret' unless container.fetch('env').any? { |item| item['name'] == 'MONGO_APP_PASSWORD' && item.dig('valueFrom', 'secretKeyRef') == { 'name' => 'ai-portal-mongodb', 'key' => 'app-password' } }
raise 'MongoDB init must create only LibreChat readWrite user' unless resource(documents, 'ConfigMap', 'ai-portal-mongodb-init').dig('data', '10-librechat-user.js').include?('roles: [{role: "readWrite", db: "LibreChat"}]')
%w[startupProbe readinessProbe livenessProbe].each do |probe|
  command = container.dig(probe, 'exec', 'command').join(' ')
  raise "#{probe} must authenticate" unless command.include?('--authenticationDatabase admin') && command.include?('--password')
end

service = resource(documents, 'Service', 'ai-portal-mongodb')
raise 'MongoDB must stay ClusterIP-only' unless service.dig('spec', 'type') == 'ClusterIP'
raise 'default deny missing' unless resource(documents, 'NetworkPolicy', 'default-deny').dig('spec', 'policyTypes').sort == %w[Egress Ingress]
backup_egress = resource(documents, 'NetworkPolicy', 'allow-backup-https-egress')
raise 'backup egress must select only backup pods' unless backup_egress.dig('spec', 'podSelector', 'matchLabels') == { 'app.kubernetes.io/component' => 'backup' }
raise 'backup egress must be TCP 443 only' unless backup_egress.dig('spec', 'egress', 0, 'ports') == [{ 'port' => 443, 'protocol' => 'TCP' }]
destinations = backup_egress.dig('spec', 'egress', 0, 'to').map { |peer| peer.fetch('ipBlock').fetch('cidr') }
raise 'backup egress must target published Backblaze IPv4 ranges only' unless destinations == %w[45.11.36.0/22 104.153.232.0/21 149.137.128.0/20 206.190.208.0/21 207.166.148.0/22]
ingress = resource(documents, 'NetworkPolicy', 'allow-mongodb-ingress').dig('spec', 'ingress')
raise 'MongoDB ingress must be limited to chat, backup, and recovery pods' unless ingress.fetch(0).dig('from', 0, 'podSelector', 'matchExpressions', 0, 'values').sort == %w[backup chat recovery]
raise 'MongoDB ingress must use only port 27017' unless ingress.fetch(0)['ports'] == [{ 'port' => 27017, 'protocol' => 'TCP' }]
puts 'AI Portal MongoDB authentication, storage, and network contracts hold'
RUBY
