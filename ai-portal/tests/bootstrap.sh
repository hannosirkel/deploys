#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rendered="$(mktemp)"
bootstrap="$(mktemp --suffix=.js)"
trap 'rm -f "$rendered" "$bootstrap"' EXIT

kubectl kustomize "$root/overlays/live" >"$rendered"
ruby -ryaml - "$rendered" "$bootstrap" <<'RUBY'
documents = YAML.load_stream(File.read(ARGV.fetch(0)))
find = ->(kind, name) { documents.find { |item| item['kind'] == kind && item.dig('metadata', 'name') == name } }
config = find.call('ConfigMap', 'ai-portal-librechat-bootstrap')
job = find.call('Job', 'ai-portal-librechat-bootstrap-v1')
abort 'bootstrap ConfigMap or Job missing' unless config && job
abort 'policy must precede bootstrap Job' unless find.call('ConfigMap', 'ai-portal-librechat-policy').dig('metadata', 'annotations', 'argocd.argoproj.io/sync-wave') == '-20'
abort 'bootstrap must run after MongoDB' unless job.dig('metadata', 'annotations', 'argocd.argoproj.io/sync-wave') == '-10'
pod = job.dig('spec', 'template', 'spec')
abort 'bootstrap must not mount a service account token' unless pod['automountServiceAccountToken'] == false
abort 'bootstrap must not restart implicitly' unless pod['restartPolicy'] == 'Never'
egress = find.call('NetworkPolicy', 'allow-mongodb-egress')
abort 'bootstrap egress must be limited to MongoDB' unless egress.dig('spec', 'podSelector', 'matchExpressions', 0, 'values').sort == %w[backup bootstrap chat recovery] && egress.dig('spec', 'egress', 0, 'to', 0, 'podSelector', 'matchLabels') == {'app.kubernetes.io/component' => 'mongodb'} && egress.dig('spec', 'egress', 0, 'ports') == [{'port' => 27017, 'protocol' => 'TCP'}]
container = pod.fetch('containers').fetch(0)
abort 'bootstrap must use the pinned MongoDB image' unless container.fetch('image') == find.call('StatefulSet', 'ai-portal-mongodb-store').dig('spec', 'template', 'spec', 'containers', 0, 'image')
abort 'bootstrap must read MongoDB app credentials from ESO' unless container.fetch('env').any? { |item| item['name'] == 'MONGO_APP_PASSWORD' && item.dig('valueFrom', 'secretKeyRef') == {'name' => 'ai-portal-mongodb', 'key' => 'app-password'} }
abort 'bootstrap must mount policy read-only' unless container.fetch('volumeMounts').any? { |item| item['name'] == 'policy' && item['readOnly'] == true } && pod.fetch('volumes').any? { |item| item['name'] == 'policy' && item.dig('configMap', 'name') == 'ai-portal-librechat-policy' }
abort 'bootstrap must have a read-only root filesystem' unless container.dig('securityContext', 'readOnlyRootFilesystem') == true
abort 'bootstrap script missing' unless config.dig('data', 'bootstrap.js')
File.write(ARGV.fetch(1), config.dig('data', 'bootstrap.js'))
RUBY

node --check "$bootstrap"
node - "$bootstrap" "$root/base/admin-override.json" <<'NODE'
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const script = fs.readFileSync(process.argv[2], 'utf8');
const adminPath = process.argv[3];
const data = { roles: new Map(), configs: new Map() };
let writes = 0;
function collection(name) {
  return {
    updateOne(filter, update, options) {
      assert.equal(options.upsert, true);
      assert.equal(filter.tenantId, null);
      const key = filter.name ?? `${filter.principalType}:${filter.principalId}`;
      const before = data[name].get(key) ?? {};
      const after = { ...before, ...update.$set };
      if (JSON.stringify(before) !== JSON.stringify(after)) writes++;
      data[name].set(key, after);
      return { acknowledged: true };
    },
  };
}
function run(policyPath = adminPath) {
  const database = { roles: collection('roles'), configs: collection('configs') };
  vm.runInNewContext(script, {
    db: { getSiblingDB(name) { assert.equal(name, 'LibreChat'); return database; } },
    require(name) {
      assert.equal(name, 'fs');
      return { readFileSync(path) { assert.equal(path, '/policy/admin-override.json'); return fs.readFileSync(policyPath, 'utf8'); } };
    },
    print() {},
  });
}

assert.throws(() => run('/dev/null'));
assert.equal(writes, 0, 'invalid admin policy must fail before any database write');
run();
assert.deepEqual([...data.roles.keys()].sort(), ['USER', 'ai-portal-restricted', 'ai-portal-user']);
const baseline = data.roles.get('USER').permissions;
const ordinary = data.roles.get('ai-portal-user').permissions;
for (const profile of [baseline, ordinary, data.roles.get('ai-portal-restricted').permissions]) {
  for (const type of ['AGENTS', 'MCP_SERVERS', 'SKILLS', 'REMOTE_AGENTS']) {
    assert.equal(profile[type].USE, false);
    assert.equal(profile[type].CREATE, false);
  }
  for (const type of ['RUN_CODE', 'WEB_SEARCH', 'FILE_SEARCH']) assert.equal(profile[type].USE, false);
  assert.equal(profile.SHARED_LINKS.SHARE_PUBLIC, false);
}
assert.equal(baseline.PROMPTS.USE, false);
assert.equal(ordinary.PROMPTS.USE, true);
const admin = data.configs.get('role:ADMIN');
assert.equal(admin.principalModel, 'Role');
assert.equal(admin.isActive, true);
assert.equal(JSON.stringify(admin.overrides), JSON.stringify(JSON.parse(fs.readFileSync(adminPath, 'utf8'))));
const firstWrites = writes;
run();
assert.equal(writes, firstWrites, 'bootstrap must converge without modifying unchanged records');
console.log('LibreChat role bootstrap and admin override converge');
NODE
