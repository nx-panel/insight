<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import Message from 'primevue/message'
import { api, type Alert, type NodeInfo } from '../api'
import { asnLabel, num, when } from '../format'

const { t } = useI18n()
const alerts = ref<Alert[]>([])
const nodes = ref<NodeInfo[]>([])
const more = ref(true)
const error = ref('')

async function load(before?: number) {
  try {
    const got = await api.alerts(before)
    alerts.value = before ? [...alerts.value, ...got] : got
    more.value = got.length === 100
  } catch (e) {
    error.value = (e as Error).message
  }
}
onMounted(async () => {
  nodes.value = await api.nodes().catch(() => [])
  await load()
})

const nodeName = (id: number) =>
  nodes.value.find((n) => n.nodeId === id)?.name || t('matrix.node', { id })

const severity = (k: Alert['kind']) =>
  k === 'path.degraded'
    ? 'danger'
    : k === 'asn.outage' || k === 'endpoint.probed'
      ? 'warn'
      : 'success'

function reason(a: Alert) {
  let d: Record<string, number> = {}
  try {
    d = JSON.parse(a.detail || '{}')
  } catch {
    // older row
  }
  switch (a.reason) {
    case 'failures':
      return t('alerts.failures', {
        p: num(100 * (d.failRatio ?? 0)),
        n: num(100 * (d.normalFailRatio ?? 0)),
      })
    case 'drop':
      return t('alerts.drop', {
        p: num(d.authedPerHour ?? 0),
        n: num(d.normalAuthedPerHour ?? 0),
      })
    case 'early_close':
      return t('alerts.early', {
        p: num(100 * (d.earlyRatio ?? 0)),
        n: num(100 * (d.normalEarlyRatio ?? 0)),
      })
  }
  if (a.kind === 'asn.outage') return t('alerts.outageWhy', { n: num(d.nodes ?? 0) })
  if (a.kind === 'endpoint.probed')
    return t('alerts.probedWhy', { score: num(d.score ?? 0), n: num(d.replayed ?? 0) })
  return ''
}
</script>

<template>
  <div class="stack">
    <h1>{{ t('alerts.title') }}</h1>
    <p class="muted">{{ t('alerts.intro') }}</p>
    <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
    <p v-if="!alerts.length" class="muted">{{ t('alerts.empty') }}</p>
    <ul class="list">
      <li v-for="a in alerts" :key="a.id" class="card">
        <div class="head">
          <Tag :severity="severity(a.kind)" :value="t('alerts.kind.' + a.kind)" />
          <span class="muted">{{ when(a.at) }}</span>
        </div>
        <div v-if="a.kind.startsWith('endpoint.')">
          <b>{{ nodeName(a.nodeId) }}</b> <span class="mono ltr">{{ a.inbound }}</span>
        </div>
        <div v-else>
          <b>{{ asnLabel(a.asn, a.org) }}</b>
          <template v-if="a.kind.startsWith('path.')">
            <span class="dir-arrow">→</span> {{ nodeName(a.nodeId) }}
            <span class="mono ltr">{{ a.inbound }}/{{ a.network }}</span>
          </template>
        </div>
        <div v-if="reason(a)" class="muted">{{ reason(a) }}</div>
      </li>
    </ul>
    <Button
      v-if="more && alerts.length"
      :label="t('alerts.more')"
      text
      @click="load(alerts[alerts.length - 1]!.id)"
    />
  </div>
</template>

<style scoped>
h1 {
  margin: 0;
}
.list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}
.list .card {
  padding: 0.75rem 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}
.head {
  display: flex;
  gap: 0.75rem;
  align-items: center;
}
</style>
