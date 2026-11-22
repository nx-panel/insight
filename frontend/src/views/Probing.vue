<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Message from 'primevue/message'
import { api, type Endpoint, type NodeInfo } from '../api'
import { num, when } from '../format'

const { t } = useI18n()
const endpoints = ref<Endpoint[]>([])
const nodes = ref<NodeInfo[]>([])
const error = ref('')

onMounted(async () => {
  try {
    const [e, n] = await Promise.all([api.endpoints(), api.nodes().catch(() => [])])
    endpoints.value = e
    nodes.value = n
  } catch (e) {
    error.value = (e as Error).message
  }
})

const nodeName = (id: number) =>
  nodes.value.find((n) => n.nodeId === id)?.name || t('matrix.node', { id })

// The same thresholds as the detector's (detect.ProbedAt, QuietBelow).
const severity = (e: Endpoint) =>
  e.probed || e.score >= 40 ? 'danger' : e.score >= 20 ? 'warn' : 'secondary'
</script>

<template>
  <div class="stack">
    <h1>{{ t('probing.title') }}</h1>
    <p class="muted">{{ t('probing.intro') }}</p>
    <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
    <Message
      v-for="e in endpoints.filter((x) => x.probed)"
      :key="'s' + e.nodeId + e.inbound"
      severity="warn"
      :closable="false"
    >
      <b>{{ nodeName(e.nodeId) }}</b> <span class="mono ltr">{{ e.inbound }}</span>:
      {{ t('probing.rotate') }}
    </Message>
    <DataTable
      :value="endpoints"
      :data-key="(e: Endpoint) => e.nodeId + '/' + e.inbound"
      size="small"
    >
      <template #empty>{{ t('probing.empty') }}</template>
      <Column :header="t('probing.endpoint')">
        <template #body="{ data }">
          {{ nodeName(data.nodeId) }} <span class="mono ltr">{{ data.inbound }}</span>
        </template>
      </Column>
      <Column :header="t('probing.score')">
        <template #body="{ data }">
          <Tag :severity="severity(data)" :value="num(data.score)" />
        </template>
      </Column>
      <Column :header="t('probing.replayed')">
        <template #body="{ data }">{{ num(data.replayed) }}</template>
      </Column>
      <Column :header="t('probing.followUp')">
        <template #body="{ data }">
          {{ num(data.followUpFail) }}
          <span class="muted">{{ t('probing.normally', { n: num(data.followNormal) }) }}</span>
        </template>
      </Column>
      <Column :header="t('probing.scans')">
        <template #body="{ data }">
          <span v-if="data.noRoute || data.quicStray">
            {{ t('probing.scanCounts', { sni: num(data.noRoute), quic: num(data.quicStray) }) }}
          </span>
          <span v-else class="muted">—</span>
        </template>
      </Column>
      <Column :header="t('probing.probedSince')">
        <template #body="{ data }">
          <span v-if="data.probed">{{ when(data.probedAt) }}</span>
          <span v-else-if="data.probedAt" class="muted">{{
            t('probing.lastEpisode', { at: when(data.probedAt) })
          }}</span>
          <span v-else class="muted">—</span>
        </template>
      </Column>
      <Column :header="t('probing.followed')">
        <template #body="{ data }">
          <span v-if="data.followed === true">{{ t('probing.yes') }}</span>
          <span v-else-if="data.followed === false">{{ t('probing.no') }}</span>
          <span v-else class="muted">—</span>
        </template>
      </Column>
    </DataTable>
    <p class="muted small">{{ t('probing.how') }}</p>
  </div>
</template>

<style scoped>
h1 {
  margin: 0;
}
.small {
  font-size: 0.85rem;
}
.mono {
  white-space: nowrap;
}
</style>
