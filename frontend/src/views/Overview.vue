<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import Message from 'primevue/message'
import SelectButton from 'primevue/selectbutton'
import Select from 'primevue/select'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import { api, type Cell, type Matrix, type Status, type Suggestion } from '../api'
import { asnLabel, health, num, pct, when } from '../format'

const { t } = useI18n()
const status = ref<Status>()
const matrix = ref<Matrix>()
const suggestions = ref<Suggestion[]>([])
const hours = ref(24)
const by = ref<'asn' | 'region'>('asn')
const network = ref<'all' | 'tcp' | 'udp'>('all')
const showAll = ref(false)
const error = ref('')
const loading = ref(false)

const hourChoices = computed(() => [
  { label: t('matrix.hour1'), value: 1 },
  { label: t('matrix.hour6'), value: 6 },
  { label: t('matrix.day'), value: 24 },
  { label: t('matrix.week'), value: 168 },
])
const byChoices = computed(() => [
  { label: t('matrix.byAsn'), value: 'asn' },
  { label: t('matrix.byRegion'), value: 'region' },
])
const networkChoices = computed(() => [
  { label: t('matrix.allNetworks'), value: 'all' },
  { label: 'TCP', value: 'tcp' },
  { label: 'UDP', value: 'udp' },
])

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [s, m, g] = await Promise.all([
      api.status(),
      api.matrix(hours.value, by.value),
      api.suggestions(),
    ])
    status.value = s
    matrix.value = m
    suggestions.value = g
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    loading.value = false
  }
}
watch([hours, by], load)
let timer = 0
onMounted(() => {
  void load()
  timer = window.setInterval(load, 60_000)
})
onUnmounted(() => window.clearInterval(timer))

const nodeName = (id: number) =>
  matrix.value?.nodes.find((n) => n.nodeId === id)?.name || t('matrix.node', { id })

// Columns are node × inbound; rows are client networks (or regions).
interface Column {
  key: string
  nodeId: number
  inbound: string
}
interface Row {
  key: string
  label: string
  sub: string
  total: number
  cells: Map<string, Cell>
}

const cells = computed(() =>
  (matrix.value?.cells ?? []).filter((c) => network.value === 'all' || c.network === network.value),
)

const columns = computed<Column[]>(() => {
  const seen = new Map<string, Column>()
  for (const c of cells.value) {
    const key = `${c.nodeId}/${c.inbound}`
    if (!seen.has(key)) seen.set(key, { key, nodeId: c.nodeId, inbound: c.inbound })
  }
  return [...seen.values()].toSorted(
    (a, b) => a.nodeId - b.nodeId || a.inbound.localeCompare(b.inbound),
  )
})

const rows = computed<Row[]>(() => {
  const out = new Map<string, Row>()
  for (const c of cells.value) {
    const key = by.value === 'region' ? `${c.country}/${c.region ?? ''}` : `${c.asn}`
    let row = out.get(key)
    if (!row) {
      row =
        by.value === 'region'
          ? {
              key,
              label: c.region || t('matrix.noRegion'),
              sub: c.country,
              total: 0,
              cells: new Map(),
            }
          : { key, label: asnLabel(c.asn, c.org), sub: c.country, total: 0, cells: new Map() }
      out.set(key, row)
    }
    row.total += c.accepted
    const col = `${c.nodeId}/${c.inbound}`
    const have = row.cells.get(col)
    if (have) {
      have.accepted += c.accepted
      have.authed += c.authed
      have.failed += c.failed
      have.earlyClose += c.earlyClose
      // Weighted by its samples: a UDP side with none must not halve the
      // TCP side's round trip.
      const n = have.rttN + c.rttN
      have.rttMs = n > 0 ? (have.rttMs * have.rttN + c.rttMs * c.rttN) / n : 0
      have.rttN = n
      have.degraded = have.degraded || c.degraded
    } else {
      row.cells.set(col, { ...c })
    }
  }
  return [...out.values()].toSorted((a, b) => b.total - a.total)
})

const shownRows = computed(() => (showAll.value ? rows.value : rows.value.slice(0, 40)))

function cellTitle(c: Cell) {
  if (c.kind === 'endpoint')
    return [t('matrix.handshakes', { n: num(c.authed) }), t('matrix.endpointNote')].join('\n')
  return [
    t('matrix.accepted', { n: num(c.accepted) }),
    t('matrix.authed', { n: num(c.authed) }),
    t('matrix.failed', { n: num(c.failed) }),
    t('matrix.early', { p: pct(c.earlyClose, c.authed) }),
    c.rttMs ? t('matrix.rtt', { ms: num(c.rttMs) }) : '',
  ]
    .filter(Boolean)
    .join('\n')
}

const feedSeverity = computed(() => {
  switch (status.value?.feed.state) {
    case 'ok':
      return 'success'
    case 'waiting':
      return 'info'
    default:
      return 'warn'
  }
})
</script>

<template>
  <div class="stack">
    <h1>{{ t('overview.title') }}</h1>
    <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>

    <template v-if="status">
      <Message v-if="!status.registered" severity="info" :closable="false">
        {{ t('overview.waiting') }}
        <span v-if="status.claimCode">
          {{ t('overview.claimCode') }} <b class="mono ltr">{{ status.claimCode }}</b>
        </span>
      </Message>
      <Message v-else :severity="feedSeverity" :closable="false">
        {{ t('feed.' + status.feed.state) }}
        <span v-if="status.feed.lastPoll" class="muted">
          · {{ t('overview.lastPoll', { at: when(status.feed.lastPoll) }) }}</span
        >
        <span v-if="status.feed.gaps" class="muted">
          · {{ t('overview.gaps', { n: status.feed.gaps, at: when(status.feed.lastGap) }) }}</span
        >
      </Message>
      <Message v-if="!status.asnLoaded" severity="warn" :closable="false">
        {{ t('overview.noNetinfo') }}
      </Message>
      <Message v-for="asn in status.outages" :key="asn" severity="error" :closable="false">
        {{ t('overview.outage', { asn: 'AS' + asn }) }}
      </Message>
      <Message v-for="name in status.tunnelsDown" :key="name" severity="error" :closable="false">
        {{ t('overview.tunnelDown', { name }) }}
        <RouterLink :to="{ name: 'nodes' }">{{ t('overview.seeNodes') }}</RouterLink>
      </Message>
      <Message v-if="status.tunnels?.state === 'no-scope'" severity="warn" :closable="false">
        {{ t('overview.tunnelsNoScope') }}
      </Message>
      <Message v-if="status.probed" severity="warn" :closable="false">
        {{ t('overview.probed', { n: num(status.probed) }) }}
        <RouterLink :to="{ name: 'probing' }">{{ t('overview.seeProbing') }}</RouterLink>
      </Message>
    </template>

    <section v-if="suggestions.length" class="card stack">
      <h2>{{ t('overview.suggestions') }}</h2>
      <p class="muted">{{ t('overview.suggestionsHint') }}</p>
      <ul class="suggestions">
        <li v-for="s in suggestions" :key="`${s.asn}/${s.nodeId}/${s.inbound}/${s.network}`">
          <Tag severity="danger" :value="t('overview.blocked')" />
          <b>{{ asnLabel(s.asn, s.org) }}</b> <span class="dir-arrow">→</span>
          {{ nodeName(s.nodeId) }}
          <span class="mono ltr">{{ s.inbound }}/{{ s.network }}</span>
          <span v-if="s.alternatives.length">
            · {{ t('overview.worksInstead') }}
            <span v-for="(a, i) in s.alternatives.slice(0, 3)" :key="i" class="alt">
              {{ nodeName(a.nodeId) }}
              <span class="mono ltr">{{ a.inbound }}/{{ a.network }}</span>
              ({{ pct(a.success, 1) }})
            </span>
          </span>
          <span v-else class="muted"> · {{ t('overview.noAlternative') }}</span>
        </li>
      </ul>
    </section>

    <section class="card stack">
      <div class="toolbar">
        <h2>{{ t('matrix.title') }}</h2>
        <SelectButton
          v-model="hours"
          :options="hourChoices"
          option-label="label"
          option-value="value"
          :allow-empty="false"
        />
        <SelectButton
          v-model="by"
          :options="byChoices"
          option-label="label"
          option-value="value"
          :allow-empty="false"
        />
        <Select
          v-model="network"
          :options="networkChoices"
          option-label="label"
          option-value="value"
          :aria-label="t('matrix.network')"
        />
        <Button
          icon="pi pi-refresh"
          text
          :loading="loading"
          :aria-label="t('common.refresh')"
          @click="load"
        />
      </div>
      <p class="muted">{{ t('matrix.hint') }}</p>
      <p v-if="!rows.length" class="muted">{{ t('matrix.empty') }}</p>
      <div v-else class="scroll">
        <table class="matrix">
          <thead>
            <tr>
              <th class="sticky">
                {{ by === 'region' ? t('matrix.region') : t('matrix.clientNetwork') }}
              </th>
              <th v-for="c in columns" :key="c.key">
                <div>{{ nodeName(c.nodeId) }}</div>
                <div class="mono ltr muted small">{{ c.inbound }}</div>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in shownRows" :key="r.key">
              <th class="sticky rowhead">
                <div>{{ r.label }}</div>
                <div class="muted small">{{ r.sub }} · {{ num(r.total) }}</div>
              </th>
              <td
                v-for="c in columns"
                :key="c.key"
                :class="
                  r.cells.get(c.key)
                    ? r.cells.get(c.key)!.kind === 'endpoint'
                      ? r.cells.get(c.key)!.degraded
                        ? 'bad'
                        : 'good'
                      : health(
                          r.cells.get(c.key)!.authed,
                          r.cells.get(c.key)!.accepted,
                          r.cells.get(c.key)!.degraded,
                        )
                    : 'empty'
                "
                :title="r.cells.get(c.key) ? cellTitle(r.cells.get(c.key)!) : ''"
              >
                <template v-if="r.cells.get(c.key)">
                  <i v-if="r.cells.get(c.key)!.degraded" class="pi pi-exclamation-triangle" />
                  <template v-if="r.cells.get(c.key)!.kind === 'endpoint'">
                    {{ t('matrix.handshakesShort', { n: num(r.cells.get(c.key)!.authed) }) }}
                  </template>
                  <template v-else>
                    {{ pct(r.cells.get(c.key)!.authed, r.cells.get(c.key)!.accepted) }}
                  </template>
                  <div v-if="r.cells.get(c.key)!.rttMs" class="small muted">
                    {{ num(r.cells.get(c.key)!.rttMs) }} ms
                  </div>
                </template>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <Button
        v-if="rows.length > 40 && !showAll"
        :label="t('matrix.showAll', { n: rows.length })"
        text
        @click="showAll = true"
      />
    </section>
  </div>
</template>

<style scoped>
h1,
h2 {
  margin: 0;
}
h2 {
  font-size: 1.1rem;
}
.toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  align-items: center;
}
.toolbar h2 {
  margin-inline-end: auto;
}
.scroll {
  overflow-x: auto;
}
.matrix {
  border-collapse: collapse;
  font-size: 0.875rem;
}
.matrix th,
.matrix td {
  border: 1px solid var(--insight-border);
  padding: 0.35rem 0.5rem;
  text-align: center;
  white-space: nowrap;
}
.matrix .rowhead {
  text-align: start;
}
.sticky {
  position: sticky;
  inset-inline-start: 0;
  background: var(--insight-surface);
  z-index: 1;
}
.small {
  font-size: 0.75rem;
}
td.good {
  background: color-mix(in srgb, #16a34a 22%, transparent);
}
td.fair {
  background: color-mix(in srgb, #f59e0b 28%, transparent);
}
td.bad {
  background: color-mix(in srgb, #dc2626 30%, transparent);
}
td.none {
  color: var(--insight-muted);
}
.suggestions {
  margin: 0;
  padding-inline-start: 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}
.alt + .alt::before {
  content: ', ';
}
</style>
