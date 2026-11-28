<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import Button from 'primevue/button'
import Message from 'primevue/message'
import Tabs from 'primevue/tabs'
import TabList from 'primevue/tablist'
import Tab from 'primevue/tab'
import TabPanels from 'primevue/tabpanels'
import TabPanel from 'primevue/tabpanel'
import Tag from 'primevue/tag'
import { useToast } from 'primevue/usetoast'
import {
  api,
  type AIFinding,
  type AIReport,
  type AISettings,
  type CloudFinding,
  type CloudState,
  type NodeInfo,
} from '../api'
import { asnShort, asnTagged, countryName, num, when } from '../format'
import NetName from '../components/NetName.vue'

// The results of the two readings: the admin's own model (Mode A, set up on
// the settings page) and NX's pooled report (Mode B, switched on the NX
// network page). Opening this page is also when Insight asks NX for a newer
// report, as the NX network page does.

const { t } = useI18n()
const toast = useToast()
const route = useRoute()
const router = useRouter()
// One page with a tab each, on a flat route (?tab=), as the settings page.
const tabs = ['insight', 'nx'] as const
type TabName = (typeof tabs)[number]
const tab = ref<TabName>(
  tabs.includes(route.query.tab as TabName) ? (route.query.tab as TabName) : 'insight',
)
watch(tab, (v) => void router.replace({ query: { ...route.query, tab: v } }))

const settings = ref<AISettings | null>(null)
const reports = ref<AIReport[]>([])
const orgs = ref<Record<string, string>>({})
const nodes = ref<NodeInfo[]>([])
const cloud = ref<CloudState | null>(null)
const error = ref('')
const asking = ref(false)

function fail(e: unknown) {
  toast.add({
    severity: 'error',
    summary: t('common.error'),
    detail: (e as Error).message,
    life: 5000,
  })
}

async function load() {
  try {
    const [s, r, n] = await Promise.all([api.ai(), api.aiReports(), api.nodes().catch(() => [])])
    settings.value = s
    reports.value = r.reports
    orgs.value = r.orgs
    nodes.value = n
    error.value = ''
  } catch (e) {
    error.value = (e as Error).message
  }
}

async function loadCloud() {
  try {
    cloud.value = await api.cloud()
  } catch {
    cloud.value = null
  }
}

// While a pass runs the page asks again every few seconds.
let timer: ReturnType<typeof setInterval> | undefined
onMounted(async () => {
  await Promise.all([load(), loadCloud()])
  timer = setInterval(() => {
    if (settings.value?.running) void load()
  }, 4000)
})
onUnmounted(() => clearInterval(timer))

// Set up: on, with an address and a model. Anything less has nothing to
// show but the way to the settings page.
const ready = computed(
  () => !!settings.value?.enabled && !!settings.value.url && !!settings.value.model,
)

async function run(country: string) {
  try {
    await api.runAI(country)
    if (settings.value) settings.value.running = true
  } catch (e) {
    fail(e)
  }
}

async function ask() {
  asking.value = true
  try {
    cloud.value = await api.cloudReport()
  } catch (e) {
    fail(e)
  } finally {
    asking.value = false
  }
}

// The newest report of each country.
const latest = computed(() => {
  const out: Record<string, AIReport | undefined> = {}
  for (const c of settings.value?.countries ?? [])
    out[c] = reports.value.find((r) => r.country === c)
  return out
})

function findings(r: AIReport): AIFinding[] {
  try {
    return JSON.parse(r.findings) as AIFinding[]
  } catch {
    return []
  }
}

const nodeName = (id: number) =>
  nodes.value.find((n) => n.nodeId === id)?.name || t('matrix.node', { id })

const orgOf = (asn: number) => orgs.value[String(asn)] ?? ''

function sentence(f: AIFinding) {
  return t('analysis.finding.' + f.code, {
    asn: asnShort(f.asn, orgOf(f.asn)),
    node: nodeName(f.node),
    inbound: f.inbound,
    toNode: nodeName(f.to_node),
    toInbound: f.to_inbound,
  })
}

const severity = (s: 'info' | 'warn' | 'critical') =>
  s === 'critical' ? 'danger' : s === 'warn' ? 'warn' : 'info'

const report = computed(() => cloud.value?.report.report ?? null)

const shape = (c: { proto: string; transport: string; security: string; front: string }) =>
  [c.proto, c.transport, c.security, c.front].filter((x) => x && x !== 'none').join(' · ')

function strategy(s: string) {
  const [proto, transport, security, front] = s.split('/')
  return shape({
    proto: proto ?? '',
    transport: transport === '-' ? '' : (transport ?? ''),
    security: security ?? '',
    front: front ?? '',
  })
}

// A report's own name for a network, or this install's when NX sent none.
const nxOrg = (asn: number, org: string) => org || cloud.value?.orgs?.[String(asn)] || ''

function nxSentence(f: CloudFinding) {
  return t('cloud.finding.' + f.code, {
    asn: asnTagged(f.asn, nxOrg(f.asn, f.org)),
    strategy: strategy(f.strategy),
    host: asnTagged(f.node_asn, nxOrg(f.node_asn, '')),
  })
}
</script>

<template>
  <div class="stack">
    <h1>{{ t('analysis.title') }}</h1>
    <p class="muted">{{ t('analysis.introResults') }}</p>
    <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>

    <Tabs v-model:value="tab">
      <TabList>
        <Tab value="insight"><i class="pi pi-sparkles" /> {{ t('analysis.tabInsight') }}</Tab>
        <Tab value="nx"><i class="pi pi-globe" /> {{ t('analysis.tabNx') }}</Tab>
      </TabList>
      <TabPanels>
        <TabPanel value="insight">
          <div class="stack">
            <Message v-if="settings && !ready" severity="warn" :closable="false">
              {{ t('analysis.notSet') }}
              <RouterLink :to="{ name: 'settings', query: { tab: 'ai' } }">{{
                t('analysis.setUp')
              }}</RouterLink>
            </Message>
            <template v-else-if="settings">
              <p class="muted small">
                {{ t('analysis.usingModel', { model: settings.model }) }} ·
                {{
                  t('analysis.used', {
                    used: num(settings.usedToday),
                    of: num(settings.dailyTokens),
                  })
                }}
              </p>
              <section v-for="(r, country) in latest" :key="country" class="card stack">
                <div class="head">
                  <h2>{{ t('analysis.country', { c: countryName(String(country)) }) }}</h2>
                  <Button
                    :label="t('analysis.runNow')"
                    size="small"
                    :loading="settings.running"
                    :disabled="settings.running"
                    @click="run(String(country))"
                  />
                </div>
                <p v-if="!r" class="muted">{{ t('analysis.noReport') }}</p>
                <template v-else>
                  <p class="muted small">
                    {{
                      t('analysis.meta', {
                        at: when(r.at),
                        trigger: t('analysis.trigger.' + r.trigger),
                        model: r.model || '—',
                        tokens: num(r.tokens),
                        rows: num(r.rows),
                      })
                    }}
                  </p>
                  <Message v-if="r.status === 'error'" severity="error" :closable="false">
                    {{ t('analysis.failed') }} <span class="ltr mono">{{ r.error }}</span>
                  </Message>
                  <Message v-else-if="r.status === 'budget'" severity="warn" :closable="false">
                    {{ t('analysis.overBudget') }}
                  </Message>
                  <p v-else-if="r.status === 'empty'" class="muted">{{ t('analysis.empty') }}</p>
                  <ul v-else class="findings">
                    <li v-for="(f, i) in findings(r)" :key="i">
                      <Tag
                        :severity="severity(f.severity)"
                        :value="t('analysis.severity.' + f.severity)"
                      />
                      <span>{{ sentence(f) }}</span>
                      <NetName v-if="f.asn" :asn="f.asn" :org="orgOf(f.asn)" icon-only />
                      <span class="muted">{{
                        t('analysis.confidence', { p: num(100 * f.confidence) })
                      }}</span>
                    </li>
                  </ul>
                  <p v-if="r.dropped" class="muted small">
                    {{ t('analysis.dropped', { n: num(r.dropped) }) }}
                  </p>
                </template>
              </section>
            </template>
          </div>
        </TabPanel>

        <TabPanel value="nx">
          <div class="stack">
            <Message v-if="!cloud || !cloud.on" severity="warn" :closable="false">
              {{ t('analysis.nxOff') }}
              <RouterLink :to="{ name: 'cloud' }">{{ t('nav.cloud') }}</RouterLink>
            </Message>
            <template v-else>
              <div class="head">
                <p class="muted">{{ t('cloud.reportIntro') }}</p>
                <Button
                  :label="t('cloud.checkNow')"
                  size="small"
                  :loading="asking"
                  :disabled="asking"
                  @click="ask"
                />
              </div>
              <Message v-if="cloud.report.error" severity="warn" :closable="false">
                {{ cloud.report.error }}
              </Message>
              <p v-if="!report" class="muted">{{ t('cloud.noReport') }}</p>
              <template v-else>
                <p class="muted small">
                  {{
                    t('cloud.extracted', {
                      at: when(report.extracted_at),
                      checked: when(cloud.report.checkedAt),
                    })
                  }}
                </p>
                <Message v-if="report.tier === 'disruption'" severity="info" :closable="false">
                  {{ t('cloud.tierDisruption') }}
                </Message>
                <Message severity="secondary" :closable="false">{{ t('cloud.estimate') }}</Message>
                <section v-for="c in report.countries" :key="c.cc" class="card stack">
                  <h2>
                    {{
                      t('cloud.country', {
                        c: countryName(c.cc),
                        n: c.contributors,
                        from: when(c.from),
                        to: when(c.to),
                      })
                    }}
                  </h2>
                  <p v-if="!(c.findings ?? []).length" class="muted">
                    {{ t('cloud.noFinding') }}
                  </p>
                  <ul v-else class="findings">
                    <li v-for="(f, i) in c.findings ?? []" :key="i">
                      <Tag
                        :severity="severity(f.severity)"
                        :value="t('analysis.severity.' + f.severity)"
                      />
                      <span>{{ nxSentence(f) }}</span>
                      <NetName v-if="f.asn" :asn="f.asn" :org="f.org" icon-only />
                      <span class="muted">{{
                        t('analysis.confidence', { p: num(100 * f.confidence) })
                      }}</span>
                    </li>
                  </ul>
                </section>
              </template>
            </template>
          </div>
        </TabPanel>
      </TabPanels>
    </Tabs>
  </div>
</template>

<style scoped>
h1,
h2 {
  margin: 0;
}
h2 {
  font-size: 1.05rem;
}
.head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
}
.head > :deep(.p-button) {
  flex: none;
  white-space: nowrap;
}
.findings {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}
.findings li {
  display: flex;
  gap: 0.6rem;
  align-items: baseline;
  flex-wrap: wrap;
}
.small {
  font-size: 0.85rem;
}
:deep(.p-tabpanels) {
  padding-inline: 0;
}
</style>
