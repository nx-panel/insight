<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import Button from 'primevue/button'
import Message from 'primevue/message'
import SelectButton from 'primevue/selectbutton'
import Tag from 'primevue/tag'
import { useToast } from 'primevue/usetoast'
import { api, type CloudCell, type CloudFinding, type CloudState } from '../api'
import { asnLabel, num, when } from '../format'

// Mode B (internal/cloud): the switch, what went out, NX's report. Opening
// this page is also when Insight asks NX for a newer report.

const { t, locale } = useI18n()
const toast = useToast()
const state = ref<CloudState | null>(null)
const error = ref('')
const busy = ref(false)
const open = ref<number | null>(null)
const cells = ref<CloudCell[]>([])

function countryName(code: string) {
  try {
    return new Intl.DisplayNames([locale.value], { type: 'region' }).of(code) ?? code
  } catch {
    return code
  }
}

async function load() {
  try {
    state.value = await api.cloud()
    error.value = ''
  } catch (e) {
    error.value = (e as Error).message
  }
}
onMounted(load)

function fail(e: unknown) {
  toast.add({
    severity: 'error',
    summary: t('common.error'),
    detail: (e as Error).message,
    life: 5000,
  })
}

async function setOn(on: boolean) {
  busy.value = true
  try {
    state.value = await api.setCloud(on)
    if (state.value.error) toast.add({ severity: 'warn', summary: state.value.error, life: 6000 })
  } catch (e) {
    fail(e)
  } finally {
    busy.value = false
  }
}

async function ask() {
  busy.value = true
  try {
    state.value = await api.cloudReport()
  } catch (e) {
    fail(e)
  } finally {
    busy.value = false
  }
}

async function show(hour: number) {
  if (open.value === hour) {
    open.value = null
    return
  }
  try {
    cells.value = (await api.cloudBatch(hour)).cells
    open.value = hour
  } catch (e) {
    fail(e)
  }
}

const on = computed({
  get: () => state.value?.on ?? false,
  set: (v: boolean) => void setOn(v),
})

const report = computed(() => state.value?.report.report ?? null)

function batchState(b: CloudState['recent'][number]) {
  if (b.sentAt) return 'sent'
  return b.nextAt > 1e15 ? 'refused' : 'pending'
}

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

function sentence(f: CloudFinding) {
  return t('cloud.finding.' + f.code, {
    asn: asnLabel(f.asn, f.org),
    strategy: strategy(f.strategy),
    host: 'AS' + f.node_asn,
  })
}

const severity = (s: CloudFinding['severity']) =>
  s === 'critical' ? 'danger' : s === 'warn' ? 'warn' : 'info'
</script>

<template>
  <div class="stack">
    <h1>{{ t('cloud.title') }}</h1>
    <p class="muted">{{ t('cloud.intro') }}</p>
    <Message severity="secondary" :closable="false">{{ t('cloud.privacy') }}</Message>
    <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>

    <section v-if="state" class="card stack">
      <h2>{{ t('cloud.switch') }}</h2>
      <SelectButton
        v-model="on"
        :options="[
          { label: t('cloud.off'), value: false },
          { label: t('cloud.on'), value: true },
        ]"
        option-label="label"
        option-value="value"
        :allow-empty="false"
        :disabled="busy"
      />
      <small class="muted">{{ t('cloud.offHint') }}</small>
      <p v-if="state.fingerprint">
        {{ t('cloud.key') }}: <span class="mono ltr">{{ state.fingerprint }}</span> ·
        <span :class="state.registered ? 'ok' : 'muted'">{{
          state.registered ? t('cloud.registered') : t('cloud.notRegistered')
        }}</span>
      </p>
      <Message v-if="state.on && state.error" severity="warn" :closable="false">
        <span class="ltr mono">{{ state.error }}</span>
      </Message>
      <p v-if="state.on" class="muted">
        <template v-if="state.lastSent">{{
          t('cloud.lastSent', { at: when(state.lastSent.hour), cells: num(state.lastSent.cells) })
        }}</template>
        <template v-else>{{ t('cloud.noneSent') }}</template>
        <template v-if="state.pending">
          · {{ t('cloud.waiting', { n: num(state.pending) }) }}</template
        >
        <template v-if="state.failed">
          · {{ t('cloud.failed', { n: num(state.failed) }) }}</template
        >
      </p>
    </section>

    <section v-if="state && state.recent.length" class="card stack">
      <h2>{{ t('cloud.batches') }}</h2>
      <table class="grid">
        <thead>
          <tr>
            <th>{{ t('cloud.hour') }}</th>
            <th>{{ t('cloud.cells') }}</th>
            <th>{{ t('cloud.state') }}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <template v-for="b in state.recent" :key="b.hour">
            <tr>
              <td>{{ when(b.hour) }}</td>
              <td>{{ num(b.cells) }}</td>
              <td>
                {{ t('cloud.' + batchState(b)) }}
                <span v-if="b.lastError && !b.sentAt" class="muted ltr mono small">{{
                  b.lastError
                }}</span>
              </td>
              <td>
                <Button
                  :label="open === b.hour ? t('cloud.hide') : t('cloud.show')"
                  size="small"
                  text
                  @click="show(b.hour)"
                />
              </td>
            </tr>
            <tr v-if="open === b.hour">
              <td colspan="4">
                <table class="grid inner">
                  <thead>
                    <tr>
                      <th>{{ t('cloud.network') }}</th>
                      <th>{{ t('cloud.host') }}</th>
                      <th>{{ t('cloud.shape') }}</th>
                      <th>{{ t('cloud.verdict') }}</th>
                      <th>{{ t('cloud.accepted') }}</th>
                      <th>{{ t('cloud.authed') }}</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="(c, i) in cells" :key="i">
                      <td>
                        {{ asnLabel(c.asn, c.org) }} · {{ c.cc
                        }}{{ c.region ? ' · ' + c.region : '' }}
                      </td>
                      <td>{{ asnLabel(c.node_asn, c.node_org) }} · {{ c.node_cc }}</td>
                      <td class="ltr">{{ shape(c) }} · {{ c.network }}</td>
                      <td>{{ t('cloud.verdicts.' + c.verdict) }}</td>
                      <td>{{ num(c.accepted) }}</td>
                      <td>{{ num(c.authed) }}</td>
                    </tr>
                  </tbody>
                </table>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </section>

    <section v-if="state" class="card stack">
      <div class="head">
        <h2>{{ t('cloud.report') }}</h2>
        <Button
          :label="t('cloud.checkNow')"
          size="small"
          :loading="busy"
          :disabled="!state.on || busy"
          @click="ask"
        />
      </div>
      <p class="muted">{{ t('cloud.reportIntro') }}</p>
      <Message v-if="state.on && state.report.error" severity="warn" :closable="false">
        {{ state.report.error }}
      </Message>
      <p v-if="!report" class="muted">{{ t('cloud.noReport') }}</p>
      <template v-else>
        <p class="muted">
          {{
            t('cloud.extracted', {
              at: when(report.extracted_at),
              checked: when(state.report.checkedAt),
            })
          }}
        </p>
        <Message v-if="report.tier === 'disruption'" severity="info" :closable="false">
          {{ t('cloud.tierDisruption') }}
        </Message>
        <Message severity="secondary" :closable="false">{{ t('cloud.estimate') }}</Message>
        <div v-for="c in report.countries" :key="c.cc" class="stack">
          <h3>
            {{
              t('cloud.country', {
                c: countryName(c.cc),
                n: c.contributors,
                from: when(c.from),
                to: when(c.to),
              })
            }}
          </h3>
          <p v-if="!c.findings.length" class="muted">{{ t('cloud.noFinding') }}</p>
          <ul v-else class="findings">
            <li v-for="(f, i) in c.findings" :key="i">
              <Tag :severity="severity(f.severity)" :value="t('analysis.severity.' + f.severity)" />
              <span>{{ sentence(f) }}</span>
              <span class="muted">{{
                t('analysis.confidence', { p: num(100 * f.confidence) })
              }}</span>
            </li>
          </ul>
        </div>
      </template>
    </section>
  </div>
</template>

<style scoped>
h1,
h2,
h3 {
  margin: 0;
}
h3 {
  font-size: 1rem;
}
.head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
}
.grid {
  border-collapse: collapse;
  width: 100%;
  font-size: 0.9rem;
}
.grid th,
.grid td {
  text-align: start;
  padding: 0.3rem 0.6rem;
  border-bottom: 1px solid var(--p-content-border-color);
}
.inner {
  font-size: 0.85rem;
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
.ok {
  color: var(--p-green-500);
}
</style>
