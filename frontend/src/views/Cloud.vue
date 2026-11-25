<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import Button from 'primevue/button'
import Message from 'primevue/message'
import SelectButton from 'primevue/selectbutton'
import { useToast } from 'primevue/usetoast'
import { api, type CloudCell, type CloudState } from '../api'
import { num, when } from '../format'
import NetName from '../components/NetName.vue'

// Mode B (internal/cloud): the switch and what went out; NX's report is on
// the AI analysis page. Opening this page is also when Insight asks NX for
// a newer report.

const { t } = useI18n()
const toast = useToast()
const state = ref<CloudState | null>(null)
const error = ref('')
const busy = ref(false)
const open = ref<number | null>(null)
const cells = ref<CloudCell[]>([])

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

function batchState(b: CloudState['recent'][number]) {
  if (b.sentAt) return 'sent'
  return b.refused ? 'refused' : 'pending'
}

const shape = (c: { proto: string; transport: string; security: string; front: string }) =>
  [c.proto, c.transport, c.security, c.front].filter((x) => x && x !== 'none').join(' · ')
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
      <p v-if="state.fingerprint || state.removing">
        <template v-if="state.fingerprint"
          >{{ t('cloud.key') }}: <span class="mono ltr">{{ state.fingerprint }}</span> ·
        </template>
        <span v-if="state.removing" class="muted">{{ t('cloud.removing') }}</span>
        <span v-else :class="state.registered ? 'ok' : 'muted'">{{
          state.registered ? t('cloud.registered') : t('cloud.notRegistered')
        }}</span>
      </p>
      <Message v-if="state.error" severity="warn" :closable="false">
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
                        <NetName :asn="c.asn" :org="c.org" /> · {{ c.cc
                        }}{{ c.region ? ' · ' + c.region : '' }}
                      </td>
                      <td><NetName :asn="c.node_asn" :org="c.node_org" /> · {{ c.node_cc }}</td>
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

    <Message v-if="state?.on" severity="info" :closable="false">
      {{ t('cloud.reportMoved') }}
      <RouterLink :to="{ name: 'analysis', query: { tab: 'nx' } }">{{
        t('nav.analysis')
      }}</RouterLink>
    </Message>
  </div>
</template>

<style scoped>
h1,
h2 {
  margin: 0;
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
.small {
  font-size: 0.85rem;
}
.ok {
  color: var(--p-green-500);
}
</style>
