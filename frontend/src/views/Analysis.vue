<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import InputNumber from 'primevue/inputnumber'
import Message from 'primevue/message'
import SelectButton from 'primevue/selectbutton'
import Tag from 'primevue/tag'
import { useToast } from 'primevue/usetoast'
import {
  api,
  type AIFinding,
  type AIReport,
  type AISettings,
  type AISettingsInput,
  type NodeInfo,
} from '../api'
import { asnLabel, num, when } from '../format'

const { t, locale } = useI18n()

// A country's name in the admin's language, its code when the browser has none.
function countryName(code: string) {
  try {
    return new Intl.DisplayNames([locale.value], { type: 'region' }).of(code) ?? code
  } catch {
    return code
  }
}
const toast = useToast()
const settings = ref<AISettings | null>(null)
const form = ref<AISettingsInput>({
  enabled: false,
  url: '',
  model: '',
  key: '',
  clearKey: false,
  proxy: '',
  dailyTokens: 100000,
})
const reports = ref<AIReport[]>([])
const orgs = ref<Record<string, string>>({})
const nodes = ref<NodeInfo[]>([])
const error = ref('')
const saving = ref(false)

// Where the common providers answer; the admin can type any other.
const presets = [
  { label: 'OpenAI', url: 'https://api.openai.com/v1', model: 'gpt-4.1-mini' },
  { label: 'Ollama', url: 'http://127.0.0.1:11434/v1', model: 'qwen2.5:7b' },
  { label: 'OpenRouter', url: 'https://openrouter.ai/api/v1', model: '' },
]

function fill(s: AISettings) {
  settings.value = s
  form.value = {
    enabled: s.enabled,
    url: s.url,
    model: s.model,
    key: '',
    clearKey: false,
    proxy: s.proxy,
    dailyTokens: s.dailyTokens,
  }
}

// refresh is false while a pass runs: only the reports and the running flag
// are read again then, so what the admin is typing into the form stays.
async function load(refresh = true) {
  try {
    const [s, r, n] = await Promise.all([api.ai(), api.aiReports(), api.nodes().catch(() => [])])
    if (refresh) fill(s)
    else settings.value = s
    reports.value = r.reports
    orgs.value = r.orgs
    nodes.value = n
    error.value = ''
  } catch (e) {
    error.value = (e as Error).message
  }
}

// While a pass runs the page asks again every few seconds.
let timer: ReturnType<typeof setInterval> | undefined
onMounted(async () => {
  await load()
  timer = setInterval(() => {
    if (settings.value?.running) void load(false)
  }, 4000)
})
onUnmounted(() => clearInterval(timer))

async function save() {
  saving.value = true
  try {
    fill(await api.saveAI(form.value))
    toast.add({ severity: 'success', summary: t('common.saved'), life: 2500 })
  } catch (e) {
    toast.add({
      severity: 'error',
      summary: t('common.error'),
      detail: (e as Error).message,
      life: 5000,
    })
  } finally {
    saving.value = false
  }
}

async function run(country: string) {
  try {
    await api.runAI(country)
    if (settings.value) settings.value.running = true
  } catch (e) {
    toast.add({
      severity: 'error',
      summary: t('common.error'),
      detail: (e as Error).message,
      life: 5000,
    })
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

function sentence(f: AIFinding) {
  return t('analysis.finding.' + f.code, {
    asn: asnLabel(f.asn, orgs.value[String(f.asn)] ?? ''),
    node: nodeName(f.node),
    inbound: f.inbound,
    toNode: nodeName(f.to_node),
    toInbound: f.to_inbound,
  })
}

const severity = (s: AIFinding['severity']) =>
  s === 'critical' ? 'danger' : s === 'warn' ? 'warn' : 'info'

const keyPlaceholder = computed(() =>
  settings.value?.keySet ? t('analysis.keySaved') : t('analysis.keyNone'),
)
</script>

<template>
  <div class="stack">
    <h1>{{ t('analysis.title') }}</h1>
    <p class="muted">{{ t('analysis.intro') }}</p>
    <Message severity="secondary" :closable="false">{{ t('analysis.privacy') }}</Message>
    <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>

    <form v-if="settings" class="card stack" @submit.prevent="save">
      <h2>{{ t('analysis.settings') }}</h2>
      <SelectButton
        v-model="form.enabled"
        :options="[
          { label: t('analysis.off'), value: false },
          { label: t('analysis.on'), value: true },
        ]"
        option-label="label"
        option-value="value"
        :allow-empty="false"
      />
      <div class="presets">
        <span class="muted">{{ t('analysis.presets') }}</span>
        <Button
          v-for="p in presets"
          :key="p.label"
          :label="p.label"
          size="small"
          severity="secondary"
          type="button"
          @click="((form.url = p.url), p.model && !form.model && (form.model = p.model))"
        />
      </div>
      <div class="field">
        <label for="ai-url">{{ t('analysis.url') }}</label>
        <InputText
          id="ai-url"
          v-model="form.url"
          class="ltr"
          placeholder="https://api.openai.com/v1"
        />
      </div>
      <div class="field">
        <label for="ai-model">{{ t('analysis.model') }}</label>
        <InputText id="ai-model" v-model="form.model" class="ltr" />
      </div>
      <div class="field">
        <label for="ai-key">{{ t('analysis.key') }}</label>
        <InputText
          id="ai-key"
          v-model="form.key"
          type="password"
          autocomplete="off"
          class="ltr"
          :placeholder="keyPlaceholder"
        />
        <small class="muted">{{ t('analysis.keyHint') }}</small>
        <Button
          v-if="settings?.keySet"
          :label="t('analysis.clearKey')"
          text
          size="small"
          type="button"
          @click="((form.clearKey = true), save())"
        />
      </div>
      <div class="field">
        <label for="ai-proxy">{{ t('analysis.proxy') }}</label>
        <InputText
          id="ai-proxy"
          v-model="form.proxy"
          class="ltr"
          placeholder="socks5://127.0.0.1:1080"
        />
      </div>
      <div class="field">
        <label for="ai-budget">{{ t('analysis.budget') }}</label>
        <InputNumber
          id="ai-budget"
          v-model="form.dailyTokens"
          :min="5000"
          :max="10000000"
          :step="10000"
        />
        <small class="muted">{{
          t('analysis.used', {
            used: num(settings?.usedToday ?? 0),
            of: num(settings?.dailyTokens ?? 0),
          })
        }}</small>
      </div>
      <div>
        <Button type="submit" :label="t('common.save')" :loading="saving" />
      </div>
    </form>

    <section v-for="(r, country) in latest" :key="country" class="card stack">
      <div class="head">
        <h2>{{ t('analysis.country', { c: countryName(String(country)) }) }}</h2>
        <Button
          :label="t('analysis.runNow')"
          size="small"
          :loading="settings?.running"
          :disabled="!settings?.enabled || settings?.running"
          @click="run(country)"
        />
      </div>
      <p v-if="!r" class="muted">{{ t('analysis.noReport') }}</p>
      <template v-else>
        <p class="muted">
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
            <Tag :severity="severity(f.severity)" :value="t('analysis.severity.' + f.severity)" />
            <span>{{ sentence(f) }}</span>
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
  </div>
</template>

<style scoped>
h1,
h2 {
  margin: 0;
}
.field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  max-width: 32rem;
}
.presets {
  display: flex;
  gap: 0.5rem;
  align-items: center;
  flex-wrap: wrap;
}
.head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
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
</style>
