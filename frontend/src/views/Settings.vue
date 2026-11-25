<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import Button from 'primevue/button'
import InputNumber from 'primevue/inputnumber'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import Select from 'primevue/select'
import SelectButton from 'primevue/selectbutton'
import Tabs from 'primevue/tabs'
import TabList from 'primevue/tablist'
import Tab from 'primevue/tab'
import TabPanels from 'primevue/tabpanels'
import TabPanel from 'primevue/tabpanel'
import { useToast } from 'primevue/usetoast'
import {
  api,
  type AISettings,
  type AISettingsInput,
  type Settings,
  type SettingsInput,
} from '../api'
import { countryName, num } from '../format'
import Security from './Security.vue'

// Everything the admin changes while Insight runs: where alerts go and in
// which language, the AI model, the metrics token, the account — and, to
// read only, what the installer set. One page with a tab each, on a flat
// route (?tab=), since the admin web's assets are fetched relative to it.

const { t } = useI18n()
const toast = useToast()
const route = useRoute()
const router = useRouter()

const tabs = ['alerts', 'ai', 'metrics', 'account', 'install'] as const
type TabName = (typeof tabs)[number]
const tab = ref<TabName>(
  tabs.includes(route.query.tab as TabName) ? (route.query.tab as TabName) : 'alerts',
)
watch(tab, (v) => void router.replace({ query: { ...route.query, tab: v } }))

function fail(e: unknown) {
  toast.add({
    severity: 'error',
    summary: t('common.error'),
    detail: (e as Error).message,
    life: 6000,
  })
}
function ok(summary = t('common.saved')) {
  toast.add({ severity: 'success', summary, life: 2500 })
}

// Alerts and metrics.
const st = ref<Settings | null>(null)
const form = ref<SettingsInput>({
  telegramToken: '',
  clearTelegramToken: false,
  telegramChat: '',
  telegramProxy: '',
  telegramApi: '',
  language: 'en',
  metricsToken: '',
  clearMetricsToken: false,
})
const saving = ref(false)
const testing = ref(false)

function fill(s: Settings) {
  st.value = s
  form.value = {
    telegramToken: '',
    clearTelegramToken: false,
    telegramChat: s.telegramChat,
    telegramProxy: s.telegramProxy,
    telegramApi: s.telegramApi,
    language: s.language,
    metricsToken: '',
    clearMetricsToken: false,
  }
}

async function save(patch: Partial<SettingsInput> = {}) {
  saving.value = true
  try {
    fill(await api.saveSettings({ ...form.value, ...patch }))
    ok()
  } catch (e) {
    fail(e)
  } finally {
    saving.value = false
  }
}

async function reset() {
  saving.value = true
  try {
    fill(await api.resetSettings())
    ok(t('settings.resetDone'))
  } catch (e) {
    fail(e)
  } finally {
    saving.value = false
  }
}

async function test() {
  testing.value = true
  try {
    await api.testTelegram()
    ok(t('settings.testSent'))
  } catch (e) {
    fail(e)
  } finally {
    testing.value = false
  }
}

// A token Prometheus can use: 32 random letters and digits.
function generate() {
  const abc = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
  const r = crypto.getRandomValues(new Uint32Array(32))
  form.value.metricsToken = Array.from(r, (n) => abc[n % abc.length]).join('')
}

const languages = [
  { code: 'en', name: 'English' },
  { code: 'fa', name: 'فارسی' },
  { code: 'ru', name: 'Русский' },
  { code: 'zh', name: '中文' },
]

// The AI model (Mode A).
const ai = ref<AISettings | null>(null)
const aiForm = ref<AISettingsInput>({
  enabled: false,
  url: '',
  model: '',
  key: '',
  clearKey: false,
  proxy: '',
  dailyTokens: 100000,
})
const aiSaving = ref(false)

// Where the common providers answer; the admin can type any other.
const presets = [
  { label: 'OpenAI', url: 'https://api.openai.com/v1', model: 'gpt-4.1-mini' },
  { label: 'Ollama', url: 'http://127.0.0.1:11434/v1', model: 'qwen2.5:7b' },
  { label: 'OpenRouter', url: 'https://openrouter.ai/api/v1', model: '' },
]

function fillAI(s: AISettings) {
  ai.value = s
  aiForm.value = {
    enabled: s.enabled,
    url: s.url,
    model: s.model,
    key: '',
    clearKey: false,
    proxy: s.proxy,
    dailyTokens: s.dailyTokens,
  }
}

async function saveAI() {
  aiSaving.value = true
  try {
    fillAI(await api.saveAI(aiForm.value))
    ok()
  } catch (e) {
    fail(e)
  } finally {
    aiSaving.value = false
  }
}

const keyPlaceholder = computed(() =>
  ai.value?.keySet ? t('analysis.keySaved') : t('analysis.keyNone'),
)

onMounted(async () => {
  try {
    const [s, a] = await Promise.all([api.settings(), api.ai()])
    fill(s)
    fillAI(a)
  } catch (e) {
    fail(e)
  }
})

const install = computed(() => {
  const i = st.value?.install
  if (!i) return []
  const none = t('settings.none')
  return [
    { label: t('settings.port'), value: i.port, ltr: true },
    { label: t('settings.basePath'), value: i.basePath || '/', ltr: true },
    { label: t('settings.publicUrl'), value: i.publicUrl || none, ltr: !!i.publicUrl },
    { label: t('settings.https'), value: i.https, ltr: true },
    { label: t('settings.database'), value: i.database, ltr: true },
    { label: t('settings.admin'), value: i.adminUsername, ltr: true },
    {
      label: t('settings.regions'),
      value: i.regionCountries.map((c) => `${countryName(c)} (${c})`).join(' · ') || none,
      ltr: false,
    },
    {
      label: t('settings.trustedProxies'),
      value: i.trustedProxies || none,
      ltr: !!i.trustedProxies,
    },
    { label: t('settings.asnUrl'), value: i.asnUrl, ltr: true },
    { label: t('settings.cityUrl'), value: i.cityUrl, ltr: true },
  ]
})
</script>

<template>
  <div class="stack">
    <h1>{{ t('settings.title') }}</h1>

    <Tabs v-model:value="tab">
      <TabList>
        <Tab value="alerts"><i class="pi pi-bell" /> {{ t('settings.tabs.alerts') }}</Tab>
        <Tab value="ai"><i class="pi pi-sparkles" /> {{ t('settings.tabs.ai') }}</Tab>
        <Tab value="metrics"><i class="pi pi-chart-line" /> {{ t('settings.tabs.metrics') }}</Tab>
        <Tab value="account"><i class="pi pi-shield" /> {{ t('settings.tabs.account') }}</Tab>
        <Tab value="install"><i class="pi pi-server" /> {{ t('settings.tabs.install') }}</Tab>
      </TabList>
      <TabPanels>
        <TabPanel value="alerts">
          <form v-if="st" class="card stack" @submit.prevent="save()">
            <p class="muted">{{ t('settings.alertsIntro') }}</p>
            <Message severity="secondary" :closable="false">
              {{ st.saved ? t('settings.fromSaved') : t('settings.fromInstall') }}
              <Button
                v-if="st.saved"
                :label="t('settings.reset')"
                size="small"
                text
                type="button"
                @click="reset"
              />
            </Message>
            <div class="field">
              <label for="s-token">{{ t('settings.botToken') }}</label>
              <InputText
                id="s-token"
                v-model="form.telegramToken"
                type="password"
                autocomplete="off"
                class="ltr"
                :placeholder="
                  st.telegramTokenSet ? t('settings.tokenSaved') : t('settings.tokenNone')
                "
              />
              <Button
                v-if="st.telegramTokenSet"
                :label="t('settings.clearToken')"
                text
                size="small"
                type="button"
                class="self-start"
                @click="save({ clearTelegramToken: true, telegramToken: '', telegramChat: '' })"
              />
            </div>
            <div class="field">
              <label for="s-chat">{{ t('settings.chat') }}</label>
              <InputText
                id="s-chat"
                v-model="form.telegramChat"
                inputmode="numeric"
                class="ltr mono"
                placeholder="-1001234567890"
              />
              <small class="muted">{{ t('settings.chatHint') }}</small>
            </div>
            <div class="field">
              <label for="s-proxy">{{ t('settings.proxy') }}</label>
              <InputText
                id="s-proxy"
                v-model="form.telegramProxy"
                class="ltr"
                placeholder="socks5://127.0.0.1:1080"
              />
              <small class="muted">{{ t('settings.proxyHint') }}</small>
            </div>
            <div class="field">
              <label for="s-api">{{ t('settings.api') }}</label>
              <InputText
                id="s-api"
                v-model="form.telegramApi"
                class="ltr"
                placeholder="https://tapi.bale.ai"
              />
              <small class="muted">{{ t('settings.apiHint') }}</small>
            </div>
            <div class="field">
              <label for="s-lang">{{ t('settings.language') }}</label>
              <Select
                v-model="form.language"
                input-id="s-lang"
                :options="languages"
                option-label="name"
                option-value="code"
              />
            </div>
            <div class="row">
              <Button type="submit" :label="t('common.save')" :loading="saving" />
              <Button
                type="button"
                :label="t('settings.test')"
                icon="pi pi-send"
                severity="secondary"
                outlined
                :loading="testing"
                :disabled="!st?.telegramTokenSet || !st?.telegramChat"
                @click="test"
              />
            </div>
          </form>
        </TabPanel>

        <TabPanel value="ai">
          <form v-if="ai" class="card stack" @submit.prevent="saveAI">
            <p class="muted">{{ t('analysis.intro') }}</p>
            <Message severity="secondary" :closable="false">{{ t('analysis.privacy') }}</Message>
            <SelectButton
              v-model="aiForm.enabled"
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
                @click="
                  ((aiForm.url = p.url), p.model && !aiForm.model && (aiForm.model = p.model))
                "
              />
            </div>
            <div class="field">
              <label for="ai-url">{{ t('analysis.url') }}</label>
              <InputText
                id="ai-url"
                v-model="aiForm.url"
                class="ltr"
                placeholder="https://api.openai.com/v1"
              />
            </div>
            <div class="field">
              <label for="ai-model">{{ t('analysis.model') }}</label>
              <InputText id="ai-model" v-model="aiForm.model" class="ltr" />
            </div>
            <div class="field">
              <label for="ai-key">{{ t('analysis.key') }}</label>
              <InputText
                id="ai-key"
                v-model="aiForm.key"
                type="password"
                autocomplete="off"
                class="ltr"
                :placeholder="keyPlaceholder"
              />
              <small class="muted">{{ t('analysis.keyHint') }}</small>
              <Button
                v-if="ai?.keySet"
                :label="t('analysis.clearKey')"
                text
                size="small"
                type="button"
                class="self-start"
                @click="((aiForm.clearKey = true), saveAI())"
              />
            </div>
            <div class="field">
              <label for="ai-proxy">{{ t('analysis.proxy') }}</label>
              <InputText
                id="ai-proxy"
                v-model="aiForm.proxy"
                class="ltr"
                placeholder="socks5://127.0.0.1:1080"
              />
            </div>
            <div class="field">
              <label for="ai-budget">{{ t('analysis.budget') }}</label>
              <InputNumber
                v-model="aiForm.dailyTokens"
                input-id="ai-budget"
                :min="5000"
                :max="10000000"
                :step="10000"
              />
              <small class="muted">{{
                t('analysis.used', { used: num(ai?.usedToday ?? 0), of: num(ai?.dailyTokens ?? 0) })
              }}</small>
            </div>
            <div>
              <Button type="submit" :label="t('common.save')" :loading="aiSaving" />
            </div>
          </form>
        </TabPanel>

        <TabPanel value="metrics">
          <form v-if="st" class="card stack" @submit.prevent="save()">
            <p class="muted">{{ t('settings.metricsIntro') }}</p>
            <p>
              <span :class="st.metricsTokenSet ? 'ok' : 'muted'">{{
                st.metricsTokenSet ? t('settings.metricsOn') : t('settings.metricsOff')
              }}</span>
            </p>
            <div class="field">
              <label for="m-token">{{ t('settings.metricsToken') }}</label>
              <div class="row">
                <InputText
                  id="m-token"
                  v-model="form.metricsToken"
                  autocomplete="off"
                  class="ltr mono grow"
                  :placeholder="
                    st.metricsTokenSet ? t('settings.tokenSaved') : t('settings.tokenNone')
                  "
                />
                <Button
                  type="button"
                  :label="t('settings.generate')"
                  icon="pi pi-refresh"
                  severity="secondary"
                  outlined
                  @click="generate"
                />
              </div>
              <small class="muted">{{ t('settings.metricsHint', { n: st.metricsMin }) }}</small>
            </div>
            <div class="row">
              <Button type="submit" :label="t('common.save')" :loading="saving" />
              <Button
                v-if="st.metricsTokenSet"
                type="button"
                :label="t('settings.metricsDisable')"
                severity="danger"
                text
                @click="save({ clearMetricsToken: true, metricsToken: '' })"
              />
            </div>
          </form>
        </TabPanel>

        <TabPanel value="account">
          <Security />
        </TabPanel>

        <TabPanel value="install">
          <div v-if="st" class="card stack">
            <p class="muted">{{ t('settings.installIntro') }}</p>
            <dl class="install">
              <template v-for="i in install" :key="i.label">
                <dt>{{ i.label }}</dt>
                <dd :class="{ 'ltr mono': i.ltr }">{{ i.value }}</dd>
              </template>
            </dl>
          </div>
        </TabPanel>
      </TabPanels>
    </Tabs>
  </div>
</template>

<style scoped>
h1 {
  margin: 0;
}
.field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  max-width: 34rem;
}
.row {
  display: flex;
  gap: 0.6rem;
  align-items: center;
  flex-wrap: wrap;
}
.grow {
  flex: 1;
  min-width: 14rem;
}
.self-start {
  align-self: flex-start;
}
.presets {
  display: flex;
  gap: 0.5rem;
  align-items: center;
  flex-wrap: wrap;
}
.ok {
  color: var(--p-green-600);
}
.install {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 0.5rem 1.5rem;
  margin: 0;
}
.install dt {
  color: var(--insight-muted);
}
.install dd {
  margin: 0;
  overflow-wrap: anywhere;
}
:deep(.p-tabpanels) {
  padding-inline: 0;
}
</style>
