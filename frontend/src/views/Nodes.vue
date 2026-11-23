<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useToast } from 'primevue/usetoast'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import InputNumber from 'primevue/inputnumber'
import Tag from 'primevue/tag'
import Message from 'primevue/message'
import { api, type NodeInfo, type Override, type Shape, type TunnelOnNode } from '../api'
import { num, when } from '../format'

const { t } = useI18n()
const toast = useToast()
const nodes = ref<NodeInfo[]>([])
const error = ref('')
const editing = ref<NodeInfo>()
const form = ref<Override>({ asn: 0, org: '', country: '', city: '' })
const busy = ref(false)

async function load() {
  try {
    nodes.value = await api.nodes()
  } catch (e) {
    error.value = (e as Error).message
  }
}
onMounted(load)

function edit(n: NodeInfo) {
  editing.value = n
  form.value = {
    asn: n.overrideAsn,
    org: n.overrideOrg,
    country: n.overrideCountry,
    city: n.overrideCity,
  }
}

async function save() {
  if (!editing.value) return
  busy.value = true
  try {
    await api.override(editing.value.nodeId, { ...form.value, asn: form.value.asn || 0 })
    toast.add({ severity: 'success', summary: t('common.saved'), life: 3000 })
    editing.value = undefined
    await load()
  } catch (e) {
    toast.add({
      severity: 'error',
      summary: t('common.error'),
      detail: (e as Error).message,
      life: 5000,
    })
  } finally {
    busy.value = false
  }
}

function clear() {
  form.value = { asn: 0, org: '', country: '', city: '' }
}

function shapeTitle(i: Shape) {
  if (i.kind === 'endpoint') return `${i.type} · ${t('nodes.endpointNote')}`
  return [
    i.type,
    i.transport && i.transport !== 'none' ? i.transport : '',
    i.security && i.security !== 'none' ? i.security : '',
    i.fronted ? t('nodes.fronted') : '',
  ]
    .filter(Boolean)
    .join(' · ')
}

function tunnelTitle(tn: TunnelOnNode) {
  const lines = [
    t('nodes.tunnelState.' + tn.state) +
      (tn.state === 'down' && tn.since ? ' · ' + when(tn.since) : ''),
    `${tn.relayName} → ${(tn.originNames ?? []).join(', ')}`,
    t('nodes.tunnelHours', {
      attempts: num(tn.hours.attempts),
      up: num(tn.hours.up),
      failed: num(tn.hours.failed),
      flapped: num(tn.hours.flapped),
    }),
  ]
  if (tn.state === 'up' && tn.unlinked?.length) {
    const names = tn.unlinked.map((id) => {
      const i = (tn.originIds ?? []).indexOf(id)
      return (i >= 0 && tn.originNames?.[i]) || t('matrix.node', { id })
    })
    lines.push(t('nodes.unlinked', { nodes: names.join(', ') }))
  }
  return lines.join('\n')
}

const overridden = (n: NodeInfo) =>
  !!(n.overrideAsn || n.overrideOrg || n.overrideCountry || n.overrideCity)
</script>

<template>
  <div class="stack">
    <h1>{{ t('nodes.title') }}</h1>
    <p class="muted">{{ t('nodes.intro') }}</p>
    <Message v-if="error" severity="error" :closable="false">{{ error }}</Message>
    <DataTable :value="nodes" data-key="nodeId" size="small">
      <template #empty>{{ t('nodes.empty') }}</template>
      <Column field="name" :header="t('nodes.name')" />
      <Column :header="t('nodes.address')">
        <template #body="{ data }"
          ><span class="mono ltr">{{ data.address || '—' }}</span></template
        >
      </Column>
      <Column :header="t('nodes.network')">
        <template #body="{ data }">
          <span v-if="data.effective.asn" class="ltr"
            >AS{{ data.effective.asn }} {{ data.effective.org }}</span
          >
          <span v-else class="muted">—</span>
        </template>
      </Column>
      <Column :header="t('nodes.place')">
        <template #body="{ data }">
          {{ [data.effective.city, data.effective.country].filter(Boolean).join(', ') || '—' }}
          <Tag v-if="overridden(data)" :value="t('nodes.overridden')" severity="info" />
        </template>
      </Column>
      <Column :header="t('nodes.serves')">
        <template #body="{ data }">
          <span v-if="!data.inbounds?.length" class="muted">—</span>
          <span v-else class="chips">
            <span
              v-for="i in data.inbounds"
              :key="i.tag"
              class="chip mono ltr"
              :title="shapeTitle(i)"
              >{{ i.tag }}<i v-if="i.kind === 'endpoint'" class="pi pi-shield small"
            /></span>
          </span>
        </template>
      </Column>
      <Column :header="t('nodes.tunnels')">
        <template #body="{ data }">
          <span v-if="!data.tunnels?.length" class="muted">—</span>
          <span v-else class="chips">
            <Tag
              v-for="tn in data.tunnels"
              :key="tn.id"
              :severity="
                tn.state === 'down' ? 'danger' : tn.state === 'up' ? 'success' : 'secondary'
              "
              :value="`${tn.name} · ${t('nodes.role.' + tn.role)}`"
              :title="tunnelTitle(tn)"
            />
          </span>
        </template>
      </Column>
      <Column :header="t('nodes.updated')">
        <template #body="{ data }">{{ when(data.updatedAt) }}</template>
      </Column>
      <Column>
        <template #body="{ data }">
          <Button
            icon="pi pi-pencil"
            text
            :aria-label="t('common.edit')"
            :title="t('nodes.edit')"
            @click="edit(data)"
          />
        </template>
      </Column>
    </DataTable>

    <Dialog
      :visible="!!editing"
      modal
      :header="t('nodes.edit')"
      :style="{ width: 'min(28rem, 95vw)' }"
      @update:visible="(v: boolean) => !v && (editing = undefined)"
    >
      <form v-if="editing" class="stack" @submit.prevent="save">
        <p class="muted">
          {{
            t('nodes.fromDatabase', {
              net: editing.asn ? `AS${editing.asn} ${editing.org}` : '—',
              place: [editing.city, editing.country].filter(Boolean).join(', ') || '—',
            })
          }}
        </p>
        <div class="field">
          <label for="o-asn">{{ t('nodes.asn') }}</label>
          <InputNumber id="o-asn" v-model="form.asn" :use-grouping="false" :min="0" />
        </div>
        <div class="field">
          <label for="o-org">{{ t('nodes.org') }}</label>
          <InputText id="o-org" v-model="form.org" maxlength="64" />
        </div>
        <div class="field">
          <label for="o-cc">{{ t('nodes.country') }}</label>
          <InputText id="o-cc" v-model="form.country" maxlength="2" class="mono" />
        </div>
        <div class="field">
          <label for="o-city">{{ t('nodes.city') }}</label>
          <InputText id="o-city" v-model="form.city" maxlength="64" />
        </div>
        <p class="muted small">{{ t('nodes.emptyKeeps') }}</p>
        <div class="actions">
          <Button type="button" :label="t('nodes.clear')" text @click="clear" />
          <Button type="submit" :label="t('common.save')" :loading="busy" />
        </div>
      </form>
    </Dialog>
  </div>
</template>

<style scoped>
h1 {
  margin: 0;
}
.actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
}
.small {
  font-size: 0.8rem;
}
.chips {
  display: inline-flex;
  flex-wrap: wrap;
  gap: 0.25rem;
}
.chip {
  font-size: 0.8rem;
  padding: 0.05rem 0.4rem;
  border-radius: 0.3rem;
  background: var(--p-content-hover-background);
  display: inline-flex;
  gap: 0.25rem;
  align-items: center;
}
</style>
