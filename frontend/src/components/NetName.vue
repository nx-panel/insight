<script setup lang="ts">
import { computed } from 'vue'
import { asnLabel, asnShort } from '../format'

// A client or hosting network by its short name, with its number and full
// registered name behind an ⓘ: on hover with a mouse, on a tap on a phone
// (the icon takes focus, which shows the tooltip too). iconOnly is the ⓘ
// alone, for a sentence that already names the network.
const props = defineProps<{ asn: number; org: string; iconOnly?: boolean }>()
const short = computed(() => asnShort(props.asn, props.org))
const full = computed(() => asnLabel(props.asn, props.org))
</script>

<template>
  <span class="net">
    <span v-if="!iconOnly" class="name">{{ short }}</span>
    <i
      v-if="asn"
      v-tooltip.top.both="full"
      class="pi pi-info-circle info"
      tabindex="0"
      role="img"
      :aria-label="full"
    />
  </span>
</template>

<style scoped>
.net {
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
}
.info {
  font-size: 0.8rem;
  color: var(--insight-muted);
  cursor: help;
}
.info:focus-visible {
  outline: 2px solid var(--p-primary-500);
  border-radius: 50%;
}
</style>
