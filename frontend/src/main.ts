import { createApp } from 'vue'
import PrimeVue from 'primevue/config'
import ToastService from 'primevue/toastservice'
import Aura from '@primeuix/themes/aura'
import { definePreset } from '@primeuix/themes'
import 'primeicons/primeicons.css'
import './styles.css'
import App from './App.vue'
import { router } from './router'
import { i18n } from './i18n'

// Insight's colour: a teal, so its admin is told apart from the panel's at a
// glance.
const Insight = definePreset(Aura, {
  semantic: {
    primary: {
      50: '{teal.50}',
      100: '{teal.100}',
      200: '{teal.200}',
      300: '{teal.300}',
      400: '{teal.400}',
      500: '{teal.500}',
      600: '{teal.600}',
      700: '{teal.700}',
      800: '{teal.800}',
      900: '{teal.900}',
      950: '{teal.950}',
    },
  },
})

// The admin follows the system's light or dark setting.
const dark = window.matchMedia('(prefers-color-scheme: dark)')
const applyDark = () => document.documentElement.classList.toggle('dark', dark.matches)
applyDark()
dark.addEventListener('change', applyDark)

createApp(App)
  .use(PrimeVue, {
    theme: { preset: Insight, options: { darkModeSelector: '.dark' } },
    license: import.meta.env.VITE_PRIMEUI_LICENSE,
  })
  .use(ToastService)
  .use(i18n)
  .use(router)
  .mount('#app')
