import { createRouter, createWebHistory } from 'vue-router'
import { api, whenSignedOut } from './api'
import Login from './views/Login.vue'
import Layout from './views/Layout.vue'
import Overview from './views/Overview.vue'
import Nodes from './views/Nodes.vue'
import Alerts from './views/Alerts.vue'
import Probing from './views/Probing.vue'
import Analysis from './views/Analysis.vue'
import Security from './views/Security.vue'

export const router = createRouter({
  // Relative to wherever Insight is served, the way its assets are.
  history: createWebHistory(new URL('.', document.baseURI).pathname),
  routes: [
    { path: '/login', name: 'login', component: Login, meta: { public: true } },
    {
      path: '/',
      component: Layout,
      children: [
        { path: '', name: 'overview', component: Overview },
        { path: 'nodes', name: 'nodes', component: Nodes },
        { path: 'probing', name: 'probing', component: Probing },
        { path: 'analysis', name: 'analysis', component: Analysis },
        { path: 'alerts', name: 'alerts', component: Alerts },
        { path: 'security', name: 'security', component: Security },
      ],
    },
  ],
})

let checked = false

router.beforeEach(async (to) => {
  if (to.meta.public) return true
  if (checked) return true
  try {
    await api.me()
    checked = true
    return true
  } catch {
    return { name: 'login', query: to.fullPath === '/' ? {} : { next: to.fullPath } }
  }
})

whenSignedOut(() => {
  checked = false
  if (router.currentRoute.value.name !== 'login') void router.push({ name: 'login' })
})

export function signedIn() {
  checked = true
}
