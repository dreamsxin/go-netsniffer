import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import {
  HomeFilled,
  Document,
  Search,
  Menu as IconMenu,
  Location,
  Setting,
} from '@element-plus/icons-vue'
import 'element-plus/dist/index.css'
import App from './App.vue'
import './style.css';

// 路由
import { createMemoryHistory, createRouter } from 'vue-router'

import Browser from './pages/Browser.vue'

const routes = [
  { path: '/', component: Browser, name: "浏览器", icon: Search },
]

const router = createRouter({
  history: createMemoryHistory(),
  routes,
})

createApp(App).use(router).use(ElementPlus).mount('#app')
