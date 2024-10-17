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


createApp(App).use(ElementPlus).mount('#app')
