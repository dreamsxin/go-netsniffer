import { createApp } from 'vue'
import Vue3EasyDataTable from 'vue3-easy-data-table';
import 'vue3-easy-data-table/dist/style.css';
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


createApp(App).component('EasyDataTable', Vue3EasyDataTable).use(ElementPlus).mount('#app')
