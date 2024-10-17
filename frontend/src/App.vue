<script setup>
import { ref, useTemplateRef, watch, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElNotification as notify } from 'element-plus'
import {
  Document,
  Menu as IconMenu,
  Location,
  Setting,
} from '@element-plus/icons-vue'

const route = useRoute();
const router = useRouter();

function getCurrentRouteList() {
  return router.currentRoute.value.matched;
}

const list = ref([])
watch(route, () => {
  list.value = getCurrentRouteList();
  console.log("watch", route.path)
});

const onBack = () => {
  notify('Back')
}

const handleOpen = (key, keyPath) => {
  console.log(key, keyPath)
}
const handleClose = (key, keyPath) => {
  console.log(key, keyPath)
}

// const message = ref('Hello Vue 3!')
// const input = useTemplateRef('my-input')

onMounted(() => {
  list.value = getCurrentRouteList();
})

</script>

<template>
  <el-container>
    <el-aside width="200px">
      <el-menu :default-active="$route.path" @open="handleOpen" @close="handleClose" router>
        <template v-for="(rule, index) in $router.options.routes">
          <el-sub-menu v-if="rule.children && rule.children.length > 0" :key="index" :index="rule.path">
            <template #title><el-icon>
                <component :is="rule.icon"></component>
              </el-icon>
              <span>{{ rule.name }}</span></template>
            <el-menu-item-group title="Group One">
              <el-menu-item v-for="(child, index) in rule.children" :key="index"
                :index="rule.path + '/' + child.path">{{
                  child.name }}
              </el-menu-item>
            </el-menu-item-group>
          </el-sub-menu>
          <el-menu-item v-else :key="index + 1" :index="rule.path"><el-icon>
              <component :is="rule.icon"></component>
            </el-icon>
            <span>{{ rule.name }}</span>
          </el-menu-item>
        </template>
      </el-menu>
    </el-aside>
    <el-main>
      <RouterView />
    </el-main>
  </el-container>
</template>
