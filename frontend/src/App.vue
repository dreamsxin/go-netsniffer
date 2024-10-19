<script setup>
import { EventsOn } from '../wailsjs/runtime/runtime'
import { ref, reactive, useTemplateRef, watch, onMounted, computed } from 'vue'
import { ElNotification } from 'element-plus'
import { GetConfig, SetConfig, GenerateCert, InstallCert, UninstallCert, StartProxy, StopProxy, Test } from '../wailsjs/go/main/App'

const header = useTemplateRef('header')
const footer = useTemplateRef('footer')

const data = reactive({
  config: {},
  resultText: "",
  windowHeight: 768,
  headerheight: 100,
  ftooerheight: 100,
  rate: 0,
})

let mainheight = computed(() => data.windowHeight - data.headerheight - data.ftooerheight - 40)

const getWindowInfo = () => {
  data.windowHeight = window.innerHeight
};

const debounce = (fn, delay) => {
  let timer;
  return function () {
    if (timer) {
      clearTimeout(timer);
    }
    timer = setTimeout(() => {
      fn();
    }, delay);
  }
};

onMounted(() => {
  data.headerheight = header.value?.$el.offsetHeight
  data.ftooerheight = footer.value?.$el.offsetHeight
  console.log("onMounted", data.headerheight, data.ftooerheight)

  getWindowInfo();
  GetConfig().then(config => {
    data.config = config
  })
  window.addEventListener('resize', debounce(getWindowInfo, 100));// 监听窗口大小变化
})

const activeName = ref('first')

const handleClick = (tab, event) => {
  console.log(tab, event)
}

EventsOn("error", function (v) {
  ElNotification({
    title: 'Error',
    message: v.Message,
    type: 'error',
  })
});

EventsOn("Test", function (v) {
  data.resultText = v
});

const tableData = reactive([
])

EventsOn("Packet", function (v) {
  console.log("Packet", v)
  tableData.push(v)
});


function generateCert() {
  GenerateCert().then(err => {
    if (err == null) {
      ElNotification({
        title: 'Success',
        message: "生成证书成功",
        type: 'success',
      })
    } else {
      ElNotification({
        title: 'Error',
        message: err.Message,
        type: 'error',
      })
    }
  })
}


function installCert() {
  InstallCert().then(err => {
    if (err == null) {
      ElNotification({
        title: 'Success',
        message: "安装证书成功",
        type: 'success',
      })
    } else {
      ElNotification({
        title: 'Error',
        message: err.Message,
        type: 'error',
      })
    }
  })
}


function uninstallCert() {
  UninstallCert().then(err => {
    if (err == null) {
      ElNotification({
        title: 'Success',
        message: "卸载证书成功",
        type: 'success',
      })
    } else {
      ElNotification({
        title: 'Error',
        message: err.Message,
        type: 'error',
      })
    }
  })
}


function start() {
  StartProxy(data.port, data.autoProxy).then(err => {
    if (err == null) {
      ElNotification({
        title: 'Success',
        message: "启动成功",
        type: 'success',
      })
    } else {
      ElNotification({
        title: 'Error',
        message: err.Message,
        type: 'error',
      })
    }
  })
}

function stop() {
  StopProxy().then(err => {
    if (err == null) {
      ElNotification({
        title: 'Success',
        message: "停止成功",
        type: 'success',
      })
    } else {
      ElNotification({
        title: 'Error',
        message: err.Message,
        type: 'error',
      })
    }
  })
}

function clear() {
  tableData.length = 0;
}

function test() {
  Test().then(result => {
    //data.resultText = result
    console.log(result)
  })
}


function handleChange(field) {

  SetConfig(field, data.config).then(result => {
    //data.resultText = result
    if (result == null) {
      ElNotification({
        title: 'Success',
        message: '配置修改成功',
        type: 'success',
      })
    }
  })
}

</script>

<template>
  <el-container height="100vh">
    <el-header ref="header" class="affix-container">
      <el-affix :offset="10">
        <el-backtop :right="10" :bottom="10" />
        <el-space>
          <el-button type="primary" round @click="installCert">安装证书</el-button>
          <el-button type="success" round @click="generateCert">生成证书</el-button>
          <el-button type="warning" round @click="uninstallCert">卸载证书</el-button>
          <el-input-number v-model="data.config.Port" @change="handleChange('Port')" :controls="false" label="端口号" />
          <el-switch v-model="data.config.AutoProxy" inline-prompt active-text="自动代理" inactive-text="自动代理"
            @change="handleChange('AutoProxy')" />
          <el-button-group>
            <el-button type="primary" @click="start">启动服务</el-button>
            <el-button type="warning" @click="stop">停止服务</el-button>
            <el-button type="danger" @click="clear">清除数据</el-button>
          </el-button-group>
        </el-space>
      </el-affix>
    </el-header>
    <el-main>
      <el-table :data="tableData" :height="mainheight">
        <el-table-column type="expand">
          <template #default="props">
            <div m="4">{{ props.row.Body }}
            </div>
          </template>
        </el-table-column>
        <el-table-column label="Date" prop="Date" sortable fixed width="180" />
        <el-table-column label="PacketType" prop="PacketType" width="200" />
        <el-table-column label="Method" prop="Method" width="200" />
        <el-table-column label="Host" prop="Host" width="250" />
        <el-table-column label="Path" prop="Path" width="250" />
        <el-table-column label="ContentType" prop="ContentType" width="200" />
        <el-table-column label="Status" prop="Status" width="200" />
        <el-table-column label="StatusCode" prop="StatusCode" width="200" />
      </el-table>
    </el-main>
    <el-footer ref="footer">
      <el-space>
        <el-badge is-dot class="item">帮助</el-badge>
        <el-rate v-model="data.rate" allow-half />
        <el-input v-model="data.config.FilterHost" style="max-width: 200px" placeholder="Please input" @change="handleChange('FilterHost')" >
          <template #prepend>Host</template>
        </el-input>
        <el-switch v-model="data.config.SaveLogFile" inline-prompt active-text="保存到文件" inactive-text="保存到文件"
          @change="handleChange('SaveLogFile')" />
      </el-space>
    </el-footer>
  </el-container>
</template>
<style scoped>
.affix-container {
  text-align: center;
  border-radius: 4px;
  background: var(--el-color-primary-light-9);
}

.item {
  margin-top: 10px;
  margin-right: 40px;
}
</style>