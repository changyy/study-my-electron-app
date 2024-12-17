<script setup lang="ts">
import HelloWorld from './components/HelloWorld.vue'

import { ref, onMounted } from 'vue'

const devices = ref<any[]>([])
onMounted(() => {
  if (window.mdnsAPI && typeof window.mdnsAPI.onFound === 'function') {
    window.mdnsAPI.onFound((foundDevices) => {
      devices.value = foundDevices
      console.log('Found devices:')
      console.log(foundDevices)
    })
  }
})
</script>

<template>
  <div>
    <a href="https://electron-vite.github.io" target="_blank">
      <img src="/electron-vite.svg" class="logo" alt="Vite logo" />
    </a>
    <a href="https://vuejs.org/" target="_blank">
      <img src="./assets/vue.svg" class="logo vue" alt="Vue logo" />
    </a>
  </div>
  <!--
  <HelloWorld msg="Vite + Vue" />
  -->
  <div>
    <h3>已搜尋到的裝置：</h3>
    <ul id="deviceList">
      <li v-for="(device, index) in devices" :key="index">
        [{{ new Date(device.firstSeen).toLocaleString('zh-TW', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }) }}] {{ device.name }} ({{ device.type }}) 
        <ul>
          <li v-for="(data, i) in device.data" :key="I">
            {{ data }}
          </li>
        </ul>
      </li>
    </ul>
  </div>
</template>

<style scoped>
.logo {
  height: 6em;
  padding: 1.5em;
  will-change: filter;
  transition: filter 300ms;
}
.logo:hover {
  filter: drop-shadow(0 0 2em #646cffaa);
}
.logo.vue:hover {
  filter: drop-shadow(0 0 2em #42b883aa);
}

#deviceList {
  text-align: left;
  list-style-type: none;
  padding: 0;
}
</style>
