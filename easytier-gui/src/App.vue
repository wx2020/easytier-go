<script setup lang="ts">
import { getCurrentWindow } from '~/composables/wails_bridge'
import pkg from '~/../package.json'

onBeforeMount(async () => {
  await getCurrentWindow().setTitle(`Easytier GUI: v${pkg.version}`)
})
</script>

<template>
  <Toast position="bottom-right" />
  <RouterView />
</template>
