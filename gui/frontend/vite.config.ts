import {defineConfig} from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vitejs.dev/config/
// public/.gitkeep is copied into dist/ on every build, so the committed
// dist/.gitkeep (needed by `//go:embed all:frontend/dist`) survives
// emptyOutDir.
export default defineConfig({
  plugins: [vue()]
})
