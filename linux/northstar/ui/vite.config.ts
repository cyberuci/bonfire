import path from 'path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import legacy from '@vitejs/plugin-legacy'
import tailwindcss from '@tailwindcss/vite'
import { tanstackRouter } from '@tanstack/router-plugin/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    tanstackRouter({
      target: 'react',
      autoCodeSplitting: true,
    }),
    react(),
    legacy({
      targets: ['defaults', 'Edge >= 109'],
    }),
    tailwindcss(),
  ],
  build: {
    cssTarget: 'chrome79',
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined
          if (id.includes('/react/') || id.includes('react-dom')) return 'react'
          if (id.includes('@tanstack')) return 'tanstack'
          if (id.includes('radix-ui')) return 'radix'
          if (id.includes('lucide-react')) return 'icons'
          if (id.includes('react-markdown') || id.includes('remark')) {
            return 'markdown'
          }
          if (id.includes('zod')) return 'validation'
          return undefined
        },
      },
    },
  },
  css: {
    transformer: 'lightningcss',
    lightningcss: {
      targets: {
        edge: 109,
      },
    },
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
})
