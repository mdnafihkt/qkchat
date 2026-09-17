import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { VitePWA } from 'vite-plugin-pwa'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: 'autoUpdate',
      includeAssets: ['qkchat-circle.png', 'qkchat.png'],
      manifest: {
        name: 'qkchat',
        short_name: 'qkchat',
        description: 'qkchat messaging application',
        theme_color: '#ffffff',
        background_color: '#ffffff',
        display: 'standalone',
        icons: [
          {
            src: 'qkchat-circle.png',
            sizes: '192x192',
            type: 'image/png'
          },
          {
            src: 'qkchat-circle.png',
            sizes: '512x512',
            type: 'image/png'
          },
          {
            src: 'qkchat-circle.png',
            sizes: '512x512',
            type: 'image/png',
            purpose: 'any maskable'
          }
        ]
      }
    })
  ],
})
