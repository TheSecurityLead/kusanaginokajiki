import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [tailwindcss(), sveltekit()],

	// Tauri expects a fixed port during development
	server: {
		port: 1420,
		strictPort: true
	},

	// Env prefix for Tauri
	envPrefix: ['VITE_', 'TAURI_']
});
