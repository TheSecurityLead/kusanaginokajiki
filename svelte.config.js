import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		// Static adapter required for Tauri — no server-side rendering
		adapter: adapter({
			fallback: 'index.html'
		})
	}
};

export default config;
