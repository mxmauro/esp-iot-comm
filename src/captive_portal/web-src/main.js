import { mount } from 'svelte';
import './App.css';
import App from './App.svelte';

// -----------------------------------------------------------------------------

mount(App, {
    target: document.getElementById("app")
});
