import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import App from './App.tsx';
import { initializePlugins } from './plugins';

// Initialize modular EDR plugins
initializePlugins();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

const skeleton = document.getElementById('app-skeleton');
if (skeleton) skeleton.remove();
