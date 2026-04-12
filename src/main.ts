import './style.css';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing #app element');
}

app.innerHTML = `
  <main class="shell" id="main-content" role="main">
    <header class="hero">
      <p class="eyebrow">systemslibrarian · crypto-lab</p>
      <h1>crypto-lab-ring-sign</h1>
      <p>Scaffold complete. Ring and Group signature exhibits are loading in later phases.</p>
    </header>
  </main>
`;
