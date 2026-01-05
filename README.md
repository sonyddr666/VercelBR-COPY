# 🚀 Vercel BR v2.2 (Render Edition)

Plataforma de deploy **self-hosted** otimizada para o free tier do Render.com. Permite fazer deploy de projetos estáticos (React, Vue, Astro, HTML) e Node.js diretamente do GitHub.

## ✨ Novidades v2.2
- **Dashboard Seguro:** Nova aba "Config" para gerenciar sua API Key.
- **Render Optimized:** Correções para proxy reverso e instalação de dependências.
- **Build Fix:** Suporte total a `devDependencies` (Vite, Webpack, Gulp) mesmo em ambiente de produção.

## 🛠️ Quick Start (Local)

1. **Instalar Dependências**
   ```bash
   npm install
   ```

2. **Configurar Ambiente**
   Crie um arquivo `.env`:
   ```env
   NODE_ENV=development
   # API_SECRET=sua-senha-segura (opcional em dev)
   # GITHUB_TOKEN=seu-token (opcional, para repos privados)
   ```

3. **Rodar Servidor**
   ```bash
   npm start
   ```
   Acesse: `http://localhost:3000/admin`

## ☁️ Deploy no Render.com

1. Faça push deste repositório para o GitHub.
2. Crie um novo **Web Service** no Render.
3. Conecte ao seu repositório.
4. **Environment Variables:**
   - `NODE_ENV`: `production`
   - `API_SECRET`: (Escolha uma senha forte)
   - `GITHUB_TOKEN`: (Opcional, se precisar clonar repos privados)
5. **Build Command:** `npm install`
6. **Start Command:** `npm start`

### 🔑 Autenticação no Dashboard

Ao acessar o dashboard em produção (`/admin`), vá na aba **⚙️ Config** e insira a mesma `API_SECRET` que você definiu nas variáveis de ambiente do Render.

O dashboard salvará a senha no seu navegador e autenticará automaticamente todas as operações de deploy.

## 📦 Projetos Suportados

O sistema detecta automaticamente:
- ✅ **Next.js** (`npm run build` -> `out`) - *Requer `output: 'export'`*
- ✅ **Vite** (`npm run build` -> `dist`)
- ✅ **Create React App** (`npm run build` -> `build`)
- ✅ **Astro** (`npm run build` -> `dist`)
- ✅ **HTML Estático** (se tiver `index.html` na raiz)
- ✅ **Node.js Genérico** (qualquer script `build` no package.json)

## ⚠️ Limitações (Free Tier)

- **RAM:** 512MB (Projetos muito pesados podem falhar no build)
- **Deploys:** Limitado a 3 deploys/hora para economizar recursos.
- **Sleep:** O serviço entra em hibernação após 15min inativo (o primeiro request pode demorar 50s).

## 🐛 Troubleshooting Comum

**Erro 127 (npm not found) ou Build Falhando:**
- Certifique-se de que o `server.js` está atualizado com a flag `--production=false` no `npm install`. Isso é necessário para que o Render instale ferramentas de build como Vite/Webpack.

**Status: undefined:**
- Se o deploy falhar drasticamente, o status pode não ser capturado. Verifique os logs do Render Dashboard para detalhes.
