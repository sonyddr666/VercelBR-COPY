# Vercel BR

Plataforma de deploy all-in-one otimizada para Render.com free tier.

## 🚀 Quick Start

```bash
# 1. Instalar dependências
npm install

# 2. Configurar ambiente
cp .env.example .env
# Edite .env e defina API_SECRET

# 3. Rodar servidor
npm start
```

## 📡 API Endpoints

| Método | Endpoint | Auth | Descrição |
|--------|----------|------|-----------|
| GET | `/health` | ❌ | Status do sistema |
| GET | `/api/projects` | ✅ | Lista projetos |
| POST | `/api/projects/deploy` | ✅ | Novo deploy |
| GET | `/api/deploy-status/:jobId` | ✅ | Status do deploy |
| DELETE | `/api/projects/:id` | ✅ | Remove projeto |
| GET | `/projects/:id` | ❌ | Acessa projeto |
| GET | `/admin` | ❌ | Dashboard |

## 🔐 Autenticação

Envie o header `Authorization: Bearer <API_SECRET>` em todas as requisições autenticadas.

```bash
curl -X GET http://localhost:3000/api/projects \
  -H "Authorization: Bearer sua-api-secret"
```

## 📦 Deploy de Projeto

```bash
curl -X POST http://localhost:3000/api/projects/deploy \
  -H "Authorization: Bearer sua-api-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "projectId": "meu-site",
    "repoUrl": "https://github.com/user/repo",
    "branch": "main"
  }'
```

## 🎯 Frameworks Suportados

- ✅ Next.js (static export)
- ✅ Create React App
- ✅ Vite (React, Vue, Svelte)
- ✅ Astro
- ✅ HTML estático

## ⚠️ Limitações (Free Tier)

- RAM: 512MB
- Deploys: 3/hora
- Disco: 10GB
- O serviço "dorme" após inatividade

## 🚀 Deploy no Render

1. Push para GitHub
2. Conecte o repo no [Render Dashboard](https://dashboard.render.com)
3. Defina `API_SECRET` em Environment
4. Deploy!
