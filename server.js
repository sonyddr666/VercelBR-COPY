const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, param, validationResult } = require('express-validator');
const path = require('path');
const fs = require('fs-extra');
const { spawn } = require('child_process');
const simpleGit = require('simple-git');
// p-queue v6 compatível com CommonJS
const PQueue = require('p-queue').default || require('p-queue');
const { nanoid } = require('nanoid');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const IS_WINDOWS = process.platform === 'win32';
const IS_RENDER = !!process.env.RENDER;

// ═══════════════════════════════════════════════════════════════════
// 1. STARTUP CHECKS
// ═══════════════════════════════════════════════════════════════════

console.log(`
╔════════════════════════════════════════════╗
║   🚀 Vercel BR v2.2 - Render Optimized   ║
╚════════════════════════════════════════════╝
`);

console.log('🔍 Verificando ambiente...');
console.log(`   Plataforma: ${process.platform}`);
console.log(`   Node: ${process.version}`);
console.log(`   Render: ${IS_RENDER ? 'Sim ✅' : 'Não (local)'}`);
console.log(`   RAM Limite: ${process.env.NODE_OPTIONS || 'padrão'}`);

// Verifica variáveis obrigatórias
const requiredEnvVars = ['NODE_ENV'];
const optionalEnvVars = ['API_SECRET', 'GITHUB_TOKEN'];

const missingRequired = requiredEnvVars.filter(v => !process.env[v]);
const missingOptional = optionalEnvVars.filter(v => !process.env[v]);

if (missingRequired.length > 0) {
  console.error(`❌ Variáveis obrigatórias faltando: ${missingRequired.join(', ')}`);
  process.exit(1);
}

if (missingOptional.length > 0) {
  console.warn(`⚠️  Variáveis opcionais não definidas: ${missingOptional.join(', ')}`);
}

// Garante que pasta projects existe
const projectsRoot = path.resolve(__dirname, 'projects');
try {
  fs.ensureDirSync(projectsRoot);
  console.log(`✅ Pasta de projetos: ${projectsRoot}`);
} catch (error) {
  console.error(`❌ Erro ao criar pasta projects: ${error.message}`);
  process.exit(1);
}

// Verifica se git está disponível
(async () => {
  try {
    const git = simpleGit();
    const version = await git.version();
    console.log(`✅ Git disponível: v${version.major}.${version.minor}`);
  } catch (error) {
    console.error('❌ Git não encontrado! Deploys não funcionarão.');
  }
})();

// ═══════════════════════════════════════════════════════════════════
// 2. SEGURANÇA: HELMET + RATE LIMITING
// ═══════════════════════════════════════════════════════════════════

// Trust proxy (necessário para Render e outros serviços com reverse proxy)
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https:"], // https: para CDNs externos
      scriptSrcAttr: ["'unsafe-inline'"], // Permite onclick, onsubmit inline
      styleSrc: ["'self'", "'unsafe-inline'", "https:"], // https: para fonts e CDNs
      fontSrc: ["'self'", "https:", "data:"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'", "https:", "wss:"],
      frameSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Rate limiting global
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100,
  message: 'Muitas requisições. Aguarde 15 minutos.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiting para deploy (mais restritivo no Render por causa da RAM)
const deployLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hora
  max: IS_RENDER ? 3 : 5,
  message: 'Limite de deploys atingido. Aguarde 1 hora.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(globalLimiter);
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// ═══════════════════════════════════════════════════════════════════
// 3. QUEUE SYSTEM (in-memory, concurrency 1)
// ═══════════════════════════════════════════════════════════════════

const deployQueue = new PQueue({
  concurrency: 1,
  timeout: IS_RENDER ? 8 * 60 * 1000 : 10 * 60 * 1000
});

// Job status com TTL para evitar memory leak
const jobStatus = new Map();
const JOB_TTL = 60 * 60 * 1000; // 1 hora

setInterval(() => {
  const now = Date.now();
  let cleaned = 0;

  for (const [jobId, job] of jobStatus) {
    const createdAt = new Date(job.createdAt).getTime();
    if (now - createdAt > JOB_TTL) {
      jobStatus.delete(jobId);
      cleaned++;
    }
  }

  if (cleaned > 0) {
    console.log(`🧹 ${cleaned} jobs expirados removidos`);
  }
}, 15 * 60 * 1000);

// ═══════════════════════════════════════════════════════════════════
// 4. AUTENTICAÇÃO
// ═══════════════════════════════════════════════════════════════════

function authMiddleware(req, res, next) {
  // Se API_SECRET não estiver definida, modo desenvolvimento (INSEGURO)
  if (!process.env.API_SECRET) {
    console.warn('⚠️  API_SECRET não definida - modo desenvolvimento');
    return next();
  }

  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Autenticação necessária',
      hint: 'Envie: Authorization: Bearer <API_SECRET>'
    });
  }

  const token = authHeader.replace('Bearer ', '');

  if (token !== process.env.API_SECRET) {
    return res.status(403).json({ error: 'Token inválido' });
  }

  next();
}

// ═══════════════════════════════════════════════════════════════════
// 5. VALIDADORES DE INPUT
// ═══════════════════════════════════════════════════════════════════

const sanitizeProjectId = (value) => value.replace(/[^a-zA-Z0-9-_]/g, '');

const validateProjectId = [
  param('projectId')
    .trim()
    .isLength({ min: 3, max: 50 })
    .customSanitizer(sanitizeProjectId)
    .custom(value => /^[a-zA-Z0-9-_]+$/.test(value))
    .withMessage('ID inválido')
];

const validateDeployRequest = [
  body('projectId')
    .trim()
    .isLength({ min: 3, max: 50 })
    .customSanitizer(sanitizeProjectId),
  body('repoUrl')
    .trim()
    .matches(/^https:\/\/github\.com\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+(\.git)?$/)
    .withMessage('URL inválida (use https://github.com/user/repo)'),
  body('branch')
    .optional()
    .trim()
    .matches(/^[a-zA-Z0-9\/_-]+$/)
];

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      errors: errors.array().map(e => ({ field: e.path, message: e.msg }))
    });
  }
  next();
};

// ═══════════════════════════════════════════════════════════════════
// 6. DETECÇÃO DE TIPO DE PROJETO
// ═══════════════════════════════════════════════════════════════════

async function detectProjectType(tempPath) {
  const packageJsonPath = path.join(tempPath, 'package.json');

  // Projetos Node.js
  if (await fs.pathExists(packageJsonPath)) {
    const pkg = await fs.readJSON(packageJsonPath);

    // Next.js
    if (pkg.dependencies?.next) {
      await ensureNextExportConfig(tempPath);
      return {
        type: 'nextjs',
        buildCommand: ['run', 'build'],
        buildOutput: 'out',
        needsInstall: true
      };
    }

    // Create React App
    if (pkg.dependencies?.['react-scripts']) {
      return {
        type: 'cra',
        buildCommand: ['run', 'build'],
        buildOutput: 'build',
        needsInstall: true
      };
    }

    // Vite
    if (pkg.devDependencies?.vite || pkg.dependencies?.vite) {
      return {
        type: 'vite',
        buildCommand: ['run', 'build'],
        buildOutput: 'dist',
        needsInstall: true
      };
    }

    // Astro
    if (pkg.devDependencies?.astro || pkg.dependencies?.astro) {
      return {
        type: 'astro',
        buildCommand: ['run', 'build'],
        buildOutput: 'dist',
        needsInstall: true
      };
    }

    // Generic Node.js com build script
    if (pkg.scripts?.build) {
      return {
        type: 'node',
        buildCommand: ['run', 'build'],
        buildOutput: 'dist',
        needsInstall: true
      };
    }
  }

  // HTML estático (já pronto, não precisa build)
  if (await fs.pathExists(path.join(tempPath, 'index.html'))) {
    return {
      type: 'static',
      buildOutput: '.',
      needsInstall: false,
      noBuild: true
    };
  }

  throw new Error(
    'Tipo de projeto não reconhecido. Suportados: Next.js, CRA, Vite, Astro, HTML estático.'
  );
}

// Configura Next.js para static export
async function ensureNextExportConfig(tempPath) {
  const configPaths = [
    path.join(tempPath, 'next.config.js'),
    path.join(tempPath, 'next.config.mjs'),
  ];

  for (const configPath of configPaths) {
    if (await fs.pathExists(configPath)) {
      const config = await fs.readFile(configPath, 'utf-8');
      if (config.includes("output: 'export'") || config.includes('output: "export"')) {
        return true; // Já configurado
      }
    }
  }

  // Cria config com output: export
  const newConfig = `/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  trailingSlash: true,
  images: { unoptimized: true },
};
module.exports = nextConfig;
`;

  await fs.writeFile(path.join(tempPath, 'next.config.js'), newConfig);
  console.log('✅ next.config.js criado com output: export');
  return true;
}

// ═══════════════════════════════════════════════════════════════════
// 7. EXECUÇÃO DE COMANDOS (cross-platform)
// ═══════════════════════════════════════════════════════════════════

function getNpmCommand() {
  if (IS_WINDOWS) return 'npm.cmd';
  return 'npm';
}

function runCommand(command, args, cwd, jobId) {
  return new Promise((resolve, reject) => {
    // Constrói comando como string (mais confiável com shell)
    const fullCommand = `${command} ${args.join(' ')}`;

    const job = jobStatus.get(jobId);
    if (job) job.logs.push(`$ ${fullCommand}`);

    const child = spawn(fullCommand, [], {
      cwd,
      stdio: 'pipe',
      shell: true,
      env: {
        ...process.env,
        PATH: process.env.PATH,
        NODE_OPTIONS: process.env.NODE_OPTIONS || '--max-old-space-size=400'
      }
    });

    let output = '';

    child.stdout.on('data', (data) => {
      const text = data.toString().trim();
      if (text) {
        output += text + '\n';
        if (job) job.logs.push(text);
      }
    });

    child.stderr.on('data', (data) => {
      const text = data.toString().trim();
      if (text) {
        output += text + '\n';
        if (job) job.logs.push(`⚠️ ${text}`);
      }
    });

    child.on('close', (code) => {
      if (code === 0) {
        resolve(output);
      } else {
        reject(new Error(`'${fullCommand}' falhou (código ${code})`));
      }
    });

    child.on('error', (error) => {
      reject(error);
    });
  });
}

// ═══════════════════════════════════════════════════════════════════
// 8. FUNÇÃO DE DEPLOY
// ═══════════════════════════════════════════════════════════════════

async function deployProject(projectId, repoUrl, branch = 'main', jobId) {
  const projectPath = path.join(projectsRoot, projectId);
  const tempPath = path.join(__dirname, 'temp', nanoid());

  jobStatus.set(jobId, {
    status: 'cloning',
    progress: 10,
    logs: ['🔄 Iniciando deploy...'],
    projectId,
    createdAt: new Date().toISOString()
  });

  try {
    // Validação de path traversal
    if (!path.resolve(projectPath).startsWith(projectsRoot)) {
      throw new Error('Path inválido');
    }

    await fs.ensureDir(tempPath);
    const git = simpleGit();

    jobStatus.get(jobId).logs.push(`📦 Clonando (branch: ${branch})...`);

    // Clone com token se disponível (para repos privados)
    let cloneUrl = repoUrl;
    if (process.env.GITHUB_TOKEN && repoUrl.includes('github.com')) {
      cloneUrl = repoUrl.replace(
        'https://github.com',
        `https://${process.env.GITHUB_TOKEN}@github.com`
      );
      git.outputHandler(() => { }); // Silencia para não expor token
    }

    await git.clone(cloneUrl, tempPath, ['--depth', '1', '--branch', branch]);

    jobStatus.set(jobId, {
      ...jobStatus.get(jobId),
      status: 'detecting',
      progress: 20,
      logs: [...jobStatus.get(jobId).logs, '✅ Clone OK', '🔍 Detectando tipo...']
    });

    // Detecta tipo de projeto
    const projectType = await detectProjectType(tempPath);
    jobStatus.get(jobId).logs.push(`📋 Tipo: ${projectType.type}`);

    // Install dependencies
    if (projectType.needsInstall) {
      jobStatus.set(jobId, {
        ...jobStatus.get(jobId),
        status: 'installing',
        progress: 40,
        logs: [...jobStatus.get(jobId).logs, '📥 Instalando dependências...']
      });

      // Instala todas as deps (incluindo devDeps para build tools)
      await runCommand('npm', [
        'install',
        '--prefer-offline',
        '--no-audit',
        '--no-fund',
        '--maxsockets=1',
      ], tempPath, jobId);

      jobStatus.get(jobId).logs.push('✅ Dependências instaladas');
    }

    // Build
    if (!projectType.noBuild) {
      jobStatus.set(jobId, {
        ...jobStatus.get(jobId),
        status: 'building',
        progress: 60,
        logs: [...jobStatus.get(jobId).logs, '🔨 Buildando...']
      });

      await runCommand(
        'npm',
        projectType.buildCommand,
        tempPath,
        jobId
      );

      jobStatus.get(jobId).logs.push('✅ Build OK');
    }

    jobStatus.set(jobId, {
      ...jobStatus.get(jobId),
      status: 'deploying',
      progress: 80,
      logs: [...jobStatus.get(jobId).logs, '📤 Copiando arquivos...']
    });

    // Move build para pasta de projetos
    const buildPath = path.join(tempPath, projectType.buildOutput);

    if (!(await fs.pathExists(buildPath))) {
      throw new Error(`Build output não encontrado: ${projectType.buildOutput}`);
    }

    await fs.remove(projectPath);
    await fs.ensureDir(projectPath);
    await fs.copy(buildPath, path.join(projectPath, 'public'));

    // Salva metadata
    const metadata = {
      projectId,
      projectType: projectType.type,
      repoUrl: repoUrl.replace(process.env.GITHUB_TOKEN || '', '***'),
      branch,
      buildOutput: projectType.buildOutput,
      deployedAt: new Date().toISOString(),
      jobId
    };

    await fs.writeJSON(path.join(projectPath, 'metadata.json'), metadata, { spaces: 2 });

    // Cleanup temp
    await fs.remove(tempPath);

    jobStatus.set(jobId, {
      status: 'completed',
      progress: 100,
      logs: [
        ...jobStatus.get(jobId).logs,
        '✅ Deploy completo!',
        `🌐 URL: /projects/${projectId}`
      ],
      url: `/projects/${projectId}`,
      projectId,
      createdAt: jobStatus.get(jobId).createdAt
    });

    console.log(`✅ Deploy ${projectId} concluído`);
    return true;

  } catch (error) {
    console.error(`❌ Deploy ${projectId} falhou:`, error);

    jobStatus.set(jobId, {
      status: 'failed',
      progress: 0,
      logs: [
        ...(jobStatus.get(jobId)?.logs || []),
        `❌ Erro: ${error.message}`,
        IS_RENDER ? '💡 Free tier: 512MB RAM. Projetos grandes podem falhar.' : ''
      ].filter(Boolean),
      error: error.message,
      projectId,
      createdAt: jobStatus.get(jobId)?.createdAt || new Date().toISOString()
    });

    await fs.remove(tempPath).catch(() => { });
    throw error;
  }
}

// ═══════════════════════════════════════════════════════════════════
// 9. ROTAS DA API
// ═══════════════════════════════════════════════════════════════════

// Health check (público)
app.get('/health', (req, res) => {
  const mem = process.memoryUsage();
  res.json({
    status: 'healthy',
    uptime: Math.floor(process.uptime()),
    queue: {
      pending: deployQueue.pending,
      size: deployQueue.size
    },
    memory: {
      heap: `${Math.floor(mem.heapUsed / 1024 / 1024)}MB / ${Math.floor(mem.heapTotal / 1024 / 1024)}MB`,
      rss: `${Math.floor(mem.rss / 1024 / 1024)}MB`,
      limit: process.env.NODE_OPTIONS || 'default'
    },
    jobs: jobStatus.size,
    platform: process.platform,
    isRender: IS_RENDER,
    node: process.version
  });
});

// Lista projetos
app.get('/api/projects', authMiddleware, async (req, res) => {
  try {
    if (!(await fs.pathExists(projectsRoot))) {
      return res.json([]);
    }

    const projects = await fs.readdir(projectsRoot);
    const projectList = await Promise.all(
      projects
        .filter(p => !p.startsWith('.'))
        .map(async (projectId) => {
          const metadataPath = path.join(projectsRoot, projectId, 'metadata.json');
          try {
            const metadata = await fs.readJSON(metadataPath);
            return { id: projectId, url: `/projects/${projectId}`, ...metadata };
          } catch {
            return { id: projectId, url: `/projects/${projectId}`, deployedAt: null };
          }
        })
    );

    res.json(projectList);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Novo deploy
app.post(
  '/api/projects/deploy',
  authMiddleware,
  deployLimiter,
  validateDeployRequest,
  handleValidationErrors,
  async (req, res) => {
    const { projectId, repoUrl, branch = 'main' } = req.body;
    const jobId = nanoid();

    jobStatus.set(jobId, {
      status: 'queued',
      progress: 0,
      logs: ['⏳ Na fila...'],
      projectId,
      createdAt: new Date().toISOString()
    });

    deployQueue.add(() => deployProject(projectId, repoUrl, branch, jobId))
      .catch(() => { });

    res.json({
      success: true,
      jobId,
      statusUrl: `/api/deploy-status/${jobId}`,
      message: `Deploy iniciado. Posição na fila: ${deployQueue.size + 1}`,
      warning: IS_RENDER ? 'Free tier: 512MB RAM. Builds grandes podem falhar.' : null
    });
  }
);

// Status do deploy
app.get('/api/deploy-status/:jobId', authMiddleware, (req, res) => {
  const status = jobStatus.get(req.params.jobId);
  if (!status) {
    return res.status(404).json({
      error: 'Job não encontrado',
      hint: 'Jobs são mantidos por 1 hora após conclusão'
    });
  }
  res.json(status);
});

// Remove projeto
app.delete(
  '/api/projects/:projectId',
  authMiddleware,
  validateProjectId,
  handleValidationErrors,
  async (req, res) => {
    const projectPath = path.join(projectsRoot, req.params.projectId);

    if (!path.resolve(projectPath).startsWith(projectsRoot)) {
      return res.status(400).json({ error: 'Path inválido' });
    }

    try {
      if (!(await fs.pathExists(projectPath))) {
        return res.status(404).json({ error: 'Projeto não encontrado' });
      }
      await fs.remove(projectPath);
      res.json({ success: true, message: `Projeto ${req.params.projectId} removido` });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// ═══════════════════════════════════════════════════════════════════
// 10. SERVE PROJETOS ESTÁTICOS
// ═══════════════════════════════════════════════════════════════════

app.use('/projects/:projectId', validateProjectId, handleValidationErrors, async (req, res, next) => {
  // Redirect para garantir trailing slash (necessário para paths relativos funcionarem)
  if (req.path === '/' && !req.originalUrl.endsWith('/')) {
    return res.redirect(301, req.originalUrl + '/');
  }

  const projectPath = path.join(projectsRoot, req.params.projectId, 'public');

  // Validação de path traversal
  if (!path.resolve(projectPath).startsWith(projectsRoot)) {
    return res.status(403).send('Acesso negado');
  }

  // Verifica se projeto existe
  if (!(await fs.pathExists(projectPath))) {
    return res.status(404).send(`
      <!DOCTYPE html>
      <html lang="pt-BR">
        <head>
          <meta charset="UTF-8">
          <title>Projeto não encontrado</title>
          <style>
            body { 
              font-family: system-ui; 
              display: flex; 
              align-items: center; 
              justify-content: center; 
              min-height: 100vh;
              margin: 0;
              background: #f5f5f5;
            }
            .container { text-align: center; }
            h1 { font-size: 4em; margin: 0; }
            code { background: #e0e0e0; padding: 4px 8px; border-radius: 4px; }
            a { color: #667eea; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>🔍</h1>
            <h2>Projeto não encontrado</h2>
            <p>O projeto <code>${req.params.projectId}</code> não existe ou não foi deployado.</p>
            <p><a href="/">← Voltar</a></p>
          </div>
        </body>
      </html>
    `);
  }

  // Determina arquivo a servir
  const requestedPath = req.path === '/' ? '/index.html' : req.path;
  const filePath = path.join(projectPath, requestedPath);

  // Validação de path traversal no arquivo
  if (!path.resolve(filePath).startsWith(path.resolve(projectPath))) {
    return res.status(403).send('Acesso negado');
  }

  try {
    await fs.access(filePath);

    // Se for index.html, reescreve paths absolutos para relativos
    if (requestedPath === '/index.html') {
      let html = await fs.readFile(filePath, 'utf-8');

      // Converte paths absolutos para relativos
      // /assets/ -> ./assets/, /js/ -> ./js/, etc
      html = html
        .replace(/href="\//g, 'href="./')
        .replace(/src="\//g, 'src="./');

      res.type('html').send(html);
    } else {
      res.sendFile(filePath);
    }
  } catch {
    // Fallback para index.html (SPA routing)
    const indexPath = path.join(projectPath, 'index.html');
    if (await fs.pathExists(indexPath)) {
      let html = await fs.readFile(indexPath, 'utf-8');

      html = html
        .replace(/href="\//g, 'href="./')
        .replace(/src="\//g, 'src="./');

      res.type('html').send(html);
    } else {
      res.status(404).send('Arquivo não encontrado');
    }
  }
});

// ═══════════════════════════════════════════════════════════════════
// 11. DASHBOARD
// ═══════════════════════════════════════════════════════════════════

app.use('/admin', express.static(path.join(__dirname, 'dashboard/dist')));
app.get('/admin/*', (req, res) => {
  const indexPath = path.join(__dirname, 'dashboard/dist/index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(503).send('Dashboard não disponível');
  }
});

// ═══════════════════════════════════════════════════════════════════
// 12. HOMEPAGE
// ═══════════════════════════════════════════════════════════════════

app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vercel BR v2.2 - Deploy Simplificado</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      line-height: 1.6;
      padding: 20px;
      max-width: 900px;
      margin: 0 auto;
      background: #f5f5f5;
    }
    .header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 40px;
      border-radius: 12px;
      margin-bottom: 30px;
    }
    .card { 
      background: white;
      border-radius: 8px;
      padding: 30px;
      margin: 20px 0;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    h1 { font-size: 2.5em; margin-bottom: 10px; }
    h2 { color: #333; margin-bottom: 15px; }
    code { 
      background: #f4f4f4;
      padding: 2px 8px;
      border-radius: 4px;
      font-family: 'Fira Code', monospace;
      font-size: 0.9em;
    }
    pre {
      background: #2d2d2d;
      color: #f8f8f8;
      padding: 20px;
      border-radius: 6px;
      overflow-x: auto;
      margin: 15px 0;
      font-size: 0.85em;
    }
    a { color: #667eea; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .badge {
      display: inline-block;
      background: #10b981;
      color: white;
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 0.85em;
      margin-left: 10px;
    }
    ul { margin-left: 20px; }
    li { margin: 8px 0; }
  </style>
</head>
<body>
  <div class="header">
    <h1>🚀 Vercel BR v2.2</h1>
    <p>Plataforma de deploy simplificada e segura</p>
    <span class="badge">${IS_RENDER ? 'Render.com ✅' : 'Local'}</span>
    <span class="badge">512MB RAM</span>
  </div>
  
  <div class="card">
    <h2>🔗 Links Rápidos</h2>
    <ul>
      <li><a href="/admin">📊 Dashboard</a></li>
      <li><a href="/health">💚 Health Check</a></li>
    </ul>
  </div>
  
  <div class="card">
    <h2>⚡ Quick Start</h2>
    <p><strong>1. Configure sua API Key</strong></p>
    <pre>export API_SECRET="sua-chave-secreta"</pre>
    
    <p><strong>2. Faça um deploy</strong></p>
    <pre>curl -X POST ${req.protocol}://${req.get('host')}/api/projects/deploy \\
  -H "Authorization: Bearer \${API_SECRET}" \\
  -H "Content-Type: application/json" \\
  -d '{"projectId":"meu-site","repoUrl":"https://github.com/user/repo"}'</pre>
    
    <p><strong>3. Acompanhe o status</strong></p>
    <pre>curl ${req.protocol}://${req.get('host')}/api/deploy-status/[jobId] \\
  -H "Authorization: Bearer \${API_SECRET}"</pre>
  </div>
  
  <div class="card">
    <h2>🎯 Frameworks Suportados</h2>
    <ul>
      <li>✅ Next.js (static export)</li>
      <li>✅ Create React App</li>
      <li>✅ Vite (React, Vue, Svelte)</li>
      <li>✅ Astro</li>
      <li>✅ HTML estático</li>
    </ul>
  </div>
  
  <div class="card">
    <h2>📚 API Endpoints</h2>
    <ul>
      <li><code>GET /health</code> - Status do sistema</li>
      <li><code>GET /api/projects</code> - Lista projetos (auth)</li>
      <li><code>POST /api/projects/deploy</code> - Novo deploy (auth)</li>
      <li><code>GET /api/deploy-status/:jobId</code> - Status do deploy (auth)</li>
      <li><code>DELETE /api/projects/:id</code> - Remove projeto (auth)</li>
      <li><code>GET /projects/:id</code> - Acessa projeto (público)</li>
    </ul>
  </div>
  
  <div class="card">
    <h2>⚠️ Limitações (Free Tier)</h2>
    <ul>
      <li>RAM: 512MB (projetos grandes podem falhar)</li>
      <li>Deploys: ${IS_RENDER ? 3 : 5}/hora</li>
      <li>Disco: 10GB persistente</li>
      <li>O serviço "dorme" após inatividade</li>
    </ul>
  </div>
</body>
</html>
  `);
});

// ═══════════════════════════════════════════════════════════════════
// 13. ERROR HANDLER
// ═══════════════════════════════════════════════════════════════════

app.use((err, req, res, next) => {
  console.error('Erro não tratado:', err);
  res.status(500).json({
    error: 'Erro interno do servidor',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ═══════════════════════════════════════════════════════════════════
// 14. START SERVER
// ═══════════════════════════════════════════════════════════════════

const server = app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════╗
║   ✅ Servidor Rodando                     ║
║                                            ║
║   URL:       http://localhost:${PORT}           ║
║   Health:    http://localhost:${PORT}/health    ║
║   Dashboard: http://localhost:${PORT}/admin     ║
║                                            ║
║   🛡️  Segurança: Helmet + Rate Limit     ║
║   📦 Queue: concurrency=1                 ║
║   💾 Projetos: ${projectsRoot.length > 30 ? projectsRoot.substring(0, 30) + '...' : projectsRoot}
╚════════════════════════════════════════════╝
  `);
});

// Graceful shutdown
['SIGTERM', 'SIGINT'].forEach(signal => {
  process.on(signal, async () => {
    console.log(`\n🛑 ${signal} recebido, encerrando...`);
    server.close(() => console.log('✅ HTTP fechado'));
    await deployQueue.onIdle();
    console.log('✅ Fila finalizada');
    process.exit(0);
  });
});
