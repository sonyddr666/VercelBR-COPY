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
  return '/usr/bin/env npm';  // Mais confiável em Linux/Render
}

function runCommand(command, args, cwd, jobId) {
  return new Promise((resolve, reject) => {
    // Usa getNpmCommand() para npm
    const actualCommand = command === 'npm' ? getNpmCommand() : command;
    // Constrói comando como string (mais confiável com shell)
    const fullCommand = `${actualCommand} ${args.join(' ')}`;

    const job = jobStatus.get(jobId);
    if (job) job.logs.push(`$ ${fullCommand}`);

    const child = spawn(fullCommand, [], {
      cwd,
      stdio: 'pipe',
      shell: true,
      env: {
        ...process.env,
        PATH: process.env.PATH,
        NODE_OPTIONS: process.env.NODE_OPTIONS || '--max-old-space-size=480'
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

  // ✅ INICIALIZA status com valores padrão
  jobStatus.set(jobId, {
    status: 'cloning',
    progress: 10,
    logs: ['🔄 Iniciando deploy...'],
    projectId,
    url: null,
    error: null,
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
        logs: [...jobStatus.get(jobId).logs, '📥 Instalando dependências (prod + dev)...']
      });

      await runCommand('npm', [
        'install',
        '--production=false',
        '--prefer-offline',
        '--no-audit',
        '--no-fund',
        '--maxsockets=1',
      ], tempPath, jobId);

      jobStatus.get(jobId).logs.push('✅ Dependências instaladas (prod + dev)');
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

    // ✅ SEMPRE define todos os campos no sucesso
    jobStatus.set(jobId, {
      status: 'completed',
      progress: 100,
      logs: [
        ...jobStatus.get(jobId).logs,
        '✅ Deploy completo!',
        `🌐 URL: /projects/${projectId}`
      ],
      url: `/projects/${projectId}`,
      error: null,
      projectId,
      createdAt: jobStatus.get(jobId).createdAt
    });

    console.log(`✅ Deploy ${projectId} concluído`);
    return true;

  } catch (error) {
    console.error(`❌ Deploy ${projectId} falhou:`, error);

    // ✅ SEMPRE define todos os campos no erro
    jobStatus.set(jobId, {
      status: 'failed',
      progress: 0,
      logs: [
        ...(jobStatus.get(jobId)?.logs || []),
        `❌ Erro: ${error.message}`,
        IS_RENDER ? '💡 Free tier: 512MB RAM. Projetos grandes podem falhar.' : ''
      ].filter(Boolean),
      url: null,
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

    // ✅ INICIALIZA com TODOS os campos definidos
    jobStatus.set(jobId, {
      status: 'queued',
      progress: 0,
      logs: ['⏳ Aguardando na fila...'],
      projectId,
      url: null,
      error: null,
      createdAt: new Date().toISOString()
    });

    // ✅ Adiciona tratamento de erro na fila
    deployQueue.add(() => deployProject(projectId, repoUrl, branch, jobId))
      .catch((err) => {
        console.error(`❌ Erro na fila (${jobId}):`, err);
        jobStatus.set(jobId, {
          status: 'failed',
          progress: 0,
          logs: ['❌ Erro ao processar deploy: ' + err.message],
          error: err.message,
          url: null,
          projectId,
          createdAt: jobStatus.get(jobId)?.createdAt || new Date().toISOString()
        });
      });

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

  // ✅ SEMPRE retorna estrutura completa com valores padrão
  res.json({
    status: status.status || 'unknown',
    progress: status.progress ?? 0,
    logs: status.logs || [],
    projectId: status.projectId || null,
    url: status.url || null,
    error: status.error || null,
    createdAt: status.createdAt || new Date().toISOString()
  });
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
// 12. HOMEPAGE - LANDING PAGE PREMIUM
// ═══════════════════════════════════════════════════════════════════

app.get('/', async (req, res) => {
  // Conta projetos ativos
  let projectCount = 0;
  try {
    if (await fs.pathExists(projectsRoot)) {
      const projects = await fs.readdir(projectsRoot);
      projectCount = projects.filter(p => !p.startsWith('.')).length;
    }
  } catch { }

  res.send(`
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vercel BR - Plataforma de Deploy Simplificada</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-primary: #0a0a0f;
      --bg-secondary: #12121a;
      --glass-bg: rgba(255, 255, 255, 0.03);
      --glass-border: rgba(255, 255, 255, 0.08);
      --accent-1: #667eea;
      --accent-2: #764ba2;
      --accent-3: #f093fb;
      --text-primary: #ffffff;
      --text-secondary: rgba(255, 255, 255, 0.7);
      --text-muted: rgba(255, 255, 255, 0.4);
      --success: #10b981;
      --warning: #f59e0b;
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }
    
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      min-height: 100vh;
      overflow-x: hidden;
    }

    /* Animated gradient background */
    .bg-gradient {
      position: fixed;
      inset: 0;
      z-index: -1;
      background: 
        radial-gradient(ellipse 80% 50% at 50% -20%, rgba(102, 126, 234, 0.3), transparent),
        radial-gradient(ellipse 60% 40% at 100% 50%, rgba(118, 75, 162, 0.2), transparent),
        radial-gradient(ellipse 50% 30% at 0% 80%, rgba(240, 147, 251, 0.15), transparent);
      animation: gradientPulse 8s ease-in-out infinite alternate;
    }

    @keyframes gradientPulse {
      0% { opacity: 0.8; transform: scale(1); }
      100% { opacity: 1; transform: scale(1.1); }
    }

    /* Grid pattern overlay */
    .grid-pattern {
      position: fixed;
      inset: 0;
      z-index: -1;
      background-image: 
        linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px);
      background-size: 60px 60px;
      mask-image: radial-gradient(ellipse at center, black 30%, transparent 70%);
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 0 24px;
    }

    /* Hero Section */
    .hero {
      min-height: 45vh;
      display: flex;
      flex-direction: column;
      justify-content: flex-start;
      align-items: center;
      text-align: center;
      padding: 60px 20px;
      position: relative;
    }

    .hero-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: var(--glass-bg);
      border: 1px solid var(--glass-border);
      padding: 8px 16px;
      border-radius: 50px;
      font-size: 0.85rem;
      color: var(--text-secondary);
      margin-bottom: 32px;
      backdrop-filter: blur(10px);
      animation: fadeInUp 0.6s ease-out;
    }

    .hero-badge .dot {
      width: 8px;
      height: 8px;
      background: var(--success);
      border-radius: 50%;
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.5; transform: scale(1.2); }
    }

    .hero h1 {
      font-size: clamp(3rem, 8vw, 5.5rem);
      font-weight: 800;
      line-height: 1.1;
      margin-bottom: 24px;
      background: linear-gradient(135deg, var(--text-primary) 0%, var(--accent-1) 50%, var(--accent-3) 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      animation: fadeInUp 0.6s ease-out 0.1s backwards;
    }

    .hero p {
      font-size: 1.25rem;
      color: var(--text-secondary);
      max-width: 600px;
      margin-bottom: 48px;
      animation: fadeInUp 0.6s ease-out 0.2s backwards;
    }

    .hero-buttons {
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      justify-content: center;
      animation: fadeInUp 0.6s ease-out 0.3s backwards;
    }

    .btn {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 16px 32px;
      border-radius: 12px;
      font-size: 1rem;
      font-weight: 600;
      text-decoration: none;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      cursor: pointer;
      border: none;
    }

    .btn-primary {
      background: linear-gradient(135deg, var(--accent-1), var(--accent-2));
      color: white;
      box-shadow: 0 4px 24px rgba(102, 126, 234, 0.4);
    }

    .btn-primary:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 32px rgba(102, 126, 234, 0.6);
    }

    .btn-secondary {
      background: var(--glass-bg);
      color: var(--text-primary);
      border: 1px solid var(--glass-border);
      backdrop-filter: blur(10px);
    }

    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.08);
      border-color: rgba(255, 255, 255, 0.15);
    }

    @keyframes fadeInUp {
      from { opacity: 0; transform: translateY(30px); }
      to { opacity: 1; transform: translateY(0); }
    }

    /* Stats Section */
    .stats {
      padding: 40px 0 80px;
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 24px;
    }

    .stat-card {
      background: var(--glass-bg);
      border: 1px solid var(--glass-border);
      border-radius: 16px;
      padding: 32px;
      text-align: center;
      backdrop-filter: blur(10px);
      transition: all 0.3s ease;
    }

    .stat-card:hover {
      transform: translateY(-4px);
      border-color: var(--accent-1);
      box-shadow: 0 8px 32px rgba(102, 126, 234, 0.2);
    }

    .stat-value {
      font-size: 3rem;
      font-weight: 800;
      background: linear-gradient(135deg, var(--accent-1), var(--accent-3));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    .stat-label {
      color: var(--text-secondary);
      font-size: 0.9rem;
      margin-top: 8px;
    }

    /* Features Section */
    .features {
      padding: 80px 0;
    }

    .section-title {
      font-size: 2.5rem;
      font-weight: 700;
      text-align: center;
      margin-bottom: 16px;
    }

    .section-subtitle {
      color: var(--text-secondary);
      text-align: center;
      max-width: 500px;
      margin: 0 auto 60px;
    }

    .features-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 24px;
    }

    .feature-card {
      background: var(--glass-bg);
      border: 1px solid var(--glass-border);
      border-radius: 20px;
      padding: 40px 32px;
      backdrop-filter: blur(10px);
      transition: all 0.3s ease;
      position: relative;
      overflow: hidden;
    }

    .feature-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      background: linear-gradient(90deg, var(--accent-1), var(--accent-2), var(--accent-3));
      opacity: 0;
      transition: opacity 0.3s;
    }

    .feature-card:hover::before {
      opacity: 1;
    }

    .feature-card:hover {
      transform: translateY(-4px);
      border-color: rgba(255, 255, 255, 0.15);
    }

    .feature-icon {
      font-size: 2.5rem;
      margin-bottom: 20px;
      display: block;
    }

    .feature-card h3 {
      font-size: 1.25rem;
      font-weight: 600;
      margin-bottom: 12px;
    }

    .feature-card p {
      color: var(--text-secondary);
      font-size: 0.95rem;
      line-height: 1.6;
    }

    /* CTA Section */
    .cta {
      padding: 100px 0;
      text-align: center;
    }

    .cta-box {
      background: linear-gradient(135deg, rgba(102, 126, 234, 0.15), rgba(118, 75, 162, 0.15));
      border: 1px solid var(--glass-border);
      border-radius: 32px;
      padding: 80px 40px;
      backdrop-filter: blur(20px);
      position: relative;
      overflow: hidden;
    }

    .cta-box::before {
      content: '';
      position: absolute;
      top: -50%;
      left: -50%;
      width: 200%;
      height: 200%;
      background: radial-gradient(circle, rgba(102, 126, 234, 0.1) 0%, transparent 50%);
      animation: rotateBg 20s linear infinite;
    }

    @keyframes rotateBg {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }

    .cta-box h2 {
      font-size: 2.5rem;
      font-weight: 700;
      margin-bottom: 16px;
      position: relative;
    }

    .cta-box p {
      color: var(--text-secondary);
      margin-bottom: 32px;
      font-size: 1.1rem;
      position: relative;
    }

    /* Footer */
    footer {
      padding: 40px 0;
      border-top: 1px solid var(--glass-border);
      text-align: center;
      color: var(--text-muted);
    }

    footer a {
      color: var(--accent-1);
      text-decoration: none;
    }

    footer a:hover {
      text-decoration: underline;
    }

    .footer-links {
      display: flex;
      gap: 32px;
      justify-content: center;
      margin-bottom: 20px;
    }

    /* Mobile */
    @media (max-width: 768px) {
      .hero { min-height: 70vh; padding: 40px 20px; }
      .hero h1 { font-size: 2.5rem; }
      .hero p { font-size: 1rem; }
      .btn { padding: 14px 24px; font-size: 0.9rem; }
      .stat-value { font-size: 2rem; }
      .section-title { font-size: 1.8rem; }
      .cta-box { padding: 50px 24px; }
      .cta-box h2 { font-size: 1.8rem; }
    }
  </style>
</head>
<body>
  <div class="bg-gradient"></div>
  <div class="grid-pattern"></div>

  <!-- Hero -->
  <section class="hero">
    <div class="hero-badge">
      <span class="dot"></span>
      ${IS_RENDER ? 'Rodando no Render.com' : 'Ambiente Local'}
    </div>
    
    <h1>Deploy em<br>segundos.</h1>
    
    <p>Plataforma self-hosted para deploy de projetos React, Next.js, Vite, Astro e HTML estático. Simples, rápido e gratuito.</p>
    
    <div class="hero-buttons">
      <a href="/admin" class="btn btn-primary">
        🚀 Acessar Dashboard
      </a>
      <a href="/health" class="btn btn-secondary">
        💚 Status do Sistema
      </a>
    </div>
  </section>

  <!-- Stats -->
  <section class="stats">
    <div class="container">
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-value">${projectCount}</div>
          <div class="stat-label">Projetos Ativos</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${IS_RENDER ? '3' : '5'}</div>
          <div class="stat-label">Deploys/Hora</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">512</div>
          <div class="stat-label">MB de RAM</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">∞</div>
          <div class="stat-label">Projetos Estáticos</div>
        </div>
      </div>
    </div>
  </section>

  <!-- Features -->
  <section class="features">
    <div class="container">
      <h2 class="section-title">Frameworks Suportados</h2>
      <p class="section-subtitle">Detecta automaticamente o tipo do projeto e faz o build correto</p>
      
      <div class="features-grid">
        <div class="feature-card">
          <span class="feature-icon">⚡</span>
          <h3>Next.js</h3>
          <p>Static export automático. Seu projeto Next.js buildado e servido em segundos.</p>
        </div>
        <div class="feature-card">
          <span class="feature-icon">🔥</span>
          <h3>Vite</h3>
          <p>React, Vue, Svelte, Vanilla. Build ultrarrápido com Vite out of the box.</p>
        </div>
        <div class="feature-card">
          <span class="feature-icon">🚀</span>
          <h3>Astro</h3>
          <p>Sites performáticos com Astro. Zero JavaScript opcional incluído.</p>
        </div>
        <div class="feature-card">
          <span class="feature-icon">⚛️</span>
          <h3>Create React App</h3>
          <p>Suporte completo ao CRA. npm run build e pronto.</p>
        </div>
        <div class="feature-card">
          <span class="feature-icon">📄</span>
          <h3>HTML Estático</h3>
          <p>Projetos sem build? Só ter um index.html e está deployado.</p>
        </div>
        <div class="feature-card">
          <span class="feature-icon">🔒</span>
          <h3>Seguro</h3>
          <p>Helmet + Rate Limiting. Proteção contra ataques e abuso de recursos.</p>
        </div>
      </div>
    </div>
  </section>

  <!-- CTA -->
  <section class="cta">
    <div class="container">
      <div class="cta-box">
        <h2>Pronto para começar?</h2>
        <p>Faça seu primeiro deploy em menos de 1 minuto</p>
        <a href="/admin" class="btn btn-primary">
          Ir para o Dashboard →
        </a>
      </div>
    </div>
  </section>

  <!-- Footer -->
  <footer>
    <div class="container">
      <div class="footer-links">
        <a href="/admin">Dashboard</a>
        <a href="/health">Health</a>
        <a href="https://github.com" target="_blank">GitHub</a>
      </div>
      <p>Vercel BR v2.2 · Node ${process.version} · ${IS_RENDER ? 'Render.com' : 'Local'}</p>
    </div>
  </footer>
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