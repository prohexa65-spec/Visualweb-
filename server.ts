import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { GoogleGenAI, ThinkingLevel, Type } from '@google/genai';
import { createServer as createViteServer } from 'vite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.PORT) || 3000;
const AI_MODEL = 'gemini-4-hydrogen';

const kvStyleSchema = {
  type: Type.OBJECT,
  properties: {
    prop: { type: Type.STRING, description: 'CamelCase CSS property name, e.g. backgroundColor, padding, fontSize' },
    value: { type: Type.STRING, description: 'CSS property value, e.g. 16px, #ffffff' },
  },
  required: ['prop', 'value'],
};

const kvAttrSchema = {
  type: Type.OBJECT,
  properties: {
    name: { type: Type.STRING, description: 'HTML attribute name such as href, alt, placeholder, type, role' },
    value: { type: Type.STRING, description: 'HTML attribute value' },
  },
  required: ['name', 'value'],
};

const leafNodeSchema = {
  type: Type.OBJECT,
  properties: {
    id: { type: Type.STRING },
    tag: { type: Type.STRING },
    text: { type: Type.STRING },
    attrs: { type: Type.ARRAY, items: kvAttrSchema },
    styles: { type: Type.ARRAY, items: kvStyleSchema },
  },
  required: ['id', 'tag', 'text', 'attrs', 'styles'],
};

const midNodeSchema = {
  type: Type.OBJECT,
  properties: {
    id: { type: Type.STRING },
    tag: { type: Type.STRING },
    text: { type: Type.STRING },
    attrs: { type: Type.ARRAY, items: kvAttrSchema },
    styles: { type: Type.ARRAY, items: kvStyleSchema },
    children: { type: Type.ARRAY, items: leafNodeSchema },
  },
  required: ['id', 'tag', 'text', 'attrs', 'styles', 'children'],
};

const rootNodeSchema = {
  type: Type.OBJECT,
  properties: {
    id: { type: Type.STRING },
    tag: { type: Type.STRING },
    text: { type: Type.STRING },
    attrs: { type: Type.ARRAY, items: kvAttrSchema },
    styles: { type: Type.ARRAY, items: kvStyleSchema },
    children: { type: Type.ARRAY, items: midNodeSchema },
  },
  required: ['id', 'tag', 'text', 'attrs', 'styles', 'children'],
};

const analyzeResponseSchema = {
  type: Type.OBJECT,
  properties: {
    websiteType: { type: Type.STRING, description: 'Detected category/purpose of the website being built' },
    confidence: { type: Type.STRING, description: 'high, medium, or low' },
    summary: { type: Type.STRING, description: 'Concise analysis of the current codebase, design language, and missing pieces' },
    nextElements: {
      type: Type.ARRAY,
      items: {
        type: Type.OBJECT,
        properties: {
          title: { type: Type.STRING },
          rationale: { type: Type.STRING },
          placement: { type: Type.STRING, description: 'inside-selected or page-root' },
          tag: { type: Type.STRING },
          text: { type: Type.STRING },
          attrs: { type: Type.ARRAY, items: kvAttrSchema },
          styles: { type: Type.ARRAY, items: kvStyleSchema },
          children: { type: Type.ARRAY, items: leafNodeSchema },
        },
        required: ['title', 'rationale', 'placement', 'tag', 'text', 'attrs', 'styles', 'children'],
      },
    },
    nextStyles: {
      type: Type.ARRAY,
      items: {
        type: Type.OBJECT,
        properties: {
          title: { type: Type.STRING },
          rationale: { type: Type.STRING },
          target: { type: Type.STRING, description: 'selected-node or custom-css' },
          styles: { type: Type.ARRAY, items: kvStyleSchema },
          customCss: { type: Type.STRING, description: 'Valid CSS rules referencing [data-node-id="..."] or tags/classes, empty if target is selected-node' },
        },
        required: ['title', 'rationale', 'target', 'styles', 'customCss'],
      },
    },
    nextPrograms: {
      type: Type.ARRAY,
      items: {
        type: Type.OBJECT,
        properties: {
          title: { type: Type.STRING },
          rationale: { type: Type.STRING },
          mode: { type: Type.STRING, description: 'behavior or custom-js' },
          behaviorAction: {
            type: Type.STRING,
            description: 'One of alert, toggle, hide, text, background, show, open-modal, close-modal, tab, scroll, scroll-animation, or empty string for custom-js',
          },
          sourceNodeId: { type: Type.STRING, description: 'Existing node id that triggers the behavior, or empty string' },
          targetNodeId: { type: Type.STRING, description: 'Existing target node id affected by the behavior, or empty string' },
          behaviorValue: { type: Type.STRING },
          customJs: { type: Type.STRING, description: 'Clean vanilla JavaScript ready to attach to the exported site using [data-node-id] selectors' },
        },
        required: ['title', 'rationale', 'mode', 'behaviorAction', 'sourceNodeId', 'targetNodeId', 'behaviorValue', 'customJs'],
      },
    },
  },
  required: ['websiteType', 'confidence', 'summary', 'nextElements', 'nextStyles', 'nextPrograms'],
};

const templateResponseSchema = {
  type: Type.OBJECT,
  properties: {
    title: { type: Type.STRING },
    description: { type: Type.STRING },
    category: {
      type: Type.STRING,
      description: 'One of landing, portfolio, business, blog, ecommerce, component, other',
    },
    pageBackground: { type: Type.STRING, description: 'Hex background color like #ffffff or #0f172a' },
    customCss: { type: Type.STRING, description: 'Optional clean global CSS rules (no @import)' },
    nodes: { type: Type.ARRAY, items: rootNodeSchema },
    behaviors: {
      type: Type.ARRAY,
      items: {
        type: Type.OBJECT,
        properties: {
          sourceId: { type: Type.STRING },
          targetId: { type: Type.STRING },
          action: { type: Type.STRING },
          value: { type: Type.STRING },
        },
        required: ['sourceId', 'targetId', 'action', 'value'],
      },
    },
    starterCustomJs: { type: Type.STRING, description: 'Optional vanilla JS for local editor preview/export only' },
  },
  required: ['title', 'description', 'category', 'pageBackground', 'customCss', 'nodes', 'behaviors', 'starterCustomJs'],
};

function getConfiguredApiKey(): string {
  const key = (process.env.GEMINI_API_KEY || '').trim();
  if (!key || key === 'MY_GEMINI_API_KEY') {
    return '';
  }
  return key;
}

function createAiClient(): GoogleGenAI {
  const apiKey = getConfiguredApiKey();
  if (!apiKey) {
    throw new Error('GEMINI_API_KEY is not configured on the server.');
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

function kvArrayToRecord(list: unknown, keyField: 'prop' | 'name'): Record<string, string> {
  const out: Record<string, string> = {};
  if (!Array.isArray(list)) return out;
  for (const item of list) {
    if (!item || typeof item !== 'object') continue;
    const rawKey = String((item as Record<string, unknown>)[keyField] || '').trim();
    const rawVal = String((item as Record<string, unknown>).value ?? '').trim();
    if (rawKey && rawVal) {
      out[rawKey] = rawVal;
    }
  }
  return out;
}

interface RawAiNode {
  id?: string;
  tag?: string;
  text?: string;
  attrs?: unknown;
  styles?: unknown;
  children?: RawAiNode[];
}

function transformAiNode(raw: RawAiNode): Record<string, unknown> {
  const children = Array.isArray(raw.children) ? raw.children.map(transformAiNode) : [];
  return {
    id: String(raw.id || '').trim(),
    tag: String(raw.tag || 'div').trim().toLowerCase(),
    text: String(raw.text || ''),
    attrs: kvArrayToRecord(raw.attrs, 'name'),
    styles: kvArrayToRecord(raw.styles, 'prop'),
    children,
  };
}

function clipText(val: unknown, maxLen: number): string {
  const str = String(val || '');
  return str.length > maxLen ? str.slice(0, maxLen) + '\n/* ...truncated... */' : str;
}

async function generateJsonWithRetry<T>(promptText: string, responseSchema: Record<string, unknown>): Promise<T> {
  const ai = createAiClient();
  let lastError: unknown;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const response = await ai.models.generateContent({
        model: AI_MODEL,
        contents: promptText,
        config: {
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
          responseMimeType: 'application/json',
          responseSchema,
        },
      });
      const rawText = response.text;
      if (!rawText) {
        throw new Error('AI returned an empty response.');
      }
      return JSON.parse(rawText) as T;
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError instanceof Error ? lastError : new Error('AI request failed after retry.');
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({
      ok: true,
      aiConfigured: Boolean(getConfiguredApiKey()),
    });
  });

  app.post('/api/ai/analyze', async (req, res) => {
    const apiKey = getConfiguredApiKey();
    if (!apiKey) {
      res.status(503).json({
        error: 'Gemini API key is not configured on the server. Add GEMINI_API_KEY in AI Studio Secrets.',
      });
      return;
    }

    try {
      const body = (req.body && typeof req.body === 'object') ? req.body as Record<string, unknown> : {};
      const projectName = clipText(body.projectName || 'Untitled site', 120);
      const pageBackground = clipText(body.pageBackground || '#ffffff', 40);
      const customPrompt = clipText(body.customPrompt || '', 600);
      const selectedNode = body.selectedNode ? JSON.stringify(body.selectedNode).slice(0, 2000) : 'None selected';
      const nodeTree = clipText(JSON.stringify(body.nodeTree || []), 6000);
      const html = clipText(body.html || '', 12000);
      const css = clipText(body.css || '', 12000);
      const js = clipText(body.js || '', 8000);

      const promptText = [
        'You are the Secret AI embedded inside Studio, a visual website builder.',
        'Analyze the developer\'s current website project, DOM structure, HTML, CSS, JavaScript, and selected element.',
        'Determine what kind of website the developer is building, then propose concrete, immediately applicable next steps:',
        '- 2 to 3 nextElements: cohesive HTML elements/blocks (e.g. header, hero section, feature card, pricing tier, testimonial, contact form, CTA button, footer) that fit the current layout. Never use script/iframe/style tags or inline on* handlers. Provide camelCase CSS styles in styles[] and any safe attributes in attrs[]. If an element is a container (section/div/card/form/nav/header/footer/main), include helpful child elements in children[].',
        '- 2 to 3 nextStyles: polished CSS improvements. Use target="selected-node" (with camelCase props in styles[]) when a node is selected and style updates suit it; otherwise use target="custom-css" with clean CSS rules in customCss (never use @import or expression()).',
        '- 2 to 3 nextPrograms: interactive JS behaviors or vanilla JS enhancements tailored to the actual data-node-id elements present in the project. Use mode="behavior" when one of Studio\'s built-in click/scroll actions fits existing node IDs (alert, toggle, hide, text, background, show, open-modal, close-modal, tab, scroll, scroll-animation), OR use mode="custom-js" with concise, self-contained vanilla JS referencing [data-node-id="..."] from the HTML below.',
        '',
        `Project Name: ${projectName}`,
        `Page Background: ${pageBackground}`,
        `Selected Element: ${selectedNode}`,
        customPrompt ? `Developer Focus Request: ${customPrompt}` : '',
        '',
        `Visual Node Summary Tree:\n${nodeTree}`,
        '',
        `Generated HTML:\n${html}`,
        '',
        `Generated CSS:\n${css}`,
        '',
        `Generated JS:\n${js || '(none yet)'}`,
      ].filter(Boolean).join('\n');

      const parsed = await generateJsonWithRetry<{
        websiteType?: string;
        confidence?: string;
        summary?: string;
        nextElements?: Array<RawAiNode & { title?: string; rationale?: string; placement?: string }>;
        nextStyles?: Array<{ title?: string; rationale?: string; target?: string; styles?: unknown; customCss?: string }>;
        nextPrograms?: Array<{
          title?: string;
          rationale?: string;
          mode?: string;
          behaviorAction?: string;
          sourceNodeId?: string;
          targetNodeId?: string;
          behaviorValue?: string;
          customJs?: string;
        }>;
      }>(promptText, analyzeResponseSchema);

      const analysis = {
        websiteType: String(parsed.websiteType || 'Custom Website').slice(0, 80),
        confidence: String(parsed.confidence || 'medium').toLowerCase(),
        summary: String(parsed.summary || '').slice(0, 1200),
        nextElements: (Array.isArray(parsed.nextElements) ? parsed.nextElements : []).slice(0, 4).map((el) => ({
          title: String(el.title || el.tag || 'Element').slice(0, 80),
          rationale: String(el.rationale || '').slice(0, 320),
          placement: el.placement === 'inside-selected' ? 'inside-selected' : 'page-root',
          node: transformAiNode(el),
        })),
        nextStyles: (Array.isArray(parsed.nextStyles) ? parsed.nextStyles : []).slice(0, 4).map((st) => ({
          title: String(st.title || 'Style enhancement').slice(0, 80),
          rationale: String(st.rationale || '').slice(0, 320),
          target: st.target === 'selected-node' ? 'selected-node' : 'custom-css',
          styles: kvArrayToRecord(st.styles, 'prop'),
          customCss: String(st.customCss || ''),
        })),
        nextPrograms: (Array.isArray(parsed.nextPrograms) ? parsed.nextPrograms : []).slice(0, 4).map((prog) => ({
          title: String(prog.title || 'Interactive program').slice(0, 80),
          rationale: String(prog.rationale || '').slice(0, 320),
          mode: prog.mode === 'behavior' ? 'behavior' : 'custom-js',
          behaviorAction: String(prog.behaviorAction || ''),
          sourceNodeId: String(prog.sourceNodeId || ''),
          targetNodeId: String(prog.targetNodeId || ''),
          behaviorValue: String(prog.behaviorValue || ''),
          customJs: String(prog.customJs || ''),
        })),
      };

      res.json({ analysis });
    } catch (error) {
      console.error('AI analyze error:', error);
      const message = error instanceof Error ? error.message : 'Failed to analyze project with AI.';
      res.status(500).json({ error: message });
    }
  });

  app.post('/api/ai/generate-template', async (req, res) => {
    const apiKey = getConfiguredApiKey();
    if (!apiKey) {
      res.status(503).json({
        error: 'Gemini API key is not configured on the server. Add GEMINI_API_KEY in AI Studio Secrets.',
      });
      return;
    }

    try {
      const body = (req.body && typeof req.body === 'object') ? req.body as Record<string, unknown> : {};
      const websiteType = clipText(body.websiteType || '', 120);
      const customPrompt = clipText(body.prompt || '', 700);
      const category = clipText(body.category || 'landing', 40);
      const existingName = clipText(body.existingName || '', 120);
      const existingSummary = clipText(body.existingSummary || '', 2500);

      const promptText = [
        'You are the Secret AI Template Architect inside Studio, a visual website builder.',
        'Design a complete, visually cohesive, multi-section website template tailored to the developer\'s current website direction.',
        'Requirements:',
        '- Create 3 to 5 root sections (e.g. header, hero section, features/showcase section, CTA band, footer).',
        '- IMPORTANT nesting rule (max 3 levels): Put cards or grid containers directly as root sections (level 1 = section/header/footer, level 2 = article/div/nav/form, level 3 = h1/h2/h3/p/button/a/img/span/input). Put ALL visible headings, card titles, descriptions, and button labels inside level 2/3 text fields—never leave cards empty.',
        '- Give every node a unique alphanumeric id (e.g. "hero_sec", "cta_btn", "feat_1") and clean camelCase inline styles (padding, display, flexDirection, gap, backgroundColor, color, fontSize, borderRadius, maxWidth, margin, etc.).',
        '- Ensure strong typography contrast against pageBackground and container backgrounds.',
        '- Include 1 or 2 interactive Studio behaviors in behaviors[] linking sourceId -> targetId using allowed actions (alert, toggle, hide, text, background, show, scroll, scroll-animation).',
        '- Write clean responsive rules in customCss using tag or [data-node-id="..."] selectors (never #id selectors, @import, or expression()).',
        '- Optionally provide short clean vanilla JS in starterCustomJs for enhancements only (page must already look complete without JS).',
        '- Never use script, iframe, style, link, or meta tags, and never add inline on* attributes.',
        '',
        websiteType ? `Detected Website Type: ${websiteType}` : '',
        `Preferred Category: ${category}`,
        existingName ? `Current Project Name: ${existingName}` : '',
        customPrompt ? `Developer Template Prompt: ${customPrompt}` : 'Make an impressive, ready-to-customize template that matches the current project context.',
        existingSummary ? `Current Code Summary:\n${existingSummary}` : '',
      ].filter(Boolean).join('\n');

      const parsed = await generateJsonWithRetry<{
        title?: string;
        description?: string;
        category?: string;
        pageBackground?: string;
        customCss?: string;
        nodes?: RawAiNode[];
        behaviors?: Array<{ sourceId?: string; targetId?: string; action?: string; value?: string }>;
        starterCustomJs?: string;
      }>(promptText, templateResponseSchema);

      const template = {
        title: String(parsed.title || 'AI Starter Template').slice(0, 100),
        description: String(parsed.description || '').slice(0, 500),
        category: String(parsed.category || category || 'landing').toLowerCase(),
        page: {
          background: String(parsed.pageBackground || '#ffffff'),
        },
        customCss: String(parsed.customCss || ''),
        nodes: (Array.isArray(parsed.nodes) ? parsed.nodes : []).map(transformAiNode),
        behaviors: (Array.isArray(parsed.behaviors) ? parsed.behaviors : []).map((b) => ({
          source: String(b.sourceId || ''),
          target: String(b.targetId || ''),
          action: String(b.action || ''),
          value: String(b.value || ''),
          trigger: 'click',
        })),
        customJs: String(parsed.starterCustomJs || ''),
      };

      res.json({ template });
    } catch (error) {
      console.error('AI template generation error:', error);
      const message = error instanceof Error ? error.message : 'Failed to generate AI template.';
      res.status(500).json({ error: message });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      const indexFile = path.join(distDir, 'index.html');
      if (fs.existsSync(indexFile)) {
        res.sendFile(indexFile);
      } else {
        res.status(404).send('Build output not found. Run npm run build first.');
      }
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Studio server listening on http://localhost:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
