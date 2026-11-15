import { initializeApp, getApps } from 'firebase/app';
import {
  getAuth,
  setPersistence,
  browserLocalPersistence,
  onAuthStateChanged,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut,
  sendPasswordResetEmail,
  sendEmailVerification,
  updateProfile,
} from 'firebase/auth';
import {
  getFirestore,
  doc,
  getDoc,
  getDocFromServer,
  setDoc,
  updateDoc,
  deleteDoc,
  collection,
  query,
  where,
  limit,
  getDocs,
  serverTimestamp,
} from 'firebase/firestore';
import {
  getStorage,
  ref as storageRef,
  uploadString,
  getBytes,
  getDownloadURL,
  listAll,
  deleteObject,
} from 'firebase/storage';
import firebaseAppletConfig from './firebase-applet-config.json';

// ============================================================================
// CONFIGURATION & PLACEHOLDER SUPPORT
// Replace MANUAL_FIREBASE_CONFIG values if deploying outside AI Studio.
// Never place Firebase Admin SDK secrets, service accounts, or private keys here.
// ============================================================================
const MANUAL_FIREBASE_CONFIG = {
  apiKey: 'YOUR_FIREBASE_API_KEY',
  authDomain: 'YOUR_PROJECT_ID.firebaseapp.com',
  projectId: 'YOUR_PROJECT_ID',
  storageBucket: 'YOUR_PROJECT_ID.firebasestorage.app',
  messagingSenderId: 'YOUR_MESSAGING_SENDER_ID',
  appId: 'YOUR_FIREBASE_APP_ID',
  firestoreDatabaseId: '(default)',
};

function resolveFirebaseConfig() {
  const runtimeOverride = typeof window !== 'undefined' ? window.STUDIO_FIREBASE_CONFIG : null;
  const candidate = runtimeOverride || firebaseAppletConfig || MANUAL_FIREBASE_CONFIG;
  if (!candidate || !candidate.apiKey || String(candidate.apiKey).startsWith('YOUR_')) {
    return null;
  }
  return candidate;
}

// ============================================================================
// PURE HELPERS (Validation, Sanitization, Hashing, Conflict Detection)
// ============================================================================
const VALID_CATEGORIES = ['landing', 'portfolio', 'business', 'blog', 'ecommerce', 'component', 'other'];
const VALID_REPORT_REASONS = ['malicious-script', 'spam', 'inappropriate', 'copyright', 'other'];
const SAFE_BEHAVIOR_ACTIONS = new Set([
  'alert', 'toggle', 'hide', 'text', 'background',
  'show', 'open-modal', 'close-modal', 'tab', 'scroll', 'scroll-animation',
]);
const BLOCKED_TAGS = new Set(['script', 'iframe', 'object', 'embed', 'link', 'meta', 'base', 'style', 'noscript']);
const CONTAINER_TAGS = ['div', 'section', 'header', 'nav', 'main', 'article', 'footer', 'form'];

export function computeProjectHash(proj) {
  const canonical = JSON.stringify({
    name: String(proj?.name || 'Untitled site'),
    page: proj?.page || { background: '#ffffff' },
    nodes: Array.isArray(proj?.nodes) ? proj.nodes : [],
    customCss: String(proj?.customCss || ''),
    customJs: String(proj?.customJs || ''),
    behaviors: Array.isArray(proj?.behaviors) ? proj.behaviors : [],
    backendIntegration: proj?.backendIntegration || { provider: 'none', endpoint: '', notes: '' },
  });
  let h1 = 0x811c9dc5;
  let h2 = 0x9e3779b9;
  for (let i = 0; i < canonical.length; i++) {
    const ch = canonical.charCodeAt(i);
    h1 ^= ch;
    h1 = Math.imul(h1, 0x01000193);
    h2 ^= ch + (i & 255);
    h2 = Math.imul(h2, 0x85ebca6b);
  }
  return (h1 >>> 0).toString(16).padStart(8, '0') + (h2 >>> 0).toString(16).padStart(8, '0');
}

export function countProjectNodes(nodes) {
  if (!Array.isArray(nodes)) return 0;
  let total = 0;
  for (const node of nodes) {
    total += 1;
    if (Array.isArray(node?.children)) {
      total += countProjectNodes(node.children);
    }
  }
  return total;
}

export function sanitizeUrl(rawUrl, options = {}) {
  const { allowDataImage = true } = options;
  const trimmed = String(rawUrl ?? '').trim();
  if (!trimmed) return '';
  if (trimmed.startsWith('#') || (trimmed.startsWith('/') && !trimmed.startsWith('//'))) {
    return trimmed;
  }
  const lower = trimmed.toLowerCase().replace(/[\u0000-\u0020]+/g, '');
  if (lower.startsWith('javascript:') || lower.startsWith('vbscript:') || lower.startsWith('data:text/html')) {
    return '#';
  }
  if (allowDataImage && /^data:image\/(png|jpeg|jpg|gif|webp);base64,[a-z0-9+/=]+$/i.test(trimmed)) {
    return trimmed;
  }
  if (allowDataImage && /^data:image\/svg\+xml[,;]/i.test(trimmed)) {
    if (/<script|\bon[a-z]+\s*=|javascript:/i.test(decodeURIComponentSafe(trimmed))) {
      return '';
    }
    return trimmed;
  }
  try {
    const parsed = new URL(trimmed);
    if (['http:', 'https:', 'mailto:', 'tel:'].includes(parsed.protocol)) {
      return trimmed;
    }
  } catch {
    return '#';
  }
  return '#';
}

function decodeURIComponentSafe(val) {
  try {
    return decodeURIComponent(val);
  } catch {
    return val;
  }
}

export function sanitizeCssText(css) {
  return String(css || '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/@import\b[^;]*;?/gi, '')
    .replace(/expression\s*\([^)]*\)/gi, '')
    .replace(/behavior\s*:[^;]*;?/gi, '')
    .replace(/-moz-binding\s*:[^;]*;?/gi, '')
    .replace(/javascript\s*:/gi, '')
    .trim();
}

export function sanitizeTemplateNodes(nodes, makeUid = () => 'n' + Math.random().toString(36).slice(2, 10)) {
  if (!Array.isArray(nodes)) return [];
  const clean = [];
  for (const rawNode of nodes) {
    if (!rawNode || typeof rawNode !== 'object') continue;
    const rawTag = String(rawNode.tag || 'div').toLowerCase().trim();
    if (BLOCKED_TAGS.has(rawTag)) continue;
    const tag = /^[a-z][a-z0-9-]*$/.test(rawTag) ? rawTag : 'div';
    const id = typeof rawNode.id === 'string' && /^[\w-]+$/.test(rawNode.id) ? rawNode.id : makeUid();
    const attrs = {};
    if (rawNode.attrs && typeof rawNode.attrs === 'object') {
      for (const [key, val] of Object.entries(rawNode.attrs)) {
        if (!/^[a-zA-Z_:][\w:.-]*$/.test(key)) continue;
        if (/^on/i.test(key)) continue;
        if (key === 'srcdoc') continue;
        if (['href', 'src', 'action', 'formaction', 'poster'].includes(key.toLowerCase())) {
          const safe = sanitizeUrl(val, { allowDataImage: true });
          if (safe) attrs[key] = safe;
        } else if (val !== false && val != null) {
          attrs[key] = String(val).slice(0, 2000);
        }
      }
    }
    const styles = {};
    if (rawNode.styles && typeof rawNode.styles === 'object') {
      for (const [key, val] of Object.entries(rawNode.styles)) {
        if (/^[a-zA-Z][\w-]*$/.test(key) && val != null) {
          const strVal = String(val);
          if (!/expression\s*\(|javascript\s*:/i.test(strVal)) {
            styles[key] = strVal.slice(0, 500);
          }
        }
      }
    }
    const safeNode = {
      id,
      tag,
      text: typeof rawNode.text === 'string' ? rawNode.text.slice(0, 20000) : '',
      attrs,
      styles,
      children: sanitizeTemplateNodes(rawNode.children || [], makeUid),
      responsive: rawNode.responsive && typeof rawNode.responsive === 'object' ? rawNode.responsive : {},
    };
    if (rawNode.hidden) safeNode.hidden = true;
    if (rawNode.states && typeof rawNode.states === 'object') safeNode.states = rawNode.states;
    if (rawNode.gradient && typeof rawNode.gradient === 'object') safeNode.gradient = rawNode.gradient;
    if (rawNode.editorTransform && typeof rawNode.editorTransform === 'object') safeNode.editorTransform = rawNode.editorTransform;
    if (rawNode.editorTransition && typeof rawNode.editorTransition === 'object') safeNode.editorTransition = rawNode.editorTransition;
    if (rawNode.animation && typeof rawNode.animation === 'object') safeNode.animation = rawNode.animation;
    clean.push(safeNode);
  }
  return clean;
}

export function sanitizeImportedTemplateProject(rawTemplate, titleFallback = 'Imported template', makeUid) {
  const safeNodes = sanitizeTemplateNodes(rawTemplate?.nodes || [], makeUid);
  const safeBehaviors = Array.isArray(rawTemplate?.behaviors)
    ? rawTemplate.behaviors.filter((b) =>
        b &&
        typeof b === 'object' &&
        /^[\w-]+$/.test(String(b.source || '')) &&
        SAFE_BEHAVIOR_ACTIONS.has(b.action)
      ).map((b) => ({
        source: String(b.source),
        target: /^[\w-]+$/.test(String(b.target || '')) ? String(b.target) : '',
        action: b.action,
        value: String(b.value || '').slice(0, 500),
        trigger: 'click',
      }))
    : [];
  const hadUntrustedScript = Boolean(rawTemplate?.customJs && String(rawTemplate.customJs).trim());
  const now = Date.now();
  return {
    project: {
      schemaVersion: 2,
      id: (makeUid ? makeUid() : 'p_' + Math.random().toString(36).slice(2, 10)),
      name: String(rawTemplate?.title || rawTemplate?.name || titleFallback).slice(0, 100) || titleFallback,
      created: now,
      updated: now,
      page: {
        background: typeof rawTemplate?.page?.background === 'string' && /^#[0-9a-f]{3,8}$/i.test(rawTemplate.page.background)
          ? rawTemplate.page.background
          : '#ffffff',
      },
      nodes: safeNodes,
      customCss: sanitizeCssText(rawTemplate?.customCss || ''),
      // Never auto-import executable JavaScript from community templates
      customJs: '',
      behaviors: safeBehaviors,
      backendIntegration: {
        provider: 'none',
        endpoint: '',
        notes: '',
      },
      syncMeta: {
        cloudVersion: 0,
        lastSyncedHash: '',
        lastSyncedAt: 0,
      },
    },
    strippedScripts: hadUntrustedScript,
  };
}

export function detectSyncConflict(localProject, remoteMeta) {
  if (!remoteMeta) return { hasConflict: false, reason: 'no-remote' };
  const localHash = computeProjectHash(localProject);
  const remoteVersion = Number(remoteMeta.version || 0);
  const knownVersion = Number(localProject?.syncMeta?.cloudVersion || 0);
  const lastSyncedHash = String(localProject?.syncMeta?.lastSyncedHash || '');
  const remoteHash = String(remoteMeta.contentHash || '');

  if (localHash === remoteHash) {
    return { hasConflict: false, reason: 'identical' };
  }
  if (remoteVersion > knownVersion && lastSyncedHash && localHash !== lastSyncedHash) {
    return { hasConflict: true, reason: 'diverged' };
  }
  if (remoteVersion > 0 && knownVersion === 0 && remoteHash && localHash !== remoteHash) {
    return { hasConflict: true, reason: 'unlinked-remote-exists' };
  }
  return { hasConflict: false, reason: 'local-ahead' };
}

export function buildExportSafeProjectPayload(proj) {
  return {
    schemaVersion: 2,
    id: proj.id,
    name: proj.name,
    created: proj.created,
    updated: proj.updated,
    page: proj.page || { background: '#ffffff' },
    nodes: proj.nodes || [],
    customCss: proj.customCss || '',
    customJs: proj.customJs || '',
    behaviors: proj.behaviors || [],
    // Separated user-website backend connector metadata (no platform Firebase keys)
    backendIntegration: proj.backendIntegration || { provider: 'none', endpoint: '', notes: '' },
  };
}

export function mapAuthErrorMessage(error) {
  const code = error?.code || '';
  const map = {
    'auth/email-already-in-use': 'An account with this email already exists. Try signing in instead.',
    'auth/invalid-email': 'Please enter a valid email address.',
    'auth/weak-password': 'Password must be at least 6 characters long.',
    'auth/user-not-found': 'No account found with that email address.',
    'auth/wrong-password': 'Incorrect password. Please try again or reset your password.',
    'auth/invalid-credential': 'Invalid email or password. Please check your credentials.',
    'auth/too-many-requests': 'Too many attempts. Please wait a few moments before trying again.',
    'auth/network-request-failed': 'Network error. Check your internet connection and try again.',
    'auth/operation-not-allowed': 'Email/password sign-in is not enabled in Firebase Console Authentication yet.',
    'auth/requires-recent-login': 'Please sign out and sign in again to complete this sensitive action.',
  };
  return map[code] || error?.message || 'Authentication failed. Please try again.';
}

const VALID_AI_CONFIDENCE = new Set(['high', 'medium', 'low']);

/**
 * @param {any} proj
 * @param {string | null} [selectedNodeId]
 * @param {{ html?: string, css?: string, js?: string }} [codeSnapshot]
 */
export function buildAiProjectContext(proj, selectedNodeId = null, codeSnapshot = {}) {
  const summarizeNode = (node, depth = 0) => {
    if (!node || typeof node !== 'object' || depth > 5) return null;
    return {
      id: String(node.id || ''),
      tag: String(node.tag || 'div'),
      text: String(node.text || '').slice(0, 140),
      styleKeys: Object.keys(node.styles || {}).slice(0, 14),
      children: Array.isArray(node.children)
        ? node.children.slice(0, 20).map((c) => summarizeNode(c, depth + 1)).filter(Boolean)
        : [],
    };
  };

  const findById = (nodes, id) => {
    for (const n of nodes || []) {
      if (n.id === id) return n;
      const found = findById(n.children || [], id);
      if (found) return found;
    }
    return null;
  };

  const selected = selectedNodeId ? findById(proj?.nodes || [], selectedNodeId) : null;
  return {
    projectName: String(proj?.name || 'Untitled site').slice(0, 120),
    pageBackground: String(proj?.page?.background || '#ffffff'),
    selectedNode: selected
      ? {
          id: selected.id,
          tag: selected.tag,
          text: String(selected.text || '').slice(0, 240),
          attrs: selected.attrs || {},
          styles: selected.styles || {},
        }
      : null,
    nodeTree: (Array.isArray(proj?.nodes) ? proj.nodes : []).slice(0, 30).map((n) => summarizeNode(n, 0)).filter(Boolean),
    html: String(codeSnapshot.html || '').slice(0, 12000),
    css: String(codeSnapshot.css || '').slice(0, 12000),
    js: String(codeSnapshot.js || '').slice(0, 8000),
  };
}

export function normalizeAiAnalysisResult(raw, validNodeIds = new Set(), makeUid) {
  const idSet = validNodeIds instanceof Set ? validNodeIds : new Set(Array.isArray(validNodeIds) ? validNodeIds : []);
  const confidenceRaw = String(raw?.confidence || 'medium').toLowerCase();
  const nextElements = (Array.isArray(raw?.nextElements) ? raw.nextElements : [])
    .map((item) => {
      const sanitizedList = sanitizeTemplateNodes(item?.node ? [item.node] : [], makeUid);
      if (!sanitizedList.length) return null;
      return {
        title: String(item.title || sanitizedList[0].tag || 'Element').slice(0, 80),
        rationale: String(item.rationale || '').slice(0, 320),
        placement: item.placement === 'inside-selected' ? 'inside-selected' : 'page-root',
        node: sanitizedList[0],
      };
    })
    .filter(Boolean);

  const nextStyles = (Array.isArray(raw?.nextStyles) ? raw.nextStyles : [])
    .map((item) => {
      const cleanStyles = {};
      if (item?.styles && typeof item.styles === 'object') {
        for (const [k, v] of Object.entries(item.styles)) {
          if (/^[a-zA-Z][\w-]*$/.test(k) && v != null && !/expression\s*\(|javascript\s*:/i.test(String(v))) {
            cleanStyles[k] = String(v).slice(0, 500);
          }
        }
      }
      const cleanCss = sanitizeCssText(item?.customCss || '');
      if (!Object.keys(cleanStyles).length && !cleanCss) return null;
      return {
        title: String(item?.title || 'Style suggestion').slice(0, 80),
        rationale: String(item?.rationale || '').slice(0, 320),
        target: item?.target === 'selected-node' ? 'selected-node' : 'custom-css',
        styles: cleanStyles,
        customCss: cleanCss,
      };
    })
    .filter(Boolean);

  const nextPrograms = (Array.isArray(raw?.nextPrograms) ? raw.nextPrograms : [])
    .map((item) => {
      const action = String(item?.behaviorAction || '');
      const sourceNodeId = idSet.has(String(item?.sourceNodeId || '')) ? String(item.sourceNodeId) : '';
      const targetNodeId = idSet.has(String(item?.targetNodeId || '')) ? String(item.targetNodeId) : '';
      const customJs = String(item?.customJs || '').slice(0, 6000).trim();
      const validBehavior = item?.mode === 'behavior' && SAFE_BEHAVIOR_ACTIONS.has(action);
      if (!validBehavior && !customJs) return null;
      return {
        title: String(item?.title || 'Interactive behavior').slice(0, 80),
        rationale: String(item?.rationale || '').slice(0, 320),
        mode: validBehavior ? 'behavior' : 'custom-js',
        behaviorAction: validBehavior ? action : '',
        sourceNodeId,
        targetNodeId,
        behaviorValue: String(item?.behaviorValue || '').slice(0, 500),
        customJs,
      };
    })
    .filter(Boolean);

  return {
    websiteType: String(raw?.websiteType || 'Custom Website').slice(0, 80),
    confidence: VALID_AI_CONFIDENCE.has(confidenceRaw) ? confidenceRaw : 'medium',
    summary: String(raw?.summary || '').slice(0, 1200),
    nextElements,
    nextStyles,
    nextPrograms,
  };
}

export function normalizeAiGeneratedTemplate(raw, makeUid = () => 'n' + Math.random().toString(36).slice(2, 10)) {
  const safeNodes = sanitizeTemplateNodes(raw?.nodes || [], makeUid);
  const idMap = new Map();
  const rekeyWithMap = (node) => {
    const oldId = node.id;
    const newId = makeUid();
    if (oldId) idMap.set(oldId, newId);
    node.id = newId;
    (node.children || []).forEach(rekeyWithMap);
  };
  safeNodes.forEach(rekeyWithMap);

  const rawCategory = String(raw?.category || 'landing').toLowerCase();
  const category = VALID_CATEGORIES.includes(rawCategory) ? rawCategory : 'other';
  const rawBg = String(raw?.page?.background || '#ffffff').trim();
  const background = /^#[0-9a-f]{3,8}$/i.test(rawBg) ? rawBg : '#ffffff';

  const safeBehaviors = (Array.isArray(raw?.behaviors) ? raw.behaviors : [])
    .filter((b) => b && typeof b === 'object' && SAFE_BEHAVIOR_ACTIONS.has(b.action))
    .map((b) => {
      const mappedSource = idMap.get(b.source) || (idMap.size ? [...idMap.values()][0] : '');
      const mappedTarget = idMap.get(b.target) || '';
      if (!mappedSource) return null;
      return {
        source: mappedSource,
        target: mappedTarget,
        action: b.action,
        value: String(b.value || '').slice(0, 500),
        trigger: 'click',
      };
    })
    .filter(Boolean);

  return {
    title: String(raw?.title || 'AI Template').trim().slice(0, 100) || 'AI Template',
    description: String(raw?.description || '').trim().slice(0, 500),
    category,
    page: { background },
    nodes: safeNodes,
    customCss: sanitizeCssText(raw?.customCss || ''),
    customJs: String(raw?.customJs || '').slice(0, 8000).trim(),
    behaviors: safeBehaviors,
  };
}

export function buildAiTemplateCommunityPayload(normalizedTemplate) {
  const safeNodes = sanitizeTemplateNodes(normalizedTemplate?.nodes || []);
  const rawCat = String(normalizedTemplate?.category || 'other').toLowerCase();
  const category = VALID_CATEGORIES.includes(rawCat) ? rawCat : 'other';
  return {
    schemaVersion: 2,
    title: String(normalizedTemplate?.title || 'AI Template').trim().slice(0, 100) || 'AI Template',
    description: String(normalizedTemplate?.description || '').trim().slice(0, 500),
    category,
    page: {
      background: /^#[0-9a-f]{3,8}$/i.test(String(normalizedTemplate?.page?.background || ''))
        ? normalizedTemplate.page.background
        : '#ffffff',
    },
    nodes: safeNodes,
    customCss: sanitizeCssText(normalizedTemplate?.customCss || ''),
    // Community templates never auto-execute arbitrary JavaScript
    customJs: '',
    behaviors: (normalizedTemplate?.behaviors || []).filter((b) => SAFE_BEHAVIOR_ACTIONS.has(b.action)),
  };
}

/**
 * @param {any} proj
 * @param {any} suggestion
 * @param {any} [selectedNode]
 */
export function applyAiStyleSuggestion(proj, suggestion, selectedNode = null) {
  if (suggestion.target === 'selected-node' && selectedNode && Object.keys(suggestion.styles || {}).length) {
    selectedNode.styles = { ...(selectedNode.styles || {}), ...suggestion.styles };
    return { appliedTo: 'selected-node' };
  }
  const declarations = Object.entries(suggestion.styles || {})
    .map(([k, v]) => `  ${k.replace(/[A-Z]/g, (m) => '-' + m.toLowerCase())}: ${v};`)
    .join('\n');
  let block = sanitizeCssText(suggestion.customCss || '');
  if (!block && declarations) {
    const selector = selectedNode?.id ? `[data-node-id="${selectedNode.id}"]` : 'body';
    block = `${selector} {\n${declarations}\n}`;
  }
  if (block) {
    proj.customCss = proj.customCss ? `${proj.customCss.trim()}\n\n${block}` : block;
  }
  return { appliedTo: 'custom-css' };
}

export function applyAiProgramSuggestion(proj, suggestion, fallbackSourceId = '') {
  if (suggestion.mode === 'behavior' && SAFE_BEHAVIOR_ACTIONS.has(suggestion.behaviorAction)) {
    const source = suggestion.sourceNodeId || fallbackSourceId;
    if (source) {
      proj.behaviors = (Array.isArray(proj.behaviors) ? proj.behaviors : []).filter((b) => b.source !== source);
      proj.behaviors.push({
        source,
        target: suggestion.targetNodeId || '',
        action: suggestion.behaviorAction,
        value: String(suggestion.behaviorValue || '').slice(0, 500),
        trigger: 'click',
      });
      return { appliedTo: 'behavior' };
    }
  }
  const snippet = String(suggestion.customJs || '').trim();
  if (snippet) {
    const header = `// ${String(suggestion.title || 'AI JS Suggestion').replace(/[\r\n]/g, ' ')}`;
    proj.customJs = proj.customJs ? `${proj.customJs.trim()}\n\n${header}\n${snippet}` : `${header}\n${snippet}`;
    return { appliedTo: 'custom-js' };
  }
  return { appliedTo: 'none' };
}

// ============================================================================
// APPLICATION BOOTSTRAP (Only executes in browser DOM)
// ============================================================================
if (typeof document !== 'undefined') {
  (() => {
    'use strict';
    const $ = (selector, root = document) => root.querySelector(selector);
    const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
    const STORAGE_KEY = 'studio-builder-projects-v1';
    const IDB_NAME = 'studio-builder-db';
    const IDB_VERSION = 1;

    // ------------------------------------------------------------------------
    // Firebase Platform Initialization (Isolated strictly to Studio Editor)
    // ------------------------------------------------------------------------
    const firebaseConfig = resolveFirebaseConfig();
    let firebaseApp = null;
    let auth = null;
    let db = null;
    let storage = null;
    let firebaseReady = false;
    let currentUser = null;
    let currentProfile = null;
    let authInitialized = false;

    if (firebaseConfig) {
      try {
        firebaseApp = getApps().length ? getApps()[0] : initializeApp(firebaseConfig);
        auth = getAuth(firebaseApp);
        setPersistence(auth, browserLocalPersistence).catch(() => {});
        db = getFirestore(firebaseApp, firebaseConfig.firestoreDatabaseId || '(default)');
        storage = getStorage(firebaseApp);
        firebaseReady = true;
      } catch (err) {
        console.error('Firebase initialization failed:', err);
      }
    }

    const OperationType = {
      CREATE: 'create',
      UPDATE: 'update',
      DELETE: 'delete',
      LIST: 'list',
      GET: 'get',
      WRITE: 'write',
    };

    function handleFirestoreError(error, operationType, path) {
      const errInfo = {
        error: error instanceof Error ? error.message : String(error),
        authInfo: {
          userId: auth?.currentUser?.uid || null,
          email: auth?.currentUser?.email || null,
          emailVerified: auth?.currentUser?.emailVerified ?? null,
          isAnonymous: auth?.currentUser?.isAnonymous ?? null,
          tenantId: auth?.currentUser?.tenantId || null,
          providerInfo: auth?.currentUser?.providerData?.map((p) => ({
            providerId: p.providerId,
            email: p.email,
          })) || [],
        },
        operationType,
        path,
      };
      console.error('Firestore Error:', JSON.stringify(errInfo));
      return new Error(JSON.stringify(errInfo));
    }

    async function testFirestoreConnection() {
      if (!db) return;
      try {
        await getDocFromServer(doc(db, 'test', 'connection'));
      } catch (error) {
        if (error instanceof Error && error.message.includes('the client is offline')) {
          console.error('Please check your Firebase configuration.');
        }
      }
    }
    testFirestoreConnection();

    // ------------------------------------------------------------------------
    // IndexedDB Local-First Storage + localStorage Migration
    // ------------------------------------------------------------------------
    let idbPromise = null;

    function openStudioDB() {
      if (idbPromise) return idbPromise;
      if (typeof indexedDB === 'undefined') return Promise.resolve(null);
      idbPromise = new Promise((resolve) => {
        try {
          const req = indexedDB.open(IDB_NAME, IDB_VERSION);
          req.onupgradeneeded = (event) => {
            const database = event.target.result;
            if (!database.objectStoreNames.contains('projects')) {
              database.createObjectStore('projects', { keyPath: 'id' });
            }
            if (!database.objectStoreNames.contains('syncQueue')) {
              database.createObjectStore('syncQueue', { keyPath: 'projectId' });
            }
            if (!database.objectStoreNames.contains('meta')) {
              database.createObjectStore('meta', { keyPath: 'key' });
            }
          };
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => resolve(null);
        } catch {
          resolve(null);
        }
      });
      return idbPromise;
    }

    async function idbPut(storeName, value) {
      const database = await openStudioDB();
      if (!database) return false;
      return new Promise((resolve) => {
        try {
          const tx = database.transaction(storeName, 'readwrite');
          tx.objectStore(storeName).put(value);
          tx.oncomplete = () => resolve(true);
          tx.onerror = () => resolve(false);
        } catch {
          resolve(false);
        }
      });
    }

    async function idbDelete(storeName, key) {
      const database = await openStudioDB();
      if (!database) return false;
      return new Promise((resolve) => {
        try {
          const tx = database.transaction(storeName, 'readwrite');
          tx.objectStore(storeName).delete(key);
          tx.oncomplete = () => resolve(true);
          tx.onerror = () => resolve(false);
        } catch {
          resolve(false);
        }
      });
    }

    async function idbGetAll(storeName) {
      const database = await openStudioDB();
      if (!database) return [];
      return new Promise((resolve) => {
        try {
          const tx = database.transaction(storeName, 'readonly');
          const req = tx.objectStore(storeName).getAll();
          req.onsuccess = () => resolve(Array.isArray(req.result) ? req.result : []);
          req.onerror = () => resolve([]);
        } catch {
          resolve([]);
        }
      });
    }

    // ------------------------------------------------------------------------
    // Original Editor Data & State
    // ------------------------------------------------------------------------
    const tags = [
      ['STRUCTURE', [['div', 'Container', '▱'], ['section', 'Section', '▰'], ['header', 'Header', '⌑'], ['nav', 'Navigation', '☰'], ['main', 'Main', '▤'], ['article', 'Article', '▧'], ['aside', 'Aside', '◫'], ['footer', 'Footer', '⌄'], ['details', 'Accordion', '⌄'], ['accordion', 'Accordion section', '⌄'], ['tabs', 'Tabs group', '▤'], ['navbar', 'Navigation bar', '☰'], ['card', 'Card block', '▣'], ['badge', 'Badge', '●'], ['modal', 'Modal panel', '▣']]],
      ['TEXT', [['h1', 'Heading 1', 'H1'], ['h2', 'Heading 2', 'H2'], ['h3', 'Heading 3', 'H3'], ['p', 'Paragraph', '¶'], ['span', 'Inline text', 'T'], ['blockquote', 'Quote', '❝'], ['ul', 'List', '☷'], ['small', 'Small text', 'T'], ['strong', 'Bold text', 'B']]],
      ['MEDIA & ACTIONS', [['img', 'Image', '▧'], ['video', 'Video', '▶'], ['image-container', 'Image container', '▧'], ['video-container', 'Video container', '▶'], ['a', 'Link', '↗'], ['button', 'Button', '▣'], ['hr', 'Divider', '―'], ['input', 'Input', '▭'], ['textarea', 'Text area', '▤'], ['select', 'Dropdown', '⌄'], ['form', 'Form', '▱']]],
    ];

    const starterPresets = [
      {
        name: 'Hero starter',
        description: 'A clean landing page with a call to action',
        nodes: [
          { tag: 'header', text: 'Studio', styles: { padding: '20px', fontWeight: '700', backgroundColor: '#f6f3ff' } },
          {
            tag: 'main',
            children: [
              { tag: 'h1', text: 'Make something wonderful', styles: { fontSize: '42px', color: '#35265e', textAlign: 'center', margin: '48px 22px 12px' } },
              { tag: 'p', text: 'A beautiful place to share your next big idea.', styles: { textAlign: 'center', color: '#686579', margin: '0 22px 24px' } },
              { tag: 'button', text: 'Get started', styles: { display: 'block', margin: '0 auto', padding: '12px 22px', backgroundColor: '#8061ed', color: '#ffffff', borderRadius: '9px', border: '0' } },
            ],
          },
          { tag: 'footer', text: 'Made with care', styles: { textAlign: 'center', padding: '38px 12px', color: '#85818f' } },
        ],
      },
      {
        name: 'Simple card',
        description: 'A centered profile or product card',
        nodes: [
          { tag: 'section', text: 'NEW COLLECTION', styles: { margin: '24px', padding: '28px 22px', borderRadius: '18px', backgroundColor: '#f4f0ff', color: '#4a3b70', textAlign: 'center', boxShadow: '0 12px 34px #2d1b5618' } },
          { tag: 'h2', text: 'A little inspiration', styles: { textAlign: 'center', color: '#29233a' } },
          { tag: 'p', text: 'Start with a blank canvas and make it yours.', styles: { textAlign: 'center', color: '#696574' } },
        ],
      },
    ];

    const defaultProject = () => ({
      schemaVersion: 2,
      id: uid(),
      name: 'Untitled site',
      created: Date.now(),
      updated: Date.now(),
      page: { background: '#ffffff' },
      nodes: [],
      customCss: '',
      customJs: '',
      behaviors: [],
      backendIntegration: { provider: 'none', endpoint: '', notes: '' },
      syncMeta: { cloudVersion: 0, lastSyncedHash: '', lastSyncedAt: 0 },
    });

    function normalizeProject(item) {
      item.schemaVersion = 2;
      item.id = typeof item.id === 'string' && /^[\w-]+$/.test(item.id) ? item.id : uid();
      item.name = typeof item.name === 'string' && item.name.trim() ? item.name : 'Untitled site';
      item.page = item.page || { background: '#ffffff' };
      item.behaviors = Array.isArray(item.behaviors) ? item.behaviors : [];
      item.nodes = Array.isArray(item.nodes) ? item.nodes : [];
      item.backendIntegration = item.backendIntegration && typeof item.backendIntegration === 'object'
        ? {
            provider: item.backendIntegration.provider || 'none',
            endpoint: String(item.backendIntegration.endpoint || ''),
            notes: String(item.backendIntegration.notes || ''),
          }
        : { provider: 'none', endpoint: '', notes: '' };
      item.syncMeta = item.syncMeta && typeof item.syncMeta === 'object'
        ? {
            cloudVersion: Number(item.syncMeta.cloudVersion || 0),
            lastSyncedHash: String(item.syncMeta.lastSyncedHash || ''),
            lastSyncedAt: Number(item.syncMeta.lastSyncedAt || 0),
            storagePath: item.syncMeta.storagePath ? String(item.syncMeta.storagePath) : '',
          }
        : { cloudVersion: 0, lastSyncedHash: '', lastSyncedAt: 0 };
      const normalize = (nodes) => nodes.forEach((node) => {
        node.id = typeof node.id === 'string' && /^[\w-]+$/.test(node.id) ? node.id : uid();
        node.attrs = node.attrs || {};
        node.styles = node.styles || {};
        node.children = Array.isArray(node.children) ? node.children : [];
        node.responsive = node.responsive || {};
        normalize(node.children);
      });
      normalize(item.nodes);
      return item;
    }

    let projects = loadProjects().map(normalizeProject);
    let project = projects[0] || defaultProject();
    normalizeProject(project);
    if (!projects.length) {
      projects = [project];
      persistLocalProjectsSync();
    }

    let selectedId = null;
    let activePanel = 'canvas';
    let codeTab = 'html';
    let previewMode = false;
    let history = [];
    let future = [];
    let toastTimer;
    let dragId = null;
    let previewWidth = 375;
    let clipboardNode = null;

    // Cloud & Sync state
    let syncState = 'local-only';
    let lastSyncError = '';
    let syncDebounceTimer = null;
    let isSyncingNow = false;
    let cloudProjectsCache = [];
    let activeConflict = null;
    let communityTemplates = [];
    let templateSearchQuery = '';
    let templateCategoryFilter = 'all';
    let templatesLoading = false;
    let templatesError = '';

    // Secret AI workbench state
    let secretAiTab = 'analyze';
    let secretAiLoading = false;
    let secretAiError = '';
    let secretAiAnalysis = null;
    let secretAiTemplateDraft = null;
    let secretAiCustomPrompt = '';
    let secretAiTemplatePrompt = '';
    let secretAiTemplateCategory = 'landing';
    let secretAiUploading = false;
    let secretAiModalOpen = false;

    function uid() {
      return 'n' + Math.random().toString(36).slice(2, 10);
    }

    function loadProjects() {
      try {
        return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
      } catch {
        return [];
      }
    }

    function persistLocalProjectsSync() {
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(projects));
      } catch {
        // Fallback: IndexedDB holds large payloads when localStorage quota is reached
        try {
          const compact = projects.slice(0, 5).map((p) => ({ ...p, nodes: p.nodes.slice(0, 40) }));
          localStorage.setItem(STORAGE_KEY, JSON.stringify(compact));
        } catch {
          // Ignore if completely full; IndexedDB persists full payload
        }
      }
    }

    function updateSyncIndicator(state, message = '') {
      syncState = state;
      if (message) lastSyncError = message;
      else if (state === 'synchronized' || state === 'local-only') lastSyncError = '';

      const btn = $('#syncStatusButton');
      const label = $('#syncStatusText');
      if (!btn || !label) return;
      const labels = {
        'local-only': 'Local only',
        'saving-local': 'Saving locally',
        'waiting-offline': 'Waiting for internet',
        'uploading': 'Uploading',
        'synchronized': 'Synchronized',
        'sync-failed': 'Sync failed',
        'conflict': 'Conflict detected',
      };
      btn.dataset.syncState = state;
      const stateText = labels[state] || 'Local only';
      label.textContent = stateText;
      btn.title = lastSyncError ? `${stateText}: ${lastSyncError}` : stateText;
      btn.setAttribute('aria-label', `Sync status: ${stateText}`);
    }

    function saveProjects(options = {}) {
      const { skipCloudQueue = false, immediateCloud = false } = options;
      project.updated = Date.now();
      const index = projects.findIndex((item) => item.id === project.id);
      if (index < 0) projects.unshift(project);
      else projects[index] = project;

      updateSyncIndicator(currentUser ? 'saving-local' : 'local-only');
      persistLocalProjectsSync();
      idbPut('projects', clone(project));
      const titleEl = $('#projectName');
      if (titleEl) titleEl.textContent = project.name;

      if (!skipCloudQueue) {
        const currentHash = computeProjectHash(project);
        const alreadySynced = currentHash === project.syncMeta?.lastSyncedHash;
        if (currentUser) {
          if (alreadySynced && !immediateCloud) {
            updateSyncIndicator(navigator.onLine ? 'synchronized' : 'waiting-offline');
          } else {
            queueProjectSync(project.id, immediateCloud);
          }
        } else {
          updateSyncIndicator('local-only');
        }
      }
    }

    async function hydrateFromIndexedDB() {
      const idbProjects = await idbGetAll('projects');
      if (!idbProjects.length) {
        // Migrate existing localStorage projects safely into IndexedDB
        for (const p of projects) {
          await idbPut('projects', clone(p));
        }
        await idbPut('meta', { key: 'migrated-v1', migratedAt: Date.now() });
        return;
      }

      let changed = false;
      const byId = new Map(projects.map((p) => [p.id, p]));
      for (const idbProj of idbProjects) {
        const normalized = normalizeProject(idbProj);
        const existing = byId.get(normalized.id);
        if (!existing) {
          byId.set(normalized.id, normalized);
          changed = true;
        } else if ((normalized.updated || 0) > (existing.updated || 0)) {
          byId.set(normalized.id, normalized);
          changed = true;
        }
      }
      // Also ensure any localStorage-only project is saved to IndexedDB
      for (const localProj of projects) {
        const found = idbProjects.find((p) => p.id === localProj.id);
        if (!found || (localProj.updated || 0) > (found.updated || 0)) {
          await idbPut('projects', clone(localProj));
        }
      }

      if (changed) {
        projects = [...byId.values()].sort((a, b) => (b.updated || 0) - (a.updated || 0));
        const activeMatch = projects.find((p) => p.id === project.id);
        if (activeMatch) project = activeMatch;
        renderAll({ skipSave: true });
      }
    }

    // ------------------------------------------------------------------------
    // Cloud Synchronization, Conflict Resolution & Backups
    // ------------------------------------------------------------------------
    async function queueProjectSync(projectId, immediate = false) {
      await idbPut('syncQueue', {
        projectId,
        queuedAt: Date.now(),
        retryCount: 0,
      });

      if (!currentUser) {
        updateSyncIndicator('local-only');
        return;
      }
      if (!navigator.onLine) {
        updateSyncIndicator('waiting-offline', 'Changes saved locally; will upload when back online.');
        return;
      }

      clearTimeout(syncDebounceTimer);
      if (immediate) {
        processSyncQueue();
      } else {
        updateSyncIndicator('saving-local');
        syncDebounceTimer = setTimeout(() => {
          processSyncQueue();
        }, 1800);
      }
    }

    async function processSyncQueue(options = {}) {
      if (!firebaseReady || !currentUser || !db || !storage) {
        updateSyncIndicator(currentUser ? 'sync-failed' : 'local-only', !firebaseReady ? 'Firebase not configured' : '');
        return;
      }
      if (!navigator.onLine) {
        updateSyncIndicator('waiting-offline', 'Offline — saved locally.');
        return;
      }
      if (isSyncingNow) return;
      isSyncingNow = true;

      try {
        const queueItems = await idbGetAll('syncQueue');
        if (!queueItems.length && options.projectId) {
          queueItems.push({ projectId: options.projectId, queuedAt: Date.now() });
        }

        for (const item of queueItems) {
          const targetProj = projects.find((p) => p.id === item.projectId);
          if (!targetProj) {
            await idbDelete('syncQueue', item.projectId);
            continue;
          }
          const result = await syncSingleProjectToCloud(targetProj, { forceOverwrite: Boolean(options.forceOverwrite) });
          if (result === 'synced' || result === 'unchanged') {
            await idbDelete('syncQueue', item.projectId);
          } else if (result === 'conflict') {
            break;
          }
        }
      } finally {
        isSyncingNow = false;
      }
    }

    async function fetchStorageJson(path) {
      const ref = storageRef(storage, path);
      try {
        const bytes = await getBytes(ref);
        const text = new TextDecoder().decode(bytes);
        return JSON.parse(text);
      } catch (bytesErr) {
        // Fallback via download URL if getBytes encounters SDK edge case
        const url = await getDownloadURL(ref);
        const res = await fetch(url);
        if (!res.ok) throw bytesErr;
        return res.json();
      }
    }

    async function syncSingleProjectToCloud(targetProj, { forceOverwrite = false } = {}) {
      if (!currentUser || !db || !storage) return 'skipped';
      if (!navigator.onLine) {
        updateSyncIndicator('waiting-offline');
        return 'offline';
      }

      const localHash = computeProjectHash(targetProj);
      if (!forceOverwrite && localHash === targetProj.syncMeta?.lastSyncedHash && Number(targetProj.syncMeta?.cloudVersion || 0) > 0) {
        updateSyncIndicator('synchronized');
        return 'unchanged';
      }

      updateSyncIndicator('uploading');
      const docPath = `projects/${targetProj.id}`;
      const projDocRef = doc(db, 'projects', targetProj.id);

      try {
        let remoteSnap = null;
        try {
          remoteSnap = await getDoc(projDocRef);
        } catch (err) {
          // If doc doesn't exist yet and rule denies get on non-existent doc with ownerId check, handle cleanly
          if (err?.code !== 'permission-denied') throw err;
        }

        const remoteMeta = remoteSnap && remoteSnap.exists() ? remoteSnap.data() : null;
        if (remoteMeta && remoteMeta.ownerId !== currentUser.uid) {
          updateSyncIndicator('sync-failed', 'Unauthorized: project belongs to another account.');
          notify('Cloud sync blocked: project ownership mismatch.');
          return 'failed';
        }

        if (remoteMeta && !forceOverwrite) {
          const conflictCheck = detectSyncConflict(targetProj, remoteMeta);
          if (conflictCheck.hasConflict) {
            let cloudPayload = null;
            try {
              cloudPayload = await fetchStorageJson(remoteMeta.storagePath);
            } catch {
              cloudPayload = null;
            }
            activeConflict = {
              projectId: targetProj.id,
              localProject: clone(targetProj),
              remoteMeta,
              cloudProject: cloudPayload ? normalizeProject(cloudPayload) : null,
            };
            updateSyncIndicator('conflict', 'Local and cloud versions differ.');
            showConflictModal();
            return 'conflict';
          }
        }

        const nextVersion = remoteMeta ? Number(remoteMeta.version || 1) + 1 : 1;
        const storagePath = `users/${currentUser.uid}/projects/${targetProj.id}.json`;
        const payload = buildExportSafeProjectPayload(targetProj);
        payload.version = nextVersion;
        payload.contentHash = localHash;

        const fileRef = storageRef(storage, storagePath);
        await uploadString(fileRef, JSON.stringify(payload), 'raw', { contentType: 'application/json' });

        const metaPayload = {
          ownerId: currentUser.uid,
          projectName: String(targetProj.name || 'Untitled site').slice(0, 120),
          updatedAt: serverTimestamp(),
          version: nextVersion,
          storagePath,
          contentHash: localHash,
          nodeCount: countProjectNodes(targetProj.nodes),
        };

        if (!remoteMeta) {
          try {
            await setDoc(projDocRef, {
              ...metaPayload,
              createdAt: serverTimestamp(),
            });
          } catch (err) {
            throw handleFirestoreError(err, OperationType.CREATE, docPath);
          }
        } else {
          try {
            await updateDoc(projDocRef, metaPayload);
          } catch (err) {
            throw handleFirestoreError(err, OperationType.UPDATE, docPath);
          }
        }

        targetProj.syncMeta = {
          cloudVersion: nextVersion,
          lastSyncedHash: localHash,
          lastSyncedAt: Date.now(),
          storagePath,
        };
        if (targetProj.id === project.id) {
          project.syncMeta = { ...targetProj.syncMeta };
        }
        persistLocalProjectsSync();
        await idbPut('projects', clone(targetProj));
        await refreshCloudProjectsList({ silent: true });
        updateSyncIndicator('synchronized');
        return 'synced';
      } catch (err) {
        console.error('Cloud sync error:', err);
        if (!navigator.onLine || err?.code === 'unavailable' || String(err?.message || '').toLowerCase().includes('offline')) {
          updateSyncIndicator('waiting-offline', 'Waiting for internet connection.');
          return 'offline';
        }
        updateSyncIndicator('sync-failed', err?.message || 'Could not sync with cloud');
        return 'failed';
      }
    }

    async function refreshCloudProjectsList({ silent = false } = {}) {
      if (!currentUser || !db) {
        cloudProjectsCache = [];
        return [];
      }
      const path = 'projects';
      try {
        const q = query(collection(db, 'projects'), where('ownerId', '==', currentUser.uid), limit(100));
        const snap = await getDocs(q);
        cloudProjectsCache = snap.docs.map((d) => ({ id: d.id, ...d.data() }))
          .sort((a, b) => (b.updatedAt?.toMillis?.() || 0) - (a.updatedAt?.toMillis?.() || 0));
        return cloudProjectsCache;
      } catch (err) {
        if (!silent) {
          handleFirestoreError(err, OperationType.LIST, path);
        }
        return cloudProjectsCache;
      }
    }

    async function syncCloudProjectsOnAuth() {
      if (!currentUser || !db || !storage) return;
      await refreshCloudProjectsList({ silent: true });

      // Merge cloud-only projects into local catalog safely without overwriting local unsynced changes
      let addedCount = 0;
      for (const remoteMeta of cloudProjectsCache) {
        const localMatch = projects.find((p) => p.id === remoteMeta.id);
        if (!localMatch) {
          try {
            const payload = await fetchStorageJson(remoteMeta.storagePath);
            const imported = normalizeProject(payload);
            imported.syncMeta = {
              cloudVersion: Number(remoteMeta.version || 1),
              lastSyncedHash: String(remoteMeta.contentHash || computeProjectHash(imported)),
              lastSyncedAt: Date.now(),
              storagePath: remoteMeta.storagePath,
            };
            projects.push(imported);
            await idbPut('projects', clone(imported));
            addedCount++;
          } catch (err) {
            console.warn('Could not load cloud project:', remoteMeta.id, err);
          }
        } else {
          const conflictCheck = detectSyncConflict(localMatch, remoteMeta);
          if (conflictCheck.hasConflict && localMatch.id === project.id) {
            let cloudPayload = null;
            try {
              cloudPayload = await fetchStorageJson(remoteMeta.storagePath);
            } catch {
              cloudPayload = null;
            }
            activeConflict = {
              projectId: localMatch.id,
              localProject: clone(localMatch),
              remoteMeta,
              cloudProject: cloudPayload ? normalizeProject(cloudPayload) : null,
            };
            updateSyncIndicator('conflict', 'Local and cloud versions differ.');
          }
        }
      }

      if (addedCount > 0) {
        persistLocalProjectsSync();
      }
      await processSyncQueue();
    }

    async function openCloudProject(cloudMeta) {
      if (!currentUser) return notify('Sign in to load cloud projects');
      if (cloudMeta.ownerId !== currentUser.uid) return notify('Unauthorized: cannot access another user project.');
      try {
        updateSyncIndicator('uploading');
        const payload = await fetchStorageJson(cloudMeta.storagePath);
        const loaded = normalizeProject(payload);
        loaded.syncMeta = {
          cloudVersion: Number(cloudMeta.version || 1),
          lastSyncedHash: String(cloudMeta.contentHash || computeProjectHash(loaded)),
          lastSyncedAt: Date.now(),
          storagePath: cloudMeta.storagePath,
        };
        const existingIndex = projects.findIndex((p) => p.id === loaded.id);
        if (existingIndex >= 0) {
          const conflict = detectSyncConflict(projects[existingIndex], cloudMeta);
          if (conflict.hasConflict) {
            activeConflict = {
              projectId: loaded.id,
              localProject: clone(projects[existingIndex]),
              remoteMeta: cloudMeta,
              cloudProject: loaded,
            };
            updateSyncIndicator('conflict', 'Local and cloud versions differ.');
            showConflictModal();
            return;
          }
          projects[existingIndex] = loaded;
        } else {
          projects.unshift(loaded);
        }
        project = loaded;
        history = [];
        future = [];
        selectedId = null;
        await idbPut('projects', clone(project));
        persistLocalProjectsSync();
        closeModal();
        renderAll({ skipSave: true });
        updateSyncIndicator('synchronized');
        notify('Cloud project loaded');
      } catch (err) {
        updateSyncIndicator('sync-failed', err?.message || 'Failed to download project');
        notify('Could not load cloud project: ' + (err?.message || 'Error'));
      }
    }

    async function createCloudBackup(targetProj) {
      if (!currentUser || !storage || !db) return openAuthModal('signin');
      if (!navigator.onLine) return notify('Connect to the internet to create a cloud backup.');
      try {
        // Ensure cloud project exists first
        await syncSingleProjectToCloud(targetProj);
        const backupId = 'b_' + Date.now();
        const backupPath = `users/${currentUser.uid}/backups/${targetProj.id}/${backupId}.json`;
        const payload = buildExportSafeProjectPayload(targetProj);
        payload.backupCreatedAt = Date.now();
        await uploadString(storageRef(storage, backupPath), JSON.stringify(payload), 'raw', {
          contentType: 'application/json',
        });

        const projDocRef = doc(db, 'projects', targetProj.id);
        const remoteSnap = await getDoc(projDocRef);
        if (remoteSnap.exists() && remoteSnap.data().ownerId === currentUser.uid) {
          await updateDoc(projDocRef, {
            lastBackupPath: backupPath,
            lastBackupAt: serverTimestamp(),
            updatedAt: serverTimestamp(),
          });
        }
        notify('Cloud backup created');
        await showDashboard();
      } catch (err) {
        notify('Backup failed: ' + (err?.message || 'Storage error'));
      }
    }

    async function listCloudBackups(projectId) {
      if (!currentUser || !storage) return [];
      try {
        const folderRef = storageRef(storage, `users/${currentUser.uid}/backups/${projectId}`);
        const res = await listAll(folderRef);
        return res.items.map((item) => ({
          name: item.name,
          fullPath: item.fullPath,
          timestamp: Number(item.name.replace(/^b_|\.json$/g, '')) || 0,
        })).sort((a, b) => b.timestamp - a.timestamp);
      } catch {
        return [];
      }
    }

    async function restoreBackupFromPath(storagePath) {
      if (!currentUser || !storage) return;
      try {
        const payload = await fetchStorageJson(storagePath);
        const restored = normalizeProject(payload);
        remember();
        restored.updated = Date.now();
        restored.syncMeta = {
          ...(project.syncMeta || {}),
          lastSyncedHash: '',
        };
        const idx = projects.findIndex((p) => p.id === restored.id);
        if (idx >= 0) projects[idx] = restored;
        else projects.unshift(restored);
        project = restored;
        selectedId = null;
        closeModal();
        renderAll();
        notify('Backup restored locally. Syncing update...');
      } catch (err) {
        notify('Could not restore backup: ' + (err?.message || 'Error'));
      }
    }

    async function deleteCloudProject(projectId) {
      if (!currentUser || !db || !storage) return;
      try {
        const docRef = doc(db, 'projects', projectId);
        const snap = await getDoc(docRef);
        if (snap.exists()) {
          if (snap.data().ownerId !== currentUser.uid) {
            return notify('Unauthorized: cannot delete another user project.');
          }
          const path = snap.data().storagePath;
          await deleteDoc(docRef);
          if (path) {
            deleteObject(storageRef(storage, path)).catch(() => {});
          }
        }
        await refreshCloudProjectsList({ silent: true });
        notify('Cloud project deleted');
      } catch (err) {
        notify('Cloud delete failed: ' + (err?.message || 'Error'));
      }
    }

    function showConflictModal() {
      if (!activeConflict) {
        openModal('Sync status', 'SYNCHRONIZATION', `
          <div class="status-banner">${escapeHtml(lastSyncError || 'All local projects are up to date.')}</div>
          <div class="action-row">
            <button class="primary-button" id="syncNowBtn">Sync now</button>
            <button class="soft-button" id="closeSyncModal">Close</button>
          </div>
        `);
        $('#syncNowBtn').onclick = async () => {
          closeModal();
          await queueProjectSync(project.id, true);
        };
        $('#closeSyncModal').onclick = closeModal;
        return;
      }

      const { localProject, remoteMeta, cloudProject } = activeConflict;
      const localNodes = countProjectNodes(localProject.nodes);
      const cloudNodes = cloudProject ? countProjectNodes(cloudProject.nodes) : (remoteMeta.nodeCount ?? '?');
      const cloudTime = remoteMeta.updatedAt?.toDate ? remoteMeta.updatedAt.toDate().toLocaleString() : 'Cloud version ' + remoteMeta.version;

      openModal('Sync conflict detected', 'CONFLICT RESOLUTION', `
        <div class="status-banner warning">
          Local edits and cloud version v${escapeHtml(remoteMeta.version)} differ. Choose how to resolve without losing work.
        </div>
        <div class="conflict-grid">
          <div class="conflict-pane">
            <strong>Local version</strong>
            <small>Name: ${escapeHtml(localProject.name)}</small>
            <small>Elements: ${localNodes}</small>
            <small>Edited: ${new Date(localProject.updated || Date.now()).toLocaleString()}</small>
          </div>
          <div class="conflict-pane">
            <strong>Cloud version (v${escapeHtml(remoteMeta.version)})</strong>
            <small>Name: ${escapeHtml(remoteMeta.projectName)}</small>
            <small>Elements: ${cloudNodes}</small>
            <small>Updated: ${escapeHtml(cloudTime)}</small>
          </div>
        </div>
        <div class="form-stack">
          <button class="primary-button" id="resolveKeepLocal">Keep local version &amp; overwrite cloud</button>
          <button class="soft-button" id="resolveRestoreCloud">Restore cloud version (replaces local)</button>
          <button class="soft-button" id="resolveSaveCopy">Save local as separate copy &amp; restore cloud</button>
        </div>
      `);

      $('#resolveKeepLocal').onclick = async () => {
        const target = projects.find((p) => p.id === activeConflict.projectId) || project;
        activeConflict = null;
        closeModal();
        await syncSingleProjectToCloud(target, { forceOverwrite: true });
        notify('Local version kept and uploaded to cloud');
      };

      $('#resolveRestoreCloud').onclick = async () => {
        if (!cloudProject) return notify('Cloud payload unavailable right now.');
        const targetIdx = projects.findIndex((p) => p.id === activeConflict.projectId);
        const restored = normalizeProject(cloudProject);
        restored.syncMeta = {
          cloudVersion: Number(remoteMeta.version || 1),
          lastSyncedHash: String(remoteMeta.contentHash || computeProjectHash(restored)),
          lastSyncedAt: Date.now(),
          storagePath: remoteMeta.storagePath,
        };
        if (project.id === restored.id) {
          history.push(JSON.stringify(project));
          project = restored;
        }
        if (targetIdx >= 0) projects[targetIdx] = restored;
        else projects.unshift(restored);
        activeConflict = null;
        await idbPut('projects', clone(restored));
        await idbDelete('syncQueue', restored.id);
        persistLocalProjectsSync();
        closeModal();
        renderAll({ skipSave: true });
        updateSyncIndicator('synchronized');
        notify('Cloud version restored');
      };

      $('#resolveSaveCopy').onclick = async () => {
        const copy = clone(localProject);
        copy.id = uid();
        copy.name = `${localProject.name} (local copy)`;
        copy.updated = Date.now();
        copy.syncMeta = { cloudVersion: 0, lastSyncedHash: '', lastSyncedAt: 0 };
        projects.unshift(copy);
        await idbPut('projects', clone(copy));

        if (cloudProject) {
          const restored = normalizeProject(cloudProject);
          restored.syncMeta = {
            cloudVersion: Number(remoteMeta.version || 1),
            lastSyncedHash: String(remoteMeta.contentHash || computeProjectHash(restored)),
            lastSyncedAt: Date.now(),
            storagePath: remoteMeta.storagePath,
          };
          const idx = projects.findIndex((p) => p.id === restored.id);
          if (idx >= 0) projects[idx] = restored;
          if (project.id === restored.id) project = restored;
          await idbPut('projects', clone(restored));
          await idbDelete('syncQueue', restored.id);
        }

        activeConflict = null;
        persistLocalProjectsSync();
        closeModal();
        renderAll({ skipSave: true });
        queueProjectSync(copy.id, true);
        notify('Local saved as separate copy and cloud restored');
      };
    }

    // ------------------------------------------------------------------------
    // Authentication & User Profiles (users/{userId})
    // ------------------------------------------------------------------------
    async function ensureUserProfile(user, explicitDisplayName = '') {
      if (!user || !db) return null;
      const profileRef = doc(db, 'users', user.uid);
      const path = `users/${user.uid}`;
      try {
        const snap = await getDoc(profileRef);
        if (!snap.exists()) {
          const displayName = String(explicitDisplayName || user.displayName || user.email?.split('@')[0] || 'Studio User').slice(0, 80);
          const photoURL = sanitizeUrl(user.photoURL || '', { allowDataImage: false }).slice(0, 500);
          const payload = {
            displayName,
            email: String(user.email || '').slice(0, 160),
            photoURL: photoURL === '#' ? '' : photoURL,
            createdAt: serverTimestamp(),
            updatedAt: serverTimestamp(),
          };
          await setDoc(profileRef, payload);
          currentProfile = { ...payload, displayName, photoURL: payload.photoURL };
        } else {
          currentProfile = snap.data();
        }
        return currentProfile;
      } catch (err) {
        handleFirestoreError(err, OperationType.WRITE, path);
        return null;
      }
    }

    function updateAuthButtonUI() {
      const avatarEl = $('#authAvatar');
      const labelEl = $('#authButtonLabel');
      if (!avatarEl || !labelEl) return;
      if (!currentUser) {
        avatarEl.textContent = '?';
        labelEl.textContent = 'Sign in';
        return;
      }
      const name = currentProfile?.displayName || currentUser.displayName || currentUser.email || 'Account';
      const photo = currentProfile?.photoURL || currentUser.photoURL || '';
      if (photo && /^https?:\/\//i.test(photo)) {
        avatarEl.innerHTML = `<img src="${escapeHtml(photo)}" alt="${escapeHtml(name)}" referrerpolicy="no-referrer" />`;
      } else {
        avatarEl.textContent = String(name).trim().charAt(0).toUpperCase() || 'U';
      }
      labelEl.textContent = name;
    }

    if (auth) {
      onAuthStateChanged(auth, async (user) => {
        authInitialized = true;
        currentUser = user || null;
        if (currentUser) {
          updateAuthButtonUI();
          await ensureUserProfile(currentUser);
          updateAuthButtonUI();
          await syncCloudProjectsOnAuth();
        } else {
          currentProfile = null;
          cloudProjectsCache = [];
          activeConflict = null;
          updateAuthButtonUI();
          updateSyncIndicator('local-only');
        }
        if (activePanel === 'templates') renderTemplatesPanel();
      });
    }

    function openAuthModal(initialTab = 'signin', statusMsg = '', statusType = '') {
      if (!firebaseReady || !auth) {
        openModal('Firebase configuration required', 'ACCOUNT', `
          <div class="status-banner warning">
            Firebase credentials are missing or invalid. Insert your Firebase Web Config into <code>firebase-applet-config.json</code> or <code>MANUAL_FIREBASE_CONFIG</code> in <code>script.js</code>.
          </div>
          <p class="muted-copy">Local editing, IndexedDB storage, and HTML/CSS/JS export continue to work offline without Firebase.</p>
        `);
        return;
      }

      if (currentUser) {
        renderAccountModal(statusMsg, statusType);
        return;
      }

      let activeTab = initialTab;
      const renderAuthForm = (bannerText = statusMsg, bannerKind = statusType) => {
        const bannerHtml = bannerText
          ? `<div class="status-banner ${escapeHtml(bannerKind)}" id="authBanner">${escapeHtml(bannerText)}</div>`
          : '<div id="authBanner"></div>';

        const formBody = activeTab === 'signup'
          ? `<form id="authForm" class="form-stack" novalidate>
              <div><label class="field-title" for="authDisplayName">Display name</label><input class="control" id="authDisplayName" type="text" required maxlength="80" placeholder="Jane Doe" /></div>
              <div><label class="field-title" for="authEmail">Email</label><input class="control" id="authEmail" type="email" required autocomplete="email" placeholder="you@example.com" /></div>
              <div><label class="field-title" for="authPassword">Password (min 6 chars)</label><input class="control" id="authPassword" type="password" required minlength="6" autocomplete="new-password" placeholder="••••••••" /></div>
              <button class="primary-button" type="submit" id="authSubmitBtn">Create account</button>
            </form>`
          : activeTab === 'reset'
          ? `<form id="authForm" class="form-stack" novalidate>
              <div><label class="field-title" for="authEmail">Account email</label><input class="control" id="authEmail" type="email" required autocomplete="email" placeholder="you@example.com" /></div>
              <button class="primary-button" type="submit" id="authSubmitBtn">Send password reset email</button>
            </form>`
          : `<form id="authForm" class="form-stack" novalidate>
              <div><label class="field-title" for="authEmail">Email</label><input class="control" id="authEmail" type="email" required autocomplete="email" placeholder="you@example.com" /></div>
              <div><label class="field-title" for="authPassword">Password</label><input class="control" id="authPassword" type="password" required autocomplete="current-password" placeholder="••••••••" /></div>
              <button class="primary-button" type="submit" id="authSubmitBtn">Sign in</button>
            </form>`;

        openModal('Studio account', 'AUTHENTICATION', `
          <div class="auth-tabs" role="tablist">
            <button type="button" class="auth-tab ${activeTab === 'signin' ? 'active' : ''}" data-auth-tab="signin">Sign in</button>
            <button type="button" class="auth-tab ${activeTab === 'signup' ? 'active' : ''}" data-auth-tab="signup">Sign up</button>
            <button type="button" class="auth-tab ${activeTab === 'reset' ? 'active' : ''}" data-auth-tab="reset">Reset password</button>
          </div>
          ${bannerHtml}
          ${formBody}
          <p class="muted-copy" style="margin-top:12px">Your Studio account syncs projects and templates for the editor only. Generated websites never include your Studio credentials.</p>
        `);

        $$('[data-auth-tab]').forEach((btn) => {
          btn.onclick = () => {
            activeTab = btn.dataset.authTab;
            renderAuthForm('', '');
          };
        });

        $('#authForm').onsubmit = async (event) => {
          event.preventDefault();
          const email = ($('#authEmail')?.value || '').trim();
          const password = $('#authPassword')?.value || '';
          const displayName = ($('#authDisplayName')?.value || '').trim();
          const submitBtn = $('#authSubmitBtn');
          const setErr = (msg) => {
            $('#authBanner').className = 'status-banner error';
            $('#authBanner').textContent = msg;
          };

          if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return setErr('Please enter a valid email address.');
          }
          if (activeTab !== 'reset' && password.length < 6) {
            return setErr('Password must be at least 6 characters.');
          }
          if (activeTab === 'signup' && !displayName) {
            return setErr('Please enter a display name.');
          }

          submitBtn.disabled = true;
          try {
            if (activeTab === 'signup') {
              const cred = await createUserWithEmailAndPassword(auth, email, password);
              await updateProfile(cred.user, { displayName: displayName.slice(0, 80) });
              sendEmailVerification(cred.user).catch(() => {});
              await ensureUserProfile(cred.user, displayName);
              closeModal();
              notify('Account created! Verification email sent.');
            } else if (activeTab === 'signin') {
              await signInWithEmailAndPassword(auth, email, password);
              closeModal();
              notify('Signed in successfully');
            } else {
              await sendPasswordResetEmail(auth, email);
              renderAuthForm('Password reset email sent. Check your inbox.', 'success');
            }
          } catch (err) {
            setErr(mapAuthErrorMessage(err));
          } finally {
            if (submitBtn) submitBtn.disabled = false;
          }
        };
      };

      renderAuthForm();
    }

    function renderAccountModal(statusMsg = '', statusType = '') {
      const displayName = currentProfile?.displayName || currentUser.displayName || 'Studio User';
      const email = currentUser.email || '';
      const photoURL = currentProfile?.photoURL || currentUser.photoURL || '';
      const verified = currentUser.emailVerified;

      openModal('Account & settings', 'USER PROFILE', `
        ${statusMsg ? `<div class="status-banner ${escapeHtml(statusType)}">${escapeHtml(statusMsg)}</div>` : ''}
        <div class="profile-summary">
          <div class="auth-avatar">${photoURL && /^https?:\/\//i.test(photoURL) ? `<img src="${escapeHtml(photoURL)}" alt="${escapeHtml(displayName)}" referrerpolicy="no-referrer" />` : escapeHtml(displayName.charAt(0).toUpperCase())}</div>
          <div class="profile-meta">
            <strong>${escapeHtml(displayName)}</strong>
            <small>${escapeHtml(email)} · ${verified ? 'Verified' : 'Email not verified'}</small>
          </div>
          ${!verified ? '<button type="button" class="soft-button" id="resendVerifyBtn">Verify email</button>' : ''}
        </div>
        <form id="profileForm" class="form-stack">
          <div>
            <label class="field-title" for="profileDisplayName">Display name</label>
            <input class="control" id="profileDisplayName" value="${escapeHtml(displayName)}" maxlength="80" required />
          </div>
          <div>
            <label class="field-title" for="profilePhotoUrl">Avatar URL (optional https://)</label>
            <input class="control" id="profilePhotoUrl" value="${escapeHtml(photoURL)}" maxlength="500" placeholder="https://example.com/avatar.png" />
          </div>
          <div class="action-row">
            <button type="submit" class="primary-button" id="saveProfileBtn">Save profile</button>
            <button type="button" class="soft-button" id="accountSyncBtn">Sync projects now</button>
            <button type="button" class="danger-button" id="signOutBtn">Sign out</button>
          </div>
        </form>
        <div class="inspector-section" style="margin-top:18px;padding-top:14px;border-top:1px solid var(--line)">
          <h3 class="section-head">Platform &amp; User-Website Separation</h3>
          <p class="muted-copy">Your Studio authentication and Firestore/Storage project sync stay strictly inside the editor. Exported websites never include Studio's Firebase configuration or account tokens.</p>
        </div>
      `);

      const verifyBtn = $('#resendVerifyBtn');
      if (verifyBtn) {
        verifyBtn.onclick = async () => {
          try {
            await sendEmailVerification(currentUser);
            renderAccountModal('Verification email sent to ' + email, 'success');
          } catch (err) {
            renderAccountModal(mapAuthErrorMessage(err), 'error');
          }
        };
      }

      $('#profileForm').onsubmit = async (event) => {
        event.preventDefault();
        const nextName = ($('#profileDisplayName').value || '').trim();
        const rawPhoto = ($('#profilePhotoUrl').value || '').trim();
        if (!nextName) return renderAccountModal('Display name cannot be empty.', 'error');
        let nextPhoto = '';
        if (rawPhoto) {
          if (!/^https?:\/\//i.test(rawPhoto)) {
            return renderAccountModal('Avatar URL must start with https:// or http://', 'error');
          }
          nextPhoto = rawPhoto.slice(0, 500);
        }

        const btn = $('#saveProfileBtn');
        btn.disabled = true;
        try {
          await updateProfile(currentUser, { displayName: nextName.slice(0, 80), photoURL: nextPhoto || null });
          const profileRef = doc(db, 'users', currentUser.uid);
          const snap = await getDoc(profileRef);
          if (snap.exists()) {
            await updateDoc(profileRef, {
              displayName: nextName.slice(0, 80),
              email: currentUser.email || '',
              photoURL: nextPhoto,
              updatedAt: serverTimestamp(),
            });
          } else {
            await setDoc(profileRef, {
              displayName: nextName.slice(0, 80),
              email: currentUser.email || '',
              photoURL: nextPhoto,
              createdAt: serverTimestamp(),
              updatedAt: serverTimestamp(),
            });
          }
          currentProfile = { ...(currentProfile || {}), displayName: nextName, photoURL: nextPhoto };
          updateAuthButtonUI();
          renderAccountModal('Profile updated.', 'success');
        } catch (err) {
          renderAccountModal(err?.message || 'Could not update profile.', 'error');
        } finally {
          if (btn) btn.disabled = false;
        }
      };

      $('#accountSyncBtn').onclick = async () => {
        closeModal();
        await queueProjectSync(project.id, true);
      };

      $('#signOutBtn').onclick = async () => {
        await signOut(auth);
        closeModal();
        notify('Signed out. Local projects remain available offline.');
      };
    }

    // ------------------------------------------------------------------------
    // Community Templates System (templates/{templateId}, templateReports)
    // ------------------------------------------------------------------------
    async function loadCommunityTemplates() {
      if (!firebaseReady || !db) {
        communityTemplates = [];
        templatesError = 'Connect Firebase to browse community templates.';
        return;
      }
      templatesLoading = true;
      templatesError = '';
      if (activePanel === 'templates') renderTemplatesPanelView();

      try {
        const pubQuery = query(collection(db, 'templates'), where('status', '==', 'published'), limit(60));
        const pubSnap = await getDocs(pubQuery);
        const map = new Map();
        pubSnap.docs.forEach((d) => map.set(d.id, { id: d.id, ...d.data() }));

        if (currentUser) {
          const mineQuery = query(collection(db, 'templates'), where('authorId', '==', currentUser.uid), limit(40));
          const mineSnap = await getDocs(mineQuery);
          mineSnap.docs.forEach((d) => map.set(d.id, { id: d.id, ...d.data() }));
        }

        communityTemplates = [...map.values()].sort((a, b) => (b.updatedAt?.toMillis?.() || 0) - (a.updatedAt?.toMillis?.() || 0));
      } catch (err) {
        templatesError = navigator.onLine ? (err?.message || 'Could not load templates.') : 'Offline — community templates require internet.';
      } finally {
        templatesLoading = false;
        if (activePanel === 'templates') renderTemplatesPanelView();
      }
    }

    function renderTemplatesPanel() {
      renderTemplatesPanelView();
      if (!communityTemplates.length && !templatesLoading) {
        loadCommunityTemplates();
      }
    }

    function getFilteredCommunityTemplates() {
      const q = templateSearchQuery.trim().toLowerCase();
      return communityTemplates.filter((t) => {
        if (templateCategoryFilter !== 'all' && t.category !== templateCategoryFilter) return false;
        if (!q) return true;
        return (
          String(t.title || '').toLowerCase().includes(q) ||
          String(t.description || '').toLowerCase().includes(q) ||
          String(t.authorName || '').toLowerCase().includes(q)
        );
      });
    }

    function templatesListMarkup() {
      const filtered = getFilteredCommunityTemplates();
      const communityCards = filtered.map((item) => {
        const isAuthor = currentUser && item.authorId === currentUser.uid;
        return `<div class="template-library-card">
          <div class="template-library-head">
            <div>
              <strong>${escapeHtml(item.title)}</strong>
              <div class="template-meta-line">${escapeHtml(item.category)} · ${escapeHtml(item.authorName)} · ${Number(item.nodeCount || 0)} elements${item.status === 'hidden' ? ' · Hidden' : ''}</div>
            </div>
          </div>
          ${item.description ? `<p class="template-desc">${escapeHtml(item.description)}</p>` : ''}
          <div class="action-row">
            <button type="button" class="primary-button" data-import-template="${escapeHtml(item.id)}">Import</button>
            ${isAuthor ? `<button type="button" class="soft-button" data-toggle-template-status="${escapeHtml(item.id)}">${item.status === 'published' ? 'Hide' : 'Publish'}</button><button type="button" class="danger-button" data-delete-template="${escapeHtml(item.id)}">Delete</button>` : `<button type="button" class="soft-button" data-report-template="${escapeHtml(item.id)}">Report</button>`}
          </div>
        </div>`;
      }).join('');

      const emptyMsg = !templatesLoading
        ? '<p class="muted-copy" style="margin-top:8px">No matching community templates yet. Upload your own or start from a built-in starter below.</p>'
        : '';

      const startersHtml = `<div class="section-label" style="margin-top:16px">BUILT-IN STARTERS</div>` +
        starterPresets.map((item, idx) => `<div class="template-card"><div><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.description)}</small></div><button type="button" class="soft-button" data-panel-starter="${idx}">Use</button></div>`).join('');

      return (communityCards || emptyMsg) + startersHtml;
    }

    function bindTemplatesListEvents() {
      $$('[data-import-template]').forEach((btn) => {
        btn.onclick = () => importCommunityTemplate(btn.dataset.importTemplate);
      });
      $$('[data-report-template]').forEach((btn) => {
        btn.onclick = () => openReportTemplateModal(btn.dataset.reportTemplate);
      });
      $$('[data-toggle-template-status]').forEach((btn) => {
        btn.onclick = () => toggleTemplateVisibility(btn.dataset.toggleTemplateStatus);
      });
      $$('[data-delete-template]').forEach((btn) => {
        btn.onclick = () => deleteCommunityTemplate(btn.dataset.deleteTemplate);
      });
      $$('[data-panel-starter]').forEach((btn) => {
        btn.onclick = () => newProject(starterPresets[+btn.dataset.panelStarter]);
      });
    }

    function renderTemplatesPanelView() {
      const categories = ['all', ...VALID_CATEGORIES];
      $('#panelContent').innerHTML = `
        <div class="action-row" style="margin-bottom:10px">
          <button type="button" class="primary-button" id="uploadTemplateBtn" style="flex:1">＋ Upload current site</button>
          <button type="button" class="soft-button" id="refreshTemplatesBtn" title="Refresh library" aria-label="Refresh templates">↻</button>
        </div>
        <input class="search-input" id="templateSearchInput" type="search" placeholder="Search community templates..." value="${escapeHtml(templateSearchQuery)}" aria-label="Search community templates" />
        <select class="select-control" id="templateCategorySelect" style="margin-top:8px" aria-label="Filter template category">
          ${categories.map((cat) => `<option value="${cat}" ${templateCategoryFilter === cat ? 'selected' : ''}>${cat === 'all' ? 'All categories' : cat.charAt(0).toUpperCase() + cat.slice(1)}</option>`).join('')}
        </select>
        ${templatesError ? `<div class="status-banner warning" style="margin-top:10px">${escapeHtml(templatesError)}</div>` : ''}
        ${templatesLoading ? '<p class="muted-copy" style="margin-top:12px">Loading templates…</p>' : ''}
        <div id="templatesListContainer" style="margin-top:10px">${templatesListMarkup()}</div>
        <div class="hint-card" style="margin-top:12px">Imported community templates are sanitized automatically. Untrusted JavaScript is never executed in the editor.</div>
      `;

      $('#uploadTemplateBtn').onclick = openUploadTemplateModal;
      $('#refreshTemplatesBtn').onclick = loadCommunityTemplates;
      $('#templateSearchInput').oninput = (e) => {
        templateSearchQuery = e.target.value;
        const container = $('#templatesListContainer');
        if (container) {
          container.innerHTML = templatesListMarkup();
          bindTemplatesListEvents();
        }
      };
      $('#templateCategorySelect').onchange = (e) => {
        templateCategoryFilter = e.target.value;
        const container = $('#templatesListContainer');
        if (container) {
          container.innerHTML = templatesListMarkup();
          bindTemplatesListEvents();
        }
      };
      bindTemplatesListEvents();
    }

    function openUploadTemplateModal() {
      if (!currentUser) {
        return openAuthModal('signin', 'Sign in to publish a template to the community library.', 'warning');
      }
      if (!project.nodes.length) {
        return notify('Add at least one element to your canvas before uploading a template.');
      }

      openModal('Upload template', 'COMMUNITY LIBRARY', `
        <form id="uploadTemplateForm" class="form-stack">
          <div id="uploadTemplateBanner"></div>
          <div>
            <label class="field-title" for="tplTitle">Template name</label>
            <input class="control" id="tplTitle" required minlength="2" maxlength="100" value="${escapeHtml(project.name)}" />
          </div>
          <div>
            <label class="field-title" for="tplDesc">Description</label>
            <textarea class="control" id="tplDesc" rows="3" maxlength="500" placeholder="Describe the layout and intended use..."></textarea>
          </div>
          <div class="field-row">
            <div>
              <label class="field-title" for="tplCategory">Category</label>
              <select class="select-control" id="tplCategory">
                ${VALID_CATEGORIES.map((c) => `<option value="${c}">${c.charAt(0).toUpperCase() + c.slice(1)}</option>`).join('')}
              </select>
            </div>
            <div>
              <label class="field-title" for="tplStatus">Visibility</label>
              <select class="select-control" id="tplStatus">
                <option value="published">Published (Public)</option>
                <option value="hidden">Hidden (Private draft)</option>
              </select>
            </div>
          </div>
          <p class="muted-copy">Scripts and event handlers are stripped from uploaded templates to protect community users. Platform credentials are never included.</p>
          <button type="submit" class="primary-button" id="publishTemplateBtn">Upload template</button>
        </form>
      `);

      $('#uploadTemplateForm').onsubmit = async (event) => {
        event.preventDefault();
        const title = ($('#tplTitle').value || '').trim();
        const description = ($('#tplDesc').value || '').trim();
        const category = $('#tplCategory').value;
        const status = $('#tplStatus').value;
        if (title.length < 2) {
          $('#uploadTemplateBanner').className = 'status-banner error';
          $('#uploadTemplateBanner').textContent = 'Template name must be at least 2 characters.';
          return;
        }
        if (!VALID_CATEGORIES.includes(category)) return;

        const btn = $('#publishTemplateBtn');
        btn.disabled = true;
        try {
          const templateId = 'tpl_' + uid();
          const storagePath = `templates/${currentUser.uid}/${templateId}.json`;
          const sanitizedNodes = sanitizeTemplateNodes(project.nodes, uid);
          const payload = {
            schemaVersion: 2,
            title: title.slice(0, 100),
            description: description.slice(0, 500),
            category,
            page: project.page || { background: '#ffffff' },
            nodes: sanitizedNodes,
            customCss: sanitizeCssText(project.customCss || ''),
            // Never upload arbitrary JS or platform credentials in community templates
            customJs: '',
            behaviors: (project.behaviors || []).filter((b) => SAFE_BEHAVIOR_ACTIONS.has(b.action)),
          };

          await uploadString(storageRef(storage, storagePath), JSON.stringify(payload), 'raw', {
            contentType: 'application/json',
          });

          const authorName = String(currentProfile?.displayName || currentUser.displayName || 'Creator').slice(0, 80);
          await setDoc(doc(db, 'templates', templateId), {
            authorId: currentUser.uid,
            authorName,
            title: title.slice(0, 100),
            description: description.slice(0, 500),
            category,
            version: 1,
            createdAt: serverTimestamp(),
            updatedAt: serverTimestamp(),
            storagePath,
            status: status === 'hidden' ? 'hidden' : 'published',
            nodeCount: countProjectNodes(sanitizedNodes),
          });

          closeModal();
          notify('Template uploaded to community library');
          await loadCommunityTemplates();
        } catch (err) {
          $('#uploadTemplateBanner').className = 'status-banner error';
          $('#uploadTemplateBanner').textContent = err?.message || 'Could not upload template.';
        } finally {
          if (btn) btn.disabled = false;
        }
      };
    }

    async function importCommunityTemplate(templateId) {
      const meta = communityTemplates.find((t) => t.id === templateId);
      if (!meta) return;
      try {
        notify('Importing template safely...');
        const raw = await fetchStorageJson(meta.storagePath);
        const { project: imported, strippedScripts } = sanitizeImportedTemplateProject(raw, meta.title, uid);
        projects.unshift(imported);
        project = imported;
        history = [];
        future = [];
        selectedId = null;
        saveProjects();
        renderAll({ skipSave: true });
        notify(strippedScripts
          ? 'Template imported safely (untrusted scripts stripped)'
          : 'Template imported safely');
      } catch (err) {
        notify('Could not import template: ' + (err?.message || 'Error'));
      }
    }

    async function toggleTemplateVisibility(templateId) {
      if (!currentUser || !db) return;
      const meta = communityTemplates.find((t) => t.id === templateId);
      if (!meta || meta.authorId !== currentUser.uid) return notify('Unauthorized');
      const nextStatus = meta.status === 'published' ? 'hidden' : 'published';
      try {
        await updateDoc(doc(db, 'templates', templateId), {
          status: nextStatus,
          updatedAt: serverTimestamp(),
        });
        notify(`Template is now ${nextStatus}`);
        await loadCommunityTemplates();
      } catch (err) {
        notify('Could not update template: ' + (err?.message || 'Error'));
      }
    }

    async function deleteCommunityTemplate(templateId) {
      if (!currentUser || !db || !storage) return;
      const meta = communityTemplates.find((t) => t.id === templateId);
      if (!meta || meta.authorId !== currentUser.uid) return notify('Unauthorized');
      try {
        await deleteDoc(doc(db, 'templates', templateId));
        if (meta.storagePath) {
          deleteObject(storageRef(storage, meta.storagePath)).catch(() => {});
        }
        notify('Template deleted');
        await loadCommunityTemplates();
      } catch (err) {
        notify('Delete failed: ' + (err?.message || 'Error'));
      }
    }

    function openReportTemplateModal(templateId) {
      if (!currentUser) {
        return openAuthModal('signin', 'Sign in to report a template.', 'warning');
      }
      const meta = communityTemplates.find((t) => t.id === templateId);
      openModal('Report template', 'MODERATION', `
        <form id="reportForm" class="form-stack">
          <p class="muted-copy">Reporting: <strong>${escapeHtml(meta?.title || templateId)}</strong></p>
          <div>
            <label class="field-title" for="reportReason">Reason</label>
            <select class="select-control" id="reportReason">
              <option value="malicious-script">Malicious script or unsafe code</option>
              <option value="inappropriate">Inappropriate or abusive content</option>
              <option value="spam">Spam or misleading</option>
              <option value="copyright">Copyright violation</option>
              <option value="other">Other</option>
            </select>
          </div>
          <div>
            <label class="field-title" for="reportDetails">Details (optional)</label>
            <textarea class="control" id="reportDetails" rows="3" maxlength="500" placeholder="Describe the issue..."></textarea>
          </div>
          <button type="submit" class="danger-button" id="submitReportBtn">Submit report</button>
        </form>
      `);

      $('#reportForm').onsubmit = async (event) => {
        event.preventDefault();
        const reason = $('#reportReason').value;
        const details = ($('#reportDetails').value || '').trim().slice(0, 500);
        if (!VALID_REPORT_REASONS.includes(reason)) return;
        const btn = $('#submitReportBtn');
        btn.disabled = true;
        try {
          const reportId = 'rep_' + uid();
          await setDoc(doc(db, 'templateReports', reportId), {
            templateId,
            reporterId: currentUser.uid,
            reason,
            details,
            createdAt: serverTimestamp(),
          });
          closeModal();
          notify('Report submitted. Thank you for keeping templates safe.');
        } catch (err) {
          notify('Could not submit report: ' + (err?.message || 'Error'));
        } finally {
          if (btn) btn.disabled = false;
        }
      };
    }

    // ------------------------------------------------------------------------
    // Preserved Core Editor Logic
    // ------------------------------------------------------------------------
    function clone(value) {
      return JSON.parse(JSON.stringify(value));
    }

    function escapeHtml(value) {
      return String(value ?? '').replace(/[&<>"']/g, (ch) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
      }[ch]));
    }

    function notify(message) {
      const el = $('#toast');
      el.textContent = message;
      el.classList.add('show');
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => el.classList.remove('show'), 2400);
    }

    function remember() {
      history.push(JSON.stringify(project));
      if (history.length > 60) history.shift();
      future = [];
      saveProjects();
    }

    function restore(raw) {
      project = normalizeProject(JSON.parse(raw));
      projects = projects.map((item) => (item.id === project.id ? project : item));
      selectedId = null;
      renderAll();
    }

    function undo() {
      if (!history.length) return notify('Nothing to undo');
      future.push(JSON.stringify(project));
      restore(history.pop());
      notify('Undo');
    }

    function redo() {
      if (!future.length) return notify('Nothing to redo');
      history.push(JSON.stringify(project));
      restore(future.pop());
      notify('Redo');
    }

    function findNode(id, nodes = project.nodes, parent = null) {
      for (let i = 0; i < nodes.length; i++) {
        if (nodes[i].id === id) return { node: nodes[i], list: nodes, index: i, parent };
        const found = findNode(id, nodes[i].children || [], nodes[i]);
        if (found) return found;
      }
      return null;
    }

    function allNodes(nodes = project.nodes, result = []) {
      nodes.forEach((node) => {
        result.push(node);
        allNodes(node.children || [], result);
      });
      return result;
    }

    function nodeLabel(node) {
      return (node.text || node.attrs?.alt || node.attrs?.placeholder || node.tag).replace(/\s+/g, ' ').trim().slice(0, 32) || node.tag;
    }

    function attrsFor(node) {
      const attrs = { ...(node.attrs || {}) };
      if (node.hidden) attrs.hidden = true;
      if (node.locked) attrs['data-builder-locked'] = 'true';
      if (node.id) attrs['data-node-id'] = node.id;
      return attrs;
    }

    function renderNode(node) {
      const rawTag = String(node.tag || 'div').toLowerCase();
      const tag = /^[a-z][a-z0-9-]*$/i.test(rawTag) && !BLOCKED_TAGS.has(rawTag) ? rawTag : 'div';
      const attrs = attrsFor(node);
      let attrText = Object.entries(attrs)
        .filter(([key, val]) => /^[a-zA-Z_:][\w:.-]*$/.test(key) && !/^on/i.test(key) && val !== false && val != null)
        .map(([key, val]) => {
          const cleanVal = ['href', 'src', 'action', 'formaction'].includes(key.toLowerCase())
            ? sanitizeUrl(val, { allowDataImage: true })
            : val;
          return ` ${key}="${escapeHtml(cleanVal === true ? '' : cleanVal)}"`;
        })
        .join('');
      if (node.id) attrText += ` data-builder-id="${escapeHtml(node.id)}"`;
      const voidTags = ['img', 'hr', 'input', 'br', 'meta', 'link', 'source', 'area', 'base', 'col', 'embed', 'param', 'track', 'wbr'];
      if (voidTags.includes(tag)) return `<${tag}${attrText}>`;
      return `<${tag}${attrText}>${escapeHtml(node.text || '')}${(node.children || []).map(renderNode).join('')}</${tag}>`;
    }

    function gradientStopsMarkup(node) {
      const stops = node.gradient?.stops || [{ color: '#8061ed', position: 0 }, { color: '#5ec8d4', position: 100 }];
      return stops.map((stop, index) => `
        <div class="field-row" data-stop-index="${index}" style="margin:6px 0">
          <input class="control" type="color" data-stop-color value="${validColor(stop.color, '#8061ed')}" aria-label="Stop ${index + 1} color">
          <input class="control" type="number" min="0" max="100" data-stop-position value="${stop.position}" aria-label="Stop ${index + 1} position percent">
          <input type="range" min="0" max="100" value="${stop.position}" data-stop-position-range aria-label="Move stop ${index + 1}">
          <input class="control" type="number" min="0" max="100" data-stop-opacity value="${stop.opacity ?? 100}" aria-label="Stop ${index + 1} opacity percent">
          <button class="soft-button" type="button" data-remove-stop="${index}" ${stops.length <= 2 ? 'disabled' : ''}>×</button>
        </div>
      `).join('');
    }

    function gradientCss(gradient) {
      if (!gradient) return '';
      const stops = gradient.stops || [];
      if (stops.length < 2) return '';
      const list = stops.map((stop) => {
        let color = stop.color || '#8061ed';
        if (stop.opacity != null && +stop.opacity < 100 && /^#[0-9a-f]{6}$/i.test(color)) {
          const channels = color.match(/[0-9a-f]{2}/gi).map((part) => parseInt(part, 16));
          color = `rgba(${channels.join(', ')}, ${Math.max(0, Math.min(100, +stop.opacity)) / 100})`;
        }
        return `${color} ${Math.max(0, Math.min(100, +stop.position || 0))}%`;
      }).join(', ');
      const angle = +gradient.angle || 0;
      const position = gradient.position || 'center';
      if (gradient.type === 'radial') return `radial-gradient(circle at ${position}, ${list})`;
      if (gradient.type === 'conic') return `conic-gradient(from ${angle}deg at ${position}, ${list})`;
      return `linear-gradient(${angle}deg, ${list})`;
    }

    function effectiveStyles(node) {
      const styles = { ...(node.styles || {}) };
      const gradient = gradientCss(node.gradient);
      if (gradient) styles.backgroundImage = gradient;
      const transform = node.editorTransform;
      if (transform) {
        const parts = [];
        if (+transform.x) parts.push(`translateX(${transform.x}px)`);
        if (+transform.y) parts.push(`translateY(${transform.y}px)`);
        if (+(transform.scaleX ?? 1) !== 1 || +(transform.scaleY ?? 1) !== 1) parts.push(`scale(${transform.scaleX ?? 1}, ${transform.scaleY ?? 1})`);
        if (+transform.rotate) parts.push(`rotate(${transform.rotate}deg)`);
        if (+transform.skewX) parts.push(`skewX(${transform.skewX}deg)`);
        if (+transform.skewY) parts.push(`skewY(${transform.skewY}deg)`);
        if (parts.length) styles.transform = parts.join(' ');
        if (transform.origin) styles.transformOrigin = transform.origin;
      }
      const transition = node.editorTransition;
      if (transition) {
        styles.transition = `${transition.property || 'all'} ${transition.duration ?? 300}ms ${transition.timing || 'ease'} ${transition.delay ?? 0}ms`;
      }
      return styles;
    }

    function cssDeclarations(styles) {
      return Object.entries(styles || {})
        .filter(([key, value]) => /^[a-zA-Z][\w-]*$/.test(key) && value !== '' && value != null)
        .map(([key, value]) => `  ${key.replace(/[A-Z]/g, (m) => '-' + m.toLowerCase())}: ${value};`)
        .join('\n');
    }

    function styleRules(nodes = project.nodes) {
      let rules = '';
      nodes.forEach((node) => {
        const selector = `[data-node-id="${node.id}"]`;
        const declarations = cssDeclarations(effectiveStyles(node));
        if (node.id && declarations) rules += `${selector} {\n${declarations}\n}\n`;
        ['hover', 'focus', 'active'].forEach((state) => {
          const stateRules = cssDeclarations(node.states?.[state]);
          if (node.id && stateRules) rules += `${selector}:${state} {\n${stateRules}\n}\n`;
        });
        rules += styleRules(node.children || []);
      });
      return rules;
    }

    function animationCss(nodes = project.nodes) {
      let rules = '@keyframes studio-scroll-fade{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:translateY(0)}}\n.studio-scroll-fade{animation:studio-scroll-fade 700ms ease both}\n';
      nodes.forEach((node) => {
        const animation = node.animation;
        if (animation?.name && node.id) {
          const name = /^(fade|fade-out|slide|slide-out|scale|scale-out|rotate|bounce|pulse|shake)$/.test(animation.name) ? animation.name : 'fade';
          const definitions = {
            fade: 'from{opacity:0}to{opacity:1}',
            'fade-out': 'from{opacity:1}to{opacity:0}',
            slide: 'from{opacity:0;transform:translateY(24px)}to{opacity:1;transform:translateY(0)}',
            'slide-out': 'from{opacity:1;transform:translateY(0)}to{opacity:0;transform:translateY(24px)}',
            scale: 'from{opacity:0;transform:scale(.75)}to{opacity:1;transform:scale(1)}',
            'scale-out': 'from{opacity:1;transform:scale(1)}to{opacity:0;transform:scale(.75)}',
            rotate: 'from{transform:rotate(-12deg)}to{transform:rotate(0)}',
            bounce: '0%,100%{transform:translateY(0)}50%{transform:translateY(-14px)}',
            pulse: '0%,100%{transform:scale(1)}50%{transform:scale(1.06)}',
            shake: '0%,100%{transform:translateX(0)}25%{transform:translateX(-6px)}75%{transform:translateX(6px)}',
          };
          rules += `@keyframes studio-${name}{${definitions[name] || definitions.fade}}\n[data-node-id="${node.id}"]{animation:studio-${name} ${+animation.duration || 700}ms ${animation.timing || 'ease'} ${+animation.delay || 0}ms ${animation.iteration || 1} ${animation.direction || 'normal'} ${animation.fill || 'both'};}\n`;
        }
        rules += animationCss(node.children || []);
      });
      return rules;
    }

    function responsiveCss(nodes = project.nodes) {
      let rules = '';
      nodes.forEach((node) => {
        ['tablet', 'mobile'].forEach((device, index) => {
          const styles = node.responsive?.[device]?.styles || {};
          const declarations = cssDeclarations(styles);
          if (node.id && declarations) rules += `@media (max-width:${index === 0 ? 950 : 650}px){[data-node-id="${node.id}"]{\n${declarations}\n}}\n`;
        });
        rules += responsiveCss(node.children || []);
      });
      return rules;
    }

    function generatedBaseCss() {
      return '* { box-sizing: border-box; }\n[hidden] { display: none !important; }\nbody { margin: 0; font-family: Arial, sans-serif; background: ' + (project.page.background || '#ffffff') + '; }\nimg { max-width: 100%; }\n';
    }

    function generatedCss() {
      return generatedBaseCss() + styleRules() + '\n' + responsiveCss() + animationCss() + '\n' + (project.customCss || '');
    }

    function responsiveCanvasCss() {
      const device = previewWidth <= 400 ? 'mobile' : previewWidth <= 800 ? 'tablet' : null;
      if (!device) return '';
      let rules = '';
      const walk = (nodes) => nodes.forEach((node) => {
        const declarations = cssDeclarations(node.responsive?.[device]?.styles || {});
        if (node.id && declarations) rules += `[data-node-id="${node.id}"]{${declarations}}\n`;
        walk(node.children || []);
      });
      walk(project.nodes);
      return rules;
    }

    function scopeCanvasCss(source) {
      return source.replace(/(^|})\s*([^@{}][^{}]*)\{([^{}]*)\}/g, (match, boundary, selector, body) => {
        const scoped = selector.split(',').map((item) => {
          const clean = item.trim();
          if (/^body\b/.test(clean)) return clean.replace(/^body\b/, '.page-canvas');
          if (/^html\b/.test(clean)) return clean.replace(/^html\b/, '.page-canvas');
          return clean.startsWith('.page-canvas') ? clean : `.page-canvas ${clean}`;
        }).join(', ');
        return `${boundary}${scoped} {${body}}`;
      });
    }

    function parseCssIntoModel(source) {
      const nodeIds = new Set(allNodes().map((node) => node.id));
      allNodes().forEach((node) => {
        node.styles = {};
        node.states = {};
        delete node.editorTransform;
        delete node.editorTransition;
        delete node.gradient;
        node.responsive = {};
      });
      const rulePattern = /([^{}]+)\{([^{}]*)\}/g;
      const mediaPattern = /@media\s*\(max-width\s*:\s*(\d+)px\)\s*\{\s*([^{}]+)\{([^{}]*)\}\s*\}/g;
      const normalizedSource = source.replace(mediaPattern, (whole, width, selector, body) => {
        const idMatch = selector.match(/\[data-node-id\s*=\s*["']?([\w-]+)["']?\s*\]/);
        if (!idMatch || !nodeIds.has(idMatch[1])) return whole;
        const node = findNode(idMatch[1]).node;
        const device = +width <= 650 ? 'mobile' : 'tablet';
        node.responsive[device] = node.responsive[device] || { styles: {} };
        for (const declaration of body.split(';')) {
          const colon = declaration.indexOf(':');
          if (colon < 1) continue;
          const key = declaration.slice(0, colon).trim().replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
          const value = declaration.slice(colon + 1).trim();
          if (key && value) node.responsive[device].styles[key] = value;
        }
        return '';
      });
      for (const match of normalizedSource.matchAll(rulePattern)) {
        const selector = match[1].trim();
        const idMatch = selector.match(/\[data-node-id\s*=\s*["']?([\w-]+)["']?\s*\]/);
        if (!idMatch || !nodeIds.has(idMatch[1])) continue;
        const node = findNode(idMatch[1]).node;
        const stateMatch = selector.match(/:(hover|focus|active)\s*$/);
        const target = stateMatch ? (node.states[stateMatch[1]] = node.states[stateMatch[1]] || {}) : node.styles;
        for (const declaration of match[2].split(';')) {
          const colon = declaration.indexOf(':');
          if (colon < 1) continue;
          const key = declaration.slice(0, colon).trim().replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
          const value = declaration.slice(colon + 1).trim();
          if (key && value) target[key] = value;
        }
      }
      let custom = normalizedSource.replace(generatedBaseCss(), '');
      custom = custom.replace(rulePattern, (rule, selector) => (/\[data-node-id\s*=\s*["']?[\w-]+["']?\s*\]/.test(selector) && [...nodeIds].some((id) => selector.includes(id)) ? '' : rule));
      return custom.trim();
    }

    function generatedHtml() {
      // Strictly isolated from Studio platform Firebase config or account data
      return `<!DOCTYPE html>\n<html lang="en">\n<head>\n  <meta charset="UTF-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n  <title>${escapeHtml(project.name)}</title>\n  <link rel="stylesheet" href="style.css">\n</head>\n<body>\n${project.nodes.map(renderNode).join('\n')}\n  <script src="script.js"><\/script>\n</body>\n</html>`;
    }

    function generatedJs() {
      const behaviorCode = (project.behaviors || []).map((behavior) => {
        const sourceId = String(behavior.source || '');
        const targetId = String(behavior.target || '');
        if (!/^[\w-]+$/.test(sourceId)) return '';
        const sourceSelector = JSON.stringify(`[data-node-id="${sourceId}"]`);
        const targetSelector = JSON.stringify(`[data-node-id="${/^[\w-]+$/.test(targetId) ? targetId : ''}"]`);
        let action = '';
        if (behavior.action === 'alert') action = `alert(${JSON.stringify(behavior.value || 'Hello!')});`;
        if (behavior.action === 'text') action = `if(target) target.textContent = ${JSON.stringify(behavior.value || 'Updated text')};`;
        if (behavior.action === 'hide') action = `if(target) target.hidden = true;`;
        if (behavior.action === 'toggle') action = `if(target) target.hidden = !target.hidden;`;
        if (behavior.action === 'background') action = `if(target) target.style.backgroundColor = ${JSON.stringify(behavior.value || '#f0eaff')};`;
        if (behavior.action === 'show') action = `if(target) { target.hidden = false; target.style.display = ''; }`;
        if (behavior.action === 'open-modal') action = `if(target) { target.hidden = false; target.setAttribute('aria-hidden', 'false'); }`;
        if (behavior.action === 'close-modal') action = `if(target) { target.hidden = true; target.setAttribute('aria-hidden', 'true'); }`;
        if (behavior.action === 'scroll') action = `if(target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });`;
        if (behavior.action === 'tab') action = `if(target) { const group = target.parentElement; if(group) group.querySelectorAll('[data-node-id]').forEach(item => item.hidden = item !== target); target.hidden = false; }`;
        if (behavior.action === 'scroll-animation') {
          return `(()=>{const target=document.querySelector(${targetSelector});if(!target||!('IntersectionObserver' in window))return;const observer=new IntersectionObserver(entries=>entries.forEach(entry=>{if(entry.isIntersecting){entry.target.classList.add('studio-scroll-fade');observer.unobserve(entry.target)}}));observer.observe(target)})();`;
        }
        return `document.addEventListener(${JSON.stringify(behavior.trigger || 'click')}, function(event) {\n  if (event.target.closest(${sourceSelector})) { const target = document.querySelector(${targetSelector}); ${action} }\n});`;
      }).join('\n');

      // Clean architectural separation hook for future user-website backend connectors
      const connector = project.backendIntegration;
      let connectorStub = '';
      if (connector && connector.provider && connector.provider !== 'none') {
        connectorStub = `\n// User-website backend target (${connector.provider}) — configure your own credentials separately\nwindow.__SITE_BACKEND_CONFIG__ = ${JSON.stringify({ provider: connector.provider, endpoint: connector.endpoint || '' })};\n`;
      }

      return `${behaviorCode}${behaviorCode && project.customJs ? '\n' : ''}${project.customJs || ''}${connectorStub}`;
    }

    function renderCanvas() {
      const canvas = $('#pageCanvas');
      canvas.innerHTML = project.nodes.map((node) => renderNode(node)).join('');
      const canvasStyle = document.createElement('style');
      canvasStyle.textContent = styleRules() + responsiveCanvasCss() + animationCss() + (project.customCss ? '\n' + scopeCanvasCss(project.customCss) : '');
      canvas.append(canvasStyle);
      canvas.style.background = project.page.background || '#fff';
      canvas.classList.toggle('empty', !project.nodes.length);
      canvas.classList.toggle('previewing', previewMode);
      canvas.querySelectorAll('[data-node-id]').forEach((el) => {
        const id = el.dataset.nodeId;
        const modelNode = findNode(id)?.node;
        el.dataset.builderLabel = (modelNode?.tag || 'element').toUpperCase();
        if (id === selectedId && !previewMode) el.classList.add('builder-selected');
        el.addEventListener('click', (event) => {
          if (previewMode) return;
          event.preventDefault();
          event.stopPropagation();
          if (modelNode?.locked) return notify('This layer is locked. Unlock it from Layers first.');
          selectNode(id, 'styles');
        });
        el.draggable = !previewMode && !modelNode?.locked;
        el.addEventListener('dragstart', (event) => {
          dragId = id;
          event.dataTransfer.effectAllowed = 'move';
        });
        el.addEventListener('dragover', (event) => {
          if (dragId && dragId !== id) {
            event.preventDefault();
            event.dataTransfer.dropEffect = 'move';
          }
        });
        el.addEventListener('drop', (event) => {
          event.preventDefault();
          event.stopPropagation();
          moveNode(dragId, id);
        });
        el.addEventListener('dragend', () => { dragId = null; });
      });
      canvas.onclick = (event) => {
        if (event.target === canvas) {
          selectedId = null;
          renderAll();
        }
      };
    }

    function renderElements() {
      let html = '';
      tags.forEach(([heading, items]) => {
        html += `<p class="section-label">${heading}</p><div class="element-grid">${items.map(([tag, label, icon]) => `<button class="element-button" data-add="${tag}"><span class="element-icon">${icon}</span>${label}</button>`).join('')}</div>`;
      });
      html += '<div class="hint-card">Tap an element to add it to the page. Select it on the canvas to edit its content and appearance.</div>';
      $('#panelContent').innerHTML = html;
      $$('[data-add]').forEach((button) => { button.onclick = () => addNode(button.dataset.add); });
    }

    function renderLayers() {
      if (!project.nodes.length) {
        $('#panelContent').innerHTML = '<p class="empty-layers">Your layers will appear here as you build.</p>';
        return;
      }
      $('#panelContent').innerHTML = `<div class="section-label">PAGE STRUCTURE · ${allNodes().length} LAYERS</div><div class="layers-list">${project.nodes.map((node) => layerMarkup(node, 0)).join('')}</div><div class="hint-card" style="margin-top:14px">Drag a layer onto another to nest it, or before another layer to reorder.</div>`;
      $$('[data-layer]').forEach((row) => {
        row.onclick = (event) => {
          if (event.target.closest('.layer-actions')) return;
          selectNode(row.dataset.layer, 'styles');
        };
        row.ondragstart = (event) => {
          dragId = row.dataset.layer;
          event.dataTransfer.effectAllowed = 'move';
        };
        row.ondragover = (event) => {
          if (dragId && dragId !== row.dataset.layer) event.preventDefault();
        };
        row.ondrop = (event) => {
          event.preventDefault();
          moveNode(dragId, row.dataset.layer);
        };
        row.ondragend = () => { dragId = null; };
      });
      $$('[data-delete-layer]').forEach((button) => {
        button.onclick = (event) => {
          event.stopPropagation();
          deleteNode(button.dataset.deleteLayer);
        };
      });
      $$('[data-duplicate-layer]').forEach((button) => {
        button.onclick = (event) => {
          event.stopPropagation();
          duplicateNode(button.dataset.duplicateLayer);
        };
      });
      $$('[data-toggle-visibility]').forEach((button) => {
        button.onclick = (event) => {
          event.stopPropagation();
          const node = findNode(button.dataset.toggleVisibility)?.node;
          if (node) {
            remember();
            node.hidden = !node.hidden;
            renderAll();
          }
        };
      });
      $$('[data-toggle-lock]').forEach((button) => {
        button.onclick = (event) => {
          event.stopPropagation();
          const node = findNode(button.dataset.toggleLock)?.node;
          if (node) {
            remember();
            node.locked = !node.locked;
            renderAll();
          }
        };
      });
    }

    function layerMarkup(node, depth) {
      const selected = node.id === selectedId ? 'selected' : '';
      return `<div class="layer-row ${selected}" draggable="true" data-layer="${node.id}" style="padding-left:${8 + depth * 14}px"><span class="layer-tag">${escapeHtml(node.tag)}</span><span class="layer-text">${escapeHtml(nodeLabel(node))}</span><span class="layer-actions"><button title="${node.hidden ? 'Show' : 'Hide'}" aria-label="${node.hidden ? 'Show' : 'Hide'} ${escapeHtml(node.tag)}" data-toggle-visibility="${node.id}">${node.hidden ? '🙈' : '👁'}</button><button title="${node.locked ? 'Unlock' : 'Lock'}" aria-label="${node.locked ? 'Unlock' : 'Lock'} ${escapeHtml(node.tag)}" data-toggle-lock="${node.id}">${node.locked ? '🔒' : '⌑'}</button><button title="Duplicate" aria-label="Duplicate ${escapeHtml(node.tag)}" data-duplicate-layer="${node.id}">⧉</button><button title="Delete" aria-label="Delete ${escapeHtml(node.tag)}" data-delete-layer="${node.id}">×</button></span></div>${(node.children || []).map((child) => layerMarkup(child, depth + 1)).join('')}`;
    }

    function setStyle(node, key, value) {
      remember();
      node.styles = node.styles || {};
      if (value === '') delete node.styles[key];
      else node.styles[key] = value;
      renderAll();
    }

    function renderInspector() {
      const found = selectedId && findNode(selectedId);
      if (!found) {
        $('#inspectorTitle').textContent = 'Page settings';
        const bi = project.backendIntegration || { provider: 'none', endpoint: '', notes: '' };
        $('#inspectorContent').innerHTML = `
          <div class="inspector-section">
            <h3 class="section-head">Page background</h3>
            <label class="field-title">Canvas color</label>
            <input type="color" class="control" id="pageBackground" value="${escapeHtml(project.page.background || '#ffffff')}">
          </div>
          <div class="inspector-section">
            <h3 class="section-head">Quick start</h3>
            <p class="muted-copy">Add an element from the Elements panel, then select it on the canvas or in Layers to edit its properties.</p>
            <button class="soft-button" id="openElements">＋ Add an element</button>
          </div>
          <div class="inspector-section">
            <h3 class="section-head">Exported site backend (isolated)</h3>
            <label class="field-title" for="siteBackendProvider">Future connector for generated site</label>
            <select class="select-control" id="siteBackendProvider">
              <option value="none" ${bi.provider === 'none' ? 'selected' : ''}>None (Static HTML/CSS/JS)</option>
              <option value="firebase" ${bi.provider === 'firebase' ? 'selected' : ''}>Own Firebase project (Planned)</option>
              <option value="supabase" ${bi.provider === 'supabase' ? 'selected' : ''}>Supabase (Planned)</option>
              <option value="rest" ${bi.provider === 'rest' ? 'selected' : ''}>Custom REST API (Planned)</option>
              <option value="custom" ${bi.provider === 'custom' ? 'selected' : ''}>Custom backend server (Planned)</option>
            </select>
            <label class="field-title" for="siteBackendEndpoint" style="margin-top:8px">Optional public API endpoint</label>
            <input class="control" id="siteBackendEndpoint" value="${escapeHtml(bi.endpoint || '')}" placeholder="https://api.yoursite.com" />
            <p class="muted-copy" style="margin-top:6px">Separated from Studio's platform Firebase.</p>
          </div>
        `;
        $('#pageBackground').oninput = (event) => {
          remember();
          project.page.background = event.target.value;
          renderCanvas();
        };
        $('#openElements').onclick = () => setPanel('elements');
        $('#siteBackendProvider').onchange = (event) => {
          remember();
          project.backendIntegration = { ...(project.backendIntegration || {}), provider: event.target.value };
          saveProjects();
          updateCode();
          notify('Site backend target updated');
        };
        $('#siteBackendEndpoint').onchange = (event) => {
          remember();
          project.backendIntegration = { ...(project.backendIntegration || {}), endpoint: event.target.value.trim() };
          saveProjects();
          updateCode();
        };
        return;
      }

      const node = found.node;
      const style = node.styles || {};
      const tag = node.tag;
      $('#inspectorTitle').textContent = `${tag.toUpperCase()} properties`;
      const titleControl = ['img', 'video', 'hr', 'input'].includes(tag)
        ? `<label class="field-title">${tag === 'img' ? 'Image URL' : tag === 'video' ? 'Video URL' : tag === 'input' ? 'Placeholder' : 'Content'}</label><input class="control" id="nodeText" value="${escapeHtml(['img', 'video'].includes(tag) ? node.attrs?.src || '' : node.attrs?.placeholder || node.text || '')}" placeholder="${['img', 'video'].includes(tag) ? 'https://...' : 'Enter text'}">`
        : `<label class="field-title">Text content</label><textarea class="control" id="nodeText" rows="3" placeholder="Write something...">${escapeHtml(node.text || '')}</textarea>`;
      const childrenOptions = allNodes().filter((item) => item.id !== node.id).map((item) => `<option value="${item.id}">${escapeHtml(item.tag.toUpperCase() + ' · ' + nodeLabel(item))}</option>`).join('');

      $('#inspectorContent').innerHTML = `
        <div class="inspector-section">
          <h3 class="section-head">Content</h3>
          ${titleControl}
          ${['a', 'button'].includes(tag) ? '<label class="field-title" style="margin-top:10px">Link destination</label><input class="control" id="nodeHref" placeholder="https://example.com" value="' + escapeHtml(node.attrs?.href || '') + '">' : ''}
          ${tag === 'img' ? '<label class="field-title" style="margin-top:10px">Alt text</label><input class="control" id="nodeAlt" value="' + escapeHtml(node.attrs?.alt || '') + '" placeholder="Describe this image">' : ''}
          <div class="action-row" style="margin-top:11px"><button class="soft-button" id="duplicateSelected">⧉ Duplicate</button><button class="danger-button" id="deleteSelected">Delete</button></div>
        </div>
        <div class="inspector-section">
          <h3 class="section-head">Typography</h3>
          <label class="field-title">Font size</label>
          <div class="range-row"><input type="range" id="fontSize" min="10" max="80" value="${parseInt(style.fontSize, 10) || 16}"><span class="range-value" id="fontSizeValue">${style.fontSize || '16px'}</span></div>
          <div class="field-row" style="margin-top:10px">
            <div><label class="field-title">Text color</label><input class="control" type="color" id="textColor" value="${validColor(style.color, '#222222')}"></div>
            <div><label class="field-title">Alignment</label><select class="select-control" id="textAlign"><option ${style.textAlign === 'left' ? 'selected' : ''}>left</option><option ${style.textAlign === 'center' ? 'selected' : ''}>center</option><option ${style.textAlign === 'right' ? 'selected' : ''}>right</option></select></div>
          </div>
          <label class="field-title" style="margin-top:10px">Font family</label>
          <select class="select-control" id="fontFamily"><option value="Arial, sans-serif">Arial</option><option value="Georgia, serif">Georgia</option><option value="'Trebuchet MS', sans-serif">Trebuchet</option><option value="'Courier New', monospace">Monospace</option><option value="Verdana, sans-serif">Verdana</option><option value="Tahoma, sans-serif">Tahoma</option><option value="'Times New Roman', serif">Times New Roman</option><option value="'Lucida Console', monospace">Lucida Console</option><option value="custom">Custom…</option></select>
          <label class="field-title" style="margin-top:9px">Custom font family</label>
          <input class="control" id="customFontFamily" value="${escapeHtml(style.fontFamily || '')}" placeholder="Example: Inter, sans-serif">
          <div class="field-row" style="margin-top:9px">
            <div><label class="field-title">Weight</label><select class="select-control" id="fontWeight"><option>300</option><option>400</option><option>500</option><option>600</option><option>700</option><option>800</option></select></div>
            <div><label class="field-title">Line height</label><input class="control" id="lineHeight" value="${escapeHtml(style.lineHeight || '1.5')}" placeholder="1.5"></div>
          </div>
          <div class="field-row" style="margin-top:9px">
            <div><label class="field-title">Letter spacing</label><input class="control" id="letterSpacing" value="${escapeHtml(style.letterSpacing || '0px')}" placeholder="0px"></div>
            <div><label class="field-title">Word spacing</label><input class="control" id="wordSpacing" value="${escapeHtml(style.wordSpacing || '0px')}" placeholder="0px"></div>
          </div>
          <div class="field-row" style="margin-top:9px">
            <div><label class="field-title">Decoration</label><select class="select-control" id="textDecoration"><option value="none">None</option><option value="underline">Underline</option><option value="line-through">Line through</option><option value="overline">Overline</option></select></div>
            <div><label class="field-title">Transform</label><select class="select-control" id="textTransform"><option value="none">None</option><option value="uppercase">Uppercase</option><option value="lowercase">Lowercase</option><option value="capitalize">Capitalize</option></select></div>
          </div>
          <label class="field-title" style="margin-top:9px">Text shadow</label>
          <input class="control" id="textShadow" value="${escapeHtml(style.textShadow || '')}" placeholder="0 2px 4px #0003">
        </div>
        <div class="inspector-section">
          <h3 class="section-head">Background &amp; shape</h3>
          <div class="field-row">
            <div><label class="field-title">Background</label><input class="control" type="color" id="backgroundColor" value="${validColor(style.backgroundColor, '#ffffff')}"></div>
            <div><label class="field-title">Corner radius</label><input class="control" id="borderRadius" value="${escapeHtml(style.borderRadius || '0px')}" placeholder="12px"></div>
          </div>
        </div>
        <div class="inspector-section">
          <h3 class="section-head">Gradient editor</h3>
          <label class="field-title">Gradient type</label>
          <select class="select-control" id="gradientType"><option value="linear">Linear</option><option value="radial">Radial</option><option value="conic">Conic</option></select>
          <div class="field-row" style="margin-top:9px">
            <div><label class="field-title">Angle (degrees)</label><input class="control" type="number" id="gradientAngle" min="0" max="360" value="${node.gradient?.angle ?? 135}"></div>
            <div><label class="field-title">Position</label><input class="control" id="gradientPosition" value="${escapeHtml(node.gradient?.position || 'center')}" placeholder="center"></div>
          </div>
          <div id="gradientStops" style="margin-top:10px">${gradientStopsMarkup(node)}</div>
          <div class="action-row" style="margin-top:8px"><button class="soft-button" id="addGradientStop">＋ Add stop</button><button class="soft-button" data-gradient-preset="sunset">Sunset</button><button class="soft-button" data-gradient-preset="ocean">Ocean</button></div>
        </div>
        <div class="inspector-section">
          <h3 class="section-head">Transform</h3>
          <div class="field-row">
            <div><label class="field-title">Translate X</label><input class="control" type="number" id="transformX" value="${node.editorTransform?.x || 0}"><input type="range" min="-200" max="200" value="${node.editorTransform?.x || 0}" data-range-for="transformX" aria-label="Translate X slider"></div>
            <div><label class="field-title">Translate Y</label><input class="control" type="number" id="transformY" value="${node.editorTransform?.y || 0}"><input type="range" min="-200" max="200" value="${node.editorTransform?.y || 0}" data-range-for="transformY" aria-label="Translate Y slider"></div>
          </div>
          <div class="field-row" style="margin-top:8px">
            <div><label class="field-title">Scale X</label><input class="control" type="number" step="0.1" id="scaleX" value="${node.editorTransform?.scaleX ?? 1}"><input type="range" min="0" max="3" step="0.05" value="${node.editorTransform?.scaleX ?? 1}" data-range-for="scaleX" aria-label="Scale X slider"></div>
            <div><label class="field-title">Scale Y</label><input class="control" type="number" step="0.1" id="scaleY" value="${node.editorTransform?.scaleY ?? 1}"><input type="range" min="0" max="3" step="0.05" value="${node.editorTransform?.scaleY ?? 1}" data-range-for="scaleY" aria-label="Scale Y slider"></div>
          </div>
          <div class="field-row" style="margin-top:8px">
            <div><label class="field-title">Rotate (°)</label><input class="control" type="number" id="rotate" value="${node.editorTransform?.rotate || 0}"><input type="range" min="-180" max="180" value="${node.editorTransform?.rotate || 0}" data-range-for="rotate" aria-label="Rotate slider"></div>
            <div><label class="field-title">Skew X / Y (°)</label><div class="field-row"><input class="control" type="number" id="skewX" value="${node.editorTransform?.skewX || 0}"><input class="control" type="number" id="skewY" value="${node.editorTransform?.skewY || 0}"></div></div>
          </div>
          <label class="field-title" style="margin-top:8px">Transform origin</label>
          <input class="control" id="transformOrigin" value="${escapeHtml(node.editorTransform?.origin || 'center center')}" placeholder="center center">
          <button class="soft-button" id="resetTransform" style="margin-top:8px">Reset transform</button>
        </div>
        <div class="inspector-section">
          <h3 class="section-head">Transition</h3>
          <label class="field-title">Property</label>
          <input class="control" id="transitionProperty" value="${escapeHtml(node.editorTransition?.property || 'all')}" placeholder="all, opacity, transform">
          <div class="field-row" style="margin-top:8px">
            <div><label class="field-title">Duration (ms)</label><input class="control" type="number" min="0" id="transitionDuration" value="${node.editorTransition?.duration ?? 300}"></div>
            <div><label class="field-title">Delay (ms)</label><input class="control" type="number" min="0" id="transitionDelay" value="${node.editorTransition?.delay ?? 0}"></div>
          </div>
          <label class="field-title" style="margin-top:8px">Timing function (presets or cubic-bezier)</label>
          <input class="control" id="transitionTiming" list="timingPresets" value="${escapeHtml(node.editorTransition?.timing || 'ease')}">
          <datalist id="timingPresets"><option value="ease"><option value="ease-in"><option value="ease-out"><option value="ease-in-out"><option value="linear"><option value="cubic-bezier(0.2, 0.8, 0.2, 1)"></datalist>
        </div>
        <div class="inspector-section">
          <h3 class="section-head">Animation</h3>
          <label class="field-title">Entrance / emphasis</label>
          <select class="select-control" id="animationName"><option value="">None</option><option value="fade">Fade in</option><option value="fade-out">Fade out</option><option value="slide">Slide in</option><option value="slide-out">Slide out</option><option value="scale">Scale in</option><option value="scale-out">Scale out</option><option value="rotate">Rotate in</option><option value="bounce">Bounce</option><option value="pulse">Pulse</option><option value="shake">Shake</option></select>
          <div class="field-row" style="margin-top:9px">
            <div><label class="field-title">Duration (ms)</label><input class="control" type="number" min="1" id="animationDuration" value="${node.animation?.duration ?? 700}"></div>
            <div><label class="field-title">Delay (ms)</label><input class="control" type="number" min="0" id="animationDelay" value="${node.animation?.delay ?? 0}"></div>
          </div>
          <div class="field-row" style="margin-top:9px">
            <div><label class="field-title">Iterations</label><input class="control" id="animationIteration" value="${escapeHtml(node.animation?.iteration ?? 1)}" placeholder="1 or infinite"></div>
            <div><label class="field-title">Direction</label><select class="select-control" id="animationDirection"><option>normal</option><option>reverse</option><option>alternate</option><option>alternate-reverse</option></select></div>
          </div>
          <label class="field-title" style="margin-top:9px">Fill mode</label>
          <select class="select-control" id="animationFill"><option>both</option><option>forwards</option><option>backwards</option><option>none</option></select>
          <label class="field-title" style="margin-top:9px">Timing function</label>
          <input class="control" id="animationTiming" list="timingPresets" value="${escapeHtml(node.animation?.timing || 'ease')}">
        </div>
        <div class="inspector-section">
          <h3 class="section-head">Hover, focus &amp; active states</h3>
          <label class="field-title">Edit state</label>
          <select class="select-control" id="styleState"><option value="hover">Hover</option><option value="focus">Focus</option><option value="active">Active</option></select>
          <div class="field-row" style="margin-top:8px">
            <div><label class="field-title">Background</label><input class="control" type="color" id="stateBackground" value="${validColor(node.states?.hover?.backgroundColor, '#8061ed')}"></div>
            <div><label class="field-title">Text color</label><input class="control" type="color" id="stateColor" value="${validColor(node.states?.hover?.color, '#ffffff')}"></div>
          </div>
          <div class="field-row" style="margin-top:8px">
            <div><label class="field-title">Opacity</label><input class="control" type="number" min="0" max="1" step="0.1" id="stateOpacity" value="${node.states?.hover?.opacity ?? 1}"></div>
            <div><label class="field-title">Scale</label><input class="control" type="number" min="0.1" max="3" step="0.05" id="stateScale" value="${node.states?.hover?.transform?.match(/scale\(([^)]+)/)?.[1] || 1}"></div>
          </div>
          <div class="field-row" style="margin-top:8px">
            <div><label class="field-title">Rotate (°)</label><input class="control" type="number" id="stateRotate" value="${node.states?.hover?.transform?.match(/rotate\(([-\d.]+)/)?.[1] || 0}"></div>
            <div><label class="field-title">Border</label><input class="control" id="stateBorder" value="${escapeHtml(node.states?.hover?.border || '')}" placeholder="1px solid #8061ed"></div>
          </div>
          <label class="field-title" style="margin-top:8px">Box shadow</label>
          <input class="control" id="stateShadow" value="${escapeHtml(node.states?.hover?.boxShadow || '')}" placeholder="0 8px 24px #0003">
          <button class="soft-button" id="clearState" style="margin-top:8px">Clear this state</button>
        </div>
        <div class="inspector-section">
          <h3 class="section-head">Spacing</h3>
          <div class="field-row">
            <div><label class="field-title">Padding</label><input class="control" id="padding" value="${escapeHtml(style.padding || '0px')}" placeholder="12px"></div>
            <div><label class="field-title">Margin</label><input class="control" id="margin" value="${escapeHtml(style.margin || '0px')}" placeholder="12px"></div>
          </div>
          <div class="field-row" style="margin-top:9px">
            <div><label class="field-title">Width</label><input class="control" id="width" value="${escapeHtml(style.width || '')}" placeholder="auto / 100%"></div>
            <div><label class="field-title">Height</label><input class="control" id="height" value="${escapeHtml(style.height || '')}" placeholder="auto"></div>
          </div>
        </div>
        <div class="inspector-section">
          <h3 class="section-head">Responsive overrides</h3>
          <label class="field-title">Edit device-specific styles (desktop stays unchanged)</label>
          <select class="select-control" id="responsiveDevice"><option value="mobile">Mobile · ≤650px</option><option value="tablet">Tablet · 651–950px</option></select>
          <div class="field-row" style="margin-top:9px">
            <div><label class="field-title">Width</label><input class="control" id="respWidth" placeholder="inherit"></div>
            <div><label class="field-title">Height</label><input class="control" id="respHeight" placeholder="inherit"></div>
          </div>
          <div class="field-row" style="margin-top:9px">
            <div><label class="field-title">Padding</label><input class="control" id="respPadding" placeholder="inherit"></div>
            <div><label class="field-title">Margin</label><input class="control" id="respMargin" placeholder="inherit"></div>
          </div>
          <div class="field-row" style="margin-top:9px">
            <div><label class="field-title">Font size</label><input class="control" id="respFontSize" placeholder="inherit"></div>
            <div><label class="field-title">Visibility</label><select class="select-control" id="respDisplay"><option value="">Default</option><option value="none">Hidden</option><option value="block">Show (block)</option><option value="flex">Show (flex)</option></select></div>
          </div>
          <div class="field-row" style="margin-top:9px">
            <div><label class="field-title">Flex direction</label><select class="select-control" id="respFlexDirection"><option value="">Default</option><option>row</option><option>column</option><option>row-reverse</option><option>column-reverse</option></select></div>
            <div><label class="field-title">Grid columns</label><input class="control" id="respGridColumns" placeholder="1fr 1fr"></div>
          </div>
          <button class="soft-button" id="clearResponsive" style="margin-top:9px">Clear device overrides</button>
        </div>
        <div class="inspector-section">
          <h3 class="section-head">Style blocks</h3>
          <div class="action-row"><button class="soft-button" data-style-preset="glass">Glass card</button><button class="soft-button" data-style-preset="gradient">Gradient button</button></div>
          <div class="action-row" style="margin-top:7px"><button class="soft-button" data-style-preset="shadow">Shadow card</button><button class="soft-button" data-style-preset="rounded">Rounded</button></div>
        </div>
        <div class="inspector-section">
          <h3 class="section-head">Click behavior</h3>
          <label class="field-title">When this element is clicked</label>
          <select class="select-control" id="behaviorAction"><option value="">No behavior</option><option value="alert">Show alert</option><option value="toggle">Toggle another element</option><option value="hide">Hide another element</option><option value="text">Change another element's text</option><option value="background">Change another element's background</option><option value="show">Show element</option><option value="open-modal">Open modal</option><option value="close-modal">Close modal</option><option value="tab">Show tab panel</option><option value="scroll">Smooth scroll to element</option><option value="scroll-animation">Fade in when visible</option></select>
          <label class="field-title" style="margin-top:9px">Target element</label>
          <select class="select-control" id="behaviorTarget"><option value="">Select target</option>${childrenOptions}</select>
          <label class="field-title" style="margin-top:9px">Value (alert / text / color)</label>
          <input class="control" id="behaviorValue" placeholder="Hello there!" value="${escapeHtml((project.behaviors || []).find((b) => b.source === node.id)?.value || '')}">
          <button class="soft-button" id="saveBehavior" style="margin-top:9px">Save behavior</button>
          <p class="muted-copy">Behavior is included in the exported JavaScript.</p>
        </div>
      `;
      bindNodeInputs(node);
    }

    function validColor(value, fallback) {
      return /^#[0-9a-f]{6}$/i.test(value || '') ? value : fallback;
    }

    function bindNodeInputs(node) {
      const style = node.styles || {};
      const savedBehavior = (project.behaviors || []).find((item) => item.source === node.id);
      if (savedBehavior) {
        $('#behaviorAction').value = savedBehavior.action;
        $('#behaviorTarget').value = savedBehavior.target || '';
      }
      const text = $('#nodeText');
      text.oninput = () => {
        const element = $(`#pageCanvas [data-node-id="${node.id}"]`);
        if (!element) return;
        if (node.tag === 'img' || node.tag === 'video') element.setAttribute('src', sanitizeUrl(text.value, { allowDataImage: true }));
        else if (node.tag === 'input') element.setAttribute('placeholder', text.value);
        else {
          const content = [...element.childNodes].find((child) => child.nodeType === 3);
          if (content) content.textContent = text.value;
          else element.insertBefore(document.createTextNode(text.value), element.firstChild);
        }
      };
      text.onchange = () => {
        remember();
        if (node.tag === 'img' || node.tag === 'video') {
          node.attrs = node.attrs || {};
          node.attrs.src = sanitizeUrl(text.value, { allowDataImage: true });
        } else if (node.tag === 'input') {
          node.attrs = node.attrs || {};
          node.attrs.placeholder = text.value;
        } else node.text = text.value;
        renderAll();
      };
      const href = $('#nodeHref');
      if (href) {
        href.onchange = () => {
          remember();
          node.attrs = node.attrs || {};
          node.attrs.href = sanitizeUrl(href.value, { allowDataImage: false });
          renderCanvas();
          updateCode();
          saveProjects();
        };
      }
      const alt = $('#nodeAlt');
      if (alt) {
        alt.onchange = () => {
          remember();
          node.attrs = node.attrs || {};
          node.attrs.alt = alt.value;
          renderCanvas();
          updateCode();
          saveProjects();
        };
      }
      $('#duplicateSelected').onclick = () => duplicateNode(node.id);
      $('#deleteSelected').onclick = () => deleteNode(node.id);

      const bind = (id, key, transform = (value) => value) => {
        const input = $('#' + id);
        input.oninput = () => {
          const element = $(`#pageCanvas [data-node-id="${node.id}"]`);
          if (element) element.style[key] = transform(input.value);
        };
        input.onchange = () => setStyle(node, key, transform(input.value));
      };
      const size = $('#fontSize');
      size.oninput = () => {
        $('#fontSizeValue').textContent = size.value + 'px';
        const element = $(`#pageCanvas [data-node-id="${node.id}"]`);
        if (element) element.style.fontSize = size.value + 'px';
      };
      size.onchange = () => setStyle(node, 'fontSize', size.value + 'px');
      bind('textColor', 'color');
      bind('textAlign', 'textAlign');
      bind('backgroundColor', 'backgroundColor');
      bind('borderRadius', 'borderRadius');
      bind('padding', 'padding');
      bind('margin', 'margin');
      bind('width', 'width');
      bind('height', 'height');

      const family = $('#fontFamily');
      family.value = styleValue(node, 'fontFamily', 'Arial, sans-serif');
      family.onchange = () => {
        if (family.value !== 'custom') setStyle(node, 'fontFamily', family.value);
      };
      $('#customFontFamily').onchange = (event) => setStyle(node, 'fontFamily', event.target.value.trim());
      $('#fontWeight').value = style.fontWeight || '400';
      $('#fontWeight').onchange = (event) => setStyle(node, 'fontWeight', event.target.value);
      ['lineHeight', 'letterSpacing', 'wordSpacing', 'textDecoration', 'textTransform', 'textShadow'].forEach((id) => bind(id, ({
        lineHeight: 'lineHeight',
        letterSpacing: 'letterSpacing',
        wordSpacing: 'wordSpacing',
        textDecoration: 'textDecoration',
        textTransform: 'textTransform',
        textShadow: 'textShadow',
      })[id]));
      $('#textDecoration').value = style.textDecoration || 'none';
      $('#textTransform').value = style.textTransform || 'none';
      $$('[data-style-preset]').forEach((button) => { button.onclick = () => applyPreset(node, button.dataset.stylePreset); });
      $('#saveBehavior').onclick = () => saveBehavior(node.id);
      bindAdvancedInputs(node);
    }

    function bindAdvancedInputs(node) {
      const animationFields = ['animationName', 'animationDuration', 'animationDelay', 'animationIteration', 'animationDirection', 'animationFill', 'animationTiming'];
      $('#animationName').value = node.animation?.name || '';
      $('#animationDirection').value = node.animation?.direction || 'normal';
      $('#animationFill').value = node.animation?.fill || 'both';
      $('#animationTiming').value = node.animation?.timing || 'ease';
      animationFields.forEach((id) => {
        $('#' + id).onchange = () => {
          const name = $('#animationName').value;
          remember();
          if (!name) {
            delete node.animation;
          } else {
            node.animation = {
              name,
              duration: +$('#animationDuration').value || 700,
              delay: +$('#animationDelay').value || 0,
              iteration: $('#animationIteration').value || '1',
              direction: $('#animationDirection').value,
              fill: $('#animationFill').value,
              timing: $('#animationTiming').value || 'ease',
            };
          }
          renderAll();
        };
      });

      const responsiveIds = {
        respWidth: 'width',
        respHeight: 'height',
        respPadding: 'padding',
        respMargin: 'margin',
        respFontSize: 'fontSize',
        respDisplay: 'display',
        respFlexDirection: 'flexDirection',
        respGridColumns: 'gridTemplateColumns',
      };
      const loadResponsive = () => {
        const current = node.responsive?.[$('#responsiveDevice').value]?.styles || {};
        Object.entries(responsiveIds).forEach(([id, key]) => { $('#' + id).value = current[key] || ''; });
      };
      $('#responsiveDevice').onchange = loadResponsive;
      loadResponsive();
      Object.entries(responsiveIds).forEach(([id, key]) => {
        $('#' + id).onchange = (event) => {
          remember();
          const device = $('#responsiveDevice').value;
          node.responsive = node.responsive || {};
          node.responsive[device] = node.responsive[device] || { styles: {} };
          node.responsive[device].styles = node.responsive[device].styles || {};
          if (event.target.value) node.responsive[device].styles[key] = event.target.value;
          else delete node.responsive[device].styles[key];
          renderAll();
        };
      });
      $('#clearResponsive').onclick = () => {
        remember();
        delete node.responsive?.[$('#responsiveDevice').value];
        renderAll();
      };

      const gradient = node.gradient || {
        type: 'linear',
        angle: 135,
        position: 'center',
        stops: [{ color: '#8061ed', position: 0 }, { color: '#5ec8d4', position: 100 }],
      };
      $('#gradientType').value = gradient.type || 'linear';
      const saveGradient = () => {
        remember();
        node.gradient = gradient;
        renderAll();
      };
      $('#gradientType').onchange = (event) => { gradient.type = event.target.value; saveGradient(); };
      $('#gradientAngle').onchange = (event) => { gradient.angle = +event.target.value || 0; saveGradient(); };
      $('#gradientPosition').onchange = (event) => { gradient.position = event.target.value.trim() || 'center'; saveGradient(); };

      $$('[data-stop-index]').forEach((row) => {
        const i = +row.dataset.stopIndex;
        row.querySelector('[data-stop-color]').onchange = (event) => { gradient.stops[i].color = event.target.value; saveGradient(); };
        const position = row.querySelector('[data-stop-position]');
        const positionRange = row.querySelector('[data-stop-position-range]');
        position.onchange = (event) => {
          gradient.stops[i].position = +event.target.value || 0;
          positionRange.value = event.target.value;
          saveGradient();
        };
        positionRange.oninput = () => { position.value = positionRange.value; };
        positionRange.onchange = () => position.dispatchEvent(new Event('change', { bubbles: true }));
        row.querySelector('[data-stop-opacity]').onchange = (event) => { gradient.stops[i].opacity = +event.target.value; saveGradient(); };
      });
      $$('[data-remove-stop]').forEach((button) => {
        button.onclick = () => {
          gradient.stops.splice(+button.dataset.removeStop, 1);
          saveGradient();
        };
      });
      $('#addGradientStop').onclick = () => {
        gradient.stops = gradient.stops || [];
        const last = gradient.stops[gradient.stops.length - 1];
        gradient.stops.push({ color: last?.color || '#8061ed', position: Math.min(100, (+last?.position || 0) + 25) });
        saveGradient();
      };
      $$('[data-gradient-preset]').forEach((button) => {
        button.onclick = () => {
          const presets = {
            sunset: [{ color: '#ff7e5f', position: 0 }, { color: '#feb47b', position: 50 }, { color: '#7b4397', position: 100 }],
            ocean: [{ color: '#2193b0', position: 0 }, { color: '#6dd5ed', position: 55 }, { color: '#bdefff', position: 100 }],
          };
          gradient.type = 'linear';
          gradient.angle = 135;
          gradient.stops = presets[button.dataset.gradientPreset].map((stop) => ({ ...stop }));
          saveGradient();
        };
      });

      const transformIds = {
        transformX: 'x',
        transformY: 'y',
        scaleX: 'scaleX',
        scaleY: 'scaleY',
        rotate: 'rotate',
        skewX: 'skewX',
        skewY: 'skewY',
      };
      Object.entries(transformIds).forEach(([id, key]) => {
        const input = $('#' + id);
        const range = $(`[data-range-for="${id}"]`);
        input.onchange = (event) => {
          if (range) range.value = event.target.value;
          remember();
          node.editorTransform = node.editorTransform || { x: 0, y: 0, scaleX: 1, scaleY: 1, rotate: 0, skewX: 0, skewY: 0 };
          node.editorTransform[key] = +event.target.value;
          renderAll();
        };
        if (range) {
          range.oninput = () => { input.value = range.value; };
          range.onchange = () => input.dispatchEvent(new Event('change', { bubbles: true }));
        }
      });
      $('#transformOrigin').onchange = (event) => {
        remember();
        node.editorTransform = node.editorTransform || {};
        node.editorTransform.origin = event.target.value || 'center center';
        renderAll();
      };
      $('#resetTransform').onclick = () => {
        remember();
        delete node.editorTransform;
        if (node.styles) delete node.styles.transform;
        renderAll();
      };

      const transitionIds = {
        transitionProperty: 'property',
        transitionDuration: 'duration',
        transitionDelay: 'delay',
        transitionTiming: 'timing',
      };
      $('#transitionTiming').value = node.editorTransition?.timing || 'ease';
      Object.entries(transitionIds).forEach(([id, key]) => {
        $('#' + id).onchange = (event) => {
          remember();
          node.editorTransition = node.editorTransition || { property: 'all', duration: 300, delay: 0, timing: 'ease' };
          node.editorTransition[key] = event.target.value;
          renderAll();
        };
      });

      const stateSelect = $('#styleState');
      stateSelect.onchange = () => {
        const state = node.states?.[stateSelect.value] || {};
        $('#stateBackground').value = validColor(state.backgroundColor, '#8061ed');
        $('#stateColor').value = validColor(state.color, '#ffffff');
        $('#stateOpacity').value = state.opacity ?? 1;
        $('#stateScale').value = state.transform?.match(/scale\(([^)]+)/)?.[1] || 1;
        $('#stateRotate').value = state.transform?.match(/rotate\(([-\d.]+)/)?.[1] || 0;
        $('#stateBorder').value = state.border || '';
        $('#stateShadow').value = state.boxShadow || '';
      };
      const saveState = () => {
        remember();
        const state = stateSelect.value;
        node.states = node.states || {};
        const data = node.states[state] || {};
        data.backgroundColor = $('#stateBackground').value;
        data.color = $('#stateColor').value;
        data.opacity = $('#stateOpacity').value;
        const transforms = [];
        if (+$('#stateScale').value !== 1) transforms.push(`scale(${$('#stateScale').value})`);
        if (+$('#stateRotate').value) transforms.push(`rotate(${$('#stateRotate').value}deg)`);
        if (transforms.length) data.transform = transforms.join(' ');
        else delete data.transform;
        data.border = $('#stateBorder').value;
        data.boxShadow = $('#stateShadow').value;
        node.states[state] = data;
        renderAll();
      };
      ['stateBackground', 'stateColor', 'stateOpacity', 'stateScale', 'stateRotate', 'stateBorder', 'stateShadow'].forEach((id) => {
        $('#' + id).onchange = saveState;
      });
      $('#clearState').onclick = () => {
        remember();
        if (node.states) delete node.states[stateSelect.value];
        renderAll();
      };
    }

    function styleValue(node, key, fallback) {
      return node.styles?.[key] || fallback;
    }

    function applyPreset(node, name) {
      remember();
      node.styles = node.styles || {};
      const presets = {
        glass: {
          padding: '22px',
          backgroundColor: 'rgba(255,255,255,0.72)',
          border: '1px solid rgba(150,150,180,0.35)',
          borderRadius: '16px',
          boxShadow: '0 12px 34px rgba(34,27,70,0.16)',
          backdropFilter: 'blur(12px)',
        },
        gradient: {
          padding: '12px 22px',
          background: 'linear-gradient(135deg, #9672ff, #5ec8d4)',
          color: '#ffffff',
          border: '0',
          borderRadius: '10px',
          fontWeight: '700',
          boxShadow: '0 8px 20px rgba(112,83,210,0.28)',
        },
        shadow: {
          padding: '20px',
          backgroundColor: '#ffffff',
          borderRadius: '12px',
          boxShadow: '0 10px 30px rgba(20,20,45,0.14)',
        },
        rounded: {
          borderRadius: '20px',
          padding: '18px',
        },
      };
      Object.assign(node.styles, presets[name]);
      renderAll();
      notify('Style block applied');
    }

    function saveBehavior(source) {
      const action = $('#behaviorAction').value;
      const target = $('#behaviorTarget').value;
      const value = $('#behaviorValue').value;
      if (action && ['toggle', 'hide', 'text', 'background', 'show', 'open-modal', 'close-modal', 'tab', 'scroll', 'scroll-animation'].includes(action) && !target) {
        return notify('Choose a target element first');
      }
      remember();
      project.behaviors = (project.behaviors || []).filter((item) => item.source !== source);
      if (action) {
        project.behaviors.push({ source, target, action, value, trigger: 'click' });
      }
      saveProjects();
      updateCode();
      notify(action ? 'Behavior saved' : 'Behavior removed');
    }

    function addNode(tag) {
      remember();
      const component = tag;
      tag = ({
        card: 'div',
        badge: 'span',
        modal: 'div',
        tabs: 'div',
        navbar: 'nav',
        accordion: 'details',
        'image-container': 'div',
        'video-container': 'div',
      })[tag] || tag;
      const defaults = {
        h1: 'Your heading',
        h2: 'A new section',
        h3: 'A heading',
        p: 'Write your paragraph here. Click to edit this text.',
        span: 'Text',
        blockquote: 'Add a thoughtful quote here.',
        button: 'Click me',
        a: 'Link text',
        div: 'Container',
        section: 'New section',
        header: 'Header',
        nav: 'Navigation',
        main: 'Main content',
        article: 'Article content',
        footer: 'Footer',
        aside: 'Sidebar content',
        details: 'Expandable content',
        summary: 'Details',
        small: 'Small text',
        strong: 'Bold text',
        textarea: 'Write here…',
        select: 'Choose an option',
        video: '',
        img: '',
        hr: '',
        input: '',
        form: 'Form',
      };
      const node = { id: uid(), tag, text: defaults[tag] || '', attrs: {}, styles: {}, children: [] };
      if (component === 'card') {
        node.text = 'Card content';
        node.styles = { padding: '20px', backgroundColor: '#ffffff', border: '1px solid #e5e3eb', borderRadius: '12px', boxShadow: '0 8px 24px #211b3514' };
      }
      if (component === 'badge') {
        node.text = 'New';
        node.styles = { display: 'inline-block', padding: '4px 9px', borderRadius: '999px', backgroundColor: '#eee8ff', color: '#6045a8', fontSize: '12px', fontWeight: '600' };
      }
      if (component === 'modal') {
        node.text = 'Modal content';
        node.hidden = true;
        node.attrs.role = 'dialog';
        node.attrs['aria-modal'] = 'true';
        node.styles = { position: 'fixed', left: '50%', top: '50%', transform: 'translate(-50%, -50%)', zIndex: '1000', padding: '24px', backgroundColor: '#ffffff', borderRadius: '14px', boxShadow: '0 16px 48px #0003', maxWidth: '420px', width: 'min(90vw, 420px)' };
      }
      if (component === 'tabs') {
        node.text = 'Tabs group';
        node.styles = { display: 'flex', gap: '12px', padding: '12px' };
      }
      if (component === 'image-container' || component === 'video-container') {
        node.text = component === 'image-container' ? 'Image container' : 'Video container';
        node.styles = { display: 'grid', placeItems: 'center', minHeight: '180px', backgroundColor: '#f1eff7', borderRadius: '10px', color: '#777' };
      }
      if (component === 'accordion') node.text = 'Expandable section';
      if (tag === 'textarea') node.attrs = { rows: '3', placeholder: 'Write here…' };
      if (tag === 'select') {
        node.attrs = { 'aria-label': 'Choose an option' };
        node.text = '';
        node.children.push({ id: uid(), tag: 'option', text: 'Choose an option', attrs: {}, styles: {}, children: [] });
      }
      if (tag === 'details') {
        node.text = '';
        node.children.push(
          { id: uid(), tag: 'summary', text: 'Expand for details', attrs: {}, styles: {}, children: [] },
          { id: uid(), tag: 'p', text: 'Add more information here.', attrs: {}, styles: {}, children: [] }
        );
      }
      if (tag === 'video') node.attrs = { controls: true };
      if (tag === 'img') {
        node.attrs = {
          src: 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="640" height="360"><rect width="100%" height="100%" fill="#eee9ff"/><text x="50%" y="50%" text-anchor="middle" fill="#66558d" font-size="24">Add your image</text></svg>'),
          alt: 'Placeholder image',
        };
        node.styles = { width: '100%', height: 'auto', objectFit: 'cover' };
      }
      if (tag === 'a') node.attrs.href = '#';
      if (tag === 'input') node.attrs.placeholder = 'Type here';
      if (tag === 'button') node.styles = { padding: '10px 16px', borderRadius: '7px', border: '0', backgroundColor: '#8061ed', color: '#ffffff', cursor: 'pointer' };

      const selected = selectedId && findNode(selectedId);
      if (selected && CONTAINER_TAGS.includes(selected.node.tag)) {
        selected.node.children = selected.node.children || [];
        selected.node.children.push(node);
      } else {
        project.nodes.push(node);
      }
      selectedId = node.id;
      renderAll();
      setPanel('styles');
      notify(`${tag.toUpperCase()} added`);
    }

    function deleteNode(id) {
      const found = findNode(id);
      if (!found) return;
      remember();
      found.list.splice(found.index, 1);
      project.behaviors = (project.behaviors || []).filter((item) => item.source !== id && item.target !== id);
      selectedId = null;
      renderAll();
      notify('Element deleted');
    }

    function duplicateNode(id) {
      const found = findNode(id);
      if (!found) return;
      remember();
      const copy = clone(found.node);
      rekey(copy);
      found.list.splice(found.index + 1, 0, copy);
      selectedId = copy.id;
      renderAll();
      notify('Element duplicated');
    }

    function copySelected() {
      const found = selectedId && findNode(selectedId);
      if (!found) return notify('Select an element to copy');
      clipboardNode = clone(found.node);
      notify('Element copied');
    }

    function pasteSelected() {
      if (!clipboardNode) return notify('Copy an element first');
      const found = selectedId && findNode(selectedId);
      remember();
      const copy = clone(clipboardNode);
      rekey(copy);
      const list = found ? found.list : project.nodes;
      const index = found ? found.index + 1 : list.length;
      list.splice(index, 0, copy);
      selectedId = copy.id;
      renderAll();
      notify('Element pasted');
    }

    function rekey(node) {
      node.id = uid();
      (node.children || []).forEach(rekey);
    }

    function moveNode(sourceId, targetId) {
      if (!sourceId || !targetId || sourceId === targetId) return;
      const source = findNode(sourceId);
      const target = findNode(targetId);
      if (!source || !target) return;
      let cursor = target.node;
      while (cursor) {
        if (cursor.id === sourceId) return;
        cursor = findNode(cursor.id)?.parent;
      }
      remember();
      const moving = source.list.splice(source.index, 1)[0];
      const targetAfterRemoval = findNode(targetId);
      const container = CONTAINER_TAGS.includes(targetAfterRemoval.node.tag);
      if (container) {
        targetAfterRemoval.node.children = targetAfterRemoval.node.children || [];
        targetAfterRemoval.node.children.push(moving);
      } else {
        targetAfterRemoval.list.splice(targetAfterRemoval.index, 0, moving);
      }
      selectedId = moving.id;
      renderAll();
    }

    function renderPanel() {
      const titleMap = {
        canvas: ['WORKSPACE', 'Canvas'],
        elements: ['LIBRARY', 'Add elements'],
        layers: ['STRUCTURE', 'Layers'],
        styles: ['DESIGN', 'Style blocks'],
        templates: ['COMMUNITY', 'Templates'],
        code: ['SOURCE', 'Code editor'],
      };
      $('#panelEyebrow').textContent = titleMap[activePanel][0];
      $('#panelTitle').textContent = titleMap[activePanel][1];
      if (activePanel === 'elements') renderElements();
      else if (activePanel === 'layers') renderLayers();
      else if (activePanel === 'code') renderCodePanel();
      else if (activePanel === 'styles') renderStyleLibrary();
      else if (activePanel === 'templates') renderTemplatesPanel();
      else {
        $('#panelContent').innerHTML = '<div class="hint-card">Build your page with visual elements. Select a layer to open its properties.</div><button class="primary-button" id="canvasAddButton" style="margin-top:12px">＋ Add your first element</button>';
      }
      const add = $('#canvasAddButton');
      if (add) add.onclick = () => setPanel('elements');
    }

    function renderStyleLibrary() {
      $('#panelContent').innerHTML = `
        <p class="muted-copy">Choose an element first, then apply a reusable style block. Existing styles not listed in a block stay unchanged.</p>
        <div class="section-label" style="margin-top:18px">BUILT-IN STYLE BLOCKS</div>
        ${[
          ['glass', 'Modern glass card', 'Soft glass surface with blur'],
          ['gradient', 'Gradient button', 'Colorful call-to-action treatment'],
          ['shadow', 'Shadow card', 'Clean elevated card'],
          ['rounded', 'Rounded surface', 'Friendly rounded corners'],
        ].map(([id, title, desc]) => `<div class="template-card"><div><strong>${title}</strong><small>${desc}</small></div><button class="soft-button" data-library-preset="${id}">Apply</button></div>`).join('')}
        <div class="inspector-section" style="margin-top:20px">
          <label class="field-title">Custom CSS (saved with project)</label>
          <textarea class="control" id="customCssPanel" rows="8" placeholder=".my-style {\n  color: rebeccapurple;\n}"></textarea>
          <button class="soft-button" id="saveCustomCss" style="margin-top:8px">Save custom CSS</button>
        </div>
      `;
      $('#customCssPanel').value = project.customCss || '';
      $$('[data-library-preset]').forEach((button) => {
        button.onclick = () => {
          if (!selectedId) return notify('Select an element on the canvas first');
          applyPreset(findNode(selectedId).node, button.dataset.libraryPreset);
        };
      });
      $('#saveCustomCss').onclick = () => {
        remember();
        project.customCss = $('#customCssPanel').value;
        renderCanvas();
        saveProjects();
        updateCode();
        notify('Custom CSS saved');
      };
    }

    function renderCodePanel() {
      const code = codeTab === 'html' ? generatedHtml() : codeTab === 'css' ? generatedCss() : generatedJs();
      $('#panelContent').innerHTML = `
        <div class="code-tabs">
          <button class="code-tab ${codeTab === 'html' ? 'active' : ''}" data-code-tab="html">HTML</button>
          <button class="code-tab ${codeTab === 'css' ? 'active' : ''}" data-code-tab="css">CSS</button>
          <button class="code-tab ${codeTab === 'js' ? 'active' : ''}" data-code-tab="js">JavaScript</button>
        </div>
        <textarea spellcheck="false" autocapitalize="off" autocomplete="off" class="code-editor" id="codeEditor" aria-label="${codeTab.toUpperCase()} source code"></textarea>
        <div class="code-status" id="codeStatus">Generated from your visual project</div>
        <div class="code-actions"><button class="primary-button" id="applyCode">Apply changes</button><button class="soft-button" id="copyCode">Copy</button></div>
        <div class="hint-card">Edit the source and apply it to update the project. HTML is parsed by the browser; script tags are kept out of the visual model.</div>
      `;
      $('#codeEditor').value = code;
      $$('[data-code-tab]').forEach((button) => {
        button.onclick = () => {
          codeTab = button.dataset.codeTab;
          renderCodePanel();
        };
      });
      $('#applyCode').onclick = applyCodeChanges;
      $('#copyCode').onclick = async () => {
        try {
          await navigator.clipboard.writeText($('#codeEditor').value);
          notify('Code copied');
        } catch {
          const editor = $('#codeEditor');
          editor.select();
          document.execCommand('copy');
          notify('Code copied');
        }
      };
    }

    function applyCodeChanges() {
      const source = $('#codeEditor').value;
      try {
        remember();
        if (codeTab === 'html') {
          const parsed = new DOMParser().parseFromString(source, 'text/html');
          const error = parsed.querySelector('parsererror');
          if (error) throw Error('HTML could not be parsed. Check the markup and try again.');
          project.nodes = [...parsed.body.children]
            .filter((el) => !BLOCKED_TAGS.has(el.tagName.toLowerCase()))
            .map(domToNode);
          project.name = parsed.title || project.name;
          selectedId = null;
          $('#codeStatus').textContent = 'HTML applied to visual project';
          renderAll();
        } else if (codeTab === 'css') {
          project.customCss = parseCssIntoModel(source);
          $('#codeStatus').textContent = 'CSS applied to visual project';
          renderAll();
        } else {
          project.customJs = source;
          project.behaviors = [];
          $('#codeStatus').textContent = 'JavaScript saved for exported site';
          saveProjects();
          updateCode();
        }
        notify('Changes applied');
      } catch (error) {
        history.pop();
        $('#codeStatus').textContent = error.message;
        notify(error.message);
      }
    }

    function domToNode(el) {
      const tag = el.tagName.toLowerCase();
      const attrs = {};
      [...el.attributes].forEach((attr) => {
        if (!['data-node-id', 'data-builder-id', 'style', 'srcdoc'].includes(attr.name) && !/^on/i.test(attr.name)) {
          if (['href', 'src', 'action', 'formaction'].includes(attr.name.toLowerCase())) {
            const safe = sanitizeUrl(attr.value, { allowDataImage: true });
            if (safe) attrs[attr.name] = safe;
          } else {
            attrs[attr.name] = attr.value;
          }
        }
      });
      const style = {};
      if (el.getAttribute('style')) {
        el.getAttribute('style').split(';').forEach((pair) => {
          const [key, ...rest] = pair.split(':');
          if (key && rest.length) style[key.trim().replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = rest.join(':').trim();
        });
      }
      const rawId = el.getAttribute('data-node-id');
      const id = rawId && /^[\w-]+$/.test(rawId) ? rawId : uid();
      const text = [...el.childNodes].filter((child) => child.nodeType === 3).map((child) => child.textContent).join('').trim();
      return {
        id,
        tag,
        text,
        attrs,
        styles: style,
        children: [...el.children].filter((child) => !BLOCKED_TAGS.has(child.tagName.toLowerCase())).map(domToNode),
      };
    }

    function updateCode() {
      if (activePanel === 'code') renderCodePanel();
    }

    function renderAll(options = {}) {
      document.body.classList.toggle('theme-light', localStorage.getItem('studio-theme') === 'light');
      $('#projectName').textContent = project.name;
      renderCanvas();
      renderLayers();
      renderInspector();
      renderPanel();
      if (!options.skipSave) {
        saveProjects();
      }
    }

    function setPanel(name) {
      activePanel = name;
      $('.side-panel').classList.toggle('open', name !== 'canvas' && name !== 'styles');
      $('#rightPanel').classList.toggle('open', name === 'styles');
      $$('.rail-item,.dock-item').forEach((button) => button.classList.toggle('active', button.dataset.panel === name));
      renderPanel();
      if (name === 'styles' && selectedId) renderInspector();
    }

    function selectNode(id, panel = 'styles') {
      selectedId = id;
      renderCanvas();
      renderInspector();
      renderLayers();
      if (window.innerWidth <= 950) {
        setPanel('styles');
      } else if (panel === 'styles') {
        setPanel(activePanel);
      }
    }

    function newProject(template = null) {
      project = defaultProject();
      if (template) {
        project.nodes = clone(template.nodes);
        project.nodes.forEach(rekey);
        project.name = template.name;
      }
      projects.unshift(project);
      history = [];
      future = [];
      selectedId = null;
      saveProjects({ immediateCloud: Boolean(currentUser) });
      closeModal();
      renderAll({ skipSave: true });
      notify(template ? 'Starter project created' : 'Blank canvas created');
    }

    async function showDashboard() {
      openModal('Your projects', 'PROJECTS', dashboardMarkup());
      bindDashboard();
      if (currentUser) {
        await refreshCloudProjectsList({ silent: true });
        if (!$('#modalBackdrop').classList.contains('hidden')) {
          $('#modalBody').innerHTML = dashboardMarkup();
          bindDashboard();
        }
      }
    }

    function dashboardMarkup() {
      const cloudHtml = currentUser
        ? (cloudProjectsCache.length
            ? cloudProjectsCache.map((cp) => {
                const dateLabel = cp.updatedAt?.toDate ? cp.updatedAt.toDate().toLocaleDateString() : 'Cloud';
                return `<div class="project-card">
                  <div>
                    <strong>${escapeHtml(cp.projectName)}</strong>
                    <small>v${Number(cp.version || 1)} · ${Number(cp.nodeCount || 0)} elements · ${escapeHtml(dateLabel)}</small>
                  </div>
                  <div class="action-row">
                    <button class="soft-button" data-open-cloud="${escapeHtml(cp.id)}">Load</button>
                    <button class="soft-button" data-list-backups="${escapeHtml(cp.id)}">Backups</button>
                    <button class="danger-button" data-delete-cloud="${escapeHtml(cp.id)}" title="Delete from cloud">×</button>
                  </div>
                </div>`;
              }).join('')
            : '<p class="muted-copy">No cloud projects saved yet. Edit or click Save to sync your active project.</p>')
        : '<div class="status-banner">Sign in to sync projects across devices, create cloud backups, and browse community templates. <button type="button" class="link-button" id="dashSignInLink">Sign in now</button></div>';

      return `
        <div class="modal-actions">
          <button class="primary-button" id="newBlank">＋ Blank canvas</button>
          <button class="soft-button" id="importProject">Import</button>
          <button class="soft-button" id="backupCurrentBtn">${currentUser ? '☁ Backup current' : '☁ Sign in to backup'}</button>
          <button class="soft-button" id="openCommunityLibBtn">◈ Community templates</button>
        </div>
        <div class="section-label">STARTER TEMPLATES</div>
        ${starterPresets.map((item, index) => `<div class="template-card"><div><strong>${item.name}</strong><small>${item.description}</small></div><button class="soft-button" data-start-template="${index}">Use template</button></div>`).join('')}
        <div class="section-label" style="margin-top:20px">LOCAL PROJECTS (OFFLINE READY)</div>
        ${projects.map((item) => `<div class="project-card"><div><strong>${escapeHtml(item.name)}</strong><small>Edited ${new Date(item.updated || item.created).toLocaleDateString()}${item.syncMeta?.cloudVersion ? ` · Cloud v${item.syncMeta.cloudVersion}` : ' · Local'}</small></div><div class="action-row"><button class="soft-button" data-open-project="${item.id}">Open</button><button class="soft-button" data-duplicate-project="${item.id}" title="Duplicate">⧉</button><button class="danger-button" data-delete-project="${item.id}" title="Delete">×</button></div></div>`).join('') || '<p class="muted-copy">No saved projects yet.</p>'}
        <div class="section-label" style="margin-top:20px">CLOUD PROJECTS</div>
        ${cloudHtml}
      `;
    }

    function bindDashboard() {
      $('#newBlank').onclick = () => newProject();
      $('#importProject').onclick = () => $('#importFile').click();
      $('#openCommunityLibBtn').onclick = () => {
        closeModal();
        setPanel('templates');
      };
      $('#backupCurrentBtn').onclick = () => {
        if (!currentUser) return openAuthModal('signin');
        createCloudBackup(project);
      };
      const dashSignIn = $('#dashSignInLink');
      if (dashSignIn) dashSignIn.onclick = () => openAuthModal('signin');

      $$('[data-start-template]').forEach((button) => {
        button.onclick = () => newProject(starterPresets[+button.dataset.startTemplate]);
      });
      $$('[data-open-project]').forEach((button) => {
        button.onclick = () => {
          const found = projects.find((item) => item.id === button.dataset.openProject);
          if (found) {
            project = found;
            history = [];
            future = [];
            selectedId = null;
            closeModal();
            renderAll({ skipSave: true });
            notify('Project opened');
          }
        };
      });
      $$('[data-duplicate-project]').forEach((button) => {
        button.onclick = () => {
          const found = projects.find((item) => item.id === button.dataset.duplicateProject);
          if (found) {
            const copy = clone(found);
            copy.id = uid();
            copy.name += ' copy';
            copy.updated = Date.now();
            copy.syncMeta = { cloudVersion: 0, lastSyncedHash: '', lastSyncedAt: 0 };
            projects.unshift(copy);
            saveProjects();
            showDashboard();
            notify('Project duplicated');
          }
        };
      });
      $$('[data-delete-project]').forEach((button) => {
        button.onclick = async () => {
          const id = button.dataset.deleteProject;
          projects = projects.filter((item) => item.id !== id);
          await idbDelete('projects', id);
          await idbDelete('syncQueue', id);
          if (project.id === id) {
            project = projects[0] || defaultProject();
            if (!projects.length) projects.push(project);
          }
          persistLocalProjectsSync();
          showDashboard();
          renderAll({ skipSave: true });
          notify('Local project deleted');
        };
      });
      $$('[data-open-cloud]').forEach((button) => {
        button.onclick = () => {
          const meta = cloudProjectsCache.find((c) => c.id === button.dataset.openCloud);
          if (meta) openCloudProject(meta);
        };
      });
      $$('[data-delete-cloud]').forEach((button) => {
        button.onclick = async () => {
          await deleteCloudProject(button.dataset.deleteCloud);
          showDashboard();
        };
      });
      $$('[data-list-backups]').forEach((button) => {
        button.onclick = async () => {
          const pid = button.dataset.listBackups;
          const backups = await listCloudBackups(pid);
          openModal('Project backups', 'CLOUD BACKUPS', `
            <p class="muted-copy">Select a snapshot to restore into your local editor.</p>
            ${backups.map((b) => `<div class="project-card"><div><strong>Backup snapshot</strong><small>${b.timestamp ? new Date(b.timestamp).toLocaleString() : escapeHtml(b.name)}</small></div><button type="button" class="primary-button" data-restore-backup="${escapeHtml(b.fullPath)}">Restore</button></div>`).join('') || '<p class="muted-copy">No backups found for this project yet.</p>'}
            <button type="button" class="soft-button" id="backToDashBtn" style="margin-top:10px">← Back to projects</button>
          `);
          $('#backToDashBtn').onclick = showDashboard;
          $$('[data-restore-backup]').forEach((rb) => {
            rb.onclick = () => restoreBackupFromPath(rb.dataset.restoreBackup);
          });
        };
      });
    }

    function openModal(title, eyebrow, content) {
      secretAiModalOpen = false;
      $('#modalTitle').textContent = title;
      $('#modalEyebrow').textContent = eyebrow;
      $('#modalBody').innerHTML = content;
      $('#modalBackdrop').classList.remove('hidden');
    }

    function closeModal() {
      secretAiModalOpen = false;
      $('#modalBackdrop').classList.add('hidden');
    }

    // ------------------------------------------------------------------------
    // Secret AI Workbench (Code Analysis, Next Moves, Template Forge & Upload)
    // ------------------------------------------------------------------------
    function openSecretAiModal(initialTab = secretAiTab) {
      secretAiTab = initialTab === 'template' ? 'template' : 'analyze';
      secretAiModalOpen = true;
      $('#modalTitle').textContent = 'Secret AI';
      $('#modalEyebrow').textContent = 'STUDIO INTELLIGENCE · CTRL+SHIFT+K';
      $('#modalBody').innerHTML = renderSecretAiMarkup();
      $('#modalBackdrop').classList.remove('hidden');
      bindSecretAiEvents();
    }

    function refreshSecretAiModal() {
      if (!secretAiModalOpen || $('#modalBackdrop').classList.contains('hidden')) return;
      $('#modalBody').innerHTML = renderSecretAiMarkup();
      bindSecretAiEvents();
    }

    function renderStylePairsPreview(stylesObj) {
      return Object.entries(stylesObj || {})
        .map(([k, v]) => `${k.replace(/[A-Z]/g, (m) => '-' + m.toLowerCase())}: ${v};`)
        .join('\n');
    }

    function renderSecretAiMarkup() {
      const selectedNode = selectedId ? findNode(selectedId)?.node : null;
      const errBanner = secretAiError
        ? `<div class="status-banner error" id="secretAiErrorBanner">${escapeHtml(secretAiError)}</div>`
        : '';

      const tabsHtml = `
        <div class="auth-tabs" role="tablist">
          <button type="button" class="auth-tab ${secretAiTab === 'analyze' ? 'active' : ''}" data-ai-tab="analyze">Analyze &amp; Next Moves</button>
          <button type="button" class="auth-tab ${secretAiTab === 'template' ? 'active' : ''}" data-ai-tab="template">Make &amp; Upload Template</button>
        </div>
      `;

      if (secretAiTab === 'template') {
        const draft = secretAiTemplateDraft;
        const draftCount = draft ? countProjectNodes(draft.nodes) : 0;
        const draftPreviewHtml = draft
          ? `<div class="ai-template-preview" id="aiTemplateDraftCard">
              <div class="template-library-head">
                <div>
                  <strong>${escapeHtml(draft.title)}</strong>
                  <div class="template-meta-line">${escapeHtml(draft.category)} · ${draftCount} elements · ${(draft.behaviors || []).length} behaviors</div>
                </div>
                <span class="ai-confidence-badge">AI Draft</span>
              </div>
              ${draft.description ? `<p class="template-desc">${escapeHtml(draft.description)}</p>` : ''}
              <pre class="ai-code-preview">${escapeHtml((draft.nodes || []).map((n) => `<${n.tag}> ${nodeLabel(n)}`).join('\n') || '(Empty structure)')}</pre>
              <div class="action-row">
                <button type="button" class="primary-button" id="aiLoadTemplateBtn">Load into Studio</button>
                <button type="button" class="soft-button" id="aiUploadTemplateBtn" ${secretAiUploading ? 'disabled' : ''}>${secretAiUploading ? 'Uploading…' : (currentUser ? '☁ Upload to Community' : 'Sign in to Upload')}</button>
              </div>
              <p class="muted-copy">Templates are sanitized automatically. JavaScript is never auto-executed in community uploads.</p>
            </div>`
          : '';

        return `
          ${tabsHtml}
          ${errBanner}
          <div class="form-stack">
            <div>
              <label class="field-title" for="aiTemplatePrompt">What kind of website template should I craft?</label>
              <textarea class="control" id="aiTemplatePrompt" rows="2" maxlength="700" placeholder="${escapeHtml(secretAiAnalysis?.websiteType ? `Tailored for your ${secretAiAnalysis.websiteType} project...` : 'e.g. Modern SaaS waitlist with pricing cards and FAQ accordion')}">${escapeHtml(secretAiTemplatePrompt)}</textarea>
            </div>
            <div>
              <label class="field-title" for="aiTemplateCategory">Category</label>
              <select class="select-control" id="aiTemplateCategory">
                ${VALID_CATEGORIES.map((c) => `<option value="${c}" ${secretAiTemplateCategory === c ? 'selected' : ''}>${c.charAt(0).toUpperCase() + c.slice(1)}</option>`).join('')}
              </select>
            </div>
            <button type="button" class="primary-button" id="aiGenerateTemplateBtn" ${secretAiLoading ? 'disabled' : ''}>${secretAiLoading ? 'Generating template…' : '✦ Generate AI Template'}</button>
          </div>
          ${draftPreviewHtml}
        `;
      }

      const contextNote = selectedNode
        ? `Analyzing <strong>${escapeHtml(project.name)}</strong> (${countProjectNodes(project.nodes)} elements) · Selected: <code>&lt;${escapeHtml(selectedNode.tag)}&gt;</code>`
        : `Analyzing <strong>${escapeHtml(project.name)}</strong> (${countProjectNodes(project.nodes)} elements) · Page-level view`;

      const analysis = secretAiAnalysis;
      const resultsHtml = analysis
        ? `
          <div class="ai-detected-card" id="aiDetectedSummary">
            <div class="ai-detected-head">
              <strong>${escapeHtml(analysis.websiteType)}</strong>
              <span class="ai-confidence-badge">${escapeHtml(analysis.confidence)} confidence</span>
            </div>
            <p class="template-desc">${escapeHtml(analysis.summary)}</p>
          </div>

          <div class="section-label">NEXT ELEMENTS</div>
          ${analysis.nextElements.map((el, idx) => `
            <div class="ai-suggestion-card">
              <div class="ai-suggestion-head">
                <div>
                  <strong>${escapeHtml(el.title)}</strong>
                  <div class="ai-suggestion-meta">&lt;${escapeHtml(el.node.tag)}&gt; · ${el.placement === 'inside-selected' ? 'Inside selected' : 'Page root'}</div>
                </div>
                <button type="button" class="primary-button" data-ai-apply-element="${idx}">＋ Add</button>
              </div>
              ${el.rationale ? `<p class="template-desc">${escapeHtml(el.rationale)}</p>` : ''}
            </div>
          `).join('') || '<p class="muted-copy">No element suggestions returned.</p>'}

          <div class="section-label" style="margin-top:14px">NEXT CSS STYLES</div>
          ${analysis.nextStyles.map((st, idx) => {
            const codePreview = st.customCss || renderStylePairsPreview(st.styles);
            return `
              <div class="ai-suggestion-card">
                <div class="ai-suggestion-head">
                  <div>
                    <strong>${escapeHtml(st.title)}</strong>
                    <div class="ai-suggestion-meta">${st.target === 'selected-node' && selectedNode ? `Apply to <${escapeHtml(selectedNode.tag)}>` : 'Append to Custom CSS'}</div>
                  </div>
                  <button type="button" class="soft-button" data-ai-apply-style="${idx}">Apply CSS</button>
                </div>
                ${st.rationale ? `<p class="template-desc">${escapeHtml(st.rationale)}</p>` : ''}
                ${codePreview ? `<pre class="ai-code-preview">${escapeHtml(codePreview)}</pre>` : ''}
              </div>
            `;
          }).join('') || '<p class="muted-copy">No CSS suggestions returned.</p>'}

          <div class="section-label" style="margin-top:14px">NEXT PROGRAMS (JS &amp; BEHAVIORS)</div>
          ${analysis.nextPrograms.map((prog, idx) => {
            const codePreview = prog.mode === 'behavior'
              ? `onClick(${prog.sourceNodeId || 'selected'}) -> ${prog.behaviorAction}(${prog.targetNodeId || 'self'}${prog.behaviorValue ? `, "${prog.behaviorValue}"` : ''})`
              : prog.customJs;
            return `
              <div class="ai-suggestion-card">
                <div class="ai-suggestion-head">
                  <div>
                    <strong>${escapeHtml(prog.title)}</strong>
                    <div class="ai-suggestion-meta">${prog.mode === 'behavior' ? 'Interactive Studio behavior' : 'JavaScript program'}</div>
                  </div>
                  <button type="button" class="soft-button" data-ai-apply-program="${idx}">${prog.mode === 'behavior' ? 'Apply behavior' : 'Add JS'}</button>
                </div>
                ${prog.rationale ? `<p class="template-desc">${escapeHtml(prog.rationale)}</p>` : ''}
                ${codePreview ? `<pre class="ai-code-preview">${escapeHtml(codePreview)}</pre>` : ''}
              </div>
            `;
          }).join('') || '<p class="muted-copy">No behavior or JS suggestions returned.</p>'}
        `
        : '<div class="hint-card" style="margin-top:12px">Click Analyze to inspect your HTML, CSS, JavaScript, and selected element. I will detect your website type and suggest the next element, CSS style, or JS behavior.</div>';

      return `
        ${tabsHtml}
        ${errBanner}
        <div class="status-banner">${contextNote}</div>
        <div class="form-stack">
          <div>
            <label class="field-title" for="aiAnalyzePrompt">Optional direction</label>
            <input class="control" id="aiAnalyzePrompt" maxlength="600" value="${escapeHtml(secretAiCustomPrompt)}" placeholder="e.g. Suggest a pricing table, hover glow, or smooth FAQ toggle" />
          </div>
          <div class="action-row">
            <button type="button" class="primary-button" id="aiAnalyzeBtn" style="flex:1" ${secretAiLoading ? 'disabled' : ''}>${secretAiLoading ? 'Analyzing code…' : '✦ Analyze website & code'}</button>
            ${analysis ? '<button type="button" class="soft-button" id="aiTurnIntoTemplateBtn">Forge template →</button>' : ''}
          </div>
        </div>
        <div style="margin-top:12px">${resultsHtml}</div>
      `;
    }

    function bindSecretAiEvents() {
      $$('[data-ai-tab]').forEach((btn) => {
        btn.onclick = () => {
          secretAiError = '';
          secretAiTab = btn.dataset.aiTab;
          refreshSecretAiModal();
        };
      });

      const analyzeInput = $('#aiAnalyzePrompt');
      if (analyzeInput) {
        analyzeInput.oninput = (e) => {
          secretAiCustomPrompt = e.target.value;
        };
      }
      const tplInput = $('#aiTemplatePrompt');
      if (tplInput) {
        tplInput.oninput = (e) => {
          secretAiTemplatePrompt = e.target.value;
        };
      }
      const tplCat = $('#aiTemplateCategory');
      if (tplCat) {
        tplCat.onchange = (e) => {
          secretAiTemplateCategory = e.target.value;
        };
      }

      const analyzeBtn = $('#aiAnalyzeBtn');
      if (analyzeBtn) analyzeBtn.onclick = runSecretAiAnalyze;

      const toTplBtn = $('#aiTurnIntoTemplateBtn');
      if (toTplBtn) {
        toTplBtn.onclick = () => {
          if (secretAiAnalysis?.websiteType && !secretAiTemplatePrompt.trim()) {
            secretAiTemplatePrompt = `Complete ${secretAiAnalysis.websiteType} website template`;
          }
          secretAiTab = 'template';
          refreshSecretAiModal();
        };
      }

      const genBtn = $('#aiGenerateTemplateBtn');
      if (genBtn) genBtn.onclick = runSecretAiGenerateTemplate;

      const loadTplBtn = $('#aiLoadTemplateBtn');
      if (loadTplBtn) loadTplBtn.onclick = applyAiGeneratedTemplateLocally;

      const uploadTplBtn = $('#aiUploadTemplateBtn');
      if (uploadTplBtn) uploadTplBtn.onclick = uploadAiTemplateToCommunity;

      $$('[data-ai-apply-element]').forEach((btn) => {
        btn.onclick = () => {
          const item = secretAiAnalysis?.nextElements?.[+btn.dataset.aiApplyElement];
          if (!item) return;
          const fresh = sanitizeTemplateNodes([clone(item.node)], uid)[0];
          if (!fresh) return;
          rekey(fresh);
          remember();
          const sel = selectedId && findNode(selectedId);
          if (item.placement === 'inside-selected' && sel && CONTAINER_TAGS.includes(sel.node.tag)) {
            sel.node.children = sel.node.children || [];
            sel.node.children.push(fresh);
          } else {
            project.nodes.push(fresh);
          }
          selectedId = fresh.id;
          renderAll();
          notify(`AI element <${fresh.tag}> added`);
          refreshSecretAiModal();
        };
      });

      $$('[data-ai-apply-style]').forEach((btn) => {
        btn.onclick = () => {
          const item = secretAiAnalysis?.nextStyles?.[+btn.dataset.aiApplyStyle];
          if (!item) return;
          const selNode = selectedId ? findNode(selectedId)?.node : null;
          remember();
          const res = applyAiStyleSuggestion(project, item, selNode);
          renderAll();
          notify(res.appliedTo === 'selected-node' ? 'AI styles applied to selected element' : 'AI CSS rules added to project');
        };
      });

      $$('[data-ai-apply-program]').forEach((btn) => {
        btn.onclick = () => {
          const item = secretAiAnalysis?.nextPrograms?.[+btn.dataset.aiApplyProgram];
          if (!item) return;
          const fallbackId = selectedId || project.nodes[0]?.id || '';
          remember();
          const res = applyAiProgramSuggestion(project, item, fallbackId);
          saveProjects();
          renderInspector();
          updateCode();
          if (res.appliedTo === 'behavior') {
            notify(`AI click behavior (${item.behaviorAction}) saved`);
          } else if (res.appliedTo === 'custom-js') {
            notify('AI JavaScript added to project code');
          } else {
            notify('Select or add an element first to attach this behavior');
          }
        };
      });
    }

    async function runSecretAiAnalyze() {
      if (secretAiLoading) return;
      secretAiLoading = true;
      secretAiError = '';
      refreshSecretAiModal();

      try {
        const ctx = buildAiProjectContext(project, selectedId, {
          html: generatedHtml(),
          css: generatedCss(),
          js: generatedJs(),
        });
        const res = await fetch('/api/ai/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...ctx, customPrompt: secretAiCustomPrompt }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          throw new Error(data.error || `AI analysis failed (${res.status})`);
        }
        const validIds = new Set(allNodes().map((n) => n.id));
        secretAiAnalysis = normalizeAiAnalysisResult(data.analysis, validIds, uid);
        notify(`Detected: ${secretAiAnalysis.websiteType}`);
      } catch (err) {
        secretAiError = err?.message || 'Could not analyze project.';
      } finally {
        secretAiLoading = false;
        refreshSecretAiModal();
      }
    }

    async function runSecretAiGenerateTemplate() {
      if (secretAiLoading) return;
      secretAiLoading = true;
      secretAiError = '';
      refreshSecretAiModal();

      try {
        const res = await fetch('/api/ai/generate-template', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            websiteType: secretAiAnalysis?.websiteType || '',
            prompt: secretAiTemplatePrompt,
            category: secretAiTemplateCategory,
            existingName: project.name,
            existingSummary: generatedHtml().slice(0, 2500),
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          throw new Error(data.error || `Template generation failed (${res.status})`);
        }
        secretAiTemplateDraft = normalizeAiGeneratedTemplate(data.template, uid);
        notify('AI template generated');
      } catch (err) {
        secretAiError = err?.message || 'Could not generate AI template.';
      } finally {
        secretAiLoading = false;
        refreshSecretAiModal();
      }
    }

    function applyAiGeneratedTemplateLocally() {
      if (!secretAiTemplateDraft) return;
      const draftCopy = clone(secretAiTemplateDraft);
      const { project: imported } = sanitizeImportedTemplateProject(draftCopy, draftCopy.title, uid);
      if (draftCopy.customJs) {
        imported.customJs = draftCopy.customJs;
      }
      projects.unshift(imported);
      project = imported;
      history = [];
      future = [];
      selectedId = null;
      saveProjects();
      closeModal();
      renderAll({ skipSave: true });
      notify(`Loaded "${imported.name}" into Studio`);
    }

    async function uploadAiTemplateToCommunity() {
      if (!secretAiTemplateDraft) return;
      if (!firebaseReady || !db || !storage) {
        secretAiError = 'Firebase is not configured for community template uploads.';
        return refreshSecretAiModal();
      }
      if (!currentUser) {
        return openAuthModal('signin', 'Sign in to upload this AI-generated template to the community library.', 'warning');
      }
      if (!navigator.onLine) {
        secretAiError = 'Connect to the internet to upload a template.';
        return refreshSecretAiModal();
      }

      secretAiUploading = true;
      secretAiError = '';
      refreshSecretAiModal();

      try {
        const templateId = 'tpl_' + uid();
        const storagePath = `templates/${currentUser.uid}/${templateId}.json`;
        const payload = buildAiTemplateCommunityPayload(secretAiTemplateDraft);

        await uploadString(storageRef(storage, storagePath), JSON.stringify(payload), 'raw', {
          contentType: 'application/json',
        });

        const authorName = String(currentProfile?.displayName || currentUser.displayName || 'Creator').slice(0, 80);
        await setDoc(doc(db, 'templates', templateId), {
          authorId: currentUser.uid,
          authorName,
          title: payload.title,
          description: payload.description,
          category: payload.category,
          version: 1,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
          storagePath,
          status: 'published',
          nodeCount: countProjectNodes(payload.nodes),
        });

        notify('AI template uploaded to community library');
        await loadCommunityTemplates();
        closeModal();
        setPanel('templates');
      } catch (err) {
        secretAiError = err?.message || 'Could not upload template.';
        refreshSecretAiModal();
      } finally {
        secretAiUploading = false;
      }
    }

    function renameProject() {
      openModal('Rename project', 'PROJECT SETTINGS', `
        <label class="field-title">Project name</label>
        <input class="control" id="renameInput" value="${escapeHtml(project.name)}">
        <div class="modal-actions" style="margin-top:14px">
          <button class="primary-button" id="confirmRename">Save name</button>
          <button class="soft-button" id="duplicateActive">Duplicate project</button>
        </div>
      `);
      $('#confirmRename').onclick = () => {
        const value = $('#renameInput').value.trim();
        if (!value) return notify('Enter a project name');
        remember();
        project.name = value;
        renderAll();
        closeModal();
        notify('Project renamed');
      };
      $('#duplicateActive').onclick = () => {
        const copy = clone(project);
        copy.id = uid();
        copy.name += ' copy';
        copy.syncMeta = { cloudVersion: 0, lastSyncedHash: '', lastSyncedAt: 0 };
        projects.unshift(copy);
        project = copy;
        saveProjects();
        closeModal();
        renderAll({ skipSave: true });
        notify('Project duplicated');
      };
    }

    function exportDialog() {
      const bi = project.backendIntegration || { provider: 'none', endpoint: '' };
      openModal('Export your website', 'EXPORT', `
        <p class="muted-copy">Download clean website source, a self-contained HTML page, or a project backup you can import later.</p>
        <div class="status-banner">
          <strong>Clean backend separation:</strong> Exported websites never include Studio's Firebase credentials or platform data. Configured site target: <strong>${escapeHtml(bi.provider || 'none')}</strong>.
        </div>
        <div class="template-card"><div><strong>Single HTML file</strong><small>HTML + CSS + JavaScript together</small></div><button class="primary-button" id="exportSingle">Download</button></div>
        <div class="template-card"><div><strong>Separate source files</strong><small>index.html, style.css, and script.js</small></div><button class="soft-button" id="exportFiles">Download</button></div>
        <div class="template-card"><div><strong>Project backup</strong><small>Editable project JSON (without platform secrets)</small></div><button class="soft-button" id="exportJson">Download</button></div>
      `);
      $('#exportSingle').onclick = () => download('index.html', singleHtml(), 'text/html');
      $('#exportFiles').onclick = () => {
        download('index.html', generatedHtml(), 'text/html');
        download('style.css', generatedCss(), 'text/css');
        download('script.js', generatedJs(), 'text/javascript');
        notify('Source files downloaded');
      };
      $('#exportJson').onclick = () => download(
        project.name.replace(/[^a-z0-9-_]/gi, '-') + '.json',
        JSON.stringify(buildExportSafeProjectPayload(project), null, 2),
        'application/json'
      );
    }

    function singleHtml() {
      return generatedHtml()
        .replace('<link rel="stylesheet" href="style.css">', `<style>\n${generatedCss()}\n</style>`)
        .replace('<script src="script.js"></script>', `<script>\n${generatedJs().replace(/<\/script/gi, '<\\/script')}\n<\/script>`);
    }

    function download(filename, content, type) {
      const blob = new Blob([content], { type });
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = filename;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    }

    function importFile(file) {
      const reader = new FileReader();
      reader.onload = () => {
        try {
          const text = String(reader.result);
          if (file.name.toLowerCase().endsWith('.json')) {
            const imported = JSON.parse(text);
            if (!imported.nodes || !Array.isArray(imported.nodes)) throw Error('This project file is not supported');
            imported.nodes = sanitizeTemplateNodes(imported.nodes, uid);
            project = imported;
            project.id = uid();
            project.updated = Date.now();
            project.syncMeta = { cloudVersion: 0, lastSyncedHash: '', lastSyncedAt: 0 };
          } else {
            const docParsed = new DOMParser().parseFromString(text, 'text/html');
            project = defaultProject();
            project.name = docParsed.title || file.name.replace(/\.html?$/i, '');
            project.nodes = [...docParsed.body.children]
              .filter((el) => !BLOCKED_TAGS.has(el.tagName.toLowerCase()))
              .map(domToNode);
            const css = docParsed.querySelector('style');
            if (css) project.customCss = sanitizeCssText(css.textContent);
            const link = docParsed.querySelector('link[rel="stylesheet"]');
            if (link) notify('Imported HTML. External linked stylesheets are not included.');
          }
          normalizeProject(project);
          projects.unshift(project);
          selectedId = null;
          saveProjects();
          closeModal();
          renderAll({ skipSave: true });
          notify('Project imported');
        } catch (error) {
          notify('Import failed: ' + error.message);
        }
      };
      reader.readAsText(file);
    }

    function preview() {
      previewMode = true;
      const html = singleHtml();
      openModal('Live preview', 'INTERACTIVE PREVIEW', `
        <div class="action-row" style="margin-bottom:10px">
          <button class="soft-button" id="previewMobile">Mobile</button>
          <button class="soft-button" id="previewTablet">Tablet</button>
          <button class="soft-button" id="previewDesktop">Desktop</button>
        </div>
        <iframe id="previewFrame" title="Interactive website preview" sandbox="allow-scripts allow-forms allow-popups" style="width:100%;height:65dvh;border:1px solid #353746;border-radius:9px;background:white"></iframe>
      `);
      const frame = $('#previewFrame');
      frame.srcdoc = html;
      const setSize = (width) => {
        frame.style.width = width + 'px';
        frame.style.maxWidth = '100%';
      };
      $('#previewMobile').onclick = () => setSize(375);
      $('#previewTablet').onclick = () => setSize(768);
      $('#previewDesktop').onclick = () => setSize(1100);
      setSize(previewWidth);
      previewMode = false;
    }

    // ------------------------------------------------------------------------
    // Event Listeners (Attached cleanly once)
    // ------------------------------------------------------------------------
    $$('.rail-item,.dock-item').forEach((button) => {
      button.onclick = () => setPanel(button.dataset.panel);
    });
    $('#closePanel').onclick = () => setPanel('canvas');
    $('#inspectorCollapse').onclick = () => $('#rightPanel').classList.remove('open');
    $('#homeButton').onclick = showDashboard;
    $('#renameButton').onclick = renameProject;
    $('#undoButton').onclick = undo;
    $('#redoButton').onclick = redo;
    $('#saveButton').onclick = async () => {
      saveProjects({ immediateCloud: true });
      notify(currentUser
        ? (navigator.onLine ? 'Saved locally & syncing to cloud' : 'Saved locally (waiting for internet)')
        : 'Project saved on this device');
    };
    $('#previewButton').onclick = preview;
    $('#exportButton').onclick = exportDialog;
    $('#authButton').onclick = () => openAuthModal('signin');
    $('#syncStatusButton').onclick = () => {
      if (!currentUser) return openAuthModal('signin', 'Sign in to enable cloud synchronization across devices.', '');
      showConflictModal();
    };
    $('#secretAiButton').onclick = () => openSecretAiModal('analyze');
    $('#moreButton').onclick = () => {
      openModal('More options', 'PROJECT TOOLS', `
        <div class="modal-actions">
          <button class="soft-button" id="moreSecretAi">✦ Secret AI assistant</button>
          <button class="soft-button" id="themeButton">Toggle light / dark theme</button>
          <button class="soft-button" id="moreImport">Import project</button>
          <button class="soft-button" id="moreDashboard">Project dashboard</button>
          <button class="soft-button" id="moreTemplates">Community templates</button>
          <button class="soft-button" id="moreAccount">${currentUser ? 'Account & profile' : 'Sign in / Create account'}</button>
        </div>
        <p class="muted-copy">Projects save locally first in IndexedDB and browser storage, and sync to Firebase when signed in and online.</p>
      `);
      $('#moreSecretAi').onclick = () => openSecretAiModal('analyze');
      $('#themeButton').onclick = () => {
        const light = localStorage.getItem('studio-theme') !== 'light';
        localStorage.setItem('studio-theme', light ? 'light' : 'dark');
        renderAll({ skipSave: true });
        notify(light ? 'Light theme enabled' : 'Dark theme enabled');
      };
      $('#moreImport').onclick = () => $('#importFile').click();
      $('#moreDashboard').onclick = showDashboard;
      $('#moreTemplates').onclick = () => {
        closeModal();
        setPanel('templates');
      };
      $('#moreAccount').onclick = () => openAuthModal('signin');
    };

    $('#modalClose').onclick = closeModal;
    $('#modalBackdrop').onclick = (event) => {
      if (event.target === $('#modalBackdrop')) closeModal();
    };
    $('#importFile').onchange = (event) => {
      if (event.target.files[0]) importFile(event.target.files[0]);
      event.target.value = '';
    };
    $('#fullscreenButton').onclick = () => {
      const area = $('#canvasArea');
      if (!document.fullscreenElement) area.requestFullscreen?.();
      else document.exitFullscreen?.();
    };
    $$('.viewport-button').forEach((button) => {
      button.onclick = () => {
        $$('.viewport-button').forEach((item) => item.classList.toggle('active', item === button));
        previewWidth = +button.dataset.width;
        $('#pageCanvas').style.width = `${previewWidth}px`;
        renderCanvas();
      };
    });

    window.addEventListener('online', () => {
      if (currentUser) {
        notify('Internet restored — syncing queued changes');
        processSyncQueue();
      }
    });
    window.addEventListener('offline', () => {
      if (currentUser) {
        updateSyncIndicator('waiting-offline', 'Offline — edits saved locally.');
        notify('Offline mode — edits will sync when internet returns');
      }
    });

    document.addEventListener('keydown', (event) => {
      const editing = /^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName) || event.target.isContentEditable;
      const shortcut = event.ctrlKey || event.metaKey;
      if (shortcut && event.key.toLowerCase() === 'k' && (event.shiftKey || !editing)) {
        event.preventDefault();
        openSecretAiModal('analyze');
        return;
      }
      if (!editing && shortcut && event.key.toLowerCase() === 'z') {
        event.preventDefault();
        event.shiftKey ? redo() : undo();
        return;
      }
      if (!editing && shortcut && event.key.toLowerCase() === 'y') {
        event.preventDefault();
        redo();
        return;
      }
      if (!editing && shortcut && event.key.toLowerCase() === 'c') {
        event.preventDefault();
        copySelected();
        return;
      }
      if (!editing && shortcut && event.key.toLowerCase() === 'v') {
        event.preventDefault();
        pasteSelected();
        return;
      }
      if (!editing && (event.key === 'Delete' || event.key === 'Backspace') && selectedId) {
        event.preventDefault();
        deleteNode(selectedId);
        return;
      }
      if (event.key === 'Escape') {
        if (!$('#modalBackdrop').classList.contains('hidden')) closeModal();
        else if (selectedId) {
          selectedId = null;
          renderAll({ skipSave: true });
        }
      }
    });

    // Expose safe non-sensitive editor diagnostics/helpers for testing
    window.__STUDIO_STATE__ = () => ({
      authInitialized,
      signedIn: Boolean(currentUser),
      syncState,
      projectCount: projects.length,
      activeProjectId: project.id,
      activeProjectHash: computeProjectHash(project),
      secretAiHasAnalysis: Boolean(secretAiAnalysis),
      secretAiHasTemplate: Boolean(secretAiTemplateDraft),
    });

    updateSyncIndicator(currentUser ? (navigator.onLine ? 'synchronized' : 'waiting-offline') : 'local-only');
    updateAuthButtonUI();
    renderAll({ skipSave: true });
    hydrateFromIndexedDB();
  })();
}
