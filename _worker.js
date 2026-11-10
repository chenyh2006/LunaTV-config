// 统一入口：兼容 Cloudflare Workers 和 Pages Functions
// 私有访问版：配置环境变量 ACCESS_TOKEN 后，所有订阅/代理请求必须携带正确密钥
export default {
  async fetch(request, env, ctx) {
    // Pages Functions 中 KV 需要从 env 中获取
    if (env && env.KV && typeof globalThis.KV === 'undefined') {
      globalThis.KV = env.KV
    }

    return handleRequest(request, env)
  }
}

// 常量配置（避免重复创建）
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
}

const EXCLUDE_HEADERS = new Set([
  'content-encoding', 'content-length', 'transfer-encoding',
  'connection', 'keep-alive', 'set-cookie', 'set-cookie2'
])

const JSON_SOURCES = {
  'jin18': 'https://raw.githubusercontent.com/chenyh2006/LunaTV-config/refs/heads/main/jin18.json',
  'jingjian': 'https://raw.githubusercontent.com/chenyh2006/LunaTV-config/refs/heads/main/jingjian.json',
  'full': 'https://raw.githubusercontent.com/chenyh2006/LunaTV-config/refs/heads/main/LunaTV-config.json'
}

const FORMAT_CONFIG = {
  '0': { proxy: false, base58: false },
  'raw': { proxy: false, base58: false },
  '1': { proxy: true, base58: false },
  'proxy': { proxy: true, base58: false },
  '2': { proxy: false, base58: true },
  'base58': { proxy: false, base58: true },
  '3': { proxy: true, base58: true },
  'proxy-base58': { proxy: true, base58: true },
  '4': { tvbox: true },
  'tvbox': { tvbox: true }
}

// ---------- 访问鉴权（私有模式）----------
// 读取密钥：环境变量 ACCESS_TOKEN（推荐，在 CF 控制台加密配置）
function getExpectedToken(env) {
  try {
    if (env && env.ACCESS_TOKEN) return String(env.ACCESS_TOKEN).trim()
    if (typeof globalThis.ACCESS_TOKEN !== 'undefined' && globalThis.ACCESS_TOKEN) {
      return String(globalThis.ACCESS_TOKEN).trim()
    }
  } catch (e) {}
  return ''
}

// 恒定时间比较，避免时序泄露
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

function isAuthorized(request, reqUrl, expectedToken) {
  // 未配置密钥 => 兼容旧行为（公开），但本部署已配置，故不会走到这里
  if (!expectedToken) return true
  const q = reqUrl.searchParams.get('token') || ''
  if (q && timingSafeEqual(q, expectedToken)) return true
  const auth = request.headers.get('Authorization') || ''
  if (auth.startsWith('Bearer ')) {
    const t = auth.slice(7).trim()
    if (t && timingSafeEqual(t, expectedToken)) return true
  }
  const xToken = request.headers.get('X-Access-Token') || ''
  if (xToken && timingSafeEqual(xToken.trim(), expectedToken)) return true
  return false
}

// Base58 编码函数
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
function base58Encode(obj) {
  const str = JSON.stringify(obj)
  const bytes = new TextEncoder().encode(str)

  let intVal = 0n
  for (let b of bytes) {
    intVal = (intVal << 8n) + BigInt(b)
  }

  let result = ''
  while (intVal > 0n) {
    const mod = intVal % 58n
    result = BASE58_ALPHABET[Number(mod)] + result
    intVal = intVal / 58n
  }

  for (let b of bytes) {
    if (b === 0) result = BASE58_ALPHABET[0] + result
    else break
  }

  return result
}

// JSON api 字段前缀替换
function addOrReplacePrefix(obj, newPrefix) {
  if (typeof obj !== 'object' || obj === null) return obj
  if (Array.isArray(obj)) return obj.map(item => addOrReplacePrefix(item, newPrefix))
  const newObj = {}
  for (const key in obj) {
    if (key === 'api' && typeof obj[key] === 'string') {
      let apiUrl = obj[key]
      const urlIndex = apiUrl.indexOf('?url=')
      if (urlIndex !== -1) apiUrl = apiUrl.slice(urlIndex + 5)
      if (!apiUrl.startsWith(newPrefix)) apiUrl = newPrefix + apiUrl
      newObj[key] = apiUrl
    } else {
      newObj[key] = addOrReplacePrefix(obj[key], newPrefix)
    }
  }
  return newObj
}

// 从代理 URL 中还原出原始目标地址（兼容编码与未编码两种历史形式）
function extractTargetUrl(proxyUrl) {
  try {
    const u = new URL(proxyUrl)
    const t = u.searchParams.get('url')
    if (t) return t
  } catch (e) {}
  // 兜底：未编码旧链接，在顶层 token 前截断
  const m = proxyUrl.match(/[?&]url=(.*?)(?:&token=|$)/)
  return m ? decodeURIComponent(m[1]) : proxyUrl
}

// 把所有 api 代理链接规范化为：<origin>/?url=<编码后的目标>&token=<密钥>
// 目标编码后，token 始终是独立顶层参数，绝不会被并入转发目标
function normalizeProxyApi(obj, token) {
  if (typeof obj !== 'object' || obj === null) return
  if (Array.isArray(obj)) {
    for (const item of obj) normalizeProxyApi(item, token)
    return
  }
  for (const key in obj) {
    if (key === 'api' && typeof obj[key] === 'string' && obj[key].includes('?url=')) {
      try {
        const proxy = new URL(obj[key])
        const target = extractTargetUrl(obj[key])
        let rebuilt = proxy.origin + '/?url=' + encodeURIComponent(target)
        if (token) rebuilt += '&token=' + encodeURIComponent(token)
        obj[key] = rebuilt
      } catch (e) {
        if (!obj[key].includes('token=')) obj[key] += ('&token=' + token)
      }
    } else {
      normalizeProxyApi(obj[key], token)
    }
  }
}

// ---------- 安全版：KV 缓存 ----------
async function getCachedJSON(url) {
  const kvAvailable = typeof KV !== 'undefined' && KV && typeof KV.get === 'function'

  if (kvAvailable) {
    const cacheKey = 'CACHE_' + url
    const cached = await KV.get(cacheKey)
    if (cached) {
      try {
        return JSON.parse(cached)
      } catch (e) {
        await KV.delete(cacheKey)
      }
    }
    const res = await fetch(url)
    if (!res.ok) throw new Error(`Fetch failed: ${res.status}`)
    const data = await res.json()
    await KV.put(cacheKey, JSON.stringify(data), { expirationTtl: 1800 })   // 缓存十分钟
    return data
  } else {
    const res = await fetch(url)
    if (!res.ok) throw new Error(`Fetch failed: ${res.status}`)
    return await res.json()
  }
}

// ---------- 安全版：错误日志 ----------
async function logError(type, info) {
  console.error('[ERROR]', type, info)
  return
}

// ---------- 主逻辑 ----------
async function handleRequest(request, env) {
  // 快速处理 OPTIONS 请求
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS_HEADERS })
  }

  const reqUrl = new URL(request.url)
  const pathname = reqUrl.pathname
  const targetUrlParam = reqUrl.searchParams.get('url')
  const formatParam = reqUrl.searchParams.get('format')
  const prefixParam = reqUrl.searchParams.get('prefix')
  const sourceParam = reqUrl.searchParams.get('source')

  const expectedToken = getExpectedToken(env)
  const currentOrigin = reqUrl.origin
  const defaultPrefix = currentOrigin + '/?url='

  // 🩺 健康检查（不暴露任何订阅信息，无需鉴权，便于探活）
  if (pathname === '/health') {
    return new Response('OK', { status: 200, headers: CORS_HEADERS })
  }

  // 🔒 私有访问门控：订阅与代理接口一律校验密钥
  if (!isAuthorized(request, reqUrl, expectedToken)) {
    return new Response(
      JSON.stringify({ error: 'Forbidden', message: '缺少或错误的访问密钥（token）' }),
      { status: 403, headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS } }
    )
  }

  // 通用代理请求处理
  if (targetUrlParam) {
    return handleProxyRequest(request, targetUrlParam, currentOrigin)
  }

  // JSON 格式输出处理
  if (formatParam !== null) {
    return handleFormatRequest(formatParam, sourceParam, prefixParam, defaultPrefix, expectedToken, reqUrl)
  }

  // 私有模式不公开使用文档，仅返回极简提示，避免泄露接口结构
  return new Response('Private LunaTV subscription service.', {
    status: 200,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', ...CORS_HEADERS }
  })
}

// ---------- 代理请求处理子模块 ----------
async function handleProxyRequest(request, targetUrlParam, currentOrigin) {
  const reqUrl = new URL(request.url)
  // 标准解析：url 是独立查询参数（规范编码链接），token 不会被并入目标
  let fullTargetUrl = reqUrl.searchParams.get('url')
  if (!fullTargetUrl) {
    // 兜底：兼容未编码的历史链接，在顶层 token 前截断
    const m = request.url.match(/[?&]url=(.*?)(?:&token=|$)/)
    fullTargetUrl = m ? decodeURIComponent(m[1]) : targetUrlParam
  }
  // 双保险：移除误并入目标的 token；并把 TVBox 搜索/分类等业务参数透传给目标
  try {
    const tu = new URL(fullTargetUrl)
    if (tu.searchParams.has('token')) tu.searchParams.delete('token')
    const RESERVED = new Set(['url', 'token', 'prefix', 'format', 'source'])
    for (const [k, val] of reqUrl.searchParams.entries()) {
      if (!RESERVED.has(k) && !tu.searchParams.has(k)) tu.searchParams.append(k, val)
    }
    fullTargetUrl = tu.toString()
  } catch (e) {}

  // 🚨 防止递归调用自身
  if (fullTargetUrl.startsWith(currentOrigin)) {
    return errorResponse('Loop detected: self-fetch blocked', { url: fullTargetUrl }, 400)
  }

  // 🚨 防止无效 URL
  if (!/^https?:\/\//i.test(fullTargetUrl)) {
    return errorResponse('Invalid target URL', { url: fullTargetUrl }, 400)
  }

  let targetURL
  try {
    targetURL = new URL(fullTargetUrl)
  } catch {
    await logError('proxy', { message: 'Invalid URL', url: fullTargetUrl })
    return errorResponse('Invalid URL', { url: fullTargetUrl }, 400)
  }

  try {
    const proxyRequest = new Request(targetURL.toString(), {
      method: request.method,
      headers: request.headers,
      body: request.method !== 'GET' && request.method !== 'HEAD'
        ? await request.arrayBuffer()
        : undefined,
    })

    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 9000)
    const response = await fetch(proxyRequest, { signal: controller.signal })
    clearTimeout(timeoutId)

    const responseHeaders = new Headers(CORS_HEADERS)
    for (const [key, value] of response.headers) {
      if (!EXCLUDE_HEADERS.has(key.toLowerCase())) {
        responseHeaders.set(key, value)
      }
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    })
  } catch (err) {
    await logError('proxy', { message: err.message || '代理请求失败', url: fullTargetUrl })
    return errorResponse('Proxy Error', {
      message: err.message || '代理请求失败',
      target: fullTargetUrl,
      timestamp: new Date().toISOString()
    }, 502)
  }
}

// ---------- JSON 格式输出处理子模块 ----------
async function handleFormatRequest(formatParam, sourceParam, prefixParam, defaultPrefix, expectedToken, reqUrl) {
  try {
    const config = FORMAT_CONFIG[formatParam]
    if (!config) {
      return errorResponse('Invalid format parameter', { format: formatParam }, 400)
    }

    const selectedSource = JSON_SOURCES[sourceParam] || JSON_SOURCES['full']
    const data = await getCachedJSON(selectedSource)

    // TVBox 标准 sites 格式（TVBox / LMbox 等 com.github.tvbox.osc 系 App）
    if (config.tvbox) {
      const tvbox = buildTVBoxConfig(data, reqUrl, expectedToken, sourceParam)
      return new Response(JSON.stringify(tvbox), {
        headers: { 'Content-Type': 'application/json;charset=UTF-8', ...CORS_HEADERS },
      })
    }

    const newData = config.proxy
      ? addOrReplacePrefix(data, prefixParam || defaultPrefix)
      : data
    // 代理模式：把每个采集站链接规范化为编码形式并独立附带 token
    if (config.proxy && expectedToken) {
      normalizeProxyApi(newData, expectedToken)
    }

    if (config.base58) {
      const encoded = base58Encode(newData)
      return new Response(encoded, {
        headers: { 'Content-Type': 'text/plain;charset=UTF-8', ...CORS_HEADERS },
      })
    } else {
      return new Response(JSON.stringify(newData), {
        headers: { 'Content-Type': 'application/json;charset=UTF-8', ...CORS_HEADERS },
      })
    }
  } catch (err) {
    await logError('json', { message: err.message })
    return errorResponse(err.message, {}, 500)
  }
}

// 把 LunaTV 的 api_site 对象转换为标准 TVBox 配置（sites 数组，苹果 CMS type=3）
function buildTVBoxConfig(data, reqUrl, token, sourceParam) {
  const sites = []
  const apiSite = data && data.api_site
  if (apiSite && typeof apiSite === 'object') {
    const entries = Array.isArray(apiSite)
      ? apiSite.map((v, i) => [v.key || v.name || ('s' + i), v])
      : Object.entries(apiSite)
    let idx = 0
    for (const [host, v] of entries) {
      if (!v || !v.api) continue
      idx += 1
      // 采集站基础地址走 Worker 代理（带 token）；TVBox 搜索/分类参数由代理透传
      const proxied = reqUrl.origin + '/?url=' + encodeURIComponent(v.api) +
        (token ? '&token=' + encodeURIComponent(token) : '')
      sites.push({
        key: 'src' + idx,
        name: v.name || host,
        type: 3,
        api: proxied,
        searchable: 1,
        quickSearch: 1,
        filterable: 0
      })
    }
  }
  return {
    sites,
    lives: [],
    parses: [],
    flags: ['youku', 'qq', 'iqiyi', 'qiyi', 'letv', 'sohu', 'tudou', 'pptv', 'mgtv', 'wasu', 'bilibili', 'renrenmi'],
    wallPaper: 'https://picsum.photos/1920/1080'
  }
}

// ---------- 统一错误响应处理 ----------
function errorResponse(error, data = {}, status = 400) {
  return new Response(JSON.stringify({ error, ...data }), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
  })
}
