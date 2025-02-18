import express from 'express';
import axios from 'axios';
import morgan from 'morgan';
import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import { createRequire } from 'module';
import {
    PORT,
    OLLAMA_BASE_URL,
    API_KEYS,
    LOG_DIR,
    CACHE_TTL
} from './config.js';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cluster from 'cluster';
import os from 'os';
import crypto from 'crypto';

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Cluster模式优化
if (cluster.isPrimary && process.env.NODE_ENV !== 'development') {
    const numCPUs = os.cpus().length;
    for (let i = 0; i < numCPUs; i++) {
        cluster.fork();
    }
    cluster.on('exit', (worker) => {
        console.log(`Worker ${worker.process.pid} died`);
        cluster.fork();
    });
} else {
    const app = express();

    // 安全增强
    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'"],
                styleSrc: ["'self'", "'unsafe-inline'"]
            }
        }
    }));
    app.use(express.json({ limit: '10mb' }));

    // 限流配置
    const apiLimiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 1000,
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator: (req) => req.ip,
        handler: (req, res) => {
            logger.warn('Rate limit exceeded', { ip: req.ip });
            res.status(429).json({
                error: {
                    message: 'Too many requests',
                    type: 'rate_limit_exceeded'
                }
            });
        }
    });

    // 自动创建日志目录
    if (!fs.existsSync(LOG_DIR)) {
        fs.mkdirSync(LOG_DIR, { recursive: true });
    }

    // Winston日志配置
    const { combine, timestamp, json, errors } = winston.format;
    const logger = winston.createLogger({
        level: process.env.NODE_ENV === 'development' ? 'debug' : 'info',
        format: combine(
            timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
            json(),
            errors({ stack: true })
        ),
        transports: [
            new winston.transports.Console({
                format: winston.format.combine(
                    winston.format.colorize(),
                    winston.format.printf(info => {
                        const { timestamp, level, message, ...meta } = info;
                        return `[${timestamp}] ${level}: ${message} ${Object.keys(meta).length ? JSON.stringify(meta) : ''}`;
                    })
                )
            }),
            new DailyRotateFile({
                filename: path.join(LOG_DIR, 'application-%DATE%.log'),
                datePattern: 'YYYY-MM-DD',
                zippedArchive: true,
                maxSize: '100m',
                maxFiles: '14d',
                auditFile: path.join(LOG_DIR, 'audit.json')
            })
        ],
        rejectionHandlers: [
            new DailyRotateFile({
                filename: path.join(LOG_DIR, 'rejections-%DATE%.log')
            })
        ]
    });

    // 增强的Morgan配置
    morgan.token('req-body', (req) => {
        if (req.body && Object.keys(req.body).length > 0) {
            return JSON.stringify(req.body).slice(0, 1000);
        }
        return '-';
    });

    app.use(morgan(
        ':method :url :status :response-time ms - req-body: :req-body - res-length: :res[content-length]',
        {
            stream: {
                write: (message) => {
                    logger.http(message.trim());
                }
            },
            skip: (req) => req.path === '/healthcheck'
        }
    ));

    // 请求追踪中间件
    app.use((req, res, next) => {
        const start = Date.now();
        req.requestId = crypto.randomUUID();

        // 请求内容记录
        const requestLog = {
            requestId: req.requestId,
            method: req.method,
            path: req.path,
            client: {
                ip: req.ip,
                ua: req.headers['user-agent']?.slice(0, 100) || 'unknown'
            },
            parameters: {
                model: req.body.model,
                temperature: req.body.temperature,
                max_tokens: req.body.max_tokens,
                stream: req.body.stream || false
            },
            messages: req.body.messages?.map(m => ({
                role: m.role,
                content: m.content.slice(0, 500)
            })) || [],
            message_count: req.body.messages?.length || 0
        };
        logger.debug('Request started', requestLog);

        // 响应处理增强
        res.on('finish', () => {
            logger.debug('Request completed', {
                requestId: req.requestId,
                duration: `${Date.now() - start}ms`,
                statusCode: res.statusCode
            });
        });

        // 非流式响应拦截
        const originalJson = res.json;
        res.json = (body) => {
            logger.info('API Response', {
                requestId: req.requestId,
                response: {
                    content: body.choices?.[0]?.message?.content?.slice(0, 2000),
                    model: body.model,
                    token_usage: body.usage
                },
                duration: `${Date.now() - start}ms`
            });
            return originalJson.call(res, body);
        };

        // 流式响应拦截（新增）
        let streamResponse = '';
        const originalWrite = res.write;
        const originalEnd = res.end;

        res.write = function(chunk) {
            try {
                const str = chunk.toString();
                if (str.startsWith('data: {')) {
                    const jsonStr = str.replace('data: ', '');
                    const data = JSON.parse(jsonStr);
                    if (data.choices?.[0]?.delta?.content) {
                        streamResponse += data.choices[0].delta.content;
                    }
                }
            } catch (e) {
                logger.error('Stream log parse error', {
                    requestId: req.requestId,
                    error: e.message
                });
            }
            return originalWrite.apply(res, arguments);
        };

        res.end = function(chunk) {
            if (chunk) {
                try {
                    const str = chunk.toString();
                    if (str.startsWith('data: {')) {
                        const jsonStr = str.replace('data: ', '');
                        const data = JSON.parse(jsonStr);
                        if (data.choices?.[0]?.delta?.content) {
                            streamResponse += data.choices[0].delta.content;
                        }
                    }
                } catch (e) {
                    logger.error('Stream end log parse error', {
                        requestId: req.requestId,
                        error: e.message
                    });
                }
            }

            if (streamResponse) {
                logger.info('Stream Response', {
                    requestId: req.requestId,
                    response_content: streamResponse.slice(0, 2000),
                    response_length: streamResponse.length,
                    model: req.body.model
                });
            }

            return originalEnd.apply(res, arguments);
        };

        next();
    });

    // 缓存中间件
    const responseCache = new Map();
    const cacheMiddleware = (req, res, next) => {
        const key = `${req.path}:${JSON.stringify(req.body)}`;
        if (responseCache.has(key)) {
            return res.json(responseCache.get(key));
        }
        res.sendResponse = res.json;
        res.json = (body) => {
            responseCache.set(key, body);
            setTimeout(() => responseCache.delete(key), CACHE_TTL * 1000);
            res.sendResponse(body);
        };
        next();
    };

    // API Key验证
    const authenticateApiKey = (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader?.startsWith('Bearer ')) {
            logger.warn('Invalid auth header', {
                ip: req.ip,
                headers: req.headers
            });
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const apiKey = authHeader.split(' ')[1];
        if (!API_KEYS.includes(apiKey)) {
            logger.warn('Invalid API key attempt', {
                ip: req.ip,
                providedKey: apiKey.slice(0, 4) + '***'
            });
            return res.status(403).json({ error: 'Forbidden' });
        }

        next();
    };
    // 流式处理增强
    const handleOllamaStream = async (req, res) => {
        const startTime = Date.now();
        let isRequestClosed = false;
        const controller = new AbortController();

        try {
            req.on('close', () => {
                isRequestClosed = true;
                controller.abort();
                res.end();
                logger.info('Stream aborted by client', {
                    requestId: req.requestId,
                    duration: `${Date.now() - startTime}ms`
                });
            });

            logger.info('Stream started', {
                requestId: req.requestId,
                model: req.body.model,
                messageCount: req.body.messages?.length || 0
            });

            const { data: stream } = await axios.post(`${OLLAMA_BASE_URL}/api/generate`, {
                model: req.body.model,
                prompt: buildPrompt(req.body.messages),
                stream: true,
                options: {
                    temperature: req.body.temperature ?? 0.7,
                    top_p: req.body.top_p ?? 0.9,
                    max_tokens: req.body.max_tokens ?? 2048
                }
            }, {
                responseType: 'stream',
                signal: controller.signal,
                timeout: 30000
            });

            res.set({
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'X-Request-ID': req.requestId
            });

            let fullResponse = '';
            let lastActivity = Date.now();

            // 心跳检测
            const heartbeatInterval = setInterval(() => {
                if (Date.now() - lastActivity > 20000) {
                    res.write(': heartbeat\n\n');
                }
            }, 5000);

            for await (const chunk of stream) {
                if (isRequestClosed) break;
                lastActivity = Date.now();

                const lines = chunk.toString().split('\n').filter(l => l.trim());
                for (const line of lines) {
                    const { response, done } = JSON.parse(line);
                    fullResponse += response;

                    const eventData = {
                        id: `chatcmpl-${Date.now()}`,
                        object: 'chat.completion.chunk',
                        created: Math.floor(Date.now() / 1000),
                        model: req.body.model,
                        choices: [{
                            delta: { content: response },
                            finish_reason: done ? 'stop' : null
                        }]
                    };

                    res.write(`data: ${JSON.stringify(eventData)}\n\n`);

                    if (done) {
                        clearInterval(heartbeatInterval);
                        res.write('data: [DONE]\n\n');
                        logger.info('Stream completed', {
                            requestId: req.requestId,
                            model: req.body.model,
                            tokenCount: fullResponse.length,
                            duration: `${Date.now() - startTime}ms`
                        });
                        return res.end();
                    }
                }
            }
        } catch (err) {
            clearInterval(heartbeatInterval);
            if (!isRequestClosed) {
                logger.error('Stream error', {
                    requestId: req.requestId,
                    error: err.message,
                    stack: err.stack,
                    code: err.code
                });

                const errorEvent = {
                    error: {
                        message: 'Stream processing failed',
                        code: 'STREAM_ERROR',
                        details: err.message
                    }
                };
                res.write(`data: ${JSON.stringify(errorEvent)}\n\n`);
                res.write('data: [DONE]\n\n');
                res.end();
            }
        }
    };

    app.post('/v1/chat/completions',
        apiLimiter,
        authenticateApiKey,
        cacheMiddleware,
        async (req, res) => {
            try {
                if (!req.body.model) {
                    logger.warn('Missing model parameter', {
                        requestId: req.requestId
                    });
                    return res.status(400).json({
                        error: 'Missing model parameter'
                    });
                }

                if (req.body.stream) {
                    return handleOllamaStream(req, res);
                }

                const response = await axios.post(`${OLLAMA_BASE_URL}/api/generate`, {
                    model: req.body.model,
                    prompt: buildPrompt(req.body.messages),
                    stream: false,
                    options: {
                        temperature: req.body.temperature ?? 0.7,
                        top_p: req.body.top_p ?? 0.9,
                        max_tokens: req.body.max_tokens ?? 2048
                    }
                });

                const result = {
                    id: `chatcmpl-${Date.now()}`,
                    object: 'chat.completion',
                    created: Math.floor(Date.now() / 1000),
                    model: req.body.model,
                    usage: calculateTokens(response.data.response),
                    choices: [{
                        message: {
                            role: 'assistant',
                            content: response.data.response.trim()
                        }
                    }]
                };

                res.json(result);
            } catch (err) {
                logger.error('API Error', {
                    requestId: req.requestId,
                    error: err.message,
                    stack: err.stack,
                    model: req.body.model
                });

                const statusCode = err.response?.status || 502;
                res.status(statusCode).json({
                    error: {
                        type: 'backend_error',
                        message: 'Model service unavailable',
                        code: 50301,
                        details: err.message
                    }
                });
            }
        }
    );

    app.listen(PORT, () => {
        logger.info(`Server (Worker ${process.pid}) running in ${process.env.NODE_ENV} mode on port ${PORT}`);
    });
}

function buildPrompt(messages) {
    return messages.map(m => `${m.role}: ${m.content}`).join('\n') + '\nassistant:';
}

function calculateTokens(text) {
    const words = text.split(/\s+/).length;
    const chars = text.length;
    return {
        prompt_tokens: Math.ceil(chars / 4),
        completion_tokens: Math.ceil(chars / 4),
        total_tokens: Math.ceil(chars / 2)
    };
}
