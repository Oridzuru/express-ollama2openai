import { config } from 'dotenv';
config();

export const PORT = process.env.PORT || 20203;
export const OLLAMA_BASE_URL = process.env.OLLAMA_URL || 'http://127.0.0.1:20202';
export const API_KEYS = process.env.API_KEYS?.split(',') || [];
export const LOG_DIR = './logs';
export const CACHE_TTL = 3600; // 1小时缓存
// const logger = winston.createLogger({
//     // ... [保持原有transports配置] ...
//     format: combine(
//         timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
//         winston.format((info) => {
//             // 敏感信息过滤
//             if (info.body?.messages) {
//                 info.body.messages = info.body.messages.map(m => ({
//                     ...m,
//                     content: m.content.replace(/password: .+/i, '******')
//                 }));
//             }
//             return info;
//         })(),
//         json()
//     )
// });
