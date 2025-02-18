# express-ollama2openai
This repository contains a middleware designed to convert functionality similar to Ollama's API into OpenAI's style


### 项目简介
这是一个基于 Express 的聊天完成服务，支持与 Ollama 集成。该服务提供了 API Key 验证、速率限制、缓存和流式响应等功能。

### 安装指南
1. 克隆仓库：
   ```bash
   git clone <仓库地址>
   cd express-ollama2openai
   ```
2. 安装依赖项：
   ```bash
   npm install express winston axios crypto uuid
   ```

### 配置说明
编辑 `config.js` 文件，设置以下环境变量：
```javascript
const config = {
  PORT: process.env.PORT || 3000,
  OLLAMA_API: process.env.OLLAMA_API || 'http://localhost:11434',
  OPENAI_API: process.env.OPENAI_API || 'your_openai_api_key'
};
```

### 使用方法
#### 发送非流式请求
```bash
curl -X POST http://localhost:3000/api/chat/completions \
     -H "Content-Type: application/json" \
     -d '{"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "Hello!"}]}' \
     -H "Authorization: Bearer your_api_key"
```

#### 发送流式请求
```bash
curl -X POST http://localhost:3000/api/chat/completions \
     -H "Content-Type: application/json" \
     -d '{"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "Hello!"}], "stream": true}' \
     -H "Authorization: Bearer your_api_key"
```

### 错误处理
#### 401 Unauthorized
- **原因**: 无效的 API Key。
- **解决方法**: 确保在请求头中正确设置 `Authorization` 头。

#### 500 Internal Server Error
- **原因**: Ollama 服务内部错误。
- **解决方法**: 检查 Ollama 服务是否正常运行，并查看日志以获取更多信息。

### 日志记录
该服务使用 Winston 进行日志记录，日志文件位于 `logs/` 目录下。默认情况下，日志包含信息级别和错误级别记录。

### 注意事项
- **速率限制**: 服务启用了速率限制功能，请避免频繁请求。
- **缓存机制**: 非流式请求结果会被缓存，以提高响应速度。

### Project Introduction
This is an Express-based chat completion service integrated with Ollama. The service provides features such as API key verification, rate limiting, caching, and streaming responses.

### Installation Guide
1. Clone the repository:
   ```bash
   git clone <repository address>
   cd Chat Completion Service
   ```
2. Install dependencies:
   ```bash
   npm install express winston axios crypto uuid
   ```

### Configuration Instructions
Edit the `config.js` file and set the following environment variables:
```javascript
const config = {
  PORT: process.env.PORT || 3000,
  OLLAMA_API: process.env.OLLAMA_API || 'http://localhost:11434',
  OPENAI_API: process.env.OPENAI_API || 'your_openai_api_key'
};
```

### Usage Methods
#### Send Non-streaming Request
```bash
curl -X POST http://localhost:3000/api/chat/completions \
     -H "Content-Type: application/json" \
     -d '{"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "Hello!"}]}' \
     -H "Authorization: Bearer your_api_key"
```

#### Send Streaming Request
```bash
curl -X POST http://localhost:3000/api/chat/completions \
     -H "Content-Type: application/json" \
     -d '{"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "Hello!"}], "stream": true}' \
     -H "Authorization: Bearer your_api_key"
```

### Error Handling
#### 401 Unauthorized
- **Cause**: Invalid API Key.
- **Solution**: Ensure the `Authorization` header is correctly set.

#### 500 Internal Server Error
- **Cause**: Internal error in Ollama service.
- **Solution**: Check if the Ollama service is running and review logs for more information.

### Logging
The service uses Winston for logging, with log files located in the `logs/` directory. By default, logs include information-level and error-level records.

### Notes
- **Rate Limiting**: Rate limiting is enabled; avoid frequent requests.
- **Caching Mechanism**: Results of non-streaming requests are cached to improve response speed.
