# <img src="assets/logo.png" alt="Stremio AI Subtitle Translator" width="50">  Stremio AI Subtitle Translator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Self-Hosted](https://img.shields.io/badge/Self--Hosted-Yes-green.svg)](https://github.com)
[![Stremio Addon](https://img.shields.io/badge/Stremio-Addon-blue.svg)](https://www.stremio.com)

A self-hostable Stremio addon that automatically translates subtitles to your preferred languages using AI. When native subtitles aren't available, it fetches English subtitles and translates them using AI models via OpenRouter.

---

## ✨ Features

- 🌍 **Multi-language Support**: Configure unlimited preferred languages
- 🤖 **AI-Powered Translation**: Automatic translation using Llama, Gemma, and Mistral models
- 🔄 **Smart Fallback**: Automatically fetches English subtitles when native ones aren't available
- 🐳 **Docker Support**: One-command deployment
- 🔒 **Secure**: Password-protected, encrypted configurations
- 🌐 **Web Interface**: Easy configuration at `/configure`

---

## 🚀 Quick Start

### Docker (Recommended)

```bash
git clone <repository-url>
cd AISubs
cp .env.sample .env
# Add MASTER_KEY=$(openssl rand -hex 32) to .env
docker-compose up -d
```

### Local Installation

```bash
git clone <repository-url>
cd AISubs
bun install  # or npm install

# Create .env file
cat > .env << EOF
PORT=7001
BASE_URL=http://127.0.0.1:7001
MASTER_KEY=$(openssl rand -hex 32)
EOF

bun start  # or npm start
```

### Configure & Install

1. **Get OpenRouter API Key**: [Get a free key here](https://openrouter.ai/keys)
2. **Configure**: Visit `http://localhost:7001/configure`
   - Create a password
   - Enter your OpenRouter API key
   - Set preferred languages (e.g., `ta,te,hi,es,fr`)
3. **Install in Stremio**: Add `http://localhost:7001/manifest.json` in Stremio → Addons

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `7001` |
| `BASE_URL` | Base URL for addon | `http://127.0.0.1:7001` |
| `MASTER_KEY` | 32-byte hex encryption key | Required |

Generate MASTER_KEY: `openssl rand -hex 32`

### Supported Languages

Use ISO 639-1 codes: `en`, `ta`, `te`, `hi`, `es`, `fr`, `de`, `it`, `pt`, `ja`, `ko`, `zh`, etc.

[Full list of ISO 639-1 codes](https://en.wikipedia.org/wiki/List_of_ISO_639-1_codes)

### AI Models

Automatically selects from: Llama 3.1, Gemma 2 (9B, 2B, 1.1B), Mistral 7B

---

## 🔒 Security

- Password-protected configurations
- AES-256-CBC encryption
- PBKDF2 password hashing (100,000 iterations)
- Each config encrypted separately

---

## 🐛 Troubleshooting

**No subtitles appearing**: Verify OpenRouter API key is configured and wyzie-lib can find subtitles

**Translation not working**: Check OpenRouter quota and ensure languages are correctly set

**Configuration not saving**: Verify `MASTER_KEY` is set in `.env` and check file permissions

---

## 📝 License

MIT License

---

## 🙏 Acknowledgments

Built for the Stremio community. Uses [wyzie-lib](https://github.com/wyzie/subtitle-lib) and powered by [OpenRouter](https://openrouter.ai).
