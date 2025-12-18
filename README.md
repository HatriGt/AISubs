# Stremio AI Subtitle Translator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Stremio addon that provides AI-powered subtitle translation using OpenRouter. Automatically translates subtitles to your preferred languages when native subtitles are unavailable, supporting multiple AI models including Llama, Gemma, and Mistral.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Docker Deployment](#docker-deployment)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Security](#security)
- [License](#license)

## Overview

Stremio AI Subtitle Translator is an intelligent addon that enhances your Stremio experience by providing multilingual subtitle support. When subtitles in your preferred language are not available, the addon automatically fetches English subtitles from wyzie-lib and translates them using state-of-the-art AI models via OpenRouter.

### Key Capabilities

- **Multi-language Support**: Configure unlimited preferred languages
- **Intelligent Fallback**: Automatic translation when native subtitles are unavailable
- **High Performance**: Optimized parallel processing with intelligent chunking
- **Multiple AI Models**: Automatic model selection with rate limit management
- **Secure Configuration**: Password-protected, encrypted user settings

## Features

### Core Functionality

- ✅ **Multi-language Support**: Configure your preferred subtitle languages using ISO 639-1 codes
- ✅ **Smart Fallback System**: Automatically fetches and translates English subtitles when needed
- ✅ **wyzie-lib Integration**: Seamless integration with wyzie-lib for subtitle discovery
- ✅ **VTT Format Conversion**: Native Stremio-compatible subtitle format
- ✅ **Web Configuration Interface**: User-friendly configuration page for settings management

### Advanced Features

- 🚀 **Intelligent Chunking**: Optimized subtitle processing with parallel execution
- 🤖 **Multi-Model AI Support**: Automatic selection from Llama, Gemma, and Mistral models
- 🔒 **Secure Storage**: Password-protected, encrypted configuration files
- ⚡ **Rate Limit Management**: Built-in handling of API rate limits
- 📦 **Docker Support**: Production-ready containerized deployment

## Prerequisites

### System Requirements

- **Node.js**: v14 or higher, or **Bun** (recommended)
- **OpenRouter API Key**: [Get your API key here](https://openrouter.ai/keys)

### Required Services

- OpenRouter account with API access
- Network access to wyzie-lib subtitle service

## Quick Start

### Local Development

```bash
# Clone the repository
git clone <repository-url>
cd AISubs

# Install dependencies
bun install

# Create environment file
cp .env.sample .env
# Edit .env with your settings

# Generate MASTER_KEY
openssl rand -hex 32
# Add the generated key to .env

# Start the server
bun start
```

### Docker Deployment

```bash
# Clone and navigate
git clone <repository-url>
cd AISubs

# Create .env file
cp .env.sample .env
# Configure your settings

# Start with Docker Compose
docker-compose up -d
```

Access the configuration page at `http://localhost:7001/configure`

## Installation

### Step 1: Clone Repository

```bash
git clone <repository-url>
cd AISubs
```

### Step 2: Install Dependencies

```bash
bun install
# or
npm install
```

### Step 3: Environment Configuration

Create a `.env` file in the root directory:

```env
PORT=7001
BASE_URL=http://127.0.0.1:7001
MASTER_KEY=your_master_key_here_32_bytes_hex
```

#### Generating MASTER_KEY

The `MASTER_KEY` is used to encrypt public configurations for read-only access. Generate a secure 32-byte hex key:

```bash
openssl rand -hex 32
```

**Important**: Without a `MASTER_KEY`, configurations won't persist across server restarts. Always set this in production.

### Step 4: Start the Server

```bash
bun start
# or
npm start
```

The server will output:
- Manifest URL: `http://127.0.0.1:7001/manifest.json`
- Configuration page: `http://127.0.0.1:7001/configure`

### Step 5: Configure OpenRouter API Key

1. Visit the configuration page: `http://127.0.0.1:7001/configure`
2. Create a password (minimum 8 characters) for your configuration
3. Enter your OpenRouter API key in the configuration interface
4. Configure your preferred languages (comma-separated ISO 639-1 codes)
5. Save your configuration

**Note**: Each user must configure their own OpenRouter API key. The server does not provide a fallback API key.

### Step 6: Install in Stremio

1. Open Stremio application
2. Navigate to **Addons**
3. Click **Add Addon**
4. Paste the manifest URL: `http://127.0.0.1:7001/manifest.json`
5. The addon will appear in your addons list

## Configuration

### User Configuration

Access the configuration page at `http://localhost:7001/configure` to manage:

- **Preferred Languages**: Comma-separated ISO 639-1 language codes
  - Example: `ta,te,hi,es,fr,de,it,pt,ja,ko,zh`
- **OpenRouter API Key**: Your personal API key from OpenRouter
- **HTTP Referer**: Optional referer string for API requests
- **Translation Model**: Preferred AI model (optional, auto-selected if not specified)

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `PORT` | Server port number | No | `7001` |
| `BASE_URL` | Base URL for the addon | No | `http://127.0.0.1:7001` |
| `MASTER_KEY` | 32-byte hex encryption key | Yes (production) | Random (non-persistent) |
| `OPENROUTER_API_KEY` | Fallback API key | No | None |
| `OPENROUTER_REFERER` | Default referer string | No | None |

### Supported Language Codes

Use ISO 639-1 two-letter language codes:

| Code | Language | Code | Language |
|------|----------|------|----------|
| `en` | English | `ta` | Tamil |
| `te` | Telugu | `hi` | Hindi |
| `es` | Spanish | `fr` | French |
| `de` | German | `it` | Italian |
| `pt` | Portuguese | `ja` | Japanese |
| `ko` | Korean | `zh` | Chinese |

[Full list of ISO 639-1 codes](https://en.wikipedia.org/wiki/List_of_ISO_639-1_codes)

### Supported Media Types

- **Movies**: IMDB IDs (`tt1234567`) and TMDB IDs (`tmdb:123456`)
- **TV Series**: Full season and episode support

### AI Models

The addon automatically selects from available models in priority order:

| Model | Rate Limit | Priority |
|-------|------------|----------|
| `meta-llama/llama-3.1-8b-instruct` | 60 RPM, 1M TPM | 1 |
| `google/gemma-2-9b-it` | 60 RPM, 1M TPM | 2 |
| `google/gemma-2-2b-it` | 60 RPM, 1M TPM | 3 |
| `google/gemma-2-1.1b-it` | 60 RPM, 1M TPM | 4 |
| `mistralai/mistral-7b-instruct` | 60 RPM, 1M TPM | 5 |

## Usage

### Basic Workflow

1. **Start the Server**: Run `bun start` or `npm start`
2. **Configure Languages**: Visit the configuration page and set your preferred languages
3. **Watch Content**: Play any movie or TV show in Stremio
4. **Automatic Translation**: The addon automatically:
   - Searches for subtitles in your preferred languages
   - Falls back to English subtitles if not found
   - Translates English subtitles using AI
   - Serves translated subtitles in VTT format

### How It Works

```
┌─────────────────┐
│  Stremio Request│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Check Preferred │
│   Languages     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      Yes      ┌──────────────┐
│ Search wyzie-lib│ ────────────► │ Serve Native │
│  for Subtitles  │                │  Subtitles   │
└────────┬────────┘                └──────────────┘
         │ No
         ▼
┌─────────────────┐
│ Fetch English   │
│   Subtitles     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  AI Translation │
│  via OpenRouter │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Convert to VTT  │
│  and Serve      │
└─────────────────┘
```

### Translation Process

1. **Subtitle Discovery**: Searches wyzie-lib for subtitles in preferred languages
2. **Fallback Mechanism**: If not found, fetches English subtitles
3. **Intelligent Chunking**: Splits large subtitle files into optimized chunks
4. **Parallel Processing**: Processes chunks concurrently with rate limit management
5. **AI Translation**: Translates each chunk using the best available AI model
6. **Output Cleaning**: Removes AI commentary and instructions from translations
7. **Format Conversion**: Converts to VTT format for Stremio compatibility

## Docker Deployment

### Quick Start

```bash
# Clone repository
git clone <repository-url>
cd AISubs

# Create environment file
cp .env.sample .env
# Edit .env with your settings

# Generate MASTER_KEY
openssl rand -hex 32
# Add to .env

# Start services
docker-compose up -d
```

### Docker Commands

| Command | Description |
|---------|-------------|
| `npm run docker:build` | Build Docker image |
| `npm run docker:run` | Start container |
| `npm run docker:stop` | Stop container |
| `npm run docker:logs` | View container logs |
| `npm run docker:restart` | Restart container |

### Docker Features

- **Health Checks**: Automatic monitoring via `/health` endpoint
- **Volume Persistence**: Configurations stored in `./configs` directory
- **Auto-restart**: Container restarts automatically unless stopped
- **Port Mapping**: Configurable via `PORT` environment variable

### Docker Environment Variables

All variables from `.env` are automatically passed to the container. See [Configuration](#configuration) for details.

### Access Points

- **Configuration Page**: `http://localhost:7001/configure`
- **Manifest URL**: `http://localhost:7001/manifest.json`
- **Health Check**: `http://localhost:7001/health`

## Architecture

### System Components

- **stremio-addon-sdk**: Core SDK for Stremio addon functionality
- **wyzie-lib**: Subtitle fetching and discovery library
- **express**: HTTP server framework
- **axios**: HTTP client for OpenRouter API integration
- **OpenRouter**: Unified API gateway for multiple AI models

### Data Flow

1. **Request Handling**: Express server receives Stremio subtitle requests
2. **Configuration Lookup**: Retrieves user preferences from encrypted config files
3. **Subtitle Search**: Queries wyzie-lib for available subtitles
4. **Translation Pipeline**: Processes translations through OpenRouter API
5. **Response Formatting**: Converts and serves subtitles in VTT format

## API Reference

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/manifest.json` | GET | Stremio addon manifest |
| `/configure` | GET | Configuration web interface |
| `/health` | GET | Health check endpoint |
| `/subtitles/:type/:id/:extra` | GET | Subtitle retrieval endpoint |

### Health Check

```bash
curl http://localhost:7001/health
```

Returns server status and version information.

## Development

### Project Structure

```
AISubs/
├── addon.js              # Main addon server
├── test-endpoints.js     # Endpoint testing script
├── test-movie.js         # Full movie translation test
├── configs/              # Encrypted user configurations
├── package.json          # Dependencies and scripts
└── README.md             # This file
```

### Testing

```bash
# Test all endpoints
bun test
# or
npm test

# Test full movie translation flow
bun run test:movie
# or
npm run test:movie
```

### Development Dependencies

- Node.js v14+ or Bun
- OpenRouter API key for testing
- Network access to wyzie-lib

## Troubleshooting

### Common Issues

#### No Subtitles Appearing

**Symptoms**: Subtitles don't appear in Stremio

**Solutions**:
1. Verify wyzie-lib can find subtitles for the media
2. Check that your OpenRouter API key is valid and configured
3. Ensure the addon is properly installed in Stremio
4. Check server logs for error messages

#### Translation Not Working

**Symptoms**: Subtitles appear but are not translated

**Solutions**:
1. Verify OpenRouter API key is configured in the configuration page
2. Check your OpenRouter account quota and limits
3. Ensure preferred languages are correctly configured
4. Review server logs for API errors

#### Configuration Not Saving

**Symptoms**: Settings don't persist after saving

**Solutions**:
1. Verify `MASTER_KEY` is set in `.env` file
2. Check file permissions on `configs/` directory
3. Ensure server has write access to the configuration directory
4. Verify password was entered correctly when saving

#### Rate Limit Errors

**Symptoms**: API rate limit errors in logs

**Solutions**:
1. The addon automatically handles rate limits, but check your OpenRouter quota
2. Consider upgrading your OpenRouter plan for higher limits
3. Reduce the number of concurrent translation requests

### Debug Mode

Enable verbose logging by checking server console output. All operations are logged with timestamps and error details.

## Security

### Password Protection

Each user configuration is protected with a password:

1. **Initial Setup**: Create a password (minimum 8 characters) on first visit
2. **Unlocking**: Enter password to access and modify settings
3. **Session Duration**: Configuration remains unlocked for 30 minutes
4. **Saving Changes**: Password required to save modifications
5. **Password Recovery**: Not supported - create new configuration if forgotten

### Security Features

- **Password Hashing**: PBKDF2 with 100,000 iterations
- **Encryption**: AES-256-CBC for configuration files
- **File Permissions**: Restricted to owner only (600)
- **Independent Encryption**: Each configuration file encrypted separately
- **Read-Only Access**: Subtitle requests don't require password

### Security Best Practices

1. **MASTER_KEY**: Always use a secure, randomly generated key in production
2. **API Keys**: Never share your OpenRouter API key
3. **Network Security**: Use HTTPS in production environments
4. **File Permissions**: Ensure `configs/` directory has restricted access
5. **Regular Updates**: Keep dependencies updated for security patches

### Data Storage

- **Configuration Files**: Stored in `configs/` directory with encryption
- **Subtitle Cache**: In-memory cache for performance (not persisted)
- **No User Data**: No personal information is stored or transmitted

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Note**: This addon requires each user to provide their own OpenRouter API key. The server does not provide a shared API key for security and quota management reasons.
