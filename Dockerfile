FROM node:20-alpine

WORKDIR /app

# Install bun globally
RUN npm install -g bun

# Copy package files
COPY package.json ./
# Copy bun.lock if it exists (optional for compatibility)
COPY bun.lock* ./

# Install dependencies using bun
# Use --frozen-lockfile if bun.lock exists, otherwise install normally
RUN if [ -f bun.lock ]; then bun install --frozen-lockfile; else bun install; fi

# Copy application files
COPY . .

# Create configs directory with proper permissions
RUN mkdir -p configs && chmod 700 configs

# Expose port
EXPOSE 7001

# Health check (uses PORT env var, defaults to 7001)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "const port = process.env.PORT || 7001; require('http').get(`http://localhost:${port}/health`, (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start the application
CMD ["bun", "start"]

