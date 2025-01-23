# Add multi-stage build
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .

FROM node:18-alpine
WORKDIR /app
COPY --from=builder /app .

# Expose port
EXPOSE 3000

# Start the application
CMD ["npm", "start"] 