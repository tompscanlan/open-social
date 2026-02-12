# Structured Logging with Pino

This document describes the structured logging implementation using Pino in the OpenSocial API.

## Overview

The application uses [Pino](https://github.com/pinojs/pino), a high-performance JSON logger for Node.js, to provide structured logging capabilities.

## Features

✅ **Structured JSON Logs** - All logs are structured objects for easy parsing and aggregation  
✅ **Request Correlation IDs** - Unique IDs track requests across the application  
✅ **Performance Monitoring** - Automatic warnings for slow operations (>1000ms)  
✅ **Environment-Based Output** - Human-readable in development, JSON in production  
✅ **Configurable Log Levels** - Set via `LOG_LEVEL` environment variable  

## Configuration

### Environment Variables

```bash
# Log level: trace, debug, info, warn, error, fatal
LOG_LEVEL=info

# Node environment (affects log formatting)
NODE_ENV=development  # Human-readable output
NODE_ENV=production   # JSON output
```

### Log Levels

- `trace` (10): Very detailed information, typically for debugging
- `debug` (20): Debug information
- `info` (30): General informational messages (default)
- `warn` (40): Warning messages for potential issues
- `error` (50): Error messages for failures
- `fatal` (60): Critical errors causing application shutdown

## Usage

### Basic Logging

```typescript
import { logger } from './lib/logger';

// Info log
logger.info('Server started');

// With structured context
logger.info({ port: 3001, mode: 'production' }, 'Server started');

// Warning
logger.warn({ userId: 'user123' }, 'User attempted unauthorized action');

// Error
logger.error({ error, userId: 'user123' }, 'Failed to process request');
```

### Child Loggers

Create child loggers with persistent context:

```typescript
import { createLogger } from './lib/logger';

const serviceLogger = createLogger({ service: 'webhook' });

// All logs from this logger will include { service: 'webhook' }
serviceLogger.info({ webhookUrl: 'https://example.com' }, 'Dispatching webhook');
serviceLogger.error({ error }, 'Webhook delivery failed');
```

### Request Correlation IDs

The `requestLogger` middleware automatically:
- Generates unique correlation IDs for each request
- Logs incoming requests
- Logs completed requests with duration
- Warns about slow requests (>1000ms)
- Attaches `correlationId` to the Express request object

```typescript
import { logger } from './lib/logger';

app.get('/api/endpoint', (req, res) => {
  // Use correlation ID in route handlers
  logger.info({ 
    correlationId: req.correlationId,
    action: 'processing-data' 
  }, 'Processing user data');
  
  // ... your code
});
```

## Log Output Examples

### Development Mode

Human-readable output with colors:

```
[18:25:22 UTC] INFO: Server started
    port: 3001
    mode: "development"

[18:25:23 UTC] WARN: Slow request (1502ms)
    correlationId: "54ba6503-014f-40fd-b40e-9b7b5c381f6c"
    method: "GET"
    path: "/api/communities"
    duration: 1502
```

### Production Mode

Structured JSON for log aggregation:

```json
{"level":30,"time":1770920727439,"pid":5562,"hostname":"server1","port":3001,"mode":"production","msg":"Server started"}
{"level":40,"time":1770920728941,"pid":5562,"hostname":"server1","correlationId":"54ba6503-014f-40fd-b40e-9b7b5c381f6c","method":"GET","path":"/api/communities","duration":1502,"msg":"Slow request (1502ms)"}
```

## Best Practices

### ✅ Do

- Include relevant context objects with all logs
- Use correlation IDs to trace requests
- Log at appropriate levels (info for normal flow, error for failures)
- Include error objects in error logs: `logger.error({ error }, 'message')`

```typescript
// Good
logger.error({ 
  error, 
  correlationId: req.correlationId,
  userId: user.did,
  communityDid: community.did 
}, 'Failed to add member to community');
```

### ❌ Don't

- Don't use console.log, console.error, or console.warn
- Don't log sensitive data (passwords, tokens, etc.)
- Don't use string concatenation for context

```typescript
// Bad
console.log('User ' + userId + ' failed');  // ❌

// Good
logger.error({ userId, error }, 'User action failed');  // ✅
```

## Migration from console.log

The codebase has been fully migrated from `console.*` to structured logging:

| Before | After |
|--------|-------|
| `console.log('Server started')` | `logger.info('Server started')` |
| `console.error('Error:', err)` | `logger.error({ error: err }, 'Error occurred')` |
| `console.warn('Warning:', msg)` | `logger.warn({ context }, 'Warning message')` |

## Performance Monitoring

The request logger automatically monitors performance:

- Requests < 1000ms: Logged as INFO
- Requests ≥ 1000ms: Logged as WARN with duration
- HTTP 5xx: Logged as ERROR
- HTTP 4xx: Logged as WARN

## Integration with Log Aggregation

The structured JSON logs in production mode are designed to work seamlessly with:

- **Datadog**: Import JSON logs and query by correlation ID
- **Splunk**: Parse JSON automatically and create dashboards
- **ELK Stack**: Index logs in Elasticsearch for searching
- **CloudWatch**: Group logs by correlation ID and create metrics
- **New Relic**: Automatic APM integration with structured logs

Query examples:
```
# Find all logs for a specific request
correlationId:"54ba6503-014f-40fd-b40e-9b7b5c381f6c"

# Find all slow requests
duration >= 1000

# Find all errors for a specific user
level:50 AND userId:"did:plc:abc123"
```

## Files

- `/src/lib/logger.ts` - Logger configuration and exports
- `/src/middleware/requestLogger.ts` - Request correlation middleware
- All route and service files - Updated to use structured logging

## Resources

- [Pino Documentation](https://getpino.io/)
- [Pino Pretty (Development Formatter)](https://github.com/pinojs/pino-pretty)
- [Best Practices for Logging](https://getpino.io/#/docs/best-practices)
