# Test Suite Documentation

This document describes the test suite for OpenSocial API.

## Overview

The project uses [Vitest](https://vitest.dev/) as the test framework with the following setup:
- **Test Runner**: Vitest 4.0
- **Coverage Tool**: V8 coverage provider
- **API Testing**: Supertest (for future integration tests)
- **Test Data**: @faker-js/faker for generating realistic test data

## Running Tests

### Run all tests
```bash
npm test
```

### Run tests in watch mode
```bash
npm run test:watch
```

### Run tests with coverage
```bash
npm run test:coverage
```

Coverage reports are generated in the `coverage/` directory.

## Test Structure

```
src/
├── lib/
│   ├── crypto.ts
│   ├── crypto.test.ts          # 24 tests - encryption, hashing
│   ├── cache.ts
│   ├── cache.test.ts           # 17 tests - TTL cache
│   ├── adminUtils.ts
│   └── adminUtils.test.ts      # 22 tests - admin list handling
├── services/
│   ├── permissions.ts
│   ├── permissions.test.ts     # 31 tests - role & permission checks
│   ├── webhook.ts
│   └── webhook.test.ts         # 12 tests - webhook dispatch
└── test/
    ├── setup.ts                # Global test configuration
    └── helpers.ts              # Test utilities and factories
```

## Test Coverage

Current coverage (as of latest commit):

| File | Statements | Branches | Functions | Lines |
|------|-----------|----------|-----------|-------|
| **Overall** | **97.54%** | **86.51%** | **96.87%** | **97.35%** |
| crypto.ts | 94.28% | 87.5% | 100% | 94.11% |
| permissions.ts | 100% | 94.44% | 100% | 100% |
| webhook.ts | 90.47% | 83.33% | 83.33% | 90.47% |
| cache.ts | 100% | 100% | 100% | 100% |
| adminUtils.ts | 100% | 100% | 100% | 100% |

**Target**: Minimum 70% coverage on critical paths ✅ **Exceeded**

## Test Helpers

### Factory Functions

Located in `src/test/helpers.ts`:

```typescript
// Generate fake DIDs
createFakeDid()

// Generate fake app data
createFakeApp({ name: 'My App', status: 'active' })

// Generate fake community data
createFakeCommunity({ handle: 'mygroup', display_name: 'My Group' })

// Generate fake webhook data
createFakeWebhook({ events: ['member.joined'], active: true })
```

### Mock Objects

```typescript
// Mock Kysely database
const db = createMockDb()

// Mock AT Proto agent
const agent = createMockAgent()

// Mock Express request/response
const req = createMockRequest({ body: { ... } })
const res = createMockResponse()
```

### Utilities

```typescript
// Wait for async operations
await waitForAsync(100) // Wait 100ms
```

## Test Organization

### Unit Tests

Unit tests focus on individual functions and modules with mocked dependencies:

- **crypto.test.ts**: Tests encryption/decryption, API key hashing
- **cache.test.ts**: Tests TTL cache operations
- **adminUtils.test.ts**: Tests admin list format handling
- **permissions.test.ts**: Tests permission checks with mocked database
- **webhook.test.ts**: Tests webhook dispatching with mocked fetch

### Integration Tests

Integration tests (future work) would test full API endpoints with real database connections.

## Writing Tests

### Basic Test Structure

```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { myFunction } from './myModule';

describe('myModule.ts', () => {
  describe('myFunction', () => {
    it('should do something', () => {
      const result = myFunction('input');
      expect(result).toBe('expected');
    });

    it('should handle edge cases', () => {
      expect(() => myFunction('')).toThrow();
    });
  });
});
```

### Testing Async Code

```typescript
it('should handle async operations', async () => {
  const result = await asyncFunction();
  expect(result).toBeDefined();
});
```

### Mocking

```typescript
import { vi } from 'vitest';

it('should mock functions', () => {
  const mockFn = vi.fn().mockReturnValue('mocked');
  expect(mockFn()).toBe('mocked');
  expect(mockFn).toHaveBeenCalled();
});
```

### Database Mocking

```typescript
const db = createMockDb();
const selectFrom = vi.fn().mockReturnValue({
  select: vi.fn().mockReturnValue({
    where: vi.fn().mockReturnValue({
      execute: vi.fn().mockResolvedValue([{ id: 1, name: 'test' }])
    })
  })
});
db.selectFrom = selectFrom;
```

## CI/CD Integration

Tests run automatically on:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop`

### GitHub Actions Workflow

Located in `.github/workflows/test.yml`:

1. Sets up Node.js 20
2. Starts PostgreSQL 16 container
3. Installs dependencies with `npm ci`
4. Runs `npm test`
5. Generates coverage report with `npm run test:coverage`
6. Uploads coverage to Codecov

### Required Environment Variables

Tests require the following environment variables (set in `.env.test`):

```env
DATABASE_URL=postgresql://opensocial_api:test_password@localhost:5432/opensocial_test
NODE_ENV=test
ENCRYPTION_KEY=aaaa...aaaa  # 64 hex chars
COOKIE_SECRET=test-cookie-secret-for-testing
```

## Best Practices

1. **Test Naming**: Use descriptive test names that explain what is being tested
2. **Isolation**: Each test should be independent and not rely on other tests
3. **Mocking**: Mock external dependencies (database, APIs, file system)
4. **Coverage**: Aim for high coverage but prioritize critical paths
5. **Fast Tests**: Keep unit tests fast; use integration tests for slower operations
6. **Clear Assertions**: Use specific assertions that make failures obvious

## Testing Guidelines

### What to Test

✅ **DO TEST**:
- Public API functions
- Business logic
- Error handling
- Edge cases
- Security-critical code (encryption, authentication)

❌ **DON'T TEST**:
- Third-party libraries
- Simple getters/setters
- Framework internals
- Configuration files

### Test Structure

Follow the AAA pattern:
- **Arrange**: Set up test data and mocks
- **Act**: Execute the function being tested
- **Assert**: Verify the expected outcome

```typescript
it('should validate user input', () => {
  // Arrange
  const input = { email: 'test@example.com' };

  // Act
  const result = validateInput(input);

  // Assert
  expect(result.valid).toBe(true);
});
```

## Troubleshooting

### Tests Timing Out

Increase timeout in test or globally:

```typescript
it('long test', async () => {
  // test code
}, 10000); // 10 second timeout
```

Or in `vitest.config.ts`:
```typescript
test: {
  testTimeout: 10000
}
```

### Mock Not Working

Ensure mocks are cleared between tests:

```typescript
afterEach(() => {
  vi.clearAllMocks();
});
```

### Coverage Not Updating

Clear coverage cache:

```bash
rm -rf coverage/
npm run test:coverage
```

## Future Improvements

- [ ] Integration tests for API endpoints
- [ ] E2E tests for critical user flows
- [ ] Performance benchmarks
- [ ] Load testing for webhook dispatch
- [ ] Database migration tests
- [ ] Test fixtures for common scenarios

## Resources

- [Vitest Documentation](https://vitest.dev/)
- [Testing Best Practices](https://kentcdodds.com/blog/common-mistakes-with-react-testing-library)
- [Test Coverage Guide](https://istanbul.js.org/docs/tutorials/)
