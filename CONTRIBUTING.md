# Contributing to Overwatch

Thank you for your interest in contributing to Overwatch!

## Development Setup

### Prerequisites

- Node.js 20 or later
- npm

### Getting Started

```bash
# Clone the repository
git clone https://github.com/dotsetlabs/overwatch.git
cd overwatch

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Run linter
npm run lint
```

## Making Changes

### Branch Naming

- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes

### Code Style

- Follow existing TypeScript patterns
- Ensure `npm run lint` passes
- Use ESM imports (`.js` extensions required)

### Testing

- Add tests for new functionality
- Use Vitest for testing
- Ensure all tests pass: `npm test`
- Run in watch mode for development: `npm run test:watch`

## Pull Requests

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `npm run build && npm run lint && npm test`
5. Submit a pull request

### PR Guidelines

- Keep changes focused and atomic
- Update documentation as needed
- Add changelog entry for user-facing changes
- Reference any related issues

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include reproduction steps for bugs
- Check existing issues before creating new ones

## Security

For security vulnerabilities, please see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
