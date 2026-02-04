# Publishing SkillGuard to npm

## Quick Start

```bash
# 1. Login to npm
npm login

# 2. Build and test
npm run build && npm test

# 3. Publish
npm publish
```

## Prerequisites

- npm account at https://www.npmjs.com
- Authenticated with `npm login`
- Package name `@gauravsingh1995/skillgaurd` available

## Current Status

- ✅ Package name: `@gauravsingh1995/skillgaurd`
- ✅ Version: `1.1.2`
- ✅ Tests passing
- ✅ CI will pass after latest push
- ❌ **Not yet published to npm**

## To Publish Now

```bash
npm login
npm publish
```

Then verify:
```bash
npm view @gauravsingh1995/skillgaurd
npx @gauravsingh1995/skillgaurd scan --help
```
