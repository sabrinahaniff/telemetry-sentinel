# Contributing to Telemetry Sentinel

Thanks for your interest in contributing! This project welcomes improvements to detection rules, the alert panel UI, and attack simulations.

## Getting Started
1. Fork the repo
2. Clone your fork
3. Follow the setup instructions in README.md

## Ways to Contribute
- **New detection rules** - add them in `backend/src/detector.js`
- **New attack simulations** - add scripts in `simulator/attack-scripts/`
- **UI improvements** - the alert panel is in `openmct-index.html`
- **Bug fixes** - open an issue first to discuss

## Guidelines
- One feature per pull request
- Add a unit test in `backend/src/detector.test.js` for any new detection rule
- Run `npx jest` and make sure all tests pass before submitting
- Use clear commit messages: `feat:`, `fix:`, `docs:`, `test:`, `chore:`

## Running Tests
```bash
cd backend && npx jest
```
