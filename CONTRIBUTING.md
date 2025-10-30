# Contributing to Phantom-shroud

Thank you for your interest in contributing to Phantom-shroud!

## Development Setup

### Backend Setup
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
./setup.sh
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

## Project Structure

- **backend/** - Python backend (API, security modules, ML)
- **frontend/** - React dashboard (UI components, visualizations)
- **docs/** - Documentation and architecture guides

## Making Changes

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/your-feature-name`
3. **Make your changes**
4. **Run tests**: `cd backend && pytest tests/`
5. **Commit your changes**: `git commit -m "feat: add your feature"`
6. **Push to your fork**: `git push origin feature/your-feature-name`
7. **Create a Pull Request**

## Commit Message Convention

Follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, etc.)
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks

## Code Style

### Python (Backend)
- Follow PEP 8 style guide
- Use type hints where possible
- Add docstrings to functions and classes
- Maximum line length: 100 characters

### JavaScript (Frontend)
- Use ES6+ syntax
- Follow React best practices
- Use functional components with hooks
- Use meaningful variable and function names

## Testing

### Backend Tests
```bash
cd backend
pytest tests/ -v
```

### Frontend Tests
```bash
cd frontend
npm test
```

## Pull Request Guidelines

- Provide a clear description of the changes
- Reference any related issues
- Ensure all tests pass
- Update documentation if needed
- Keep PRs focused on a single feature/fix

## Questions?

Feel free to open an issue for any questions or concerns!
