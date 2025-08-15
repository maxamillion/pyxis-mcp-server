# Contributing to Red Hat Pyxis MCP Server

Thank you for your interest in contributing to the Red Hat Pyxis MCP Server! This document provides guidelines for contributing to the project.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/pyxis-mcp-server.git
   cd pyxis-mcp-server
   ```
3. **Set up the development environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev]"
   ```

## Development Workflow

### Setting up API Access

You'll need a Red Hat Pyxis API key for testing. Contact pyxis-dev@redhat.com to obtain one, then:

```bash
cp .env.example .env
# Edit .env and add your API key
```

### Making Changes

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the coding standards below

3. **Run tests**:
   ```bash
   pytest
   ```

4. **Check code formatting**:
   ```bash
   black src/
   isort src/
   ```

5. **Run type checking**:
   ```bash
   mypy src/
   ```

6. **Commit your changes**:
   ```bash
   git add .
   git commit -m "Add descriptive commit message"
   ```

7. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

8. **Create a Pull Request** on GitHub

## Coding Standards

### Code Style

- Use **Black** for code formatting with default settings
- Use **isort** for import sorting
- Follow **PEP 8** style guidelines
- Use **type hints** for all function parameters and return values
- Write **docstrings** for all public functions, classes, and modules

### Code Organization

- Keep functions focused and small (generally under 50 lines)
- Use descriptive variable and function names
- Group related functionality into appropriate modules
- Follow the existing project structure

### Error Handling

- Use specific exception types from `client.py` (PyxisError, PyxisAuthError, etc.)
- Provide user-friendly error messages
- Log errors appropriately using the logging module
- Handle edge cases gracefully

### Documentation

- Update docstrings when modifying functions
- Add type hints for new parameters
- Update README.md if adding new features
- Include examples in docstrings where helpful

## Testing Guidelines

### Writing Tests

- Write tests for new functionality
- Use pytest for test framework
- Use pytest-asyncio for async tests
- Mock external API calls using pytest-httpx
- Aim for good test coverage of critical paths

### Test Structure

```python
import pytest
from unittest.mock import AsyncMock, patch
from pyxis_mcp.client import PyxisClient
from pyxis_mcp.models import ContainerImage

@pytest.mark.asyncio
async def test_search_images():
    # Test implementation
    pass
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/pyxis_mcp

# Run specific test file
pytest tests/test_client.py

# Run with verbose output
pytest -v
```

## Adding New Features

### New API Endpoints

When adding support for new Pyxis API endpoints:

1. **Add client methods** in `client.py`
2. **Create data models** in `models.py` if needed
3. **Implement MCP tools** in `server.py`
4. **Add formatting functions** for display
5. **Write tests** for the new functionality
6. **Update documentation**

### Example: Adding a New Tool

```python
@mcp.tool()
async def new_tool_name(
    parameter1: str,
    parameter2: int = 10,
) -> str:
    """Tool description here.
    
    Args:
        parameter1: Description of parameter1
        parameter2: Description of parameter2 with default
    
    Returns:
        Description of return value
    """
    try:
        client = await get_client()
        # Implementation here
        return formatted_result
    except PyxisError as e:
        logger.error(f"Pyxis API error in new_tool_name: {e}")
        return f"Error: {e}"
    except Exception as e:
        logger.error(f"Unexpected error in new_tool_name: {e}")
        return f"Unexpected error: {e}"
```

## Documentation Updates

### README Updates

When adding new features, update:
- Features list
- Available tools section
- Example usage
- Changelog

### API Documentation

- Keep docstrings up to date
- Include parameter descriptions
- Provide usage examples
- Document error conditions

## Release Process

1. Update version in `pyproject.toml` and `__init__.py`
2. Update CHANGELOG in README.md
3. Ensure all tests pass
4. Create a release branch
5. Submit PR for review
6. After merge, tag the release

## Code of Conduct

### Be Respectful

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community

### Be Professional

- Keep discussions focused on technical matters
- Provide constructive feedback
- Help others learn and grow
- Be patient with newcomers

## Getting Help

If you need help:

1. **Check existing issues** on GitHub
2. **Ask questions** in pull request discussions
3. **Contact maintainers** through GitHub
4. **Read the documentation** thoroughly

For Pyxis API questions, contact: pyxis-dev@redhat.com

## License

By contributing to this project, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing!