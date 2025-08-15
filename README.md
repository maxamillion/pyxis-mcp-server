# Red Hat Pyxis MCP Server

A Model Context Protocol (MCP) server for interacting with the Red Hat Pyxis service, providing access to container images, certification projects, operators, and repositories metadata.

## Features

- **Container Image Search**: Search and get detailed information about container images
- **Security Vulnerabilities**: Retrieve security vulnerability information for images
- **Certification Projects**: Search and manage Red Hat certification projects
- **Operator Bundles**: Discover and analyze operator bundles and packages
- **Repository Management**: Search and explore container repositories
- **Authentication**: Secure API key-based authentication
- **Error Handling**: Comprehensive error handling with user-friendly messages

## Installation

### Prerequisites

- Python 3.10 or higher
- Red Hat Pyxis API key

### Install from Source

```bash
git clone https://github.com/admiller/pyxis-mcp-server
cd pyxis-mcp-server
pip install -e .
```

### Install from PyPI (when available)

```bash
pip install pyxis-mcp
```

## Configuration

### API Key Setup

You need a Red Hat Pyxis API key to use this server. Set it as an environment variable:

```bash
export PYXIS_API_KEY="your-api-key-here"
```

Alternatively, create a `.env` file in your project directory:

```
PYXIS_API_KEY=your-api-key-here
```

To obtain an API key, contact the Pyxis development team at pyxis-dev@redhat.com.

## Usage

### Running the Server

```bash
pyxis-mcp
```

Or run directly:

```bash
python -m pyxis_mcp.server
```

### Available Tools

The server provides the following MCP tools:

#### Container Image Tools

- **`search_images`**: Search for container images
  - Parameters: `query`, `architecture`, `registry`, `certified`, `max_results`
  - Example: Search for RHEL images on specific registry

- **`get_image_details`**: Get detailed information about a specific image
  - Parameters: `image_id`
  - Returns: Comprehensive image metadata including repositories, tags, size

- **`get_image_vulnerabilities`**: Get security vulnerabilities for an image
  - Parameters: `image_id`, `max_results`
  - Returns: List of CVEs with severity and CVSS scores

#### Certification Project Tools

- **`search_certification_projects`**: Search certification projects
  - Parameters: `query`, `status`, `max_results`
  - Example: Find projects by name or certification status

- **`get_certification_project_details`**: Get detailed project information
  - Parameters: `project_id`
  - Returns: Project timeline, status, descriptions, and container details

#### Operator Tools

- **`search_operators`**: Search operator bundles
  - Parameters: `query`, `package`, `max_results`
  - Example: Find operators by name or package

- **`get_operator_details`**: Get detailed operator information
  - Parameters: `operator_id`
  - Returns: Bundle details, versions, channels, and certification status

#### Repository Tools

- **`search_repositories`**: Search container repositories
  - Parameters: `query`, `registry`, `max_results`
  - Returns: Repository listings with tags and publication status

## Example Usage

### With Claude Desktop

Add to your MCP settings configuration:

```json
{
  "mcpServers": {
    "pyxis": {
      "command": "pyxis-mcp",
      "env": {
        "PYXIS_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### Example Queries

1. **Search for certified RHEL images**:
   ```
   search_images(query="rhel", certified=true, max_results=10)
   ```

2. **Get vulnerability information for a specific image**:
   ```
   get_image_vulnerabilities(image_id="507f1f77bcf86cd799439011")
   ```

3. **Find certification projects for containers**:
   ```
   search_certification_projects(query="container", status="approved")
   ```

4. **Search for OpenShift operators**:
   ```
   search_operators(query="openshift", max_results=15)
   ```

## Development

### Setting up Development Environment

```bash
git clone https://github.com/admiller/pyxis-mcp-server
cd pyxis-mcp-server

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```

### Code Formatting

```bash
black src/
isort src/
```

### Type Checking

```bash
mypy src/
```

## API Reference

The server interacts with the Red Hat Pyxis API v1. For detailed API documentation, visit:
- [Pyxis API Documentation](https://catalog.redhat.com/api/containers/docs/index.html)

## Error Handling

The server provides comprehensive error handling for common scenarios:

- **Authentication Errors**: Clear messages when API key is missing or invalid
- **Connection Errors**: Timeout and connection failure handling
- **API Errors**: Proper handling of API rate limits and server errors
- **Validation Errors**: Input validation with helpful error messages

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues related to this MCP server, please open an issue on GitHub.

For questions about the Pyxis API itself, contact: pyxis-dev@redhat.com

## Changelog

### v0.1.0
- Initial release
- Container image search and details
- Security vulnerability reporting
- Certification project management
- Operator bundle discovery
- Repository search functionality
