"""Red Hat Pyxis MCP Server.

A Model Context Protocol server that provides tools for interacting with
the Red Hat Pyxis service, including container images, certification projects,
operators, and repositories.
"""

import asyncio
import logging
import os
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from .client import PyxisClient, PyxisError
from .models import (
    ContainerImage,
    CertificationProject,
    OperatorBundle,
    ImageSearchResults,
    ProjectSearchResults,
    OperatorSearchResults,
    VulnerabilitySearchResults,
    format_image_summary,
    format_project_summary,
    format_operator_summary,
    format_vulnerability_summary,
)

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize MCP server
mcp = FastMCP("pyxis")

# Global client instance
_client: Optional[PyxisClient] = None


async def get_client() -> PyxisClient:
    """Get or create Pyxis client instance."""
    global _client
    if _client is None:
        _client = PyxisClient()
    return _client


# Container Image Tools

@mcp.tool()
async def search_images(
    query: str = "",
    architecture: str = "",
    registry: str = "",
    certified: bool = False,
    max_results: int = 20,
) -> str:
    """Search for container images in Red Hat Pyxis.
    
    Args:
        query: Search query for image names/repositories
        architecture: Filter by architecture (e.g., 'amd64', 'arm64')
        registry: Filter by registry (e.g., 'registry.redhat.io')
        certified: Only show certified images
        max_results: Maximum number of results to return (1-100)
    
    Returns:
        Formatted list of matching container images
    """
    try:
        client = await get_client()
        
        # Clean up parameters
        query = query.strip() if query else None
        architecture = architecture.strip() if architecture else None
        registry = registry.strip() if registry else None
        certified_filter = certified if certified else None
        max_results = min(max(max_results, 1), 100)
        
        response = await client.search_images(
            query=query,
            architecture=architecture,
            registry=registry,
            certified=certified_filter,
            page_size=max_results,
        )
        
        if not response.get("data"):
            return "No images found matching the specified criteria."
        
        # Parse results
        results = ImageSearchResults(**response)
        
        if not results.data:
            return "No images found matching the specified criteria."
        
        # Format results
        lines = [f"Found {results.total} images (showing {len(results.data)}):"]
        lines.append("")
        
        for image in results.data:
            lines.append(f"• {format_image_summary(image)}")
        
        if results.has_more:
            lines.append("")
            lines.append(f"... and {results.total - len(results.data)} more results available")
        
        return "\n".join(lines)
        
    except PyxisError as e:
        logger.error(f"Pyxis API error in search_images: {e}")
        return f"Error searching images: {e}"
    except Exception as e:
        logger.error(f"Unexpected error in search_images: {e}")
        return f"Unexpected error: {e}"


@mcp.tool()
async def get_image_details(image_id: str) -> str:
    """Get detailed information about a specific container image.
    
    Args:
        image_id: The unique ID of the container image
    
    Returns:
        Detailed information about the container image
    """
    try:
        if not image_id.strip():
            return "Error: image_id is required"
        
        client = await get_client()
        response = await client.get_image_by_id(image_id.strip())
        
        # Parse the image data
        image = ContainerImage(**response)
        
        lines = [f"Container Image Details: {image.id}"]
        lines.append("=" * 50)
        
        if image.repositories:
            lines.append("Repositories:")
            for repo in image.repositories:
                if repo.registry and repo.repository:
                    lines.append(f"  • {repo.registry}/{repo.repository}")
                    if repo.tags:
                        lines.append(f"    Tags: {', '.join(repo.tags[:5])}")
                        if len(repo.tags) > 5:
                            lines.append(f"    ... and {len(repo.tags) - 5} more tags")
        
        lines.append("")
        lines.append(f"Architecture: {image.architecture or 'Unknown'}")
        lines.append(f"Certified: {'Yes' if image.certified else 'No'}")
        
        if image.creation_date:
            lines.append(f"Created: {image.creation_date}")
        
        if image.last_update_date:
            lines.append(f"Last Updated: {image.last_update_date}")
        
        if image.sum_layer_size_bytes:
            size_mb = image.sum_layer_size_bytes / (1024 * 1024)
            lines.append(f"Size: {size_mb:.1f} MB")
        
        if image.docker_image_digest:
            lines.append(f"Digest: {image.docker_image_digest}")
        
        if image.cpe_ids:
            lines.append(f"CPE IDs: {', '.join(image.cpe_ids[:3])}")
            if len(image.cpe_ids) > 3:
                lines.append(f"... and {len(image.cpe_ids) - 3} more")
        
        if image.content_sets:
            lines.append(f"Content Sets: {len(image.content_sets)} available")
        
        if image.freshness_grades:
            lines.append(f"Freshness Grades: {len(image.freshness_grades)} available")
        
        return "\n".join(lines)
        
    except PyxisError as e:
        logger.error(f"Pyxis API error in get_image_details: {e}")
        return f"Error getting image details: {e}"
    except Exception as e:
        logger.error(f"Unexpected error in get_image_details: {e}")
        return f"Unexpected error: {e}"


@mcp.tool()
async def get_image_vulnerabilities(image_id: str, max_results: int = 50) -> str:
    """Get security vulnerabilities for a specific container image.
    
    Args:
        image_id: The unique ID of the container image
        max_results: Maximum number of vulnerabilities to return (1-100)
    
    Returns:
        List of security vulnerabilities found in the image
    """
    try:
        if not image_id.strip():
            return "Error: image_id is required"
        
        client = await get_client()
        max_results = min(max(max_results, 1), 100)
        
        response = await client.get_image_vulnerabilities(image_id.strip())
        
        if not response.get("data"):
            return f"No vulnerabilities found for image {image_id}"
        
        # Parse results
        results = VulnerabilitySearchResults(**response)
        
        if not results.data:
            return f"No vulnerabilities found for image {image_id}"
        
        # Limit results
        vulns = results.data[:max_results]
        
        lines = [f"Security Vulnerabilities for Image {image_id}"]
        lines.append("=" * 60)
        lines.append(f"Found {results.total} vulnerabilities (showing {len(vulns)}):")
        lines.append("")
        
        # Group by severity
        severity_groups = {}
        for vuln in vulns:
            severity = vuln.severity or "Unknown"
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(vuln)
        
        # Order severities by priority
        severity_order = ["Critical", "High", "Medium", "Low", "Unknown"]
        
        for severity in severity_order:
            if severity in severity_groups:
                lines.append(f"{severity} Severity ({len(severity_groups[severity])}):")
                for vuln in severity_groups[severity][:10]:  # Show first 10 per severity
                    lines.append(f"  • {format_vulnerability_summary(vuln)}")
                if len(severity_groups[severity]) > 10:
                    lines.append(f"  ... and {len(severity_groups[severity]) - 10} more {severity.lower()} vulnerabilities")
                lines.append("")
        
        if results.total > max_results:
            lines.append(f"... and {results.total - max_results} more vulnerabilities available")
        
        return "\n".join(lines)
        
    except PyxisError as e:
        logger.error(f"Pyxis API error in get_image_vulnerabilities: {e}")
        return f"Error getting vulnerabilities: {e}"
    except Exception as e:
        logger.error(f"Unexpected error in get_image_vulnerabilities: {e}")
        return f"Unexpected error: {e}"


# Certification Project Tools

@mcp.tool()
async def search_certification_projects(
    query: str = "",
    status: str = "",
    max_results: int = 20,
) -> str:
    """Search for certification projects in Red Hat Pyxis.
    
    Args:
        query: Search query for project names
        status: Filter by certification status
        max_results: Maximum number of results to return (1-100)
    
    Returns:
        Formatted list of matching certification projects
    """
    try:
        client = await get_client()
        
        # Clean up parameters
        query = query.strip() if query else None
        status = status.strip() if status else None
        max_results = min(max(max_results, 1), 100)
        
        response = await client.search_certification_projects(
            query=query,
            status=status,
            page_size=max_results,
        )
        
        if not response.get("data"):
            return "No certification projects found matching the specified criteria."
        
        # Parse results
        results = ProjectSearchResults(**response)
        
        if not results.data:
            return "No certification projects found matching the specified criteria."
        
        # Format results
        lines = [f"Found {results.total} certification projects (showing {len(results.data)}):"]
        lines.append("")
        
        for project in results.data:
            lines.append(f"• {format_project_summary(project)}")
            if project.short_description:
                lines.append(f"  {project.short_description}")
            lines.append("")
        
        if results.has_more:
            lines.append(f"... and {results.total - len(results.data)} more results available")
        
        return "\n".join(lines)
        
    except PyxisError as e:
        logger.error(f"Pyxis API error in search_certification_projects: {e}")
        return f"Error searching certification projects: {e}"
    except Exception as e:
        logger.error(f"Unexpected error in search_certification_projects: {e}")
        return f"Unexpected error: {e}"


@mcp.tool()
async def get_certification_project_details(project_id: str) -> str:
    """Get detailed information about a specific certification project.
    
    Args:
        project_id: The unique ID of the certification project
    
    Returns:
        Detailed information about the certification project
    """
    try:
        if not project_id.strip():
            return "Error: project_id is required"
        
        client = await get_client()
        response = await client.get_certification_project(project_id.strip())
        
        # Parse the project data
        project = CertificationProject(**response)
        
        lines = [f"Certification Project Details: {project.name or 'Unnamed Project'}"]
        lines.append("=" * 60)
        lines.append(f"ID: {project.id}")
        lines.append(f"Type: {project.type or 'Unknown'}")
        lines.append(f"Application Type: {project.application_type or 'Unknown'}")
        lines.append(f"Project Status: {project.project_status or 'Unknown'}")
        lines.append(f"Certification Status: {project.certification_status or 'Unknown'}")
        
        if project.vendor_label:
            lines.append(f"Vendor: {project.vendor_label}")
        
        if project.creation_date:
            lines.append(f"Created: {project.creation_date}")
        
        if project.last_update_date:
            lines.append(f"Last Updated: {project.last_update_date}")
        
        if project.short_description:
            lines.append("")
            lines.append("Short Description:")
            lines.append(project.short_description)
        
        if project.long_description:
            lines.append("")
            lines.append("Description:")
            lines.append(project.long_description)
        
        if project.registry_override_instruct:
            lines.append("")
            lines.append("Registry Override Instructions:")
            lines.append(project.registry_override_instruct)
        
        if project.container:
            lines.append("")
            lines.append("Container Information:")
            for key, value in project.container.items():
                if isinstance(value, (str, int, float, bool)):
                    lines.append(f"  {key}: {value}")
        
        return "\n".join(lines)
        
    except PyxisError as e:
        logger.error(f"Pyxis API error in get_certification_project_details: {e}")
        return f"Error getting project details: {e}"
    except Exception as e:
        logger.error(f"Unexpected error in get_certification_project_details: {e}")
        return f"Unexpected error: {e}"


# Operator Tools

@mcp.tool()
async def search_operators(
    query: str = "",
    package: str = "",
    max_results: int = 20,
) -> str:
    """Search for operator bundles in Red Hat Pyxis.
    
    Args:
        query: Search query for operator names/bundles
        package: Filter by package name
        max_results: Maximum number of results to return (1-100)
    
    Returns:
        Formatted list of matching operator bundles
    """
    try:
        client = await get_client()
        
        # Clean up parameters
        query = query.strip() if query else None
        package = package.strip() if package else None
        max_results = min(max(max_results, 1), 100)
        
        response = await client.search_operators(
            query=query,
            package=package,
            page_size=max_results,
        )
        
        if not response.get("data"):
            return "No operators found matching the specified criteria."
        
        # Parse results
        results = OperatorSearchResults(**response)
        
        if not results.data:
            return "No operators found matching the specified criteria."
        
        # Format results
        lines = [f"Found {results.total} operators (showing {len(results.data)}):"]
        lines.append("")
        
        for operator in results.data:
            lines.append(f"• {format_operator_summary(operator)}")
            if operator.organization:
                lines.append(f"  Organization: {operator.organization}")
            if operator.bundle_path:
                lines.append(f"  Bundle Path: {operator.bundle_path}")
            lines.append("")
        
        if results.has_more:
            lines.append(f"... and {results.total - len(results.data)} more results available")
        
        return "\n".join(lines)
        
    except PyxisError as e:
        logger.error(f"Pyxis API error in search_operators: {e}")
        return f"Error searching operators: {e}"
    except Exception as e:
        logger.error(f"Unexpected error in search_operators: {e}")
        return f"Unexpected error: {e}"


@mcp.tool()
async def get_operator_details(operator_id: str) -> str:
    """Get detailed information about a specific operator bundle.
    
    Args:
        operator_id: The unique ID of the operator bundle
    
    Returns:
        Detailed information about the operator bundle
    """
    try:
        if not operator_id.strip():
            return "Error: operator_id is required"
        
        client = await get_client()
        response = await client.get_operator_by_id(operator_id.strip())
        
        # Parse the operator data
        operator = OperatorBundle(**response)
        
        lines = [f"Operator Bundle Details: {operator.csv_name or operator.package_name or 'Unknown'}"]
        lines.append("=" * 60)
        lines.append(f"ID: {operator.id}")
        
        if operator.csv_name:
            lines.append(f"CSV Name: {operator.csv_name}")
        
        if operator.package_name:
            lines.append(f"Package: {operator.package_name}")
        
        if operator.version:
            lines.append(f"Version: {operator.version}")
        
        if operator.channel_name:
            lines.append(f"Channel: {operator.channel_name}")
        
        if operator.ocp_version:
            lines.append(f"OCP Version: {operator.ocp_version}")
        
        if operator.organization:
            lines.append(f"Organization: {operator.organization}")
        
        lines.append(f"Certified: {'Yes' if operator.certified else 'No'}")
        
        if operator.registry and operator.repository:
            lines.append(f"Registry: {operator.registry}/{operator.repository}")
        
        if operator.bundle_path:
            lines.append(f"Bundle Path: {operator.bundle_path}")
        
        if operator.creation_date:
            lines.append(f"Created: {operator.creation_date}")
        
        if operator.last_update_date:
            lines.append(f"Last Updated: {operator.last_update_date}")
        
        return "\n".join(lines)
        
    except PyxisError as e:
        logger.error(f"Pyxis API error in get_operator_details: {e}")
        return f"Error getting operator details: {e}"
    except Exception as e:
        logger.error(f"Unexpected error in get_operator_details: {e}")
        return f"Unexpected error: {e}"


# Repository Tools

@mcp.tool()
async def search_repositories(
    query: str = "",
    registry: str = "",
    max_results: int = 20,
) -> str:
    """Search for repositories in Red Hat Pyxis.
    
    Args:
        query: Search query for repository names
        registry: Filter by registry
        max_results: Maximum number of results to return (1-100)
    
    Returns:
        Formatted list of matching repositories
    """
    try:
        client = await get_client()
        
        # Clean up parameters
        query = query.strip() if query else None
        registry = registry.strip() if registry else None
        max_results = min(max(max_results, 1), 100)
        
        response = await client.search_repositories(
            query=query,
            registry=registry,
            page_size=max_results,
        )
        
        if not response.get("data"):
            return "No repositories found matching the specified criteria."
        
        # Format results
        total = response.get("total", 0)
        data = response.get("data", [])
        
        lines = [f"Found {total} repositories (showing {len(data)}):"]
        lines.append("")
        
        for repo in data:
            registry_name = repo.get("registry", "unknown")
            repo_name = repo.get("repository", "unknown")
            published = "Published" if repo.get("published") else "Not Published"
            
            lines.append(f"• {registry_name}/{repo_name} - {published}")
            
            if repo.get("push_date"):
                lines.append(f"  Last Push: {repo.get('push_date')}")
            
            tags = repo.get("tags", [])
            if tags:
                tag_display = ", ".join(tags[:5])
                if len(tags) > 5:
                    tag_display += f" +{len(tags) - 5} more"
                lines.append(f"  Tags: {tag_display}")
            
            lines.append("")
        
        if total > len(data):
            lines.append(f"... and {total - len(data)} more results available")
        
        return "\n".join(lines)
        
    except PyxisError as e:
        logger.error(f"Pyxis API error in search_repositories: {e}")
        return f"Error searching repositories: {e}"
    except Exception as e:
        logger.error(f"Unexpected error in search_repositories: {e}")
        return f"Unexpected error: {e}"


def main():
    """Main entry point for the Pyxis MCP server."""
    # Ensure we have an API key
    api_key = os.getenv("PYXIS_API_KEY")
    if not api_key:
        print("Error: PYXIS_API_KEY environment variable is required")
        print("Please set your Red Hat Pyxis API key before running the server")
        return 1
    
    print("Starting Red Hat Pyxis MCP Server...")
    print("Available tools:")
    print("  • search_images - Search container images")
    print("  • get_image_details - Get detailed image information")
    print("  • get_image_vulnerabilities - Get image security vulnerabilities")
    print("  • search_certification_projects - Search certification projects")
    print("  • get_certification_project_details - Get project details")
    print("  • search_operators - Search operator bundles")
    print("  • get_operator_details - Get operator details")
    print("  • search_repositories - Search repositories")
    print("")
    
    # Run the MCP server
    mcp.run()


if __name__ == "__main__":
    main()