"""Pyxis API client for making authenticated requests to Red Hat Pyxis service."""

import logging
import os
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urljoin

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class PyxisError(Exception):
    """Base exception for Pyxis API errors."""
    pass


class PyxisAuthError(PyxisError):
    """Exception raised when authentication fails."""
    pass


class PyxisConnectionError(PyxisError):
    """Exception raised when connection to Pyxis fails."""
    pass


class PyxisClient:
    """Async client for Red Hat Pyxis API.
    
    Provides methods for interacting with the Pyxis service including
    container images, certification projects, operators, and repositories.
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://catalog.redhat.com/api/containers/v1/",
        timeout: float = 30.0,
    ):
        """Initialize Pyxis client.
        
        Args:
            api_key: API key for authentication. If None, will try to get from
                    PYXIS_API_KEY environment variable.
            base_url: Base URL for Pyxis API.
            timeout: Request timeout in seconds.
            
        Raises:
            PyxisAuthError: If no API key is provided or found in environment.
        """
        self.api_key = api_key or os.getenv("PYXIS_API_KEY")
        if not self.api_key:
            raise PyxisAuthError(
                "No API key provided. Set PYXIS_API_KEY environment variable "
                "or pass api_key parameter."
            )
        
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        
        # Configure HTTP client
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={
                "User-Agent": "pyxis-mcp-server/0.1.0",
                "Accept": "application/json",
                "X-API-KEY": self.api_key,
            },
        )
    
    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
    
    async def __aenter__(self) -> "PyxisClient":
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()
    
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Make authenticated request to Pyxis API.
        
        Args:
            method: HTTP method (GET, POST, etc.).
            endpoint: API endpoint path.
            params: Query parameters.
            json_data: JSON data for POST/PUT requests.
            
        Returns:
            Parsed JSON response.
            
        Raises:
            PyxisConnectionError: If request fails.
            PyxisAuthError: If authentication fails.
            PyxisError: For other API errors.
        """
        url = urljoin(self.base_url, endpoint.lstrip("/"))
        
        try:
            logger.debug(f"Making {method} request to {url}")
            response = await self._client.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
            )
            
            # Handle authentication errors
            if response.status_code == 401:
                raise PyxisAuthError("Authentication failed. Check your API key.")
            
            # Handle other client errors
            if response.status_code >= 400:
                error_msg = f"Request failed with status {response.status_code}"
                try:
                    error_data = response.json()
                    if "detail" in error_data:
                        error_msg += f": {error_data['detail']}"
                    elif "message" in error_data:
                        error_msg += f": {error_data['message']}"
                except Exception:
                    error_msg += f": {response.text}"
                
                raise PyxisError(error_msg)
            
            # Parse JSON response
            try:
                return response.json()
            except Exception as e:
                raise PyxisError(f"Failed to parse JSON response: {e}")
                
        except httpx.TimeoutException:
            raise PyxisConnectionError(f"Request to {url} timed out after {self.timeout}s")
        except httpx.ConnectError:
            raise PyxisConnectionError(f"Failed to connect to {url}")
        except (PyxisError, PyxisAuthError, PyxisConnectionError):
            raise
        except Exception as e:
            raise PyxisError(f"Unexpected error during request: {e}")
    
    async def get(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Make GET request to Pyxis API."""
        return await self._make_request("GET", endpoint, params=params)
    
    async def post(
        self,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Make POST request to Pyxis API."""
        return await self._make_request("POST", endpoint, params=params, json_data=data)
    
    # Convenience methods for specific endpoints
    
    async def search_images(
        self,
        query: Optional[str] = None,
        architecture: Optional[str] = None,
        registry: Optional[str] = None,
        certified: Optional[bool] = None,
        page: int = 0,
        page_size: int = 20,
    ) -> Dict[str, Any]:
        """Search container images.
        
        Args:
            query: Search query string.
            architecture: Filter by architecture (e.g., 'amd64', 'arm64').
            registry: Filter by registry.
            certified: Filter by certification status.
            page: Page number for pagination.
            page_size: Number of results per page.
            
        Returns:
            Search results with images and pagination info.
        """
        params = {
            "page": page,
            "page_size": min(page_size, 100),  # Cap at 100
        }
        
        if query:
            params["filter"] = f"repositories.repository=match={query}"
        if architecture:
            params["architecture"] = architecture
        if registry:
            params["registry"] = registry
        if certified is not None:
            params["certified"] = certified
        
        return await self.get("images", params)
    
    async def get_image_by_id(self, image_id: str) -> Dict[str, Any]:
        """Get image details by ID."""
        return await self.get(f"images/{image_id}")
    
    async def get_image_vulnerabilities(self, image_id: str) -> Dict[str, Any]:
        """Get vulnerabilities for an image."""
        return await self.get(f"images/{image_id}/vulnerabilities")
    
    async def search_certification_projects(
        self,
        query: Optional[str] = None,
        status: Optional[str] = None,
        page: int = 0,
        page_size: int = 20,
    ) -> Dict[str, Any]:
        """Search certification projects."""
        params = {
            "page": page,
            "page_size": min(page_size, 100),
        }
        
        if query:
            params["filter"] = f"name=match={query}"
        if status:
            params["certification_status"] = status
        
        return await self.get("projects/certification", params)
    
    async def get_certification_project(self, project_id: str) -> Dict[str, Any]:
        """Get certification project details by ID."""
        return await self.get(f"projects/certification/{project_id}")
    
    async def search_operators(
        self,
        query: Optional[str] = None,
        package: Optional[str] = None,
        page: int = 0,
        page_size: int = 20,
    ) -> Dict[str, Any]:
        """Search operator bundles."""
        params = {
            "page": page,
            "page_size": min(page_size, 100),
        }
        
        if query:
            params["filter"] = f"bundle_path=match={query}"
        if package:
            params["package"] = package
        
        return await self.get("operators", params)
    
    async def get_operator_by_id(self, operator_id: str) -> Dict[str, Any]:
        """Get operator details by ID."""
        return await self.get(f"operators/{operator_id}")
    
    async def search_repositories(
        self,
        query: Optional[str] = None,
        registry: Optional[str] = None,
        page: int = 0,
        page_size: int = 20,
    ) -> Dict[str, Any]:
        """Search repositories."""
        params = {
            "page": page,
            "page_size": min(page_size, 100),
        }
        
        if query:
            params["filter"] = f"repository=match={query}"
        if registry:
            params["registry"] = registry
        
        return await self.get("repositories", params)
    
    async def get_repository_by_id(self, repo_id: str) -> Dict[str, Any]:
        """Get repository details by ID."""
        return await self.get(f"repositories/{repo_id}")