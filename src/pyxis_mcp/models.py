"""Pydantic models for Red Hat Pyxis API responses."""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class Repository(BaseModel):
    """Container repository information."""
    
    registry: Optional[str] = None
    repository: Optional[str] = None
    push_date: Optional[datetime] = None
    tags: Optional[List[str]] = None
    published: Optional[bool] = None


class Architecture(BaseModel):
    """Container architecture information."""
    
    name: str
    digest: Optional[str] = None
    manifest_digest: Optional[str] = None


class Vulnerability(BaseModel):
    """Security vulnerability information."""
    
    cve: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe: Optional[str] = None
    impact: Optional[str] = None
    public_date: Optional[datetime] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    fixed_version: Optional[str] = None


class ContentSet(BaseModel):
    """Content set information."""
    
    name: Optional[str] = None
    type: Optional[str] = None


class BrewBuild(BaseModel):
    """Brew build information."""
    
    build: Optional[str] = None
    nvr: Optional[str] = None
    id: Optional[int] = None


class ContainerImage(BaseModel):
    """Container image metadata."""
    
    id: str = Field(..., alias="_id")
    architecture: Optional[str] = None
    brew: Optional[BrewBuild] = None
    certified: Optional[bool] = None
    content_sets: Optional[List[ContentSet]] = None
    cpe_ids: Optional[List[str]] = None
    creation_date: Optional[datetime] = None
    docker_image_digest: Optional[str] = None
    freshness_grades: Optional[List[Dict[str, Any]]] = None
    image_id: Optional[str] = None
    last_update_date: Optional[datetime] = None
    media_type: Optional[str] = None
    parsed_data: Optional[Dict[str, Any]] = None
    repositories: Optional[List[Repository]] = None
    sum_layer_size_bytes: Optional[int] = None
    uncompressed_size_bytes: Optional[int] = None
    vulnerabilities: Optional[List[Vulnerability]] = None
    
    class Config:
        allow_population_by_field_name = True


class CertificationProject(BaseModel):
    """Certification project information."""
    
    id: str = Field(..., alias="_id")
    name: Optional[str] = None
    project_status: Optional[str] = None
    certification_status: Optional[str] = None
    type: Optional[str] = None
    application_type: Optional[str] = None
    vendor_label: Optional[str] = None
    registry_override_instruct: Optional[str] = None
    short_description: Optional[str] = None
    long_description: Optional[str] = None
    creation_date: Optional[datetime] = None
    last_update_date: Optional[datetime] = None
    container: Optional[Dict[str, Any]] = None
    
    class Config:
        allow_population_by_field_name = True


class OperatorPackage(BaseModel):
    """Operator package information."""
    
    name: Optional[str] = None
    default_channel: Optional[str] = None
    channels: Optional[List[str]] = None


class OperatorBundle(BaseModel):
    """Operator bundle metadata."""
    
    id: str = Field(..., alias="_id")
    bundle_path: Optional[str] = None
    csv_name: Optional[str] = None
    package_name: Optional[str] = None
    channel_name: Optional[str] = None
    version: Optional[str] = None
    ocp_version: Optional[str] = None
    organization: Optional[str] = None
    registry: Optional[str] = None
    repository: Optional[str] = None
    creation_date: Optional[datetime] = None
    last_update_date: Optional[datetime] = None
    certified: Optional[bool] = None
    
    class Config:
        allow_population_by_field_name = True


class SearchResults(BaseModel):
    """Generic search results container."""
    
    data: List[Union[ContainerImage, CertificationProject, OperatorBundle]]
    total: int
    page: int
    page_size: int
    
    @property
    def has_more(self) -> bool:
        """Check if there are more results available."""
        return (self.page + 1) * self.page_size < self.total


class ImageSearchResults(BaseModel):
    """Container image search results."""
    
    data: List[ContainerImage]
    total: int
    page: int
    page_size: int
    
    @property
    def has_more(self) -> bool:
        """Check if there are more results available."""
        return (self.page + 1) * self.page_size < self.total


class ProjectSearchResults(BaseModel):
    """Certification project search results."""
    
    data: List[CertificationProject]
    total: int
    page: int
    page_size: int
    
    @property
    def has_more(self) -> bool:
        """Check if there are more results available."""
        return (self.page + 1) * self.page_size < self.total


class OperatorSearchResults(BaseModel):
    """Operator search results."""
    
    data: List[OperatorBundle]
    total: int
    page: int
    page_size: int
    
    @property
    def has_more(self) -> bool:
        """Check if there are more results available."""
        return (self.page + 1) * self.page_size < self.total


class VulnerabilitySearchResults(BaseModel):
    """Vulnerability search results."""
    
    data: List[Vulnerability]
    total: int
    page: int
    page_size: int
    
    @property
    def has_more(self) -> bool:
        """Check if there are more results available."""
        return (self.page + 1) * self.page_size < self.total


# Utility functions for formatting

def format_image_summary(image: ContainerImage) -> str:
    """Format container image for display."""
    repos = ""
    if image.repositories:
        repo_strs = []
        for repo in image.repositories[:3]:  # Show first 3 repos
            if repo.registry and repo.repository:
                repo_strs.append(f"{repo.registry}/{repo.repository}")
        if repo_strs:
            repos = f" ({', '.join(repo_strs)})"
            if len(image.repositories) > 3:
                repos += f" +{len(image.repositories) - 3} more"
    
    certified = "✓ Certified" if image.certified else "⚠ Not Certified"
    arch = f" [{image.architecture}]" if image.architecture else ""
    
    return f"{image.id}{repos}{arch} - {certified}"


def format_project_summary(project: CertificationProject) -> str:
    """Format certification project for display."""
    name = project.name or "Unnamed Project"
    status = project.certification_status or "Unknown"
    project_type = project.type or "Unknown Type"
    
    return f"{name} ({project_type}) - Status: {status}"


def format_operator_summary(operator: OperatorBundle) -> str:
    """Format operator bundle for display."""
    name = operator.csv_name or operator.package_name or "Unknown Operator"
    version = f" v{operator.version}" if operator.version else ""
    certified = "✓ Certified" if operator.certified else "⚠ Not Certified"
    
    return f"{name}{version} - {certified}"


def format_vulnerability_summary(vuln: Vulnerability) -> str:
    """Format vulnerability for display."""
    cve = vuln.cve or "Unknown CVE"
    severity = vuln.severity or "Unknown"
    score = f" (CVSS: {vuln.cvss_score})" if vuln.cvss_score else ""
    package = f" in {vuln.package_name}" if vuln.package_name else ""
    
    return f"{cve} - {severity}{score}{package}"