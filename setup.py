#!/usr/bin/env python3
"""
Setup configuration for VMware vCenter MCP Server.

This setup script provides enterprise-grade packaging and installation
capabilities for the VMware vCenter MCP Server project.
"""

from setuptools import setup, find_packages
import os
import re

# Read version from __init__.py
def get_version():
    with open(os.path.join("src", "vmware_vcenter_mcp", "__init__.py"), "r") as f:
        content = f.read()
        match = re.search(r'__version__ = ["\']([^"\']+)["\']', content)
        if match:
            return match.group(1)
        raise RuntimeError("Unable to find version string")

# Read long description from README
def get_long_description():
    with open("README.md", "r", encoding="utf-8") as f:
        return f.read()

# Read requirements
def get_requirements():
    with open("requirements.txt", "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="vmware-vcenter-mcp",
    version=get_version(),
    author="uldyssian-sh",
    author_email="25517637+uldyssian-sh@users.noreply.github.com",
    description="Enterprise-grade Model Context Protocol (MCP) server for comprehensive VMware vCenter Server management",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/uldyssian-sh/vmware-vcenter-mcp",
    project_urls={
        "Bug Reports": "https://github.com/uldyssian-sh/vmware-vcenter-mcp/issues",
        "Source": "https://github.com/uldyssian-sh/vmware-vcenter-mcp",
        "Documentation": "https://github.com/uldyssian-sh/vmware-vcenter-mcp/blob/main/README.md",
        "Changelog": "https://github.com/uldyssian-sh/vmware-vcenter-mcp/blob/main/CHANGELOG.md",
        "Security": "https://github.com/uldyssian-sh/vmware-vcenter-mcp/blob/main/SECURITY.md",
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Systems Administration",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Clustering",
        "Topic :: System :: Distributed Computing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Environment :: No Input/Output (Daemon)",
    ],
    python_requires=">=3.8",
    install_requires=get_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "pytest-benchmark>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pylint>=2.17.0",
            "bandit>=1.7.0",
            "safety>=2.0.0",
            "pre-commit>=3.0.0",
        ],
        "docs": [
            "sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.2.0",
            "myst-parser>=1.0.0",
            "sphinx-autodoc-typehints>=1.23.0",
        ],
        "monitoring": [
            "prometheus-client>=0.16.0",
            "grafana-api>=1.0.0",
            "psutil>=5.9.0",
        ],
        "enterprise": [
            "ldap3>=2.9.0",
            "cryptography>=40.0.0",
            "redis>=4.5.0",
            "sqlalchemy>=2.0.0",
            "alembic>=1.10.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "vmware-vcenter-mcp=vmware_vcenter_mcp.cli:main",
            "vcenter-mcp-server=vmware_vcenter_mcp.server:main",
            "vcenter-mcp-admin=vmware_vcenter_mcp.admin:main",
        ],
    },
    include_package_data=True,
    package_data={
        "vmware_vcenter_mcp": [
            "config/*.yaml",
            "templates/*.json",
            "schemas/*.json",
            "migrations/*.sql",
            "static/*",
        ],
    },
    zip_safe=False,
    keywords=[
        "vmware", "vcenter", "vsphere", "mcp", "model-context-protocol", 
        "virtualization", "datacenter", "cluster-management", "automation", 
        "enterprise", "api", "infrastructure", "cloud"
    ],
)