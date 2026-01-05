# Contributing to VMware vCenter MCP Server

Thank you for your interest in contributing to the VMware vCenter MCP Server project! This document provides comprehensive guidelines for contributors to ensure high-quality, enterprise-ready code.

## Code of Conduct

This project maintains professional standards and promotes an inclusive environment for all contributors. Please adhere to respectful communication and collaborative development practices.

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git with proper configuration
- VMware vCenter Server environment for testing
- Understanding of MCP (Model Context Protocol) specification
- Knowledge of VMware vSphere APIs

### Development Environment Setup

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/vmware-vcenter-mcp.git
   cd vmware-vcenter-mcp
   ```

3. Create and activate virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

5. Configure development tools:
   ```bash
   pre-commit install
   ```

6. Set up test environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your test vCenter details
   ```

## Development Standards

### Code Quality

- **Style**: Follow PEP 8 with Black formatting
- **Type Safety**: Use comprehensive type hints
- **Documentation**: Write detailed docstrings for all public APIs
- **Error Handling**: Implement robust error handling and logging
- **Security**: Follow secure coding practices

### Architecture Principles

- **Modularity**: Keep components loosely coupled
- **Scalability**: Design for enterprise-scale deployments
- **Performance**: Optimize for high-throughput operations
- **Reliability**: Implement proper retry and failover mechanisms
- **Maintainability**: Write clean, self-documenting code

### Testing Requirements

- **Unit Tests**: 95%+ code coverage required
- **Integration Tests**: Test against real vCenter environments
- **Performance Tests**: Benchmark critical operations
- **Security Tests**: Validate authentication and authorization
- **End-to-End Tests**: Complete workflow validation

## Contribution Workflow

### 1. Planning Phase

Before starting development:
- Review existing issues and discussions
- Create detailed issue for new features/bugs
- Discuss approach with maintainers
- Get approval for significant changes

### 2. Development Phase

Create feature branch:
```bash
git checkout -b feature/descriptive-name
```

Development guidelines:
- Make atomic, focused commits
- Write descriptive commit messages
- Follow established patterns and conventions
- Add comprehensive tests
- Update documentation

### 3. Quality Assurance

Run complete test suite:
```bash
# Code formatting
black src/ tests/
isort src/ tests/

# Linting
flake8 src/ tests/
pylint src/

# Type checking
mypy src/

# Unit tests
pytest tests/unit/ --cov=src --cov-report=html

# Integration tests
pytest tests/integration/ --vcenter-host=test-vcenter

# Security tests
bandit -r src/

# Performance tests
pytest tests/performance/ --benchmark-only
```

### 4. Documentation

Update relevant documentation:
- API documentation for new tools
- Configuration examples
- Troubleshooting guides
- Performance tuning recommendations

### 5. Pull Request Submission

Create comprehensive pull request:
- Clear title and description
- Link to related issues
- Include testing evidence
- Add screenshots/examples if applicable
- Request appropriate reviewers

## MCP Tool Development

### Tool Design Principles

1. **Consistency**: Follow established naming and parameter conventions
2. **Validation**: Comprehensive input validation and sanitization
3. **Error Handling**: Graceful error handling with informative messages
4. **Performance**: Efficient resource utilization and caching
5. **Security**: Proper authentication and authorization checks

### Tool Implementation Template

```python
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from ..auth import require_permissions
from ..utils import validate_vcenter_object
from ..exceptions import VCenterOperationError

class ToolNameRequest(BaseModel):
    """Request model for tool_name operation."""
    
    parameter1: str = Field(..., description="Description of parameter")
    parameter2: Optional[int] = Field(None, description="Optional parameter")
    
    class Config:
        schema_extra = {
            "example": {
                "parameter1": "example_value",
                "parameter2": 100
            }
        }

@mcp_tool(
    name="tool_name",
    description="Comprehensive description of tool functionality",
    input_schema=ToolNameRequest.schema()
)
@require_permissions(["VirtualMachine.Interact.PowerOn"])
async def tool_name(request: ToolNameRequest) -> Dict[str, Any]:
    """
    Detailed description of tool operation.
    
    This tool performs specific vCenter operations with enterprise-grade
    error handling and performance optimization.
    
    Args:
        request: Validated request parameters
        
    Returns:
        Dictionary containing operation results and metadata
        
    Raises:
        VCenterOperationError: When vCenter operation fails
        ValidationError: When input validation fails
        AuthenticationError: When authentication is invalid
        
    Example:
        >>> result = await tool_name(ToolNameRequest(
        ...     parameter1="test",
        ...     parameter2=50
        ... ))
        >>> print(result["status"])
        "success"
    """
    try:
        # Implementation with proper error handling
        logger.info(f"Executing tool_name with parameters: {request}")
        
        # Validate vCenter connectivity
        await validate_vcenter_connection()
        
        # Perform operation
        result = await perform_vcenter_operation(request)
        
        # Log success
        logger.info(f"tool_name completed successfully: {result}")
        
        return {
            "status": "success",
            "data": result,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "operation": "tool_name"
            }
        }
        
    except Exception as e:
        logger.error(f"tool_name failed: {str(e)}")
        raise VCenterOperationError(f"Operation failed: {str(e)}")
```

## Specialized Contribution Areas

### Performance Optimization

- Profile critical code paths
- Implement efficient caching strategies
- Optimize database queries
- Use async/await properly
- Minimize API calls to vCenter

### Security Enhancements

- Implement additional authentication methods
- Add audit logging capabilities
- Enhance input validation
- Improve error message security
- Add rate limiting features

### Enterprise Features

- Multi-tenancy support
- Advanced monitoring capabilities
- Backup and recovery tools
- Compliance reporting features
- High availability improvements

### Documentation

- API reference documentation
- Deployment guides
- Performance tuning guides
- Troubleshooting documentation
- Best practices guides

## Testing Guidelines

### Unit Testing

```python
import pytest
from unittest.mock import AsyncMock, patch
from src.tools.vm_operations import create_vm

@pytest.mark.asyncio
async def test_create_vm_success():
    """Test successful VM creation."""
    with patch('src.vcenter.client.VCenterClient') as mock_client:
        mock_client.create_vm.return_value = {"vm_id": "vm-123"}
        
        result = await create_vm(CreateVMRequest(
            name="test-vm",
            cpu_count=2,
            memory_mb=4096
        ))
        
        assert result["status"] == "success"
        assert "vm-123" in result["data"]["vm_id"]
```

### Integration Testing

```python
@pytest.mark.integration
@pytest.mark.asyncio
async def test_vm_lifecycle_integration(vcenter_client):
    """Test complete VM lifecycle operations."""
    # Create VM
    create_result = await create_vm_tool(test_vm_config)
    vm_id = create_result["data"]["vm_id"]
    
    # Power on VM
    power_result = await power_vm_tool(vm_id, "on")
    assert power_result["status"] == "success"
    
    # Clean up
    await delete_vm_tool(vm_id)
```

## Release Process

### Version Management

- Follow semantic versioning (MAJOR.MINOR.PATCH)
- Update CHANGELOG.md for each release
- Tag releases with proper annotations
- Maintain backward compatibility

### Release Checklist

- [ ] All tests passing
- [ ] Documentation updated
- [ ] Performance benchmarks run
- [ ] Security scan completed
- [ ] Changelog updated
- [ ] Version bumped
- [ ] Release notes prepared

## Community Guidelines

### Communication

- Use clear, professional language
- Provide constructive feedback
- Be patient with new contributors
- Share knowledge and best practices

### Issue Management

- Use appropriate issue templates
- Provide detailed reproduction steps
- Include environment information
- Follow up on requested information

### Code Review

- Review code thoroughly
- Provide specific, actionable feedback
- Test changes locally when possible
- Approve only when confident in quality

## Recognition

Contributors are acknowledged through:
- GitHub contributors list
- Release notes mentions
- Documentation credits
- Community recognition

## Getting Support

- Create issues for bugs and feature requests
- Join community discussions
- Check existing documentation
- Contact maintainers for guidance

Thank you for contributing to VMware vCenter MCP Server and helping build enterprise-grade virtualization management tools!