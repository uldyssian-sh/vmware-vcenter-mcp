"""
VMware vCenter MCP Server - Main Entry Point

Command-line interface for running the VMware vCenter MCP Server.

Author: uldyssian-sh
License: MIT
"""

import asyncio
import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Optional

from .server import VCenterMCPServer
from .enterprise_server import EnterpriseServer, create_server_from_config


def setup_logging(level: str = "INFO") -> None:
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('vcenter-mcp.log')
        ]
    )


async def run_basic_server(config_file: Optional[str] = None) -> None:
    """Run basic MCP server"""
    import yaml
    
    # Load configuration
    if config_file and os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
    else:
        config = {
            "vcenter_host": os.getenv("VCENTER_HOST", ""),
            "vcenter_username": os.getenv("VCENTER_USERNAME", ""),
            "vcenter_password": os.getenv("VCENTER_PASSWORD", ""),
            "vcenter_port": int(os.getenv("VCENTER_PORT", "443")),
            "vcenter_ssl_verify": os.getenv("VCENTER_SSL_VERIFY", "true").lower() == "true"
        }
    
    # Validate required configuration
    if not config.get("vcenter_host"):
        print("Error: vCenter host is required. Set VCENTER_HOST environment variable or provide config file.")
        sys.exit(1)
    
    if not config.get("vcenter_username"):
        print("Error: vCenter username is required. Set VCENTER_USERNAME environment variable or provide config file.")
        sys.exit(1)
    
    if not config.get("vcenter_password"):
        print("Error: vCenter password is required. Set VCENTER_PASSWORD environment variable or provide config file.")
        sys.exit(1)
    
    # Create and start server
    server = VCenterMCPServer(config)
    await server.start()


async def run_enterprise_server(config_file: str) -> None:
    """Run enterprise server"""
    if not os.path.exists(config_file):
        print(f"Error: Configuration file {config_file} not found.")
        sys.exit(1)
    
    try:
        server = await create_server_from_config(config_file)
        await server.start()
    except Exception as e:
        print(f"Error starting enterprise server: {e}")
        sys.exit(1)


def main() -> None:
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="VMware vCenter MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run basic MCP server with environment variables
  python -m vmware_vcenter_mcp
  
  # Run basic MCP server with config file
  python -m vmware_vcenter_mcp --config config.yaml
  
  # Run enterprise server
  python -m vmware_vcenter_mcp --enterprise --config config/enterprise.yaml
  
  # Enable debug logging
  python -m vmware_vcenter_mcp --log-level DEBUG
        """
    )
    
    parser.add_argument(
        "--config", "-c",
        help="Configuration file path",
        default=None
    )
    
    parser.add_argument(
        "--enterprise", "-e",
        action="store_true",
        help="Run enterprise server with full architecture"
    )
    
    parser.add_argument(
        "--log-level", "-l",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level"
    )
    
    parser.add_argument(
        "--version", "-v",
        action="version",
        version="VMware vCenter MCP Server 1.0.0"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    
    # Print startup banner
    print("=" * 60)
    print("VMware vCenter MCP Server v1.0.0")
    print("Enterprise virtualization management via MCP")
    print("Author: uldyssian-sh")
    print("=" * 60)
    
    try:
        if args.enterprise:
            if not args.config:
                print("Error: Enterprise mode requires --config parameter")
                sys.exit(1)
            print("Starting enterprise server...")
            asyncio.run(run_enterprise_server(args.config))
        else:
            print("Starting basic MCP server...")
            asyncio.run(run_basic_server(args.config))
            
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()