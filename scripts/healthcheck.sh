#!/bin/bash
# VMware vCenter MCP Server - Health Check Script
# Enterprise health check for container monitoring

set -euo pipefail

# Configuration
HEALTH_ENDPOINT="http://localhost:8080/health"
METRICS_ENDPOINT="http://localhost:9090/metrics"
TIMEOUT=10
MAX_RETRIES=3
RETRY_DELAY=2

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >&2
}

# Error function
error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Warning function
warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

# Success function
success() {
    echo -e "${GREEN}[OK]${NC} $1" >&2
}

# Check if curl is available
check_curl() {
    if ! command -v curl &> /dev/null; then
        error "curl is not available"
        return 1
    fi
}

# Check HTTP endpoint with retries
check_endpoint() {
    local endpoint="$1"
    local description="$2"
    local expected_status="${3:-200}"
    
    for ((i=1; i<=MAX_RETRIES; i++)); do
        log "Checking $description (attempt $i/$MAX_RETRIES)"
        
        if response=$(curl -s -w "%{http_code}" -o /tmp/health_response --max-time "$TIMEOUT" "$endpoint" 2>/dev/null); then
            http_code="${response: -3}"
            
            if [[ "$http_code" == "$expected_status" ]]; then
                success "$description is healthy (HTTP $http_code)"
                return 0
            else
                warn "$description returned HTTP $http_code (expected $expected_status)"
            fi
        else
            warn "$description is not responding"
        fi
        
        if [[ $i -lt $MAX_RETRIES ]]; then
            log "Retrying in $RETRY_DELAY seconds..."
            sleep "$RETRY_DELAY"
        fi
    done
    
    error "$description failed after $MAX_RETRIES attempts"
    return 1
}

# Check application health
check_application_health() {
    log "Checking application health endpoint"
    
    if check_endpoint "$HEALTH_ENDPOINT" "Application health"; then
        # Parse health response for detailed status
        if [[ -f /tmp/health_response ]]; then
            local health_status
            health_status=$(cat /tmp/health_response | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('status', 'unknown'))
except:
    print('unknown')
" 2>/dev/null || echo "unknown")
            
            case "$health_status" in
                "healthy")
                    success "Application status: healthy"
                    return 0
                    ;;
                "degraded")
                    warn "Application status: degraded"
                    return 0
                    ;;
                "unhealthy")
                    error "Application status: unhealthy"
                    return 1
                    ;;
                *)
                    warn "Application status: $health_status"
                    return 0
                    ;;
            esac
        fi
        return 0
    else
        return 1
    fi
}

# Check metrics endpoint
check_metrics() {
    log "Checking metrics endpoint"
    
    if check_endpoint "$METRICS_ENDPOINT" "Metrics endpoint"; then
        # Verify metrics format
        if [[ -f /tmp/health_response ]]; then
            local metrics_count
            metrics_count=$(grep -c "^# HELP" /tmp/health_response 2>/dev/null || echo "0")
            
            if [[ "$metrics_count" -gt 0 ]]; then
                success "Metrics endpoint has $metrics_count metric definitions"
                return 0
            else
                warn "Metrics endpoint returned unexpected format"
                return 1
            fi
        fi
        return 0
    else
        return 1
    fi
}

# Check process status
check_process() {
    log "Checking application process"
    
    # Check if Python process is running
    if pgrep -f "vmware_vcenter_mcp" > /dev/null; then
        success "Application process is running"
        
        # Check process memory usage
        local memory_usage
        memory_usage=$(ps -o pid,ppid,cmd,%mem,%cpu --sort=-%mem -C python3 | grep vmware_vcenter_mcp | awk '{print $4}' | head -1)
        
        if [[ -n "$memory_usage" ]]; then
            log "Memory usage: ${memory_usage}%"
            
            # Warn if memory usage is high
            if (( $(echo "$memory_usage > 80" | bc -l 2>/dev/null || echo "0") )); then
                warn "High memory usage detected: ${memory_usage}%"
            fi
        fi
        
        return 0
    else
        error "Application process is not running"
        return 1
    fi
}

# Check disk space
check_disk_space() {
    log "Checking disk space"
    
    local disk_usage
    disk_usage=$(df /app | tail -1 | awk '{print $5}' | sed 's/%//')
    
    if [[ -n "$disk_usage" ]]; then
        log "Disk usage: ${disk_usage}%"
        
        if [[ "$disk_usage" -gt 90 ]]; then
            error "Critical disk space: ${disk_usage}% used"
            return 1
        elif [[ "$disk_usage" -gt 80 ]]; then
            warn "High disk usage: ${disk_usage}% used"
        else
            success "Disk space is adequate: ${disk_usage}% used"
        fi
        
        return 0
    else
        warn "Could not determine disk usage"
        return 0
    fi
}

# Check log files
check_logs() {
    log "Checking log files"
    
    local log_dir="/app/logs"
    
    if [[ -d "$log_dir" ]]; then
        # Check if logs are being written
        local recent_logs
        recent_logs=$(find "$log_dir" -name "*.log" -mmin -5 2>/dev/null | wc -l)
        
        if [[ "$recent_logs" -gt 0 ]]; then
            success "Log files are being updated"
        else
            warn "No recent log activity detected"
        fi
        
        # Check for error patterns in recent logs
        local error_count
        error_count=$(find "$log_dir" -name "*.log" -mmin -5 -exec grep -i "error\|exception\|failed" {} \; 2>/dev/null | wc -l)
        
        if [[ "$error_count" -gt 0 ]]; then
            warn "Found $error_count recent error messages in logs"
        fi
        
        return 0
    else
        warn "Log directory not found: $log_dir"
        return 0
    fi
}

# Check network connectivity
check_network() {
    log "Checking network connectivity"
    
    # Check if we can resolve DNS
    if nslookup google.com > /dev/null 2>&1; then
        success "DNS resolution is working"
    else
        warn "DNS resolution issues detected"
    fi
    
    # Check if application port is listening
    if netstat -ln 2>/dev/null | grep -q ":8080.*LISTEN" || ss -ln 2>/dev/null | grep -q ":8080.*LISTEN"; then
        success "Application is listening on port 8080"
        return 0
    else
        error "Application is not listening on port 8080"
        return 1
    fi
}

# Main health check function
main() {
    log "Starting enterprise health check"
    
    local exit_code=0
    
    # Check curl availability
    if ! check_curl; then
        exit 1
    fi
    
    # Run all health checks
    check_process || exit_code=1
    check_network || exit_code=1
    check_application_health || exit_code=1
    check_metrics || exit_code=1
    check_disk_space || exit_code=1
    check_logs
    
    # Cleanup
    rm -f /tmp/health_response
    
    if [[ $exit_code -eq 0 ]]; then
        success "All health checks passed"
        log "Health check completed successfully"
    else
        error "Some health checks failed"
        log "Health check completed with errors"
    fi
    
    exit $exit_code
}

# Run main function
main "$@"