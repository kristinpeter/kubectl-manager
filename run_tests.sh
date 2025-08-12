#!/bin/bash
set -euo pipefail

# Test runner script for kubectl-manager in Podman container
# This script builds the test container and runs comprehensive tests

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="kubectl-manager-test"
CONTAINER_NAME="kubectl-manager-test-run"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if podman is available
check_podman() {
    if ! command -v podman &> /dev/null; then
        error "Podman is not installed or not in PATH"
        echo "Please install Podman to run containerized tests"
        exit 1
    fi
    log "Podman version: $(podman --version)"
}

# Function to build test image
build_test_image() {
    log "Building test container image..."
    
    if podman build -f Dockerfile.test -t "$IMAGE_NAME" .; then
        success "Test image built successfully"
    else
        error "Failed to build test image"
        exit 1
    fi
}

# Function to run basic unit tests
run_unit_tests() {
    log "Running unit tests..."
    
    podman run --rm \
        --name "$CONTAINER_NAME-unit" \
        "$IMAGE_NAME" \
        python -m pytest test_kubectl_manager.py -v --tb=short
}

# Function to run tests with coverage
run_coverage_tests() {
    log "Running tests with coverage analysis..."
    
    podman run --rm \
        --name "$CONTAINER_NAME-coverage" \
        "$IMAGE_NAME" \
        python -m pytest test_kubectl_manager.py --cov=kubectl_manager --cov-report=term-missing --cov-report=html
}

# Function to run security analysis
run_security_tests() {
    log "Running security analysis with bandit..."
    
    podman run --rm \
        --name "$CONTAINER_NAME-security" \
        "$IMAGE_NAME" \
        bandit -r kubectl-manager.py -f json || warning "Security issues found - review bandit output"
}

# Function to run static analysis
run_static_analysis() {
    log "Running static analysis..."
    
    # Pylint
    log "Running pylint..."
    podman run --rm \
        --name "$CONTAINER_NAME-pylint" \
        "$IMAGE_NAME" \
        pylint kubectl-manager.py --score=y --reports=y || warning "Pylint issues found"
    
    # MyPy type checking
    log "Running mypy type checking..."
    podman run --rm \
        --name "$CONTAINER_NAME-mypy" \
        "$IMAGE_NAME" \
        mypy kubectl-manager.py --ignore-missing-imports || warning "Type checking issues found"
    
    # Code formatting check
    log "Checking code formatting with black..."
    podman run --rm \
        --name "$CONTAINER_NAME-black" \
        "$IMAGE_NAME" \
        black --check --diff kubectl-manager.py || warning "Code formatting issues found"
}

# Function to run shell script analysis
run_shell_analysis() {
    log "Running shellcheck on shell scripts..."
    
    podman run --rm \
        --name "$CONTAINER_NAME-shellcheck" \
        "$IMAGE_NAME" \
        sh -c 'find . -name "*.sh" -exec shellcheck {} +' || warning "Shell script issues found"
}

# Function to run dependency vulnerability check
run_dependency_check() {
    log "Checking for vulnerable dependencies..."
    
    podman run --rm \
        --name "$CONTAINER_NAME-safety" \
        "$IMAGE_NAME" \
        safety check || warning "Vulnerable dependencies found"
}

# Function to run performance tests
run_performance_tests() {
    log "Running performance tests..."
    
    podman run --rm \
        --name "$CONTAINER_NAME-perf" \
        "$IMAGE_NAME" \
        python -c "
import time
import sys
sys.path.append('/app')
from kubectl_manager import KubectlManager

# Test initialization performance
start = time.time()
manager = KubectlManager()
init_time = time.time() - start

print(f'Initialization time: {init_time:.3f}s')
if init_time > 1.0:
    print('WARNING: Slow initialization')
    exit(1)
else:
    print('Performance test passed')
"
}

# Function to run integration tests
run_integration_tests() {
    log "Running integration tests..."
    
    podman run --rm \
        --name "$CONTAINER_NAME-integration" \
        -v /tmp:/tmp:rw \
        "$IMAGE_NAME" \
        python -m pytest test_kubectl_manager.py::TestIntegration -v --tb=short
}

# Function to clean up containers and images
cleanup() {
    log "Cleaning up test containers and images..."
    
    # Remove any running test containers
    podman ps -a --filter "name=$CONTAINER_NAME" --format "{{.Names}}" | \
        xargs -r podman rm -f
    
    # Optionally remove test image (uncomment if desired)
    # podman rmi "$IMAGE_NAME" 2>/dev/null || true
    
    success "Cleanup completed"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] [TEST_TYPE]"
    echo ""
    echo "Test Types:"
    echo "  unit        Run unit tests only"
    echo "  coverage    Run tests with coverage analysis"
    echo "  security    Run security analysis"
    echo "  static      Run static analysis (pylint, mypy, black)"
    echo "  shell       Run shell script analysis"
    echo "  deps        Check for vulnerable dependencies"
    echo "  perf        Run performance tests"
    echo "  integration Run integration tests"
    echo "  all         Run all tests (default)"
    echo ""
    echo "Options:"
    echo "  --build-only    Build test image and exit"
    echo "  --cleanup       Clean up containers and exit"
    echo "  --no-build      Skip building test image"
    echo "  -h, --help      Show this help message"
}

# Main execution
main() {
    local test_type="all"
    local build_image=true
    local run_cleanup=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --build-only)
                build_image=true
                run_cleanup=false
                test_type="none"
                shift
                ;;
            --cleanup)
                cleanup
                exit 0
                ;;
            --no-build)
                build_image=false
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            unit|coverage|security|static|shell|deps|perf|integration|all)
                test_type=$1
                shift
                ;;
            *)
                error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Check prerequisites
    check_podman
    
    # Build test image if requested
    if [ "$build_image" = true ]; then
        build_test_image
    fi
    
    # Exit if only building
    if [ "$test_type" = "none" ]; then
        exit 0
    fi
    
    log "Starting test execution..."
    
    # Run tests based on type
    case $test_type in
        unit)
            run_unit_tests
            ;;
        coverage)
            run_coverage_tests
            ;;
        security)
            run_security_tests
            ;;
        static)
            run_static_analysis
            ;;
        shell)
            run_shell_analysis
            ;;
        deps)
            run_dependency_check
            ;;
        perf)
            run_performance_tests
            ;;
        integration)
            run_integration_tests
            ;;
        all)
            run_unit_tests
            run_coverage_tests
            run_security_tests
            run_static_analysis
            run_shell_analysis
            run_dependency_check
            run_performance_tests
            run_integration_tests
            ;;
    esac
    
    success "Test execution completed!"
}

# Trap for cleanup on exit
trap cleanup EXIT

# Run main function
main "$@"