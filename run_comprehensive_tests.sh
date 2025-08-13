#!/bin/bash
# Comprehensive test runner for kubectl-manager
# Supports multiple test types and environments

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }

# Test configuration
DOCKER_IMAGE="kubectl-manager-test"
CONTAINER_ENGINE=""
TEST_TYPE="all"
CLEANUP=true
VERBOSE=false
PARALLEL=false

# Detect container engine
if command -v podman &> /dev/null; then
    CONTAINER_ENGINE="podman"
    print_info "Using Podman container engine"
elif command -v docker &> /dev/null; then
    CONTAINER_ENGINE="docker"
    print_info "Using Docker container engine"
else
    print_error "Neither Podman nor Docker found. Please install a container engine."
    exit 1
fi

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        basic|security|functionality|performance|integration|all)
            TEST_TYPE="$1"
            shift
            ;;
        --no-cleanup)
            CLEANUP=false
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --parallel|-j)
            PARALLEL=true
            shift
            ;;
        --help|-h)
            cat << EOF
Usage: $0 [TEST_TYPE] [OPTIONS]

Test Types:
  basic          Run basic functionality tests
  security       Run security validation tests  
  functionality  Run comprehensive functionality tests
  performance    Run performance benchmarks
  integration    Run integration tests
  all            Run all tests (default)

Options:
  --no-cleanup   Keep test containers after completion
  --verbose, -v  Enable verbose output
  --parallel, -j Run tests in parallel
  --help, -h     Show this help message

Examples:
  $0 basic                    # Run basic tests
  $0 security --verbose       # Run security tests with verbose output
  $0 all --parallel          # Run all tests in parallel
EOF
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo "🧪 kubectl-manager Comprehensive Test Suite"
echo "==========================================="
print_info "Test type: $TEST_TYPE"
print_info "Container engine: $CONTAINER_ENGINE"
print_info "Cleanup: $CLEANUP"
echo ""

# Build test container
build_container() {
    print_info "Building test container..."
    if ! $CONTAINER_ENGINE build -f Dockerfile.test -t $DOCKER_IMAGE .; then
        print_error "Failed to build test container"
        exit 1
    fi
    print_success "Test container built successfully"
}

# Run basic tests
run_basic_tests() {
    print_info "Running basic functionality tests..."
    
    local args=(
        "run" "--rm"
        "-v" "$(pwd)/test-results:/app/test-results:Z"
        "$DOCKER_IMAGE"
        "python3" "-m" "pytest" "test_basic.py" "-v"
    )
    
    if $VERBOSE; then
        args+=("-s")
    fi
    
    if ! $CONTAINER_ENGINE "${args[@]}"; then
        print_error "Basic tests failed"
        return 1
    fi
    
    print_success "Basic tests passed"
}

# Run security tests
run_security_tests() {
    print_info "Running security validation tests..."
    
    # Security-focused pytest markers
    local args=(
        "run" "--rm"
        "-v" "$(pwd)/test-results:/app/test-results:Z"
        "$DOCKER_IMAGE"
        "python3" "-m" "pytest" "test_comprehensive.py" "-v" "-m" "security"
    )
    
    if ! $CONTAINER_ENGINE "${args[@]}"; then
        print_error "Security tests failed"
        return 1
    fi
    
    # Run bandit security analysis
    print_info "Running bandit security analysis..."
    
    local bandit_args=(
        "run" "--rm"
        "-v" "$(pwd):/app/src:Z"
        "$DOCKER_IMAGE"
        "bandit" "-r" "/app/src/kubectl-manager.py" "-f" "json" "-o" "/app/test-results/bandit-report.json"
    )
    
    if ! $CONTAINER_ENGINE "${bandit_args[@]}"; then
        print_warning "Bandit analysis completed with findings"
    else
        print_success "Bandit analysis passed"
    fi
    
    print_success "Security tests completed"
}

# Run functionality tests
run_functionality_tests() {
    print_info "Running comprehensive functionality tests..."
    
    local args=(
        "run" "--rm"
        "-v" "$(pwd)/test-results:/app/test-results:Z"
        "-v" "$(pwd)/coverage:/app/coverage:Z"
        "$DOCKER_IMAGE"
        "python3" "-m" "pytest" "test_comprehensive.py" "-v"
        "--cov=kubectl_manager" 
        "--cov-report=html:/app/coverage/"
        "--cov-report=term"
        "--junit-xml=/app/test-results/junit.xml"
    )
    
    if $PARALLEL; then
        args+=("-n" "auto")
    fi
    
    if $VERBOSE; then
        args+=("-s")
    fi
    
    if ! $CONTAINER_ENGINE "${args[@]}"; then
        print_error "Functionality tests failed"
        return 1
    fi
    
    print_success "Functionality tests passed"
}

# Run performance tests
run_performance_tests() {
    print_info "Running performance benchmarks..."
    
    local args=(
        "run" "--rm"
        "-v" "$(pwd)/test-results:/app/test-results:Z"
        "$DOCKER_IMAGE"
        "python3" "-m" "pytest" "test_comprehensive.py" "-v" "-m" "performance"
        "--benchmark-json=/app/test-results/benchmark.json"
    )
    
    if ! $CONTAINER_ENGINE "${args[@]}"; then
        print_error "Performance tests failed"
        return 1
    fi
    
    print_success "Performance tests passed"
}

# Run integration tests
run_integration_tests() {
    print_info "Running integration tests..."
    
    # Test in Ubuntu environment
    local args=(
        "run" "--rm"
        "-v" "$(pwd)/test-results:/app/test-results:Z"
        "--privileged"  # Needed for some integration tests
        "$DOCKER_IMAGE"
        "bash" "-c" "
            set -e
            echo 'Testing installation process...'
            ./install.sh --auto
            
            echo 'Testing basic functionality...'
            ./kubectl-manager.py --help >/dev/null
            
            echo 'Testing version listing...'
            timeout 30 ./kubectl-manager.py versions list || true
            
            echo 'Integration tests completed'
        "
    )
    
    if ! $CONTAINER_ENGINE "${args[@]}"; then
        print_error "Integration tests failed"  
        return 1
    fi
    
    print_success "Integration tests passed"
}

# Run code quality checks
run_quality_checks() {
    print_info "Running code quality checks..."
    
    # Check code formatting
    print_info "Checking code formatting with black..."
    if ! $CONTAINER_ENGINE run --rm -v "$(pwd):/app/src:Z" "$DOCKER_IMAGE" \
        black --check --diff /app/src/kubectl-manager.py; then
        print_warning "Code formatting issues found"
    else
        print_success "Code formatting is correct"
    fi
    
    # Check with flake8
    print_info "Running flake8 linting..."
    if ! $CONTAINER_ENGINE run --rm -v "$(pwd):/app/src:Z" "$DOCKER_IMAGE" \
        flake8 /app/src/kubectl-manager.py --max-line-length=120; then
        print_warning "Linting issues found"
    else
        print_success "Linting passed"
    fi
    
    # Check shell scripts
    if command -v shellcheck >/dev/null; then
        print_info "Checking shell scripts with shellcheck..."
        for script in install.sh setup-completion.sh run_comprehensive_tests.sh; do
            if [[ -f "$script" ]]; then
                if ! shellcheck "$script"; then
                    print_warning "Shellcheck issues found in $script"
                else
                    print_success "Shellcheck passed for $script"
                fi
            fi
        done
    fi
}

# Create test results directory
mkdir -p test-results coverage

# Build container
build_container

# Run tests based on type
case $TEST_TYPE in
    basic)
        run_basic_tests
        ;;
    security)
        run_security_tests
        ;;
    functionality)
        run_functionality_tests
        ;;
    performance) 
        run_performance_tests
        ;;
    integration)
        run_integration_tests
        ;;
    all)
        print_info "Running complete test suite..."
        echo ""
        
        run_basic_tests || exit 1
        echo ""
        
        run_security_tests || exit 1
        echo ""
        
        run_functionality_tests || exit 1
        echo ""
        
        run_performance_tests || exit 1
        echo ""
        
        run_integration_tests || exit 1
        echo ""
        
        run_quality_checks || exit 1
        ;;
esac

# Generate test report
print_info "Generating test report..."

cat > test-results/test-summary.md << EOF
# kubectl-manager Test Results

**Test Date:** $(date)
**Test Type:** $TEST_TYPE  
**Container Engine:** $CONTAINER_ENGINE
**Environment:** Ubuntu 22.04 (Docker)

## Test Results

EOF

if [[ -f test-results/junit.xml ]]; then
    print_info "JUnit XML report: test-results/junit.xml"
fi

if [[ -d coverage ]]; then
    print_info "Coverage report: coverage/index.html"
fi

if [[ -f test-results/bandit-report.json ]]; then
    print_info "Security report: test-results/bandit-report.json"
fi

# Cleanup containers if requested
if $CLEANUP; then
    print_info "Cleaning up test containers..."
    $CONTAINER_ENGINE image rm $DOCKER_IMAGE 2>/dev/null || true
fi

echo ""
print_success "🎉 Test suite completed successfully!"
echo ""
print_info "Test results are available in: test-results/"
if [[ -d coverage ]]; then
    print_info "Coverage report is available in: coverage/index.html"
fi