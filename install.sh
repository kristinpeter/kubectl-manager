#!/bin/bash
# kubectl Manager Installation Script
# This script sets up kubectl-manager for first-time use

set -e  # Exit on any error

echo "🚀 kubectl Manager - Installation Script"
echo "========================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if we're in the right directory
if [[ ! -f "kubectl-manager.py" ]]; then
    print_error "kubectl-manager.py not found in current directory"
    print_info "Please run this script from the kubectl-manager directory"
    exit 1
fi

print_info "Installing kubectl Manager..."
echo ""

# 1. Check Python 3
print_info "Checking Python 3 installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    print_success "Python 3 found: $PYTHON_VERSION"
else
    print_error "Python 3 is required but not found"
    print_info "Please install Python 3.6+ and try again"
    exit 1
fi

# 2. Make kubectl-manager.py executable
print_info "Making kubectl-manager.py executable..."
chmod +x kubectl-manager.py
print_success "kubectl-manager.py is now executable"

# 3. Install Python dependencies
print_info "Installing Python dependencies..."
if command -v pip3 &> /dev/null; then
    pip3 install requests 2>/dev/null || {
        print_warning "pip3 install failed, trying alternative methods..."
        if command -v python3 &> /dev/null; then
            python3 -m pip install requests 2>/dev/null || {
                print_warning "Could not install requests via pip"
                print_info "You may need to install python3-requests via your system package manager:"
                print_info "  Ubuntu/Debian: sudo apt install python3-requests"
                print_info "  RHEL/CentOS: sudo yum install python3-requests"
                print_info "  Fedora: sudo dnf install python3-requests"
                print_info "  macOS: brew install python3-requests"
            }
        fi
    }
else
    print_warning "pip3 not found, trying system package managers..."
    if command -v apt &> /dev/null; then
        print_info "Detected Debian/Ubuntu system"
        print_info "Run: sudo apt install python3-requests"
    elif command -v yum &> /dev/null; then
        print_info "Detected RHEL/CentOS system"
        print_info "Run: sudo yum install python3-requests"
    elif command -v dnf &> /dev/null; then
        print_info "Detected Fedora system"
        print_info "Run: sudo dnf install python3-requests"
    elif command -v brew &> /dev/null; then
        print_info "Detected macOS with Homebrew"
        print_info "Run: brew install python3-requests"
    fi
fi

# 4. Test basic functionality
print_info "Testing kubectl-manager basic functionality..."
if ./kubectl-manager.py --help > /dev/null 2>&1; then
    print_success "kubectl-manager.py is working correctly"
else
    print_error "kubectl-manager.py test failed"
    print_info "Please check that Python requests library is installed"
    exit 1
fi

# 5. Create initial directory structure (kubectl-manager.py will create these on first run, but we can check)
print_info "Initial directory structure will be created on first use"

# 6. Setup bash completion (optional)
if [[ -f "setup-completion.sh" ]]; then
    print_info "Setting up bash completion..."
    read -p "Setup bash completion and aliases? [Y/n]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
        ./setup-completion.sh
        print_success "Bash completion configured"
    else
        print_info "Skipped bash completion setup"
        print_info "You can run './setup-completion.sh' later to enable it"
    fi
else
    print_warning "setup-completion.sh not found, skipping completion setup"
fi

echo ""
echo "🎉 Installation Complete!"
echo "========================"
echo ""
print_success "kubectl-manager is ready to use!"
echo ""
print_info "Quick start commands:"
echo "  ./kubectl-manager.py                          # Interactive mode"
echo "  ./kubectl-manager.py help                     # Comprehensive help"
echo "  ./kubectl-manager.py configs add <name> <path> # Import your first cluster"
echo ""
print_info "Example usage:"
echo "  ./kubectl-manager.py configs add prod ~/.kube/config"
echo "  ./kubectl-manager.py use prod"
echo "  ./kubectl get pods"
echo ""

# Check if completion was installed
if grep -q "kubectl-manager-completion.bash" ~/.bashrc 2>/dev/null || grep -q "kubectl-manager-completion.bash" ~/.bash_profile 2>/dev/null; then
    print_info "Bash completion installed! Aliases available:"
    echo "  km                    # Short alias for kubectl-manager.py"
    echo "  kubectl-manager       # Full alias for kubectl-manager.py"
    echo ""
    print_info "To use completion in current session:"
    echo "  source ~/.bashrc"
    echo ""
fi

print_info "Documentation:"
echo "  README.md            # Getting started guide"
echo "  USER_MANUAL.md       # Comprehensive user manual"  
echo "  QUICK_REFERENCE.md   # Command cheat sheet"
echo "  TROUBLESHOOTING.md   # Common issues and solutions"
echo ""

print_success "Happy kubectl managing! 🎯"