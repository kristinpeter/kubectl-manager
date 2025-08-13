#!/bin/bash
# kubectl Manager Installation Script
# This script sets up kubectl-manager for first-time use

set -e  # Exit on any error

# Parse command line arguments
AUTO_MODE=false
SKIP_COMPLETION=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --auto)
            AUTO_MODE=true
            shift
            ;;
        --skip-completion)
            SKIP_COMPLETION=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--auto] [--skip-completion] [--help]"
            echo "  --auto              Run in fully automatic mode (no prompts)"
            echo "  --skip-completion   Skip bash completion setup"
            echo "  --help              Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo "🚀 kubectl Manager - Installation Script"
echo "========================================"
if [[ "$AUTO_MODE" == "true" ]]; then
    echo "Running in automatic mode..."
fi
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

# Function to check if requests module is available
check_requests() {
    python3 -c "import requests" &>/dev/null
}

# If requests is already installed, skip installation
if check_requests; then
    print_success "Python requests library already available"
else
    # Try pip3 first
    if command -v pip3 &> /dev/null; then
        print_info "Attempting to install requests via pip3..."
        if pip3 install requests &>/dev/null; then
            print_success "Successfully installed requests via pip3"
        elif python3 -m pip install requests &>/dev/null; then
            print_success "Successfully installed requests via python3 -m pip"
        else
            print_warning "pip install failed, trying system package managers..."
            INSTALL_FAILED=true
        fi
    else
        print_warning "pip3 not found, trying system package managers..."
        INSTALL_FAILED=true
    fi

    # If pip failed, try system package managers
    if [[ "$INSTALL_FAILED" == "true" ]]; then
        if command -v apt &> /dev/null; then
            print_info "Detected Debian/Ubuntu system, installing python3-requests..."
            if command -v sudo &> /dev/null; then
                if sudo apt update &>/dev/null && sudo apt install -y python3-requests &>/dev/null; then
                    print_success "Successfully installed python3-requests via apt"
                else
                    print_error "Failed to install python3-requests via apt"
                    print_info "Please run: sudo apt install python3-requests"
                    exit 1
                fi
            else
                print_info "sudo not available, attempting without sudo..."
                if apt update &>/dev/null && apt install -y python3-requests &>/dev/null; then
                    print_success "Successfully installed python3-requests via apt"
                else
                    print_error "Failed to install python3-requests via apt"
                    print_info "Please run: apt install python3-requests (as root)"
                    exit 1
                fi
            fi
        elif command -v yum &> /dev/null; then
            print_info "Detected RHEL/CentOS system, installing python3-requests..."
            if command -v sudo &> /dev/null; then
                if sudo yum install -y python3-requests &>/dev/null; then
                    print_success "Successfully installed python3-requests via yum"
                else
                    print_error "Failed to install python3-requests via yum"
                    print_info "Please run: sudo yum install python3-requests"
                    exit 1
                fi
            else
                if yum install -y python3-requests &>/dev/null; then
                    print_success "Successfully installed python3-requests via yum"
                else
                    print_error "Failed to install python3-requests via yum"
                    print_info "Please run: yum install python3-requests (as root)"
                    exit 1
                fi
            fi
        elif command -v dnf &> /dev/null; then
            print_info "Detected Fedora system, installing python3-requests..."
            if command -v sudo &> /dev/null; then
                if sudo dnf install -y python3-requests &>/dev/null; then
                    print_success "Successfully installed python3-requests via dnf"
                else
                    print_error "Failed to install python3-requests via dnf"
                    print_info "Please run: sudo dnf install python3-requests"
                    exit 1
                fi
            else
                if dnf install -y python3-requests &>/dev/null; then
                    print_success "Successfully installed python3-requests via dnf"
                else
                    print_error "Failed to install python3-requests via dnf"
                    print_info "Please run: dnf install python3-requests (as root)"
                    exit 1
                fi
            fi
        elif command -v brew &> /dev/null; then
            print_info "Detected macOS with Homebrew, installing python-requests..."
            if brew install python-requests &>/dev/null; then
                print_success "Successfully installed python-requests via brew"
            else
                print_error "Failed to install python-requests via brew"
                print_info "Please run: brew install python-requests"
                exit 1
            fi
        else
            print_error "No supported package manager found"
            print_info "Please install the Python requests library manually:"
            print_info "  pip3 install requests"
            print_info "  OR install via your system package manager"
            exit 1
        fi
    fi

    # Final check to ensure requests is now available
    if ! check_requests; then
        print_error "Python requests library installation failed"
        print_info "Please install it manually and run this script again"
        exit 1
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

# 5. Initialize kubectl-manager and trigger auto-download
print_info "Initializing kubectl-manager and downloading latest kubectl..."
if ./kubectl-manager.py --help > /dev/null 2>&1; then
    # The initialization already happened during the --help call
    # Check if kubectl wrapper was created
    if [[ -f "./kubectl" ]]; then
        print_success "kubectl wrapper created and ready to use"
        print_info "You can now use: ./kubectl get nodes"
    else
        print_warning "kubectl wrapper not found, checking versions..."
        # Try to trigger initialization by running versions list
        ./kubectl-manager.py versions list > /dev/null 2>&1 || true
        if [[ -f "./kubectl" ]]; then
            print_success "kubectl wrapper created successfully"
        else
            print_warning "kubectl wrapper not created automatically"
        fi
    fi
else
    print_error "kubectl-manager.py initialization failed"
    exit 1
fi

# 6. Setup bash completion (optional)
if [[ -f "setup-completion.sh" ]] && [[ "$SKIP_COMPLETION" != "true" ]]; then
    print_info "Setting up bash completion..."
    
    if [[ "$AUTO_MODE" == "true" ]]; then
        # In auto mode, automatically set up completion
        if ./setup-completion.sh &>/dev/null; then
            print_success "Bash completion configured automatically"
        else
            print_warning "Bash completion setup failed, but continuing..."
        fi
    else
        # Interactive mode - ask user
        read -p "Setup bash completion and aliases? [Y/n]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
            if ./setup-completion.sh; then
                print_success "Bash completion configured"
            else
                print_warning "Bash completion setup failed, but continuing..."
            fi
        else
            print_info "Skipped bash completion setup"
            print_info "You can run './setup-completion.sh' later to enable it"
        fi
    fi
elif [[ "$SKIP_COMPLETION" == "true" ]]; then
    print_info "Skipping bash completion setup as requested"
elif [[ ! -f "setup-completion.sh" ]]; then
    print_warning "setup-completion.sh not found, skipping completion setup"
fi

echo ""
echo "🎉 Installation Complete!"
echo "========================"
echo ""
print_success "kubectl-manager is ready to use!"
echo ""
print_info "Quick start commands:"
echo "  ./kubectl-manager.py help                     # Comprehensive help"
echo "  ./kubectl get nodes                           # Use kubectl immediately with KUBECONFIG"
echo "  ./kubectl-manager.py configs add <name> <path> # Import your first cluster"
echo ""
print_info "Example usage:"
echo "  # Option 1: Use existing KUBECONFIG"
echo "  export KUBECONFIG=~/.kube/config"
echo "  ./kubectl get pods"
echo ""
echo "  # Option 2: Import and manage clusters"
echo "  ./kubectl-manager.py configs add prod ~/.kube/config"
echo "  ./kubectl-manager.py use prod"
echo "  ./kubectl get pods"
echo ""

# Check if completion was installed
if grep -q "kubectl-manager-completion.bash" ~/.bashrc 2>/dev/null || grep -q "kubectl-manager-completion.bash" ~/.bash_profile 2>/dev/null; then
    print_info "Bash completion installed! Aliases available:"
    echo "  km                    # Short alias for kubectl-manager.py"
    echo "  kubectl-manager       # Full alias for kubectl-manager.py"
    echo "  k8s                   # kubectl wrapper with autocompletion"
    echo ""
    if [[ -f "./kubectl" ]]; then
        print_info "kubectl wrapper ready:"
        echo "  ./kubectl             # kubectl with latest version"
    fi
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

if [[ "$AUTO_MODE" == "true" ]]; then
    print_info "Automatic installation completed successfully!"
    echo "You can now use kubectl-manager without any additional setup."
    echo ""
fi

print_success "Happy kubectl managing! 🎯"