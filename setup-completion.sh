#!/bin/bash
# Setup script for kubectl-manager bash completion

echo "🚀 kubectl Manager - Setting up bash completion..."

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPLETION_FILE="$SCRIPT_DIR/kubectl-manager-completion.bash"

# Check if completion file exists
if [[ ! -f "$COMPLETION_FILE" ]]; then
    echo "❌ Completion file not found: $COMPLETION_FILE"
    exit 1
fi

# Determine shell configuration file
if [[ -f "$HOME/.bashrc" ]]; then
    SHELL_RC="$HOME/.bashrc"
elif [[ -f "$HOME/.bash_profile" ]]; then
    SHELL_RC="$HOME/.bash_profile"
elif [[ -f "$HOME/.profile" ]]; then
    SHELL_RC="$HOME/.profile"
else
    echo "⚠️  Could not find shell configuration file"
    echo "Please add this line to your shell configuration manually:"
    echo "source $COMPLETION_FILE"
    exit 1
fi

# Check if already added
if grep -q "kubectl-manager-completion.bash" "$SHELL_RC" 2>/dev/null; then
    echo "✅ kubectl-manager completion is already configured in $SHELL_RC"
else
    echo "📝 Adding completion to $SHELL_RC..."
    {
        echo ""
        echo "# kubectl-manager bash completion"
        echo "if [[ -f \"$COMPLETION_FILE\" ]]; then"
        echo "    source \"$COMPLETION_FILE\""
        echo "fi"
    } >> "$SHELL_RC"
    echo "✅ Added kubectl-manager completion to $SHELL_RC"
fi

# Create convenience aliases
echo "🔧 Setting up convenience aliases..."
if ! grep -q "alias km=" "$SHELL_RC" 2>/dev/null; then
    {
        echo ""
        echo "# kubectl-manager aliases"
        echo "alias km=\"$SCRIPT_DIR/kubectl-manager.py\""
        echo "alias kubectl-manager=\"$SCRIPT_DIR/kubectl-manager.py\""
    } >> "$SHELL_RC"
    echo "✅ Added aliases: km, kubectl-manager"
fi

# Load completion in current session
# shellcheck source=/dev/null
source "$COMPLETION_FILE"

echo ""
echo "🎉 Setup complete!"
echo ""
echo "To use in current session:"
echo "  source $SHELL_RC"
echo ""
echo "Or start a new terminal session."
echo ""
echo "Available commands:"
echo "  ./kubectl-manager.py     # Full command"
echo "  km                       # Short alias"
echo "  kubectl-manager          # Full alias"
echo ""
echo "Try tab completion:"
echo "  ./kubectl-manager.py <TAB><TAB>"
echo "  km use <TAB><TAB>"
echo "  km versions <TAB><TAB>"