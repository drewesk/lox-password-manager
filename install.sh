#!/bin/bash
# Quick Lox Installation

set -e

echo "🔐 Installing Lox Password Manager..."
echo ""

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
fi

# Install dependencies
echo "📥 Installing dependencies..."
source venv/bin/activate
pip install -r requirements.txt --quiet
deactivate
echo "✅ Dependencies installed"

# Make executable
chmod +x lox.py
chmod +x lox

# Add to PATH
SHELL_RC="${HOME}/.zshrc"
if ! grep -q "export PATH.*lox" "$SHELL_RC" 2>/dev/null; then
    echo "" >> "$SHELL_RC"
    echo "# Lox Password Manager" >> "$SHELL_RC"
    echo "export PATH=\"${PWD}:\$PATH\"" >> "$SHELL_RC"
    echo "✅ Added Lox to PATH in $SHELL_RC"
else
    echo "✅ Lox already in PATH"
fi

echo ""
echo "✅ Installation complete!"
echo ""
echo "🔐 To start using Lox:"
echo "  1. Run: source ~/.zshrc"
echo "  2. Initialize: lox init"
echo "  3. Or read: cat README.md"
echo ""
echo "📚 For help: lox --help"
