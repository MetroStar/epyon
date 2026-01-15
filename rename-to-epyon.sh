#!/bin/bash

# EPYON Rebranding Script
# This script renames the repository from comprehensive-security-architecture to epyon

set -e

echo "███████╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗"
echo "██╔════╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║"
echo "█████╗  ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║"
echo "██╔══╝  ██╔═══╝   ╚██╔╝  ██║   ██║██║╚██╗██║"
echo "███████╗██║        ██║   ╚██████╔╝██║ ╚████║"
echo "╚══════╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝"
echo ""
echo "Absolute Security Control - Repository Rebranding"
echo ""

CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$CURRENT_DIR")"
NEW_DIR="$PARENT_DIR/epyon"

echo "📋 Rebranding Plan:"
echo "   Current: $CURRENT_DIR"
echo "   New:     $NEW_DIR"
echo ""

# Check if new directory already exists
if [ -d "$NEW_DIR" ]; then
    echo "❌ Error: Directory '$NEW_DIR' already exists!"
    echo "   Please remove it first or choose a different location."
    exit 1
fi

# Ask for confirmation
read -p "⚠️  This will rename the directory and update git remote. Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Aborted."
    exit 1
fi

echo ""
echo "🔄 Step 1: Renaming directory..."
cd "$PARENT_DIR"
mv "comprehensive-security-architecture" "epyon"
echo "✅ Directory renamed to: epyon"

echo ""
echo "🔄 Step 2: Updating git remote URL..."
cd "$NEW_DIR"

# Check if there's a git remote
if git remote get-url origin &> /dev/null; then
    CURRENT_REMOTE=$(git remote get-url origin)
    echo "   Current remote: $CURRENT_REMOTE"
    
    # Update the remote URL
    NEW_REMOTE=$(echo "$CURRENT_REMOTE" | sed 's/comprehensive-security-architecture/epyon/g')
    echo "   New remote:     $NEW_REMOTE"
    
    git remote set-url origin "$NEW_REMOTE"
    echo "✅ Git remote updated"
    echo ""
    echo "📝 Note: You'll need to create the new GitHub repository:"
    echo "   1. Go to: https://github.com/new"
    echo "   2. Repository name: epyon"
    echo "   3. Description: EPYON - Absolute Security Control"
    echo "   4. Make it public or private as needed"
    echo "   5. Don't initialize with README (we already have one)"
    echo ""
    echo "   Then push with: git push -u origin main"
else
    echo "⚠️  No git remote found. Skipping remote update."
fi

echo ""
echo "✅ Rebranding complete!"
echo ""
echo "📍 Your new EPYON repository is at:"
echo "   $NEW_DIR"
echo ""
echo "🚀 Next steps:"
echo "   cd $NEW_DIR"
echo "   git status"
echo "   # Create the new GitHub repo (if updating remote)"
echo "   # git push -u origin main"
echo ""
