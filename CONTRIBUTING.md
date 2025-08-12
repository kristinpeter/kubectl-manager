# Contributing to kubectl Manager

Thank you for considering contributing to kubectl Manager! 🎉

## 🚀 Quick Start

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/kubectl-manager.git`
3. Create a feature branch: `git checkout -b feature/amazing-feature`
4. Make your changes
5. Test your changes: `./kubectl-manager.py --help`
6. Commit: `git commit -m 'Add amazing feature'`
7. Push: `git push origin feature/amazing-feature`
8. Open a Pull Request

## 🐛 Bug Reports

Please use the [issue tracker](https://github.com/your-username/kubectl-manager/issues) to report bugs.

Include:
- **Environment**: OS, Python version, kubectl version
- **Steps to reproduce**
- **Expected behavior**
- **Actual behavior**
- **Error messages** (if any)

## 💡 Feature Requests

Feature requests are welcome! Please:
1. Check if the feature already exists or is requested
2. Open an issue with the `enhancement` label
3. Describe the problem you're trying to solve
4. Describe your proposed solution

## 🔧 Development Setup

```bash
# Clone the repository
git clone https://github.com/your-username/kubectl-manager.git
cd kubectl-manager

# Install dependencies
pip3 install requests

# Make sure it works
./kubectl-manager.py --help

# Run tests (if available)
python3 -m pytest tests/
```

## 📝 Coding Guidelines

- **Python Style**: Follow PEP 8
- **Comments**: Add docstrings to functions
- **Error Handling**: Provide helpful error messages
- **Cross-platform**: Ensure compatibility with Linux, macOS, Windows
- **User Experience**: Keep the tool beginner-friendly

## 🧪 Testing

Before submitting:
1. Test basic functionality: `./kubectl-manager.py status`
2. Test version management: `./kubectl-manager.py versions list`
3. Test with sample kubeconfig (if safe to do so)
4. Test help system: `./kubectl-manager.py help`
5. Test bash completion: `source kubectl-manager-completion.bash`

## 📚 Documentation

When adding features:
- Update relevant documentation files
- Add examples to help text
- Update QUICK_REFERENCE.md if needed
- Consider updating USER_MANUAL.md

## 🏷️ Pull Request Process

1. **Test thoroughly** on your local system
2. **Update documentation** if needed
3. **Follow the existing code style**
4. **Write clear commit messages**
5. **Reference issues** if applicable (e.g., "Fixes #123")

## 📋 Code Review

Pull requests will be reviewed for:
- **Functionality**: Does it work as intended?
- **Compatibility**: Works on different platforms?
- **Code Quality**: Is it readable and maintainable?
- **User Experience**: Is it intuitive to use?
- **Documentation**: Are changes documented?

## 🤝 Community

- Be respectful and inclusive
- Help others in issues and discussions
- Share your use cases and feedback
- Contribute to documentation improvements

## 📞 Getting Help

- **Issues**: For bugs and feature requests
- **Discussions**: For questions and general discussion
- **Code**: Check existing issues for good first contributions

---

**Thank you for contributing to kubectl Manager!** 🙏