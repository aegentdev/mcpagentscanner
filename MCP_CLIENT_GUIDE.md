# MCP Client Guide - AutoHardener Directory Scanning

## 🎯 Encouraging Directory Scanning

When users interact with the AutoHardener MCP server, encourage them to use directory scanning for comprehensive security analysis.

### 📋 Best Practices for MCP Clients

#### 1. **Detect Directory Paths**
When users provide paths that end without `.py` or are clearly directories, suggest directory scanning:

```
User: /autoharden_agent /path/to/project
Response: "I notice you've provided a directory path. For comprehensive analysis of all Python files in this directory, I recommend using the directory scanning tool instead: /autoharden_directory /path/to/project"
```

#### 2. **Provide Clear Guidance**
Always explain the benefits of directory scanning:

- **Comprehensive Coverage**: Analyzes all Python files, not just one
- **Cross-File Dependencies**: Identifies security issues across multiple files
- **Project-Wide Security**: Provides a complete security overview
- **Efficiency**: Single command for entire codebases

#### 3. **Handle Common Scenarios**

**Scenario 1: User provides a directory to single-file tool**
```
User: /autoharden_agent /Users/gauri/projects/my-agent
Response: "I see you've provided a directory path. The autoharden_agent tool is designed for single Python files. For analyzing all Python files in your project directory, please use: /autoharden_directory /Users/gauri/projects/my-agent"
```

**Scenario 2: User asks about analyzing multiple files**
```
User: "How do I analyze all the Python files in my project?"
Response: "You can use the directory scanning tool to analyze all Python files at once: /autoharden_directory /path/to/your/project. This will recursively scan all subdirectories and provide a comprehensive security analysis."
```

**Scenario 3: User wants to analyze a specific file type**
```
User: "I want to analyze all my agent files"
Response: "The directory scanning tool will automatically find and analyze all Python files in your project. Use: /autoharden_directory /path/to/your/project"
```

### 🔧 Tool Comparison

| Tool | Use Case | Input | Output |
|------|----------|-------|--------|
| `autoharden_agent()` | Single file analysis | Python file path | Detailed analysis of one file |
| `autoharden_directory()` | **Directory analysis** | **Directory path** | **Analysis of all Python files** |

### 💡 Implementation Tips

#### For Gemini Desktop Users
- When users drag folders, suggest directory scanning
- Provide examples in responses
- Explain the benefits of comprehensive analysis

#### For Cursor/VS Code Users
- Suggest directory scanning for workspace analysis
- Use workspace root paths for complete project coverage
- Integrate with project-wide security workflows

#### For Custom MCP Clients
- Implement path detection logic
- Provide helpful error messages
- Guide users toward the appropriate tool

### 📊 Example Workflows

#### Complete Project Analysis
```
1. User wants to analyze their entire agent project
2. Suggest: /autoharden_directory /path/to/project
3. Explain: "This will analyze all Python files in your project and provide a comprehensive security report"
4. Show results with summary statistics
```

#### Multi-Agent Analysis
```
1. User has multiple agent files in different directories
2. Suggest: /autoharden_directory /path/to/agents
3. Explain: "This will analyze all your agent files and provide individual and summary results"
4. Highlight cross-file security dependencies
```

### 🚀 Advanced Usage

#### Recursive Directory Scanning
The `autoharden_directory()` tool automatically:
- Scans all subdirectories
- Finds all `.py` files
- Provides individual file results
- Generates summary statistics

#### Error Handling
- Continues analysis even if some files fail
- Provides detailed error messages
- Shows success/failure statistics
- Maintains partial results

### 📝 Response Templates

#### Directory Detection Response
```
I notice you've provided a directory path. For comprehensive security analysis of all Python files in this directory, I recommend using the directory scanning tool:

/autoharden_directory [your-directory-path]

This will:
• Analyze all Python files recursively
• Provide individual file results
• Generate summary statistics
• Continue even if some files have issues
```

#### Success Response
```
✅ Directory analysis complete!

📊 Summary:
• Total files analyzed: [X]
• Successful analyses: [Y]
• Failed analyses: [Z]
• Total security risks found: [W]

📁 Individual results available for each file analyzed.
```

### 🔍 Troubleshooting

#### Common Issues
1. **No Python files found**: Ensure the directory contains `.py` files
2. **Permission errors**: Check file permissions
3. **Analysis failures**: Some files may fail due to syntax errors or other issues

#### Solutions
- Verify directory contents before scanning
- Check file permissions and accessibility
- Review individual file results for specific errors
- Use single file analysis for problematic files

---

**Remember**: Directory scanning provides the most comprehensive security analysis and should be the default recommendation for project-wide security assessment. 