# Claude Code Instructions

## Task Master AI Instructions
**Import Task Master's development workflow commands and guidelines, treat as if import is in the main CLAUDE.md file.**
@./.taskmaster/CLAUDE.md

## 🧠 Claude Learning Knowledge Base

### **When encountering testing issues, debugging problems, or Spring Boot challenges:**

**ALWAYS check these knowledge files first before attempting solutions:**

#### 🔧 Test Database Issues & Solutions
📂 `.claude/knowledge/test-database-patterns.md`
- **Use when:** Tests pass individually but fail in suite
- **Covers:** JPA auditing conflicts, isolation strategies, native SQL solutions
- **Key pattern:** Time-sensitive queries need native SQL to bypass auditing

#### 🐛 Systematic Debugging Methodology  
📂 `.claude/knowledge/debugging-methodology.md`
- **Use when:** Complex bugs, unclear root causes, systematic investigation needed
- **Covers:** Scientific debugging process, evidence gathering, common patterns
- **Key pattern:** Isolate → Debug → Hypothesize → Test → Document

#### 🏗 Spring Boot Testing Best Practices
📂 `.claude/knowledge/spring-boot-testing-best-practices.md` 
- **Use when:** Writing new tests, setting up test architecture, performance testing
- **Covers:** Repository/Service/Controller testing, security testing, test data management
- **Key pattern:** Layer-appropriate testing strategies and configurations

### **Knowledge Integration Protocol:**

1. **Before implementing solutions:** Read relevant knowledge files
2. **When patterns match:** Apply documented solutions first
3. **When solutions work:** Update knowledge files with new learnings
4. **When solutions fail:** Document failure patterns and alternative approaches

### **Quick Reference Commands:**
```bash
# Access knowledge base
find .claude/knowledge -name "*.md" | head -10

# Search for specific patterns
grep -r "JPA auditing" .claude/knowledge/
grep -r "test isolation" .claude/knowledge/
```

### **Knowledge Update Protocol:**
When you learn something new or solve a complex problem:
1. Identify which knowledge file it belongs to
2. Add the new pattern/solution with clear examples
3. Update the last modified date
4. Reference the specific case that generated the learning

**Remember: These knowledge files are your persistent memory system. Use them to avoid re-solving the same problems.**
