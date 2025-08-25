# Claude Knowledge Base

This directory contains persistent learning patterns and solutions discovered during development sessions.

## 📚 **Knowledge Files**

### 🔧 [`test-database-patterns.md`](test-database-patterns.md)
**Learned from:** Certificate Authority test fixing session (2025-08-25)
**Covers:** 
- JPA auditing conflicts with manual timestamps
- Test isolation strategies (5 escalation levels)
- Native SQL solutions for precise data control
- Template for complex repository tests

**Key Breakthrough:** Time-sensitive tests fail because `@CreatedDate` overrides manual values. Solution: Use native SQL to bypass JPA auditing.

### 🐛 [`debugging-methodology.md`](debugging-methodology.md) 
**Learned from:** Systematic approach to fixing 9 failing tests
**Covers:**
- Scientific debugging process (Observe → Isolate → Gather Evidence → Analyze)
- Common Spring Boot testing patterns and solutions
- Evidence-based decision making
- Documentation templates for complex bugs

**Key Process:** Test individually first - if passes alone but fails in suite, it's an isolation issue.

### 🏗 [`spring-boot-testing-best-practices.md`](spring-boot-testing-best-practices.md)
**Learned from:** Certificate Authority backend testing architecture
**Covers:**
- Layer-specific testing strategies (@DataJpaTest, @WebMvcTest, @SpringBootTest)
- Security testing with @WithMockUser
- Test data management and builders
- Performance testing patterns

**Key Architecture:** Use appropriate test slices for each layer, mock external dependencies.

## 🔄 **Usage Protocol**

### Before Solving Problems:
1. **Search knowledge base:** `grep -r "your-issue" .claude/knowledge/`
2. **Check relevant patterns:** Match your symptoms to documented solutions
3. **Apply known solutions:** Start with documented approaches

### After Solving Problems:
1. **Update knowledge:** Add new patterns or improve existing ones
2. **Reference the case:** Link to specific project/session that generated learning
3. **Update timestamps:** Keep track of when knowledge was added/modified

## 🎯 **Quick Reference**

### Common Issue → Knowledge File Mapping:
- **Test isolation problems** → `test-database-patterns.md`
- **Complex debugging needed** → `debugging-methodology.md`  
- **Test architecture questions** → `spring-boot-testing-best-practices.md`

### Search Commands:
```bash
# Find all knowledge files
ls .claude/knowledge/*.md

# Search for specific patterns
grep -r "JPA auditing" .claude/knowledge/
grep -r "@DirtiesContext" .claude/knowledge/
grep -r "native SQL" .claude/knowledge/

# View knowledge file quickly  
cat .claude/knowledge/test-database-patterns.md | head -50
```

---
*This knowledge base grows with each solved problem. Refer to it early and often to avoid re-solving the same issues.*