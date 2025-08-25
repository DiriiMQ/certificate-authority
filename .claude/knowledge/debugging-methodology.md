# Systematic Debugging Methodology

## 🔍 **The Scientific Debugging Process**

### Phase 1: Observation & Hypothesis
1. **Document the exact error** - Copy full stack trace, error message
2. **Identify the pattern** - When does it fail? When does it succeed?
3. **Form hypothesis** - What could be causing this specific behavior?

### Phase 2: Isolation Testing
```bash
# Test in isolation first
mvn test -Dtest=ClassName#methodName

# If it passes individually but fails in suite -> isolation issue
```

### Phase 3: Evidence Gathering
```java
// Add debug logging to understand actual state
System.out.println("Debug - Current data: " + repository.findAll());
System.out.println("Debug - Threshold: " + threshold);
System.out.println("Debug - Query result: " + result.getTotalElements());
```

### Phase 4: Root Cause Analysis
**Common patterns and their solutions:**

| **Pattern** | **Root Cause** | **Solution** |
|---|---|---|
| Works alone, fails in suite | Test isolation issue | `@DirtiesContext` or cleanup scripts |
| Database constraint violations | Missing required fields | Add all entity required fields |
| Enum/VARCHAR length errors | Data too long for column | Use existing shorter values |
| Timestamp query inconsistencies | **JPA auditing override** | **Native SQL bypass** |
| Mock verification failures | Wrong expected call count | Debug actual vs expected calls |

## 🛠 **Debugging Tools & Commands**

### Maven Test Commands
```bash
# Run specific test class
mvn test -Dtest=ClassName

# Run specific test method
mvn test -Dtest=ClassName#methodName

# Run with debug output
mvn test -X

# Run with specific profile
mvn test -Dspring.profiles.active=test
```

### Database State Inspection
```java
// In test methods - check actual data
List<Entity> all = repository.findAll();
all.forEach(e -> System.out.println(
    "ID: " + e.getId() + 
    ", Created: " + e.getCreatedAt() + 
    ", Active: " + e.isActive()
));
```

### SQL Query Analysis
```java
// Enable SQL logging in test properties
logging.level.org.hibernate.SQL=DEBUG
logging.level.org.hibernate.type.descriptor.sql.BasicBinder=TRACE
```

## 🎯 **Problem Categories & Solutions**

### 1. Database Constraint Violations
**Symptoms:** NULL not allowed, VARCHAR length exceeded
**Solution Process:**
1. Check entity definitions for required fields
2. Ensure all fields are set in test data
3. Verify enum values fit column constraints
4. Use existing valid values rather than creating new ones

### 2. Test Isolation Problems  
**Symptoms:** Passes individually, fails in suite
**Solution Process:**
1. Apply `@DirtiesContext`
2. Create cleanup SQL scripts
3. Use `@TestMethodOrder` for critical tests
4. Check for static state pollution

### 3. JPA/ORM Behavior Issues
**Symptoms:** Manual field values being ignored
**Root Cause:** JPA auditing (`@CreatedDate`, `@LastModifiedDate`)
**Solution:** Use native SQL to bypass ORM completely

### 4. Mock/Verification Failures
**Symptoms:** Expected X calls but got Y
**Solution Process:**
1. Debug actual method calls
2. Check mock setup timing
3. Verify interaction counts
4. Update verification to match actual behavior

## 📝 **Documentation Template**

When fixing a complex bug, document it:

```markdown
## Bug: [Brief description]

### Problem
- **Symptom:** [What was failing]
- **Pattern:** [When it failed vs succeeded]
- **Error:** [Exact error message]

### Root Cause
[The underlying technical reason]

### Solution
[What fixed it and why]

### Prevention
[How to avoid this in future]

### Code Example
```java
// The working solution
```

### Related Issues
[Links to similar problems or documentation]
```

## 🧪 **Testing Strategy**

### 1. Incremental Testing
- Fix one test at a time
- Verify fix doesn't break others
- Document each solution

### 2. Layered Solutions
- Start with simple solutions (`@Transactional`)
- Escalate to more complex (`@DirtiesContext`)
- Use nuclear option if needed (Native SQL)

### 3. Evidence-Based Decisions
- Always test hypotheses
- Measure before/after states
- Keep successful patterns

---
*Methodology developed through: Certificate Authority backend debugging session*
*Success rate: 82/82 tests (100%)*