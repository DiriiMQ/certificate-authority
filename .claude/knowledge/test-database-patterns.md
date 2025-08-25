# Test Database Isolation Patterns & Solutions

## 🔍 **Root Cause Analysis Framework**

### Symptom: Test passes individually but fails in suite
**Primary Suspects:**
1. **JPA Auditing Override** - `@CreatedDate`/`@LastModifiedDate` ignore manual values
2. **Transaction Boundary Issues** - Data bleeding between tests
3. **Entity State Pollution** - Previous test data interfering
4. **Time-sensitive Logic** - Timestamps affected by test execution order

### Diagnostic Process:
```bash
# 1. Test individually first
mvn test -Dtest=ClassNameTest#methodName

# 2. Add debug logging to see actual data state
System.out.println("Data: " + repository.findAll());

# 3. Check for auto-auditing fields in entities
grep -r "@CreatedDate\|@LastModifiedDate" src/
```

## 🛠 **Solution Hierarchy (Escalation Order)**

### Level 1: Basic Transaction Isolation
```java
@Transactional
@Rollback
```
- **Use for:** Simple CRUD operations
- **Limitation:** Limited isolation, JPA auditing still active

### Level 2: Context Isolation
```java
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
```
- **Use for:** Complex entity relationships
- **Limitation:** Slower execution, JPA auditing still active

### Level 3: SQL Cleanup Scripts
```java
@Sql(executionPhase = Sql.ExecutionPhase.BEFORE_TEST_METHOD, scripts = "classpath:cleanup.sql")
```
- **Use for:** Explicit database state control
- **Create cleanup.sql:**
```sql
DELETE FROM child_table;
DELETE FROM parent_table;
ALTER SEQUENCE IF EXISTS hibernate_sequence RESTART WITH 1;
```

### Level 4: Test Method Ordering
```java
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Order(1) // Run time-sensitive tests first
```
- **Use for:** Preventing test interference
- **Limitation:** Creates test dependencies

### Level 5: Native SQL Bypass (Ultimate Solution)
```java
// CRITICAL: Bypasses JPA auditing for precise control
entityManager.getEntityManager().createNativeQuery("""
    INSERT INTO public.table_name 
    (id, created_at, updated_at, other_fields)
    VALUES (random_uuid(), ?1, ?2, ?3)
    """)
    .setParameter(1, specificTimestamp)
    .setParameter(2, specificTimestamp)
    .setParameter(3, value)
    .executeUpdate();
```
- **Use for:** Time-sensitive queries, JPA auditing conflicts
- **Advantage:** Complete control over data state

## 🎯 **Template for Complex Repository Tests**

```java
@DataJpaTest
@ActiveProfiles("test")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class MyRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;
    
    @Autowired
    private MyRepository repository;

    @Test
    @Order(1) // Critical tests first
    @Transactional
    @Rollback
    @Sql(executionPhase = Sql.ExecutionPhase.BEFORE_TEST_METHOD, scripts = "classpath:cleanup.sql")
    void testTimeBasedQuery() {
        // When you need precise timestamp control, bypass JPA auditing
        LocalDateTime specificDate = LocalDateTime.now().minusDays(100);
        
        entityManager.getEntityManager().createNativeQuery("""
            INSERT INTO public.signing_keys 
            (id, key_identifier, algorithm, created_at, updated_at, is_active, usage_count, version)
            VALUES (random_uuid(), ?1, ?2, ?3, ?4, ?5, ?6, ?7)
            """)
            .setParameter(1, "test-key")
            .setParameter(2, "Ed25519")
            .setParameter(3, specificDate)
            .setParameter(4, specificDate)
            .setParameter(5, true)
            .setParameter(6, 0)
            .setParameter(7, 0)
            .executeUpdate();
            
        entityManager.flush();
        
        // Now your query will work predictably
        Page<MyEntity> result = repository.findByCreatedAtBefore(
            specificDate.plusDays(50), PageRequest.of(0, 10));
            
        assertThat(result.getTotalElements()).isEqualTo(1);
    }
}
```

## 🚨 **Common Anti-Patterns to Avoid**

### ❌ Don't: Rely on JPA for timestamp-sensitive tests
```java
// This WILL be overridden by @CreatedDate auditing
entity.setCreatedAt(LocalDateTime.now().minusDays(100));
repository.save(entity);
```

### ✅ Do: Use native SQL for precise control
```java
// This bypasses auditing and gives you exact control
entityManager.getEntityManager().createNativeQuery(
    "INSERT INTO table_name (created_at, ...) VALUES (?1, ...)"
).setParameter(1, specificDate).executeUpdate();
```

## 📋 **Quick Decision Matrix**

| Issue Type | Best Solution | Performance | Control Level |
|---|---|---|---|
| Simple CRUD | `@Transactional @Rollback` | Fast | Low |
| Entity relationships | `@DirtiesContext` | Medium | Medium |
| Cross-test interference | `@Sql` + `@TestMethodOrder` | Medium | High |
| **JPA auditing conflicts** | **Native SQL** | **Fast** | **Complete** |
| Time-sensitive queries | **Native SQL** | **Fast** | **Complete** |

## 🔄 **When to Apply This Knowledge**

**Immediate triggers:**
- Test passes individually but fails in suite
- Timestamp-based queries returning unexpected results
- "expected: 1L but was: 0L" type assertion failures
- JPA entities with `@CreatedDate`/`@LastModifiedDate` annotations

**Keywords to watch for in error messages:**
- Assertion failures in repository tests
- Time-based query inconsistencies
- Database constraint violations with timestamps
- Test isolation problems

---
*Last updated: 2025-08-25*
*Learned from: Certificate Authority backend test fixing session*