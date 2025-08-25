# Spring Boot Testing Best Practices

## 🏗 **Test Architecture Principles**

### 1. Test Slice Annotations
```java
@DataJpaTest          // For repository layer testing
@WebMvcTest          // For controller layer testing  
@SpringBootTest      // For integration testing
@TestConfiguration   // For custom test configurations
```

### 2. Test Profiles
```properties
# application-test.properties
spring.datasource.url=jdbc:h2:mem:testdb
spring.jpa.hibernate.ddl-auto=create-drop
logging.level.org.hibernate.SQL=DEBUG
```

### 3. Test Database Configuration
```java
@TestPropertySource(properties = {
    "spring.datasource.url=jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=false",
    "spring.datasource.username=sa",
    "spring.datasource.password=",
    "spring.jpa.hibernate.ddl-auto=create-drop"
})
```

## 🎯 **Repository Testing Patterns**

### Standard Repository Test
```java
@DataJpaTest
@ActiveProfiles("test")
class MyRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;
    
    @Autowired 
    private MyRepository repository;

    @Test
    void testBasicCrud() {
        // Given
        MyEntity entity = new MyEntity("test-data");
        entity.setCreatedAt(LocalDateTime.now());
        entity.setUpdatedAt(LocalDateTime.now());
        
        // When
        MyEntity saved = repository.save(entity);
        entityManager.flush(); // Force immediate persistence
        
        // Then
        assertThat(saved.getId()).isNotNull();
        assertThat(repository.findById(saved.getId())).isPresent();
    }
}
```

### Time-Sensitive Repository Test (Advanced)
```java
@DataJpaTest
@ActiveProfiles("test")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class TimeBasedRepositoryTest {

    @Test
    @Order(1)
    @Transactional
    @Rollback
    void testTimeBasedQuery() {
        // Use native SQL for precise timestamp control
        LocalDateTime oldDate = LocalDateTime.now().minusDays(100);
        
        entityManager.getEntityManager().createNativeQuery("""
            INSERT INTO my_table (id, name, created_at, updated_at)
            VALUES (random_uuid(), ?1, ?2, ?3)
            """)
            .setParameter(1, "old-record")
            .setParameter(2, oldDate)
            .setParameter(3, oldDate)
            .executeUpdate();
            
        // Query will now work predictably
        List<MyEntity> oldRecords = repository.findByCreatedAtBefore(
            LocalDateTime.now().minusDays(50));
            
        assertThat(oldRecords).hasSize(1);
    }
}
```

## 🔧 **Service Layer Testing**

### Service Test with Mocks
```java
@ExtendWith(MockitoExtension.class)
class MyServiceTest {

    @Mock
    private MyRepository repository;
    
    @Mock
    private AuditRepository auditRepository;
    
    @InjectMocks
    private MyService service;
    
    @Test
    void testServiceMethod() {
        // Given
        when(repository.findById(any())).thenReturn(Optional.of(entity));
        
        // When
        Result result = service.performOperation(id);
        
        // Then
        assertThat(result.isSuccess()).isTrue();
        verify(auditRepository).save(any(AuditLog.class));
    }
}
```

### Integration Service Test
```java
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class MyServiceIntegrationTest {

    @Autowired
    private MyService service;
    
    @MockBean
    private ExternalApiClient externalApiClient; // Mock external dependencies
    
    @Test
    void testCompleteWorkflow() {
        // Given
        when(externalApiClient.callExternalApi(any())).thenReturn(response);
        
        // When
        Result result = service.performComplexOperation(data);
        
        // Then
        assertThat(result.isSuccess()).isTrue();
        // Verify database state changed correctly
    }
}
```

## 🌐 **Controller Testing**

### Controller Unit Test
```java
@WebMvcTest(MyController.class)
class MyControllerTest {

    @Autowired
    private MockMvc mockMvc;
    
    @MockBean
    private MyService service;
    
    @Test
    @WithMockUser(roles = "ADMIN")
    void testControllerEndpoint() throws Exception {
        // Given
        when(service.getData()).thenReturn(expectedData);
        
        // When & Then
        mockMvc.perform(get("/api/data"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("success"))
            .andExpect(jsonPath("$.data").exists());
    }
}
```

## 🔐 **Security Testing**

### Authentication Testing
```java
@Test
@WithMockUser(username = "admin", roles = {"KEY_ADMIN"})
void testSecuredEndpoint() {
    // Test passes with proper role
}

@Test 
@WithMockUser(username = "user", roles = {"USER"})
void testUnauthorizedAccess() {
    // Should fail with insufficient permissions
    assertThrows(AccessDeniedException.class, () -> {
        service.adminOnlyOperation();
    });
}
```

## 📊 **Test Data Management**

### Test Data Builders
```java
public class TestDataBuilder {
    
    public static SigningKey createSigningKey(String identifier) {
        SigningKey key = new SigningKey(identifier, "Ed25519", "pub", "priv", 256, "testuser");
        key.setCreatedAt(LocalDateTime.now());
        key.setUpdatedAt(LocalDateTime.now());
        key.setIsActive(true);
        return key;
    }
    
    public static AuditLog createAuditLog(String operation, String result) {
        AuditLog log = new AuditLog();
        log.setOperation(OperationType.valueOf(operation));
        log.setResult(ResultType.valueOf(result));
        log.setTimestamp(LocalDateTime.now());
        log.setAlgorithm("Ed25519");
        log.setImageHash("test-hash");
        log.setCreatedAt(LocalDateTime.now());
        log.setUpdatedAt(LocalDateTime.now());
        return log;
    }
}
```

### SQL Test Data
```sql
-- test-data.sql
INSERT INTO signing_keys (id, key_identifier, algorithm, public_key_data, private_key_data, 
                         key_size_bits, is_active, created_at, updated_at, usage_count, version)
VALUES ('test-uuid-1', 'test-key-1', 'Ed25519', 'pub1', 'priv1', 256, 
        true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 0, 0);
```

## 🚀 **Performance Testing**

### Repository Performance Test
```java
@Test
@Timeout(value = 2, unit = TimeUnit.SECONDS)
void testQueryPerformance() {
    // Create test data
    IntStream.range(0, 1000)
        .forEach(i -> repository.save(createTestEntity("entity-" + i)));
    entityManager.flush();
    
    // Test query performance
    long start = System.currentTimeMillis();
    Page<MyEntity> result = repository.findByComplexCriteria(criteria, pageable);
    long duration = System.currentTimeMillis() - start;
    
    assertThat(result.getTotalElements()).isGreaterThan(0);
    assertThat(duration).isLessThan(1000); // Should complete in < 1 second
}
```

## 📋 **Test Quality Checklist**

### ✅ **Good Test Characteristics**
- [ ] **Isolated** - Each test is independent
- [ ] **Repeatable** - Same result every time
- [ ] **Fast** - Runs quickly (< 1 second per test)
- [ ] **Self-Validating** - Clear pass/fail result
- [ ] **Timely** - Written with the code

### ✅ **Test Coverage Goals**
- [ ] **Repository Layer** - All custom queries tested
- [ ] **Service Layer** - Business logic and error cases
- [ ] **Controller Layer** - HTTP interactions and security
- [ ] **Integration** - End-to-end workflows

### ✅ **Common Pitfalls to Avoid**
- [ ] **Time dependencies** - Use fixed dates/times in tests
- [ ] **Order dependencies** - Tests should not depend on execution order
- [ ] **External dependencies** - Mock external services
- [ ] **Database state** - Clean up or isolate properly
- [ ] **Hardcoded values** - Use constants or test data builders

---
*Compiled from: Spring Boot 3.x + JUnit 5 + Mockito best practices*
*Tested on: Certificate Authority backend project*