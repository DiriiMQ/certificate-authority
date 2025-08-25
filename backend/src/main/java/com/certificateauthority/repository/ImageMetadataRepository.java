package com.certificateauthority.repository;

import com.certificateauthority.entity.ImageMetadata;
import com.certificateauthority.entity.MetadataType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository interface for ImageMetadata entity operations
 */
@Repository
public interface ImageMetadataRepository extends JpaRepository<ImageMetadata, UUID> {
    
    /**
     * Find all metadata for a specific image signature
     */
    List<ImageMetadata> findByImageSignatureId(UUID imageSignatureId);
    
    /**
     * Find specific metadata by image signature ID and metadata key
     */
    Optional<ImageMetadata> findByImageSignatureIdAndMetadataKey(UUID imageSignatureId, String metadataKey);
    
    /**
     * Find metadata by image signature ID, key, and source
     */
    Optional<ImageMetadata> findByImageSignatureIdAndMetadataKeyAndMetadataSource(
            UUID imageSignatureId, String metadataKey, String metadataSource);
    
    /**
     * Find metadata by source type (e.g., EXIF, IPTC, XMP)
     */
    List<ImageMetadata> findByMetadataSource(String metadataSource);
    
    /**
     * Find metadata by type
     */
    List<ImageMetadata> findByMetadataType(MetadataType metadataType);
    
    /**
     * Find metadata by key across all images
     */
    List<ImageMetadata> findByMetadataKey(String metadataKey);
    
    /**
     * Find metadata by key and source
     */
    List<ImageMetadata> findByMetadataKeyAndMetadataSource(String metadataKey, String metadataSource);
    
    /**
     * Search metadata values containing specific text
     */
    List<ImageMetadata> findByMetadataValueContaining(String searchText);
    
    /**
     * Count metadata entries for a specific image signature
     */
    long countByImageSignatureId(UUID imageSignatureId);
    
    /**
     * Count metadata entries by source
     */
    long countByMetadataSource(String metadataSource);
    
    /**
     * Count metadata entries by type
     */
    long countByMetadataType(MetadataType metadataType);
    
    /**
     * Get all unique metadata keys
     */
    @Query("SELECT DISTINCT m.metadataKey FROM ImageMetadata m ORDER BY m.metadataKey")
    List<String> findAllUniqueMetadataKeys();
    
    /**
     * Get all unique metadata sources
     */
    @Query("SELECT DISTINCT m.metadataSource FROM ImageMetadata m ORDER BY m.metadataSource")
    List<String> findAllUniqueMetadataSources();
    
    /**
     * Find metadata with non-null values
     */
    @Query("SELECT m FROM ImageMetadata m WHERE m.metadataValue IS NOT NULL AND m.metadataValue != ''")
    List<ImageMetadata> findNonEmptyMetadata();
    
    /**
     * Find metadata by image signature and source
     */
    List<ImageMetadata> findByImageSignatureIdAndMetadataSource(UUID imageSignatureId, String metadataSource);
    
    /**
     * Get metadata statistics
     */
    @Query("SELECT " +
           "COUNT(m) as totalMetadata, " +
           "COUNT(DISTINCT m.metadataKey) as uniqueKeys, " +
           "COUNT(DISTINCT m.metadataSource) as uniqueSources, " +
           "COUNT(CASE WHEN m.metadataType = 'STRING' THEN 1 END) as stringCount, " +
           "COUNT(CASE WHEN m.metadataType = 'NUMBER' THEN 1 END) as numberCount, " +
           "COUNT(CASE WHEN m.metadataType = 'BOOLEAN' THEN 1 END) as booleanCount, " +
           "COUNT(CASE WHEN m.metadataType = 'JSON' THEN 1 END) as jsonCount " +
           "FROM ImageMetadata m")
    Object[] getMetadataStatistics();
    
    /**
     * Check if metadata exists for image signature, key, and source
     */
    boolean existsByImageSignatureIdAndMetadataKeyAndMetadataSource(
            UUID imageSignatureId, String metadataKey, String metadataSource);
    
    /**
     * Delete all metadata for a specific image signature
     */
    void deleteByImageSignatureId(UUID imageSignatureId);
    
    /**
     * Find metadata entries that contain specific values (case insensitive)
     */
    @Query("SELECT m FROM ImageMetadata m WHERE LOWER(m.metadataValue) LIKE LOWER(CONCAT('%', :value, '%'))")
    List<ImageMetadata> findByMetadataValueContainingIgnoreCase(@Param("value") String value);
}