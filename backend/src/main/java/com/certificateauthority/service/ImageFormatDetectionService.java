package com.certificateauthority.service;

import com.certificateauthority.entity.ImageFormat;
import org.apache.tika.Tika;
import org.apache.tika.config.TikaConfig;
import org.apache.tika.detect.Detector;
import org.apache.tika.io.TikaInputStream;
import org.apache.tika.metadata.Metadata;
import org.apache.tika.mime.MediaType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Service for detecting and validating image formats
 * Supports PNG, JPEG, and TIFF formats as specified in requirements
 */
@Service
public class ImageFormatDetectionService {
    
    private static final Logger logger = LoggerFactory.getLogger(ImageFormatDetectionService.class);
    
    // Maximum file size: 100 MB as per requirements
    public static final long MAX_FILE_SIZE = 100 * 1024 * 1024L;
    
    // Magic bytes for image format detection
    private static final byte[] PNG_MAGIC = {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    private static final byte[] JPEG_MAGIC_1 = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF};
    private static final byte[] TIFF_LE_MAGIC = {0x49, 0x49, 0x2A, 0x00}; // Little endian
    private static final byte[] TIFF_BE_MAGIC = {0x4D, 0x4D, 0x00, 0x2A}; // Big endian
    
    private final Tika tika;
    private final Detector detector;
    
    public ImageFormatDetectionService() {
        this.tika = new Tika();
        this.detector = TikaConfig.getDefaultConfig().getDetector();
    }
    
    /**
     * Detect image format from byte array
     */
    public ImageFormatResult detectFormat(byte[] imageData, String originalFilename) {
        if (imageData == null || imageData.length == 0) {
            return ImageFormatResult.invalid("Image data is empty");
        }
        
        // Check file size limit
        if (imageData.length > MAX_FILE_SIZE) {
            return ImageFormatResult.invalid("File size exceeds 100MB limit: " + imageData.length + " bytes");
        }
        
        try {
            // Primary detection using magic bytes
            ImageFormat detectedFormat = detectByMagicBytes(imageData);
            if (detectedFormat != null) {
                
                // Verify with Apache Tika for additional validation
                String mimeType = detectMimeType(imageData);
                if (isValidMimeTypeForFormat(detectedFormat, mimeType)) {
                    return ImageFormatResult.valid(detectedFormat, mimeType, originalFilename);
                } else {
                    logger.warn("Magic bytes indicate {} but MIME type is {}", detectedFormat, mimeType);
                }
            }
            
            // Fallback to MIME type detection only
            String mimeType = detectMimeType(imageData);
            ImageFormat formatFromMime = getFormatFromMimeType(mimeType);
            if (formatFromMime != null) {
                return ImageFormatResult.valid(formatFromMime, mimeType, originalFilename);
            }
            
            return ImageFormatResult.invalid("Unsupported image format. Detected MIME type: " + mimeType);
            
        } catch (Exception e) {
            logger.error("Error detecting image format: {}", e.getMessage(), e);
            return ImageFormatResult.invalid("Error detecting image format: " + e.getMessage());
        }
    }
    
    /**
     * Validate if file size is within limits
     */
    public boolean isValidFileSize(long fileSize) {
        return fileSize > 0 && fileSize <= MAX_FILE_SIZE;
    }
    
    /**
     * Check if format is supported
     */
    public boolean isSupportedFormat(ImageFormat format) {
        return format == ImageFormat.PNG || 
               format == ImageFormat.JPEG || 
               format == ImageFormat.JPG || 
               format == ImageFormat.TIFF;
    }
    
    /**
     * Get expected file extension for format
     */
    public String getExpectedExtension(ImageFormat format) {
        switch (format) {
            case PNG: return ".png";
            case JPEG:
            case JPG: return ".jpg";
            case TIFF: return ".tiff";
            default: return "";
        }
    }
    
    /**
     * Validate file extension matches detected format
     */
    public boolean validateExtension(String filename, ImageFormat detectedFormat) {
        if (filename == null || !filename.contains(".")) {
            return false;
        }
        
        String extension = filename.toLowerCase().substring(filename.lastIndexOf('.'));
        
        switch (detectedFormat) {
            case PNG:
                return ".png".equals(extension);
            case JPEG:
            case JPG:
                return ".jpg".equals(extension) || ".jpeg".equals(extension);
            case TIFF:
                return ".tiff".equals(extension) || ".tif".equals(extension);
            default:
                return false;
        }
    }
    
    // Private helper methods
    
    private ImageFormat detectByMagicBytes(byte[] data) {
        if (data.length < 8) {
            return null;
        }
        
        // Check PNG
        if (startsWith(data, PNG_MAGIC)) {
            return ImageFormat.PNG;
        }
        
        // Check JPEG
        if (startsWith(data, JPEG_MAGIC_1)) {
            return ImageFormat.JPEG;
        }
        
        // Check TIFF
        if (startsWith(data, TIFF_LE_MAGIC) || startsWith(data, TIFF_BE_MAGIC)) {
            return ImageFormat.TIFF;
        }
        
        return null;
    }
    
    private boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) {
            return false;
        }
        
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }
    
    private String detectMimeType(byte[] imageData) {
        try (InputStream stream = TikaInputStream.get(new ByteArrayInputStream(imageData))) {
            Metadata metadata = new Metadata();
            MediaType mediaType = detector.detect(stream, metadata);
            return mediaType.toString();
        } catch (IOException e) {
            logger.warn("Failed to detect MIME type using Tika: {}", e.getMessage());
            // Fallback to simple Tika detection
            return tika.detect(imageData);
        }
    }
    
    private boolean isValidMimeTypeForFormat(ImageFormat format, String mimeType) {
        if (mimeType == null) {
            return false;
        }
        
        switch (format) {
            case PNG:
                return "image/png".equals(mimeType);
            case JPEG:
            case JPG:
                return "image/jpeg".equals(mimeType);
            case TIFF:
                return "image/tiff".equals(mimeType);
            default:
                return false;
        }
    }
    
    private ImageFormat getFormatFromMimeType(String mimeType) {
        if (mimeType == null) {
            return null;
        }
        
        switch (mimeType.toLowerCase()) {
            case "image/png":
                return ImageFormat.PNG;
            case "image/jpeg":
                return ImageFormat.JPEG;
            case "image/tiff":
                return ImageFormat.TIFF;
            default:
                return null;
        }
    }
    
    /**
     * Result class for format detection
     */
    public static class ImageFormatResult {
        private final boolean valid;
        private final ImageFormat format;
        private final String mimeType;
        private final String filename;
        private final String errorMessage;
        
        private ImageFormatResult(boolean valid, ImageFormat format, String mimeType, 
                                String filename, String errorMessage) {
            this.valid = valid;
            this.format = format;
            this.mimeType = mimeType;
            this.filename = filename;
            this.errorMessage = errorMessage;
        }
        
        public static ImageFormatResult valid(ImageFormat format, String mimeType, String filename) {
            return new ImageFormatResult(true, format, mimeType, filename, null);
        }
        
        public static ImageFormatResult invalid(String errorMessage) {
            return new ImageFormatResult(false, null, null, null, errorMessage);
        }
        
        // Getters
        public boolean isValid() { return valid; }
        public ImageFormat getFormat() { return format; }
        public String getMimeType() { return mimeType; }
        public String getFilename() { return filename; }
        public String getErrorMessage() { return errorMessage; }
        
        @Override
        public String toString() {
            if (valid) {
                return String.format("Valid %s image (%s)", format, mimeType);
            } else {
                return "Invalid: " + errorMessage;
            }
        }
    }
}