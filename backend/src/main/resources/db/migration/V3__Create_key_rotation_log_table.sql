-- V3__Create_key_rotation_log_table.sql  
-- Creates the key_rotation_log table for tracking key rotation operations and audit trail

-- Create enums for rotation types and reasons
CREATE TYPE rotation_type AS ENUM (
    'INITIAL_KEY_CREATION',
    'SCHEDULED_ROTATION', 
    'MANUAL_ROTATION',
    'EMERGENCY_ROTATION',
    'POLICY_DRIVEN_ROTATION'
);

CREATE TYPE rotation_reason AS ENUM (
    'TIME_BASED',
    'USAGE_BASED',
    'SECURITY_INCIDENT',
    'KEY_COMPROMISE',
    'ALGORITHM_UPDATE',
    'COMPLIANCE_REQUIREMENT',
    'MAINTENANCE',
    'ADMINISTRATOR_REQUEST'
);

-- Create key_rotation_log table
CREATE TABLE key_rotation_log (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    old_key_id              UUID REFERENCES signing_keys(id),
    new_key_id              UUID NOT NULL REFERENCES signing_keys(id),
    rotation_type           rotation_type NOT NULL,
    rotation_reason         rotation_reason NOT NULL,
    algorithm               VARCHAR(50) NOT NULL,
    rotation_timestamp      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    initiated_by            VARCHAR(255) NOT NULL,
    rotation_notes          VARCHAR(1000),
    old_key_usage_count     BIGINT,
    old_key_age_days        INTEGER,
    success                 BOOLEAN NOT NULL DEFAULT TRUE,
    error_message           VARCHAR(500),
    rotation_duration_ms    BIGINT
);

-- Create indexes for performance optimization
CREATE INDEX idx_key_rotation_log_rotation_timestamp ON key_rotation_log (rotation_timestamp DESC);
CREATE INDEX idx_key_rotation_log_old_key_id ON key_rotation_log (old_key_id);
CREATE INDEX idx_key_rotation_log_new_key_id ON key_rotation_log (new_key_id);
CREATE INDEX idx_key_rotation_log_rotation_type ON key_rotation_log (rotation_type);
CREATE INDEX idx_key_rotation_log_initiated_by ON key_rotation_log (initiated_by);
CREATE INDEX idx_key_rotation_log_algorithm ON key_rotation_log (algorithm);
CREATE INDEX idx_key_rotation_log_rotation_reason ON key_rotation_log (rotation_reason);
CREATE INDEX idx_key_rotation_log_success ON key_rotation_log (success);

-- Create composite indexes for complex queries
CREATE INDEX idx_key_rotation_log_type_timestamp ON key_rotation_log (rotation_type, rotation_timestamp DESC);
CREATE INDEX idx_key_rotation_log_reason_timestamp ON key_rotation_log (rotation_reason, rotation_timestamp DESC);
CREATE INDEX idx_key_rotation_log_algorithm_timestamp ON key_rotation_log (algorithm, rotation_timestamp DESC);
CREATE INDEX idx_key_rotation_log_success_timestamp ON key_rotation_log (success, rotation_timestamp DESC);
CREATE INDEX idx_key_rotation_log_user_timestamp ON key_rotation_log (initiated_by, rotation_timestamp DESC);

-- Create partial indexes for specific scenarios
CREATE INDEX idx_key_rotation_log_failed_only ON key_rotation_log (rotation_timestamp DESC, error_message)
    WHERE success = FALSE;

CREATE INDEX idx_key_rotation_log_emergency_only ON key_rotation_log (rotation_timestamp DESC)
    WHERE rotation_type = 'EMERGENCY_ROTATION';

CREATE INDEX idx_key_rotation_log_initial_creation ON key_rotation_log (new_key_id, rotation_timestamp)
    WHERE old_key_id IS NULL AND rotation_type = 'INITIAL_KEY_CREATION';

-- Add comments for documentation
COMMENT ON TABLE key_rotation_log IS 'Audit trail for all key rotation operations and lifecycle events';
COMMENT ON COLUMN key_rotation_log.id IS 'Primary key UUID';
COMMENT ON COLUMN key_rotation_log.old_key_id IS 'Reference to the old key being replaced (NULL for initial key creation)';
COMMENT ON COLUMN key_rotation_log.new_key_id IS 'Reference to the new key being activated';
COMMENT ON COLUMN key_rotation_log.rotation_type IS 'Type of rotation operation performed';
COMMENT ON COLUMN key_rotation_log.rotation_reason IS 'Business reason for the rotation';
COMMENT ON COLUMN key_rotation_log.algorithm IS 'Cryptographic algorithm for the new key';
COMMENT ON COLUMN key_rotation_log.rotation_timestamp IS 'When the rotation was performed';
COMMENT ON COLUMN key_rotation_log.initiated_by IS 'User who initiated the rotation';
COMMENT ON COLUMN key_rotation_log.rotation_notes IS 'Additional notes about the rotation';
COMMENT ON COLUMN key_rotation_log.old_key_usage_count IS 'Usage count of the old key at time of rotation';
COMMENT ON COLUMN key_rotation_log.old_key_age_days IS 'Age of the old key in days at time of rotation';
COMMENT ON COLUMN key_rotation_log.success IS 'Whether the rotation completed successfully';
COMMENT ON COLUMN key_rotation_log.error_message IS 'Error message if rotation failed';
COMMENT ON COLUMN key_rotation_log.rotation_duration_ms IS 'Duration of rotation operation in milliseconds';

-- Create views for common queries and reporting
CREATE OR REPLACE VIEW key_rotation_summary AS
SELECT 
    rotation_type,
    rotation_reason,
    algorithm,
    COUNT(*) as total_rotations,
    COUNT(CASE WHEN success = TRUE THEN 1 END) as successful_rotations,
    COUNT(CASE WHEN success = FALSE THEN 1 END) as failed_rotations,
    ROUND(COUNT(CASE WHEN success = TRUE THEN 1 END) * 100.0 / COUNT(*), 2) as success_rate,
    AVG(rotation_duration_ms) as avg_duration_ms,
    AVG(old_key_usage_count) as avg_old_key_usage,
    AVG(old_key_age_days) as avg_old_key_age_days
FROM key_rotation_log
WHERE rotation_timestamp >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY rotation_type, rotation_reason, algorithm
ORDER BY total_rotations DESC;

COMMENT ON VIEW key_rotation_summary IS 'Summary statistics of key rotations in the last 30 days';

-- Create view for recent rotation activity
CREATE OR REPLACE VIEW recent_key_rotations AS
SELECT 
    krl.id,
    krl.rotation_timestamp,
    krl.rotation_type,
    krl.rotation_reason,
    krl.algorithm,
    krl.initiated_by,
    old_sk.key_identifier as old_key_identifier,
    new_sk.key_identifier as new_key_identifier,
    krl.old_key_usage_count,
    krl.old_key_age_days,
    krl.success,
    krl.error_message,
    krl.rotation_duration_ms
FROM key_rotation_log krl
LEFT JOIN signing_keys old_sk ON krl.old_key_id = old_sk.id
JOIN signing_keys new_sk ON krl.new_key_id = new_sk.id
WHERE krl.rotation_timestamp >= CURRENT_TIMESTAMP - INTERVAL '7 days'
ORDER BY krl.rotation_timestamp DESC;

COMMENT ON VIEW recent_key_rotations IS 'Recent key rotation activity in the last 7 days with key details';

-- Create view for failed rotations that need attention
CREATE OR REPLACE VIEW failed_key_rotations AS
SELECT 
    krl.id,
    krl.rotation_timestamp,
    krl.rotation_type,
    krl.rotation_reason,
    krl.algorithm,
    krl.initiated_by,
    krl.error_message,
    krl.rotation_notes,
    new_sk.key_identifier as attempted_new_key_identifier
FROM key_rotation_log krl
JOIN signing_keys new_sk ON krl.new_key_id = new_sk.id
WHERE krl.success = FALSE
    AND krl.rotation_timestamp >= CURRENT_TIMESTAMP - INTERVAL '30 days'
ORDER BY krl.rotation_timestamp DESC;

COMMENT ON VIEW failed_key_rotations IS 'Failed key rotations in the last 30 days that may need investigation';

-- Create view for rotation frequency analysis
CREATE OR REPLACE VIEW key_rotation_frequency AS
SELECT 
    algorithm,
    DATE_TRUNC('month', rotation_timestamp) as rotation_month,
    COUNT(*) as rotations_per_month,
    COUNT(CASE WHEN rotation_type = 'EMERGENCY_ROTATION' THEN 1 END) as emergency_rotations,
    COUNT(CASE WHEN rotation_type = 'SCHEDULED_ROTATION' THEN 1 END) as scheduled_rotations,
    AVG(old_key_age_days) as avg_key_lifespan_days,
    AVG(old_key_usage_count) as avg_usage_before_rotation
FROM key_rotation_log
WHERE old_key_id IS NOT NULL  -- Exclude initial key creations
    AND rotation_timestamp >= CURRENT_TIMESTAMP - INTERVAL '12 months'
GROUP BY algorithm, DATE_TRUNC('month', rotation_timestamp)
ORDER BY algorithm, rotation_month DESC;

COMMENT ON VIEW key_rotation_frequency IS 'Monthly key rotation frequency analysis by algorithm over the last year';

-- Create a function to calculate key rotation metrics
CREATE OR REPLACE FUNCTION get_key_rotation_metrics(
    p_algorithm VARCHAR DEFAULT NULL,
    p_days_back INTEGER DEFAULT 30
) RETURNS TABLE (
    metric_name VARCHAR,
    metric_value NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        'total_rotations'::VARCHAR as metric_name,
        COUNT(*)::NUMERIC as metric_value
    FROM key_rotation_log
    WHERE ($1 IS NULL OR algorithm = $1)
        AND rotation_timestamp >= CURRENT_TIMESTAMP - ($2 || ' days')::INTERVAL
    
    UNION ALL
    
    SELECT 
        'success_rate'::VARCHAR,
        (COUNT(CASE WHEN success = TRUE THEN 1 END) * 100.0 / NULLIF(COUNT(*), 0))::NUMERIC
    FROM key_rotation_log
    WHERE ($1 IS NULL OR algorithm = $1)
        AND rotation_timestamp >= CURRENT_TIMESTAMP - ($2 || ' days')::INTERVAL
    
    UNION ALL
    
    SELECT 
        'avg_key_lifespan_days'::VARCHAR,
        AVG(old_key_age_days)::NUMERIC
    FROM key_rotation_log
    WHERE ($1 IS NULL OR algorithm = $1)
        AND rotation_timestamp >= CURRENT_TIMESTAMP - ($2 || ' days')::INTERVAL
        AND old_key_id IS NOT NULL
    
    UNION ALL
    
    SELECT 
        'emergency_rotation_count'::VARCHAR,
        COUNT(CASE WHEN rotation_type = 'EMERGENCY_ROTATION' THEN 1 END)::NUMERIC
    FROM key_rotation_log
    WHERE ($1 IS NULL OR algorithm = $1)
        AND rotation_timestamp >= CURRENT_TIMESTAMP - ($2 || ' days')::INTERVAL;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_key_rotation_metrics IS 'Calculate key rotation metrics for a specific algorithm and time period';