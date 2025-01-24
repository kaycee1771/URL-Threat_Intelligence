CREATE TABLE scam_urls (
    url_id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    threat_category VARCHAR(50),
    source VARCHAR(100),
    added_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'unknown',
    CONSTRAINT unique_url UNIQUE (url)
);

CREATE TABLE detection_metrics (
    metric_id SERIAL PRIMARY KEY,
    url_id INT REFERENCES scam_urls(url_id) ON DELETE CASCADE,
    detection_method VARCHAR(50),
    detection_success BOOLEAN,
    detection_time FLOAT,
    detection_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
