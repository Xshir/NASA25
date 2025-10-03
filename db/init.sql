-- Enable PostGIS
CREATE EXTENSION IF NOT EXISTS postgis;

-- Minimal schema for now
CREATE TABLE IF NOT EXISTS locations (
    id SERIAL PRIMARY KEY,
    name TEXT,
    geom GEOGRAPHY(POINT, 4326) NOT NULL
);
