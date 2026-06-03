# NASA Earthdata CMR API Notes

## Overview
- **Base URL:** https://cmr.earthdata.nasa.gov/search/
- **Response Format:** JSON (default)
- **Authentication:** 
  - Collection search: OPEN (no token required)
  - Granule search: OPEN (no token required)
  - Data download: Requires Earthdata Login (EDL) bearer token

## Collection Search (OPEN)
Query endpoint: https://cmr.earthdata.nasa.gov/search/collections.json

Parameters:
- `keyword`: Free-text search (soil carbon, land temperature, biomass, weathering, etc.)
- `page_size`: Results per page (max 2000)
- `page_num`: Pagination
- `concept_id`: Direct collection ID lookup (e.g., C2517662316-ORNL_CLOUD)

Response structure:
```
feed:
  - updated: timestamp
  - id: query URL
  - title: "ECHO dataset metadata"
  - entry[]: array of collections
    - id: concept_id (e.g. C2517662316-ORNL_CLOUD)
    - entry_id: short_name (e.g. SOC_Stocks_Great_Plains_1603_1)
    - short_name: machine-friendly ID
    - title: dataset title
    - summary: description
    - time_start: first data timestamp
    - time_end: last data timestamp
    - data_center: DAAC/archive (ORNL_CLOUD, NSIDC_CPRD, LPDAAC, etc.)
    - links[]: download, metadata, documentation URLs
```

## Granule Search (OPEN)
Query endpoint: https://cmr.earthdata.nasa.gov/search/granules.json

Parameters:
- `collection_concept_id`: Collection ID (required for indexed search)
- `bounding_box`: Spatial filter (west,south,east,north)
- `temporal`: Temporal range (YYYY-MM-DD or ISO-8601)
- `page_size`: Results per page

## Authentication for Download
Earthdata Login (EDL) required for granule data access:
- Create account: https://urs.earthdata.nasa.gov/
- Generate token: https://auth.earthdata.nasa.gov/tokens
- Use in requests: 
  ```
  Authorization: Bearer <EDL_TOKEN>
  ```
- Token expires after 1 year of inactivity
- Program access via: Personal Tokens or username/password (deprecated for new users)

## Key Collections for MRV (Measurement, Reporting, Verification)
1. Soil Organic Carbon:
   - C2517662316-ORNL_CLOUD: "Stocks of Surface Soil Organic Carbon Fractions, Great Plains Region"
   - SMAP L4 Carbon data (C3252907767-NSIDC_CPRD)

2. Biomass / Above-ground carbon:
   - GEDI products (C4102339168-ORNL_CLOUD): "West African Footprint-Level GEDI Aboveground Biomass"
   - SMAP L4 Carbon ancillary (C3252907767-NSIDC_CPRD)

3. Land Surface Monitoring:
   - MODIS Land Surface Temperature
   - SMAP soil moisture products
   - Landsat-8/9 surface reflectance

## Search Behavior & Gotchas
- Collections returned in relevance order (score field)
- Partial keyword matches supported (e.g., "soil" matches "surface soil organic carbon")
- Empty entry[] array = no matching collections (check spelling, broaden terms)
- No authentication required for searching, only for downloading
- Rate limiting: Reasonable limits (~100 req/min); includes backoff retry guidance in 503 responses
