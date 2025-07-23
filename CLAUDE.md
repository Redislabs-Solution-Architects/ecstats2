# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ECstats is a Python-based tool for extracting AWS ElastiCache (Redis/Valkey) database metrics via CloudWatch. It's a single-file application that generates Excel reports containing performance metrics and instance information.

## Commands

### Running the Application
- Main execution: `python ecstats.py -c config.ini`
- With custom config: `python ecstats.py -c <config_file>`
- With output directory: `python ecstats.py -c config.ini -d <output_dir>`
- Docker execution: `docker run -v $(pwd):/app -t sumitshatwara/redis-ecstats python3 ecstats.py`

### Environment Setup
```bash
python3 -m venv .env && source .env/bin/activate
pip install -r requirements.txt
cp config.ini.example config.ini
# Edit config.ini with your AWS credentials and regions
```

### Testing
```bash
# Run all tests
pytest test_ecstats.py -v

# Run with coverage
coverage run -m pytest test_ecstats.py
coverage report -m
```

### Code Formatting
```bash
# Format code with black
black ecstats.py test_ecstats.py

# Check formatting without making changes
black --check --diff ecstats.py test_ecstats.py
```

### Docker Build
```bash
docker build -t ecstats .
```

## Architecture

### Core Components

**Single File Application (`ecstats.py`):**
- **Main execution flow**: `main()` → `process_aws_account()` → metric collection functions
- **Configuration parsing**: Uses Python `configparser` to read multi-section config files
- **AWS Integration**: Boto3 sessions with support for both credentials and IAM roles
- **Metric collection**: Two metric categories with different collection periods:
  - `get_max_metrics_weekly()`: 7-day metrics (configurable via `METRIC_COLLECTION_PERIOD_DAYS`)
  - `get_max_metrics_hourly()`: Hourly command-based metrics
- **Output generation**: Excel workbooks with two worksheets (ClusterData, ReservedData)

### Key Functions
- `get_clusters_info()`: Discovers ElastiCache instances and reserved instances
- `get_metric()`/`get_metric_curr()`: CloudWatch metric retrieval
- `get_running_instances_metrics()`: Collects and processes all metrics for active instances
- `create_workbook()`: Generates Excel output structure

### Configuration System
- Multi-environment support via config sections (e.g., `[production]`, `[staging]`)
- Supports both AWS credentials and IAM role-based authentication
- Environment variable support for metric collection period: `METRIC_COLLECTION_PERIOD_DAYS`

### Dependencies
- `boto3`: AWS SDK for ElastiCache and CloudWatch APIs
- `openpyxl`: Excel file generation
- `pytest`: Testing framework with comprehensive test coverage
- `black`: Code formatter for consistent Python style
- Python 3.6+ required (tested on 3.8-3.12)

### AWS Permissions Required
- `CloudWatchReadOnlyAccess`
- `AmazonElastiCacheReadOnlyAccess`

### Output Format
Excel files named `{section}-{region}.xlsx` containing:
- **ClusterData sheet**: Instance details with ~45 performance metrics
- **ReservedData sheet**: Reserved instance information
- Metrics include Redis/Valkey command counts, latencies, memory usage, network stats