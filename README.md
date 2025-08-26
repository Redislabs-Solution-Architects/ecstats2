# ECSTATS

ECstats is a tool for extracting ElasticCache database metrics. The script is able to process all the Redis databases, both single instance, replicated and clustered ones that belong to specific AWS region. Multiple regions can be defined in the configuration.

The script will purely query cloudwatch for the metrics. It will never connect to the Redis databases and it will NOT send any commands to the databases.

This script by no means will affect the performance and the data stored in the Redis databases it is scanning.

The script will need at minimum CloudwatchReadOnlyAccess & AmazonElastiCacheReadOnlyAccess privilleges for extracting the information.

## 🚀 New Multithreaded Version

ECstats now includes a **multithreaded version** (`elasticache_metrics_multithreaded_fixed.py`) that significantly improves performance by processing multiple clusters and AWS accounts in parallel.

### Key Features:
- **🏃‍♂️ Parallel Processing**: Process multiple AWS accounts and ElastiCache clusters simultaneously
- **⚙️ Configurable Threading**: Adjust thread counts for optimal performance
- **🛡️ Thread-Safe Operations**: Safe concurrent access to shared resources
- **📊 Progress Monitoring**: Real-time progress tracking with detailed logs
- **⏱️ Performance Metrics**: Execution time tracking and statistics

### Default Thread Configuration:
- **Account Threads**: 1 (processes AWS accounts sequentially)
- **Cluster Threads**: 10 (processes up to 10 clusters/nodes in parallel within each account)

This configuration optimizes performance while respecting AWS API rate limits.

## Installation

There are couple of ways to run the script which are mentioned as below:

### 1. Running the script from source

**Pre-requisites:** The script will run on any system with Python 3.9 or greater installed.

Download the repository

```bash
git clone https://github.com/Redislabs-Solution-Architects/ecstats2 && cd ecstats2
```

Prepare and activate the virtual environment

```bash
python3 -m venv .env && source .env/bin/activate
```

Install necessary libraries and dependencies

```bash
pip install -r requirements.txt
```

Copy the example configuration file and update its contents to match your configuration. AWS User Access Key ID and Secret Access Key are needed to access your AWS ElastiCache instances. Multiple AWS Environments (e.g Production, Staging) and AWS Regions can be defined in this file and the script will process all the AWS ElastiCache instances that are defined as separate sections in the config.ini file.

```bash
cp config.ini.example config.ini && vim config.ini
```

#### Standard Version
Execute below python command to run the script. Use -c option with configuration file if the file name is different from config.ini

```bash
python ecstats.py -c config.ini
```

#### 🚀 Multithreaded Version (Recommended)
For improved performance, use the multithreaded version:

```bash
# Basic usage with default threading (1 account thread, 10 cluster threads)
python elasticache_metrics_multithreaded_fixed.py -c config.ini

# Custom thread configuration
python elasticache_metrics_multithreaded_fixed.py -c config.ini --max-account-threads 2 --max-cluster-threads 15

# With custom output directory
python elasticache_metrics_multithreaded_fixed.py -c config.ini -d ./output --max-cluster-threads 20
```

##### Thread Configuration Options:
- `--max-account-threads`: Number of AWS accounts to process in parallel (default: 1)
- `--max-cluster-threads`: Number of clusters/nodes to process in parallel within each account (default: 10)

##### Environment Variables:
You can also set thread limits via environment variables:
```bash
export MAX_ACCOUNT_THREADS=1
export MAX_CLUSTER_THREADS=10
python elasticache_metrics_multithreaded_fixed.py -c config.ini
```

##### Performance Guidelines:
| Scenario | Account Threads | Cluster Threads | Use Case |
|----------|----------------|-----------------|----------|
| **Small Environment** | 1 | 5-8 | Few clusters, conservative approach |
| **Medium Environment** | 1 | 10-15 | Balanced performance and stability |
| **Large Environment** | 1-2 | 15-20 | Many clusters, maximum performance |
| **Rate Limit Sensitive** | 1 | 5 | When AWS API limits are a concern |

When finished do not forget to deactivate the virtual environment

```bash
deactivate
```

### 2. Running the script from Docker image

**Pre-requisites:** You have Docker engine installed on your machine. Refer this link to install Docker engine: `https://docs.docker.com/engine/install/`

Download the repository

```bash
git clone https://github.com/Redislabs-Solution-Architects/ecstats2 && cd ecstats2
```

Copy the example configuration file and update its contents to match your configuration. AWS User Access Key ID and Secret Access Key are needed to access your AWS ElastiCache instances. Multiple AWS Environments (e.g Production, Staging) and AWS Regions can be defined in this file and the script will process all the AWS ElastiCache instances that are defined as separate sections in the config.ini file.

```bash
cp config.ini.example config.ini && vim config.ini
```

Execute the script using `docker run` command. Use -c option with configuration file if the file name is different from config.ini

```bash
pwd
```
For example, output of this command is `/a/path/to/ecstats`. Use the below docker command to run the script

#### Standard Version
```bash
docker run -v /a/path/to/ecstats:/app -t sumitshatwara/redis-ecstats python3 ecstats.py
```

#### Multithreaded Version
```bash
docker run -v /a/path/to/ecstats:/app -t sumitshatwara/redis-ecstats python3 elasticache_metrics_multithreaded_fixed.py --max-cluster-threads 10
```

### 3. Running the Script Using EC2 Instance Profiles (No AWS Keys and Credentials Required on config.ini)

If you are running this script on an EC2 instance that has an attached IAM role, you can avoid specifying the AWS Access Key ID and Secret Access Key in the configuration file.
The script will automatically use the IAM role's credentials to access AWS services like ElastiCache and CloudWatch.

#### Steps:

**Ensure the EC2 instance has an IAM role with the required permissions:**
- CloudWatchReadOnlyAccess
- AmazonElastiCacheReadOnlyAccess

**Modify the config.ini file:**

Simply omit the aws_access_key_id and aws_secret_access_key fields from the configuration file. You only need to specify the region_name for each environment.

_Example config.ini:_

```ini
[production-us-east-1]
region_name = us-east-1

[production-us-west-1]
region_name = us-west-1

[staging-account-with-credentials]
aws_access_key_id     = AKI<...>
aws_secret_access_key = <ACME_BLABLABLA>
region_name           = us-east-1
```

**Run the script normally:**
```bash
# Standard version
python ecstats.py -c config.ini

# Multithreaded version
python elasticache_metrics_multithreaded_fixed.py -c config.ini
```

## 📊 Output

Both versions of the script generate Excel files with comprehensive ElastiCache metrics:

### File Structure:
- **File naming**: `{environment}-{region}.xlsx`
- **ClusterData sheet**: Individual node metrics and performance data
- **ReservedData sheet**: Reserved instance information

### Metrics Collected:
- **Performance Metrics**: CPU utilization, memory usage, cache hits/misses
- **Network Metrics**: Bytes in/out, packets in/out
- **Command Metrics**: Redis command statistics (GET, SET, etc.)
- **Latency Metrics**: Command latency for different operation types
- **Administrative**: Node roles, snapshot retention, engine information

## 🔧 Troubleshooting

### Common Issues:

**Rate Limiting**: If you encounter AWS API rate limits, reduce the number of cluster threads:
```bash
python elasticache_metrics_multithreaded_fixed.py -c config.ini --max-cluster-threads 5
```

**Memory Usage**: For very large environments, process accounts sequentially:
```bash
python elasticache_metrics_multithreaded_fixed.py -c config.ini --max-account-threads 1 --max-cluster-threads 8
```

**Thread-safe Errors**: If you encounter threading issues, fall back to the standard single-threaded version:
```bash
python ecstats.py -c config.ini
```

## 🚀 Performance Comparison

| Environment Size | Standard Version | Multithreaded Version | Improvement |
|------------------|------------------|-----------------------|-------------|
| 10 clusters | ~5 minutes | ~1-2 minutes | 60-75% faster |
| 50 clusters | ~25 minutes | ~5-8 minutes | 70-80% faster |
| 100+ clusters | ~50+ minutes | ~10-15 minutes | 70-85% faster |

*Results may vary based on AWS API response times and system resources.*

## 📋 Requirements

### Python Dependencies
- boto3 >= 1.26.0
- openpyxl >= 3.0.0
- configparser (built-in)
- threading (built-in)
- concurrent.futures (built-in)

### AWS Permissions
- CloudWatchReadOnlyAccess
- AmazonElastiCacheReadOnlyAccess

### System Requirements
- Python 3.9 or higher
- Sufficient memory for concurrent operations (recommended: 4GB+ RAM for large environments)
- Network connectivity to AWS APIs
