import os
import sys
import datetime
import configparser
import optparse
import boto3
import openpyxl

# Metric Collection Period (in days)
METRIC_COLLECTION_PERIOD_DAYS = int(
    os.environ.get("METRIC_COLLECTION_PERIOD_DAYS") or 7
)

SECONDS_IN_MINUTE = 60
SECONDS_IN_HOUR = 60 * SECONDS_IN_MINUTE
SECONDS_IN_DAY = 24 * SECONDS_IN_HOUR

RUNNING_INSTANCES_WORKSHEET_NAME = "ClusterData"
RESERVED_INSTANCES_WORKSHEET_NAME = "ReservedData"

# ElastiCache instance specifications mapping
# Source: https://aws.amazon.com/elasticache/pricing/
# Format: {instance_type: (memory_gb, vcpus, network_performance)}
INSTANCE_SPECS = {
    # Current generation - Memory optimized (R7g)
    "cache.r7g.large": (13.07, 2, "Up to 12.5 Gigabit"),
    "cache.r7g.xlarge": (26.32, 4, "Up to 12.5 Gigabit"),
    "cache.r7g.2xlarge": (52.82, 8, "Up to 15 Gigabit"),
    "cache.r7g.4xlarge": (105.81, 16, "Up to 15 Gigabit"),
    "cache.r7g.8xlarge": (211.79, 32, "15 Gigabit"),
    "cache.r7g.12xlarge": (317.77, 48, "22.5 Gigabit"),
    "cache.r7g.16xlarge": (423.75, 64, "30 Gigabit"),
    # Current generation - Memory optimized (R6g)
    "cache.r6g.large": (13.07, 2, "Up to 10 Gigabit"),
    "cache.r6g.xlarge": (26.32, 4, "Up to 10 Gigabit"),
    "cache.r6g.2xlarge": (52.82, 8, "Up to 10 Gigabit"),
    "cache.r6g.4xlarge": (105.81, 16, "Up to 10 Gigabit"),
    "cache.r6g.8xlarge": (211.79, 32, "12 Gigabit"),
    "cache.r6g.12xlarge": (317.77, 48, "20 Gigabit"),
    "cache.r6g.16xlarge": (423.75, 64, "25 Gigabit"),
    # Current generation - Memory optimized with NVMe SSD (R6gd)
    "cache.r6gd.large": (13.07, 2, "Up to 10 Gigabit"),
    "cache.r6gd.xlarge": (26.32, 4, "Up to 10 Gigabit"),
    "cache.r6gd.2xlarge": (52.82, 8, "Up to 10 Gigabit"),
    "cache.r6gd.4xlarge": (105.81, 16, "Up to 10 Gigabit"),
    "cache.r6gd.8xlarge": (211.79, 32, "12 Gigabit"),
    "cache.r6gd.12xlarge": (317.77, 48, "20 Gigabit"),
    "cache.r6gd.16xlarge": (423.75, 64, "25 Gigabit"),
    # Current generation - Memory optimized (R5)
    "cache.r5.large": (13.07, 2, "Up to 10 Gigabit"),
    "cache.r5.xlarge": (26.32, 4, "Up to 10 Gigabit"),
    "cache.r5.2xlarge": (52.82, 8, "Up to 10 Gigabit"),
    "cache.r5.4xlarge": (105.81, 16, "Up to 10 Gigabit"),
    "cache.r5.12xlarge": (317.77, 48, "10 Gigabit"),
    "cache.r5.24xlarge": (635.61, 96, "25 Gigabit"),
    # Current generation - Memory optimized (R4)
    "cache.r4.large": (12.3, 2, "Up to 10 Gigabit"),
    "cache.r4.xlarge": (25.05, 4, "Up to 10 Gigabit"),
    "cache.r4.2xlarge": (50.47, 8, "Up to 10 Gigabit"),
    "cache.r4.4xlarge": (101.38, 16, "Up to 10 Gigabit"),
    "cache.r4.8xlarge": (203.26, 32, "10 Gigabit"),
    "cache.r4.16xlarge": (407.00, 64, "25 Gigabit"),
    # Current generation - Compute optimized (C7gn)
    "cache.c7gn.large": (3.19, 2, "Up to 30 Gigabit"),
    "cache.c7gn.xlarge": (6.38, 4, "Up to 40 Gigabit"),
    "cache.c7gn.2xlarge": (12.76, 8, "Up to 50 Gigabit"),
    "cache.c7gn.4xlarge": (25.52, 16, "Up to 50 Gigabit"),
    "cache.c7gn.8xlarge": (51.04, 32, "50 Gigabit"),
    "cache.c7gn.12xlarge": (76.56, 48, "75 Gigabit"),
    "cache.c7gn.16xlarge": (102.08, 64, "100 Gigabit"),
    # Current generation - Compute optimized (C7g)
    "cache.c7g.large": (3.19, 2, "Up to 12.5 Gigabit"),
    "cache.c7g.xlarge": (6.38, 4, "Up to 12.5 Gigabit"),
    "cache.c7g.2xlarge": (12.76, 8, "Up to 15 Gigabit"),
    "cache.c7g.4xlarge": (25.52, 16, "Up to 15 Gigabit"),
    "cache.c7g.8xlarge": (51.04, 32, "15 Gigabit"),
    "cache.c7g.12xlarge": (76.56, 48, "22.5 Gigabit"),
    "cache.c7g.16xlarge": (102.08, 64, "30 Gigabit"),
    # Current generation - General purpose (M7g)
    "cache.m7g.large": (6.38, 2, "Up to 12.5 Gigabit"),
    "cache.m7g.xlarge": (12.93, 4, "Up to 12.5 Gigabit"),
    "cache.m7g.2xlarge": (26.04, 8, "Up to 15 Gigabit"),
    "cache.m7g.4xlarge": (52.26, 16, "Up to 15 Gigabit"),
    "cache.m7g.8xlarge": (104.71, 32, "15 Gigabit"),
    "cache.m7g.12xlarge": (157.25, 48, "22.5 Gigabit"),
    "cache.m7g.16xlarge": (209.99, 64, "30 Gigabit"),
    # Current generation - General purpose (M6g)
    "cache.m6g.large": (6.38, 2, "Up to 10 Gigabit"),
    "cache.m6g.xlarge": (12.93, 4, "Up to 10 Gigabit"),
    "cache.m6g.2xlarge": (26.04, 8, "Up to 10 Gigabit"),
    "cache.m6g.4xlarge": (52.26, 16, "Up to 10 Gigabit"),
    "cache.m6g.8xlarge": (104.71, 32, "12 Gigabit"),
    "cache.m6g.12xlarge": (157.25, 48, "20 Gigabit"),
    "cache.m6g.16xlarge": (209.99, 64, "25 Gigabit"),
    # Current generation - General purpose (M5)
    "cache.m5.large": (6.38, 2, "Up to 10 Gigabit"),
    "cache.m5.xlarge": (12.93, 4, "Up to 10 Gigabit"),
    "cache.m5.2xlarge": (26.04, 8, "Up to 10 Gigabit"),
    "cache.m5.4xlarge": (52.26, 16, "Up to 10 Gigabit"),
    "cache.m5.12xlarge": (157.25, 48, "10 Gigabit"),
    "cache.m5.24xlarge": (315.49, 96, "25 Gigabit"),
    # Current generation - General purpose (M4)
    "cache.m4.large": (6.42, 2, "Moderate"),
    "cache.m4.xlarge": (14.28, 4, "High"),
    "cache.m4.2xlarge": (29.70, 8, "High"),
    "cache.m4.4xlarge": (60.78, 16, "High"),
    "cache.m4.10xlarge": (154.64, 40, "10 Gigabit"),
    # Previous generation - General purpose (M3)
    "cache.m3.medium": (2.78, 1, "Moderate"),
    "cache.m3.large": (6.05, 2, "Moderate"),
    "cache.m3.xlarge": (13.30, 4, "High"),
    "cache.m3.2xlarge": (27.90, 8, "High"),
    # Burstable performance (T4g)
    "cache.t4g.micro": (0.5, 2, "Up to 5 Gigabit"),
    "cache.t4g.small": (1.37, 2, "Up to 5 Gigabit"),
    "cache.t4g.medium": (3.09, 2, "Up to 5 Gigabit"),
    # Burstable performance (T3)
    "cache.t3.micro": (0.5, 2, "Up to 5 Gigabit"),
    "cache.t3.small": (1.37, 2, "Up to 5 Gigabit"),
    "cache.t3.medium": (3.09, 2, "Up to 5 Gigabit"),
    # Burstable performance (T2)
    "cache.t2.micro": (0.555, 1, "Low to Moderate"),
    "cache.t2.small": (1.55, 1, "Low to Moderate"),
    "cache.t2.medium": (3.22, 2, "Low to Moderate"),
}


def get_instance_specs(instance_type):
    """Get the specifications for a given instance type.
    Args:
        instance_type (str): The ElastiCache instance type (e.g., cache.r6g.xlarge)
    Returns:
        tuple: (memory_gb, vcpus, network_performance) or (None, None, None) if unknown
    """
    return INSTANCE_SPECS.get(instance_type, (None, None, None))


def get_max_metrics_hourly():
    metrics = [
        # GetTypeCmds   The total number of read-only type commands. This is derived from the Redis commandstats statistic by summing all of the read-only type commands (get, hget, scard, lrange, and so on.)
        ("GetTypeCmds", "Maximum", SECONDS_IN_HOUR),
        # SetTypeCmds	The total number of write types of commands. This is derived from the Redis commandstats statistic by summing all of the mutative types of commands that operate on data (set, hset, sadd, lpop, and so on.)
        ("SetTypeCmds", "Maximum", SECONDS_IN_HOUR),
        # ClusterBasedCmds	The total number of commands that are cluster-based. This is derived from the Redis commandstats statistic by summing all of the commands that act upon a cluster (cluster slot, cluster info, and so on).
        ("ClusterBasedCmds", "Maximum", SECONDS_IN_HOUR),
        # EvalBasedCmds	The total number of commands for eval-based commands. This is derived from the Redis commandstats statistic by summing eval, evalsha.
        ("EvalBasedCmds", "Maximum", SECONDS_IN_HOUR),
        # GeoSpatialBasedCmds	The total number of commands for geospatial-based commands. This is derived from the Redis commandstats statistic. It's derived by summing all of the geo type of commands: geoadd, geodist, geohash, geopos, georadius, and georadiusbymember.
        ("GeoSpatialBasedCmds", "Maximum", SECONDS_IN_HOUR),
        # HashBasedCmds	The total number of commands that are hash-based. This is derived from the Redis commandstats statistic by summing all of the commands that act upon one or more hashes (hget, hkeys, hvals, hdel, and so on).
        ("HashBasedCmds", "Maximum", SECONDS_IN_HOUR),
        # HyperLogLogBasedCmds	The total number of HyperLogLog-based commands. This is derived from the Redis commandstats statistic by summing all of the pf type of commands (pfadd, pfcount, pfmerge, and so on.).
        ("HyperLogLogBasedCmds", "Maximum", SECONDS_IN_HOUR),
        # KeyBasedCmds	The total number of commands that are key-based. This is derived from the Redis commandstats statistic by summing all of the commands that act upon one or more keys across multiple data structures (del, expire, rename, and so on.).
        ("KeyBasedCmds", "Maximum", SECONDS_IN_HOUR),
        # ListBasedCmds	The total number of commands that are list-based. This is derived from the Redis commandstats statistic by summing all of the commands that act upon one or more lists (lindex, lrange, lpush, ltrim, and so on).
        ("ListBasedCmds", "Maximum", SECONDS_IN_HOUR),
        # PubSubBasedCmds	The total number of commands for pub/sub functionality. This is derived from the Redis commandstatsstatistics by summing all of the commands used for pub/sub functionality: psubscribe, publish, pubsub, punsubscribe, subscribe, and unsubscribe.
        ("PubSubBasedCmds", "Maximum", SECONDS_IN_HOUR),
        # SetBasedCmds	The total number of commands that are set-based. This is derived from the Redis commandstats statistic by summing all of the commands that act upon one or more sets (scard, sdiff, sadd, sunion, and so on).
        ("SetBasedCmds", "Maximum", SECONDS_IN_HOUR),
        # SortedSetBasedCmds	The total number of commands that are sorted set-based. This is derived from the Redis commandstats statistic by summing all of the commands that act upon one or more sorted sets (zcount, zrange, zrank, zadd, and so on).
        ("SortedSetBasedCmds", "Maximum", SECONDS_IN_HOUR),
        # StringBasedCmds	The total number of commands that are string-based. This is derived from the Redis commandstats statistic by summing all of the commands that act upon one or more strings (strlen, setex, setrange, and so on).
        ("StringBasedCmds", "Maximum", SECONDS_IN_HOUR),
        # StreamBasedCmds	The total number of commands that are stream-based. This is derived from the Redis commandstats statistic by summing all of the commands that act upon one or more streams data types (xrange, xlen, xadd, xdel, and so on).
        ("StreamBasedCmds", "Maximum", SECONDS_IN_HOUR),
    ]
    return metrics


def get_max_metrics_weekly():
    metrics = [
        ("CurrItems", "Maximum", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        (
            "BytesUsedForCache",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        ("CacheHits", "Maximum", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ("CacheHitRate", "Maximum", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ("CacheMisses", "Maximum", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ("CurrConnections", "Maximum", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ("NetworkBytesIn", "Maximum", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ("NetworkBytesOut", "Maximum", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ("NetworkPacketsIn", "Maximum", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        (
            "NetworkPacketsOut",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "EngineCPUUtilization",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        ("Evictions", "Maximum", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ("ReplicationBytes", "Maximum", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ("ReplicationLag", "Maximum", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ("FreeableMemory", "Maximum", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ("SwapUsage", "Maximum", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        (
            "DatabaseMemoryUsagePercentage",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "NetworkBandwidthInAllowanceExceeded",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "NetworkBandwidthOutAllowanceExceeded",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "NetworkPacketsPerSecondAllowanceExceeded",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "AuthenticationFailures",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "ChannelAuthorizationFailures",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "CommandAuthorizationFailures",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "KeyAuthorizationFailures",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "TrafficManagementActive",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "ClusterBasedCmdsLatency",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "EvalBasedCmdsLatency",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "GetTypeCmdsLatency",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "KeyBasedCmdsLatency",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "ListBasedCmdsLatency",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "HashBasedCmdsLatency",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "PubSubBasedCmdsLatency",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "SetBasedCmdsLatency",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "SetTypeCmdsLatency",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "SortedSetBasedCmdsLatency",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "StringBasedCmdsLatency",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        (
            "StreamBasedCmdsLatency",
            "Maximum",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
    ]
    return metrics


def get_avg_metrics_weekly():
    """Get average metrics for the weekly collection period.
    These metrics complement the max metrics and provide better insight into typical workload.
    """
    metrics = [
        ("CurrItems", "Average", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        (
            "BytesUsedForCache",
            "Average",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
        ("CacheHits", "Average", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ("CacheHitRate", "Average", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ("CacheMisses", "Average", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ("CurrConnections", "Average", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ("NetworkBytesIn", "Average", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        ("NetworkBytesOut", "Average", SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS),
        (
            "EngineCPUUtilization",
            "Average",
            SECONDS_IN_DAY * METRIC_COLLECTION_PERIOD_DAYS,
        ),
    ]
    return metrics


def get_avg_metrics_hourly():
    """Get average metrics for hourly command-based metrics.
    These metrics complement the max hourly metrics and provide better insight into typical throughput.
    """
    metrics = [
        ("GetTypeCmds", "Average", SECONDS_IN_HOUR),
        ("SetTypeCmds", "Average", SECONDS_IN_HOUR),
        ("KeyBasedCmds", "Average", SECONDS_IN_HOUR),
        ("StringBasedCmds", "Average", SECONDS_IN_HOUR),
        ("HashBasedCmds", "Average", SECONDS_IN_HOUR),
        ("ListBasedCmds", "Average", SECONDS_IN_HOUR),
        ("SetBasedCmds", "Average", SECONDS_IN_HOUR),
        ("SortedSetBasedCmds", "Average", SECONDS_IN_HOUR),
    ]
    return metrics


def calc_expiry_time(expiry):
    """Calculate the number of days until the reserved instance expires.
    Args:
        expiry (DateTime): A timezone-aware DateTime object of the date when
            the reserved instance will expire.
    Returns:
        The number of days between the expiration date and now.
    """
    return (expiry.replace(tzinfo=None) - datetime.datetime.utcnow()).days


def get_clusters_info(session):
    """Calculate the running/reserved instances in ElastiCache.
    Args:
        session (:boto3:session.Session): The authenticated boto3 session.
    Returns:
        A dictionary of the running/reserved instances for ElastiCache nodes.
    """
    conn = session.client("elasticache")
    results = {
        "elc_running_instances": {},
        "elc_reserved_instances": {},
    }

    paginator = conn.get_paginator("describe_cache_clusters")
    page_iterator = paginator.paginate(ShowCacheNodeInfo=True)

    # Get all the present snapshots
    snapshots = {}
    try:
        snapshots = conn.describe_snapshots()
    except:
        pass

    snaps = {}

    # Loop through the snaps and add them to a dict
    if "Snapshots" in snapshots:
        for snapshot in snapshots["Snapshots"]:
            try:
                if (
                    snapshot["SnapshotRetentionLimit"] > 0
                    and snapshot["ReplicationGroupId"]
                ):
                    snaps[snapshot["ReplicationGroupId"]] = snapshot[
                        "SnapshotRetentionLimit"
                    ]
            except:
                pass

    # Loop through running ElastiCache instance and record their engine,
    # type, and name.
    for page in page_iterator:
        for instance in page["CacheClusters"]:
            if instance["CacheClusterStatus"] == "available" and (
                instance["Engine"] == "redis" or instance["Engine"] == "valkey"
            ):
                cluster_id = instance["CacheClusterId"]
                results["elc_running_instances"][cluster_id] = instance

    paginator = conn.get_paginator("describe_reserved_cache_nodes")
    page_iterator = paginator.paginate()

    # Loop through active ElastiCache RIs and record their type and engine.
    for page in page_iterator:
        for reserved_instance in page["ReservedCacheNodes"]:
            if reserved_instance["State"] == "active" and (
                reserved_instance["ProductDescription"] == "redis"
                or reserved_instance["ProductDescription"] == "valkey"
            ):
                instance_type = reserved_instance["CacheNodeType"]
                # No end datetime is returned, so calculate from 'StartTime'
                # (a `DateTime`) and 'Duration' in seconds (integer)
                expiry_time = reserved_instance["StartTime"] + datetime.timedelta(
                    seconds=reserved_instance["Duration"]
                )
                results["elc_reserved_instances"][instance_type] = {
                    "count": reserved_instance["CacheNodeCount"],
                    "expiry_time": calc_expiry_time(expiry=expiry_time),
                }

    # Add the snapshots set to the result dict
    results["snapshots"] = snaps

    return results


def get_metric(cloud_watch, cluster_id, node, metric, aggregation, period):
    """Write node related metrics to file
    Args:
        ClusterId, node and metric to write
    Returns:
    The metric value
    """
    today = datetime.date.today() + datetime.timedelta(days=1)
    then = today - datetime.timedelta(days=METRIC_COLLECTION_PERIOD_DAYS)
    response = cloud_watch.get_metric_statistics(
        Namespace="AWS/ElastiCache",
        MetricName=metric,
        Dimensions=[
            {"Name": "CacheClusterId", "Value": cluster_id},
            {"Name": "CacheNodeId", "Value": node},
        ],
        StartTime=then.isoformat(),
        EndTime=today.isoformat(),
        Period=period,
        Statistics=[aggregation],
    )

    raw_data = [rec[aggregation] for rec in response["Datapoints"]]
    return raw_data


def get_metric_curr(cloud_watch, cluster_id, node, metric):
    """Write node related metrics to file
    Args:
        ClusterId, node and metric to write
    Returns:
    The metric value
    """
    now = datetime.datetime.now()

    response = cloud_watch.get_metric_data(
        MetricDataQueries=[
            {
                "Id": "is_master_test",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/ElastiCache",
                        "MetricName": metric,
                        "Dimensions": [
                            {"Name": "CacheClusterId", "Value": cluster_id},
                            {"Name": "CacheNodeId", "Value": node},
                        ],
                    },
                    "Period": 60,
                    "Stat": "Maximum",
                    "Unit": "Count",
                },
                "Label": "string",
                "ReturnData": True,
            },
        ],
        StartTime=int(round(now.timestamp())) - SECONDS_IN_HOUR,
        EndTime=int(round(now.timestamp())),
        ScanBy="TimestampDescending",
        MaxDatapoints=1,
    )

    raw_data = [rec["Values"] for rec in response["MetricDataResults"]]
    try:
        return raw_data[0][0]
    except:
        return -1


def create_workbook(outDir, section, region_name):
    """Create an empty workbook dataframe with headers
    Args:
    Returns:
    The newely created pandas dataframe
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = RUNNING_INSTANCES_WORKSHEET_NAME

    df_columns = [
        "Source",
        "ClusterId",
        "NodeId",
        "NodeRole",
        "NodeType",
        "Region",
        "SnapshotRetentionLimit",
    ]

    # Add instance specifications
    df_columns.extend(["NodeMemoryGB", "NodeVCPUs", "NodeNetworkPerformance"])

    # Add existing max metrics
    for metric, _, _ in get_max_metrics_weekly():
        df_columns.append(metric)
    for metric, _, _ in get_max_metrics_hourly():
        df_columns.append(metric)

    # Add new average metrics with "Avg" prefix
    for metric, _, _ in get_avg_metrics_weekly():
        df_columns.append(f"Avg{metric}")
    for metric, _, _ in get_avg_metrics_hourly():
        df_columns.append(f"Avg{metric}")

    # Add calculated columns
    df_columns.extend(
        [
            "AvgKeySize",  # Average key size in bytes
            "MaxThroughputOpsPerSec",  # Max throughput (ops/sec)
            "AvgThroughputOpsPerSec",  # Average throughput (ops/sec)
        ]
    )

    df_columns.append("Engine")
    df_columns.append("QPF")
    ws.append(df_columns)

    ws = wb.create_sheet(RESERVED_INSTANCES_WORKSHEET_NAME)
    df_columns = ["Instance Type", "Count", "Remaining Time (days)"]
    ws.append(df_columns)
    return wb


def get_running_instances_metrics(wb, clusters_info, session):
    """
    Get all the metrics for the clusters in the given set of clusters
    Args:
        The cluster information dictionary
    Returns:
    """
    cloud_watch = session.client("cloudwatch")
    running_instances = clusters_info["elc_running_instances"]
    ws = wb[RUNNING_INSTANCES_WORKSHEET_NAME]
    row = []

    for instanceId, instanceDetails in running_instances.items():
        for node in instanceDetails.get("CacheNodes"):
            print("Fetching node %s details" % (instanceDetails["CacheClusterId"]))
            clusterId = instanceId
            if "ReplicationGroupId" in instanceDetails:
                clusterId = instanceDetails["ReplicationGroupId"]

            nodeRole = (
                "Master"
                if get_metric_curr(
                    cloud_watch, instanceId, node.get("CacheNodeId"), "IsMaster"
                )
                > 0
                else "Replica"
            )

            # If the name of cluster in the snapshots set set SnapshotRetentionLimit else 0
            snapshotRetentionLimit = (
                clusters_info["snapshots"][clusterId]
                if clusterId in clusters_info["snapshots"]
                else -1
            )

            row.append("EC")
            row.append("%s" % clusterId)
            row.append("%s" % instanceId)
            row.append("%s" % nodeRole)
            row.append("%s" % instanceDetails["CacheNodeType"])
            row.append("%s" % instanceDetails["PreferredAvailabilityZone"])
            row.append("%s" % snapshotRetentionLimit)

            # Add instance specifications
            node_type = instanceDetails["CacheNodeType"]
            memory_gb, vcpus, network_perf = get_instance_specs(node_type)
            row.append(memory_gb if memory_gb is not None else "Unknown")
            row.append(vcpus if vcpus is not None else "Unknown")
            row.append(network_perf if network_perf is not None else "Unknown")

            # Collect metrics and store for calculations
            max_weekly_metrics = {}
            avg_weekly_metrics = {}
            max_hourly_metrics = {}
            avg_hourly_metrics = {}

            # Get max weekly metrics
            for metric, aggregation, period in get_max_metrics_weekly():
                data_points = get_metric(
                    cloud_watch,
                    instanceId,
                    node.get("CacheNodeId"),
                    metric,
                    aggregation,
                    period,
                )
                data_point = 0 if len(data_points) == 0 else data_points[0]
                max_weekly_metrics[metric] = data_point
                row.append(data_point)

            # Get max hourly metrics
            for metric, aggregation, period in get_max_metrics_hourly():
                data_points = get_metric(
                    cloud_watch,
                    instanceId,
                    node.get("CacheNodeId"),
                    metric,
                    aggregation,
                    period,
                )
                data_point = 0 if len(data_points) == 0 else max(data_points)
                # Due to how cloudwatch is doing the data sampling we need to multiply the values by 60
                # in order to get the real hourly stats. Cloudwatch is sampling at minimum once every minute
                # so we need to multiply by 60 in order to simulate an hourly throughput. In order to get
                # actual operation per second we then need to divide by 3600.
                normalized_data_point = round(data_point / 60)
                max_hourly_metrics[metric] = normalized_data_point
                row.append(normalized_data_point)

            # Get average weekly metrics
            for metric, aggregation, period in get_avg_metrics_weekly():
                data_points = get_metric(
                    cloud_watch,
                    instanceId,
                    node.get("CacheNodeId"),
                    metric,
                    aggregation,
                    period,
                )
                data_point = 0 if len(data_points) == 0 else data_points[0]
                avg_weekly_metrics[metric] = data_point
                row.append(data_point)

            # Get average hourly metrics
            for metric, aggregation, period in get_avg_metrics_hourly():
                data_points = get_metric(
                    cloud_watch,
                    instanceId,
                    node.get("CacheNodeId"),
                    metric,
                    aggregation,
                    period,
                )
                data_point = 0 if len(data_points) == 0 else max(data_points)
                normalized_data_point = round(data_point / 60)
                avg_hourly_metrics[metric] = normalized_data_point
                row.append(normalized_data_point)

            # Calculate average key size (BytesUsedForCache / CurrItems)
            avg_bytes_used = avg_weekly_metrics.get("BytesUsedForCache", 0)
            avg_curr_items = avg_weekly_metrics.get("CurrItems", 0)
            avg_key_size = (
                round(avg_bytes_used / avg_curr_items) if avg_curr_items > 0 else 0
            )
            row.append(avg_key_size)

            # Calculate max throughput (ops/sec) - sum of all max command types
            max_throughput = sum(
                [
                    max_hourly_metrics.get("GetTypeCmds", 0),
                    max_hourly_metrics.get("SetTypeCmds", 0),
                    max_hourly_metrics.get("KeyBasedCmds", 0),
                    max_hourly_metrics.get("StringBasedCmds", 0),
                    max_hourly_metrics.get("HashBasedCmds", 0),
                    max_hourly_metrics.get("ListBasedCmds", 0),
                    max_hourly_metrics.get("SetBasedCmds", 0),
                    max_hourly_metrics.get("SortedSetBasedCmds", 0),
                    max_hourly_metrics.get("ClusterBasedCmds", 0),
                    max_hourly_metrics.get("EvalBasedCmds", 0),
                    max_hourly_metrics.get("GeoSpatialBasedCmds", 0),
                    max_hourly_metrics.get("HyperLogLogBasedCmds", 0),
                    max_hourly_metrics.get("PubSubBasedCmds", 0),
                    max_hourly_metrics.get("StreamBasedCmds", 0),
                ]
            )
            row.append(max_throughput)

            # Calculate average throughput (ops/sec) - sum of all avg command types
            avg_throughput = sum(
                [
                    avg_hourly_metrics.get("GetTypeCmds", 0),
                    avg_hourly_metrics.get("SetTypeCmds", 0),
                    avg_hourly_metrics.get("KeyBasedCmds", 0),
                    avg_hourly_metrics.get("StringBasedCmds", 0),
                    avg_hourly_metrics.get("HashBasedCmds", 0),
                    avg_hourly_metrics.get("ListBasedCmds", 0),
                    avg_hourly_metrics.get("SetBasedCmds", 0),
                    avg_hourly_metrics.get("SortedSetBasedCmds", 0),
                ]
            )
            row.append(avg_throughput)

            row.append("%s" % instanceDetails["Engine"])
            row.append("")  # Empty qpf column
            ws.append(row)
            row = []
    return wb


def get_reserved_instances_info(wb, clusters_info):
    reserved_instances = clusters_info["elc_reserved_instances"]
    ws = wb[RESERVED_INSTANCES_WORKSHEET_NAME]
    for instanceId, instanceDetails in reserved_instances.items():
        ws.append(
            [
                ("%s" % instanceId),
                ("%s" % instanceDetails["count"]),
                ("%s," % instanceDetails["expiry_time"]),
            ]
        )
    return wb


def process_aws_account(config, section, outDir):
    # Check if credentials are provided in the config file
    if config.has_option(section, "aws_access_key_id") and config.has_option(
        section, "aws_secret_access_key"
    ):
        aws_access_key_id = config.get(section, "aws_access_key_id")
        aws_secret_access_key = config.get(section, "aws_secret_access_key")
        region_name = config.get(section, "region_name")

        if config.has_option(section, "aws_session_token"):
            aws_session_token = config.get(section, "aws_session_token")
        else:
            aws_session_token = None

        # Create session with credentials
        session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            region_name=region_name,
        )
    else:
        # No credentials in config file, rely on instance profile credentials
        region_name = config.get(section, "region_name")
        session = boto3.Session(region_name=region_name)

    print(f"Requesting information for the {section} nodes")
    clusters_info = get_clusters_info(session)

    wb = create_workbook(outDir, section, region_name)
    wb = get_running_instances_metrics(wb, clusters_info, session)
    wb = get_reserved_instances_info(wb, clusters_info)

    output_file_path = "%s/%s-%s.xlsx" % (outDir, section, region_name)
    print(f"Writing output file {output_file_path}")
    wb.save(output_file_path)
    print("Done!")


def main():
    if not sys.version_info >= (3, 9):
        print("Please upgrade python to a version at least 3.9")
        exit(1)

    parser = optparse.OptionParser()
    parser.add_option(
        "-c",
        "--config",
        dest="configFile",
        default="config.ini",
        help="The filename for configuration file. By default the script will try to open the config.ini file.",
        metavar="FILE",
    )
    parser.add_option(
        "-d",
        "--out-dir",
        dest="outDir",
        default=".",
        help="The directory to output the results. If not the directory does not exist the script will try to create it.",
        metavar="PATH",
    )

    (options, _) = parser.parse_args()

    if not os.path.isdir(options.outDir):
        os.makedirs(options.outDir)

    if not os.path.isfile(options.configFile):
        print(f"Can't find the specified {options.configFile} configuration file")
        sys.exit(1)

    # Open and parse the configuration file.
    config = configparser.ConfigParser()
    config.read(options.configFile)

    # For each section defined in the config.ini file, the script
    # will try to fetch the ElastiCache utilization by parsing the
    # Cloudwatch statistics
    for section in config.sections():
        process_aws_account(config, section, options.outDir)


if __name__ == "__main__":
    main()
