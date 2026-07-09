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
UPGRADE_READINESS_WORKSHEET_NAME = "UpgradeReadiness"

TARGET_REDIS_MAJOR_VERSION = int(os.environ.get("TARGET_REDIS_MAJOR_VERSION") or 8)

HIGH_CPU_THRESHOLD_PERCENT = int(os.environ.get("HIGH_CPU_THRESHOLD_PERCENT") or 90)
WARN_CPU_THRESHOLD_PERCENT = int(os.environ.get("WARN_CPU_THRESHOLD_PERCENT") or 70)
HIGH_MEMORY_THRESHOLD_PERCENT = int(
    os.environ.get("HIGH_MEMORY_THRESHOLD_PERCENT") or 90
)
WARN_MEMORY_THRESHOLD_PERCENT = int(
    os.environ.get("WARN_MEMORY_THRESHOLD_PERCENT") or 75
)

DEPRECATED_COMMAND_GROUPS = {
    "ClusterBasedCmds": [
        "CLUSTER SLAVES -> CLUSTER REPLICAS",
        "CLUSTER SLOTS -> CLUSTER SHARDS",
    ],
    "GeoSpatialBasedCmds": [
        "GEORADIUS -> GEOSEARCH/GEOSEARCHSTORE BYRADIUS",
        "GEORADIUS_RO -> GEOSEARCH BYRADIUS",
        "GEORADIUSBYMEMBER -> GEOSEARCH/GEOSEARCHSTORE FROMMEMBER BYRADIUS",
        "GEORADIUSBYMEMBER_RO -> GEOSEARCH FROMMEMBER BYRADIUS",
    ],
    "HashBasedCmds": ["HMSET -> HSET with multiple field-value pairs"],
    "ListBasedCmds": ["BRPOPLPUSH -> BLMOVE RIGHT LEFT"],
    "StringBasedCmds": [
        "GETSET -> SET GET",
        "SETEX -> SET EX",
        "SETNX -> SET NX",
        "SUBSTR -> GETRANGE",
    ],
    "SortedSetBasedCmds": [
        "ZRANGEBYLEX -> ZRANGE BYLEX",
        "ZRANGEBYSCORE -> ZRANGE BYSCORE",
        "ZREVRANGE -> ZRANGE REV",
        "ZREVRANGEBYLEX -> ZRANGE REV BYLEX",
        "ZREVRANGEBYSCORE -> ZRANGE REV BYSCORE",
    ],
}

AUTHORIZATION_FAILURE_METRICS = [
    "AuthenticationFailures",
    "ChannelAuthorizationFailures",
    "CommandAuthorizationFailures",
    "KeyAuthorizationFailures",
]

ALLOWANCE_EXCEEDED_METRICS = [
    "NetworkBandwidthInAllowanceExceeded",
    "NetworkBandwidthOutAllowanceExceeded",
    "NetworkPacketsPerSecondAllowanceExceeded",
]

SERVERLESS_SUPPORTED_METRICS = {
    "BytesUsedForCache",
    "CacheHits",
    "CacheHitRate",
    "CacheMisses",
    "ChannelAuthorizationFailures",
    "CommandAuthorizationFailures",
    "CurrItems",
    "Evictions",
    "KeyAuthorizationFailures",
}


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


def calc_expiry_time(expiry):
    """Calculate the number of days until the reserved instance expires.
    Args:
        expiry (DateTime): A timezone-aware DateTime object of the date when
            the reserved instance will expire.
    Returns:
        The number of days between the expiration date and now.
    """
    return (expiry.replace(tzinfo=None) - datetime.datetime.utcnow()).days


def parse_major_version(version):
    if version is None:
        return None

    version_string = str(version).strip()
    if not version_string:
        return None

    digits = []
    for char in version_string:
        if char.isdigit():
            digits.append(char)
        elif digits:
            break
        else:
            return None

    if not digits:
        return None
    return int("".join(digits))


def get_region_from_arn(arn):
    if not arn:
        return ""
    parts = arn.split(":")
    if len(parts) > 3:
        return parts[3]
    return ""


def append_upgrade_readiness_issue(
    worksheet,
    cluster_id,
    node_id,
    node_role,
    instance_details,
    severity,
    category,
    signal,
    observed_value,
    recommendation,
    source="EC",
):
    worksheet.append(
        [
            source,
            cluster_id,
            node_id,
            node_role,
            instance_details["Engine"],
            instance_details.get("EngineVersion", ""),
            severity,
            category,
            signal,
            observed_value,
            recommendation,
        ]
    )


def append_upgrade_readiness_issues(
    worksheet,
    cluster_id,
    node_id,
    node_role,
    instance_details,
    snapshot_retention_limit,
    metric_values,
    source="EC",
):
    engine = instance_details["Engine"]
    engine_version = instance_details.get("EngineVersion", "")
    major_version = parse_major_version(engine_version)
    issue_count = 0

    def add_issue(severity, category, signal, observed_value, recommendation):
        nonlocal issue_count
        append_upgrade_readiness_issue(
            worksheet,
            cluster_id,
            node_id,
            node_role,
            instance_details,
            severity,
            category,
            signal,
            observed_value,
            recommendation,
            source=source,
        )
        issue_count += 1

    if engine == "redis":
        if major_version is None:
            add_issue(
                "High",
                "EngineVersion",
                "EngineVersion",
                engine_version,
                "Confirm the current engine version before planning a Redis major-version upgrade.",
            )
        elif major_version < TARGET_REDIS_MAJOR_VERSION:
            add_issue(
                "High",
                "EngineVersion",
                "EngineVersion",
                engine_version,
                "Plan and test an engine upgrade path to Redis major version %s or later."
                % TARGET_REDIS_MAJOR_VERSION,
            )
    elif engine == "valkey":
        add_issue(
            "Info",
            "EngineFamily",
            "Engine",
            engine,
            "This node is Valkey; validate client and command compatibility against the Redis target separately.",
        )

    if snapshot_retention_limit <= 0:
        add_issue(
            "Medium",
            "Recovery",
            "SnapshotRetentionLimit",
            snapshot_retention_limit,
            "Enable automatic snapshots or confirm an alternate rollback plan before upgrading.",
        )

    for metric in AUTHORIZATION_FAILURE_METRICS:
        value = metric_values.get(metric, 0)
        if value > 0:
            add_issue(
                "High",
                "Security",
                metric,
                value,
                "Resolve ACL/auth failures before upgrading so client breakage is not confused with engine changes.",
            )

    for metric, deprecated_commands in DEPRECATED_COMMAND_GROUPS.items():
        value = metric_values.get(metric, 0)
        if value > 0:
            add_issue(
                "Medium",
                "PotentialDeprecatedCommands",
                metric,
                value,
                "CloudWatch saw traffic in a command family that includes deprecated Redis commands; review exact usage for: %s."
                % "; ".join(deprecated_commands),
            )

    engine_cpu = metric_values.get("EngineCPUUtilization", 0)
    if engine_cpu >= HIGH_CPU_THRESHOLD_PERCENT:
        add_issue(
            "High",
            "Capacity",
            "EngineCPUUtilization",
            engine_cpu,
            "Reduce CPU pressure or scale before upgrading; high CPU can make upgrade validation noisy.",
        )
    elif engine_cpu >= WARN_CPU_THRESHOLD_PERCENT:
        add_issue(
            "Medium",
            "Capacity",
            "EngineCPUUtilization",
            engine_cpu,
            "Review CPU headroom before upgrade testing.",
        )

    memory_usage = metric_values.get("DatabaseMemoryUsagePercentage", 0)
    if memory_usage >= HIGH_MEMORY_THRESHOLD_PERCENT:
        add_issue(
            "High",
            "Capacity",
            "DatabaseMemoryUsagePercentage",
            memory_usage,
            "Lower memory pressure or scale before upgrading.",
        )
    elif memory_usage >= WARN_MEMORY_THRESHOLD_PERCENT:
        add_issue(
            "Medium",
            "Capacity",
            "DatabaseMemoryUsagePercentage",
            memory_usage,
            "Review memory headroom before upgrade testing.",
        )

    for metric in ALLOWANCE_EXCEEDED_METRICS:
        value = metric_values.get(metric, 0)
        if value > 0:
            add_issue(
                "Medium",
                "Capacity",
                metric,
                value,
                "Investigate node/network limits before upgrading.",
            )

    if metric_values.get("TrafficManagementActive", 0) > 0:
        add_issue(
            "High",
            "Capacity",
            "TrafficManagementActive",
            metric_values.get("TrafficManagementActive", 0),
            "Resolve active traffic management before upgrading.",
        )

    if metric_values.get("Evictions", 0) > 0:
        add_issue(
            "Medium",
            "DataRisk",
            "Evictions",
            metric_values.get("Evictions", 0),
            "Review eviction pressure and maxmemory policy before upgrading.",
        )

    if metric_values.get("SwapUsage", 0) > 0:
        add_issue(
            "Medium",
            "Capacity",
            "SwapUsage",
            metric_values.get("SwapUsage", 0),
            "Reduce swap usage before upgrading.",
        )

    if issue_count == 0:
        add_issue(
            "Info",
            "UpgradeReadiness",
            "NoRoadblocksDetected",
            "",
            "No upgrade roadblocks were detected from the collected ElastiCache and CloudWatch signals.",
        )

    return worksheet


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
        "elc_serverless_caches": {},
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

    next_token = None
    while True:
        try:
            request = {"NextToken": next_token} if next_token else {}
            serverless_caches = conn.describe_serverless_caches(**request)
        except:
            break

        if not isinstance(serverless_caches, dict):
            break

        for serverless_cache in serverless_caches.get("ServerlessCaches", []):
            if serverless_cache["Status"] == "available" and (
                serverless_cache["Engine"] == "redis"
                or serverless_cache["Engine"] == "valkey"
            ):
                cache_name = serverless_cache["ServerlessCacheName"]
                results["elc_serverless_caches"][cache_name] = serverless_cache

        next_token = serverless_caches.get("NextToken")
        if not next_token:
            break

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


def get_serverless_metric(cloud_watch, cluster_id, metric, aggregation, period):
    today = datetime.date.today() + datetime.timedelta(days=1)
    then = today - datetime.timedelta(days=METRIC_COLLECTION_PERIOD_DAYS)
    response = cloud_watch.get_metric_statistics(
        Namespace="AWS/ElastiCache",
        MetricName=metric,
        Dimensions=[
            {"Name": "clusterId", "Value": cluster_id},
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
    for metric, _, _ in get_max_metrics_weekly():
        df_columns.append(metric)
    for metric, _, _ in get_max_metrics_hourly():
        df_columns.append(metric)
    df_columns.append("Engine")
    df_columns.append("EngineVersion")
    df_columns.append("QPF")
    ws.append(df_columns)

    ws = wb.create_sheet(RESERVED_INSTANCES_WORKSHEET_NAME)
    df_columns = ["Instance Type", "Count", "Remaining Time (days)"]
    ws.append(df_columns)

    ws = wb.create_sheet(UPGRADE_READINESS_WORKSHEET_NAME)
    df_columns = [
        "Source",
        "ClusterId",
        "NodeId",
        "NodeRole",
        "Engine",
        "EngineVersion",
        "Severity",
        "Category",
        "Signal",
        "ObservedValue",
        "Recommendation",
    ]
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
    serverless_caches = clusters_info.get("elc_serverless_caches", {})
    ws = wb[RUNNING_INSTANCES_WORKSHEET_NAME]
    upgrade_ws = wb[UPGRADE_READINESS_WORKSHEET_NAME]
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

            metric_values = {}
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
                metric_values[metric] = data_point
                row.append(data_point)
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
                hourly_value = round(data_point / 60)
                metric_values[metric] = hourly_value
                row.append(hourly_value)
            row.append("%s" % instanceDetails["Engine"])
            row.append("%s" % instanceDetails.get("EngineVersion", ""))
            row.append("")  # Empty qpf column
            ws.append(row)
            append_upgrade_readiness_issues(
                upgrade_ws,
                clusterId,
                instanceId,
                nodeRole,
                instanceDetails,
                snapshotRetentionLimit,
                metric_values,
            )
            row = []

    for cacheId, cacheDetails in serverless_caches.items():
        print("Fetching serverless cache %s details" % cacheId)
        snapshotRetentionLimit = cacheDetails.get("SnapshotRetentionLimit", -1)
        region = get_region_from_arn(cacheDetails.get("ARN", ""))

        row.append("EC-Serverless")
        row.append("%s" % cacheId)
        row.append("")
        row.append("Serverless")
        row.append("serverless")
        row.append("%s" % region)
        row.append("%s" % snapshotRetentionLimit)

        metric_values = {}
        for metric, aggregation, period in get_max_metrics_weekly():
            if metric not in SERVERLESS_SUPPORTED_METRICS:
                row.append("")
                continue

            data_points = get_serverless_metric(
                cloud_watch,
                cacheId,
                metric,
                aggregation,
                period,
            )
            data_point = 0 if len(data_points) == 0 else data_points[0]
            metric_values[metric] = data_point
            row.append(data_point)

        for metric, _, _ in get_max_metrics_hourly():
            row.append("")

        row.append("%s" % cacheDetails["Engine"])
        row.append(
            "%s"
            % cacheDetails.get(
                "FullEngineVersion", cacheDetails.get("MajorEngineVersion", "")
            )
        )
        row.append("")
        ws.append(row)
        append_upgrade_readiness_issues(
            upgrade_ws,
            cacheId,
            "",
            "Serverless",
            {
                "Engine": cacheDetails["Engine"],
                "EngineVersion": cacheDetails.get(
                    "FullEngineVersion", cacheDetails.get("MajorEngineVersion", "")
                ),
            },
            snapshotRetentionLimit,
            metric_values,
            source="EC-Serverless",
        )
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
    region_name = config.get(section, "region_name")
    session_kwargs = {"region_name": region_name}

    # Prefer explicit credentials from config.ini when present.
    if config.has_option(section, "aws_access_key_id") and config.has_option(
        section, "aws_secret_access_key"
    ):
        session_kwargs["aws_access_key_id"] = config.get(section, "aws_access_key_id")
        session_kwargs["aws_secret_access_key"] = config.get(
            section, "aws_secret_access_key"
        )
        if config.has_option(section, "aws_session_token"):
            session_kwargs["aws_session_token"] = config.get(
                section, "aws_session_token"
            )
    elif config.has_option(section, "profile_name"):
        session_kwargs["profile_name"] = config.get(section, "profile_name")

    session = boto3.Session(**session_kwargs)

    sts = session.client("sts")
    identity = sts.get_caller_identity()
    print(f"Using AWS identity: {identity['Arn']}")

    print(f"Requesting information for the {section} nodes")
    clusters_info = get_clusters_info(session)

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

    options, _ = parser.parse_args()

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
