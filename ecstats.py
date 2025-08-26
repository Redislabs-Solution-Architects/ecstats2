
import os
import sys
import datetime
import configparser
import optparse
import boto3
import openpyxl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Metric Collection Period (in days)
METRIC_COLLECTION_PERIOD_DAYS = int(
    os.environ.get("METRIC_COLLECTION_PERIOD_DAYS") or 7
)

SECONDS_IN_MINUTE = 60
SECONDS_IN_HOUR = 60 * SECONDS_IN_MINUTE
SECONDS_IN_DAY = 24 * SECONDS_IN_HOUR

RUNNING_INSTANCES_WORKSHEET_NAME = "ClusterData"
RESERVED_INSTANCES_WORKSHEET_NAME = "ReservedData"

# Default threading configuration
DEFAULT_MAX_ACCOUNT_THREADS = 1
DEFAULT_MAX_CLUSTER_THREADS = 10

# Thread-safe locks (only used in threading mode)
excel_lock = threading.Lock()
print_lock = threading.Lock()


def thread_safe_print(message, use_threading=False):
    """Thread-safe print function - only locks when threading is enabled"""
    if use_threading:
        with print_lock:
            print(f"[{threading.current_thread().name}] {message}")
    else:
        print(message)


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
    for metric, _, _ in get_max_metrics_weekly():
        df_columns.append(metric)
    for metric, _, _ in get_max_metrics_hourly():
        df_columns.append(metric)
    df_columns.append("Engine")
    df_columns.append("QPF")
    ws.append(df_columns)

    ws = wb.create_sheet(RESERVED_INSTANCES_WORKSHEET_NAME)
    df_columns = ["Instance Type", "Count", "Remaining Time (days)"]
    ws.append(df_columns)
    return wb


def process_single_node(args):
    """Process metrics for a single node - used by thread pool"""
    (
        cloud_watch,
        instance_id,
        instance_details,
        node,
        clusters_info,
        use_threading,
    ) = args
    
    try:
        thread_safe_print(f"Processing node {instance_id}:{node.get('CacheNodeId')}", use_threading)
        
        cluster_id = instance_id
        if "ReplicationGroupId" in instance_details:
            cluster_id = instance_details["ReplicationGroupId"]

        node_role = (
            "Master"
            if get_metric_curr(
                cloud_watch, instance_id, node.get("CacheNodeId"), "IsMaster"
            )
            > 0
            else "Replica"
        )

        # If the name of cluster in the snapshots set set SnapshotRetentionLimit else 0
        snapshot_retention_limit = (
            clusters_info["snapshots"][cluster_id]
            if cluster_id in clusters_info["snapshots"]
            else -1
        )

        row = []
        row.append("EC")
        row.append("%s" % cluster_id)
        row.append("%s" % instance_id)
        row.append("%s" % node_role)
        row.append("%s" % instance_details["CacheNodeType"])
        row.append("%s" % instance_details["PreferredAvailabilityZone"])
        row.append("%s" % snapshot_retention_limit)

        # Process weekly metrics
        for metric, aggregation, period in get_max_metrics_weekly():
            data_points = get_metric(
                cloud_watch,
                instance_id,
                node.get("CacheNodeId"),
                metric,
                aggregation,
                period,
            )
            data_point = 0 if len(data_points) == 0 else data_points[0]
            row.append(data_point)
            
        # Process hourly metrics
        for metric, aggregation, period in get_max_metrics_hourly():
            data_points = get_metric(
                cloud_watch,
                instance_id,
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
            row.append(round(data_point / 60))
            
        row.append("%s" % instance_details["Engine"])
        row.append("")  # Empty qpf column
        
        thread_safe_print(f"Completed processing node {instance_id}:{node.get('CacheNodeId')}", use_threading)
        return row
        
    except Exception as e:
        thread_safe_print(f"Error processing node {instance_id}:{node.get('CacheNodeId')}: {str(e)}", use_threading)
        return None


def get_running_instances_metrics(wb, clusters_info, session, use_threading=False, max_cluster_threads=1):
    """
    Get all the metrics for the clusters in the given set of clusters
    Args:
        wb: workbook to write to
        clusters_info: cluster information dictionary
        session: boto3 session
        use_threading: whether to use multithreading
        max_cluster_threads: max threads for cluster processing
    Returns:
        Updated workbook
    """
    cloud_watch = session.client("cloudwatch")
    running_instances = clusters_info["elc_running_instances"]
    ws = wb[RUNNING_INSTANCES_WORKSHEET_NAME]

    if use_threading and max_cluster_threads > 1:
        # Multithreaded processing
        tasks = []
        for instance_id, instance_details in running_instances.items():
            for node in instance_details.get("CacheNodes"):
                task_args = (
                    cloud_watch,
                    instance_id,
                    instance_details,
                    node,
                    clusters_info,
                    use_threading,
                )
                tasks.append(task_args)

        thread_safe_print(f"Processing {len(tasks)} nodes using {max_cluster_threads} threads", use_threading)
        
        with ThreadPoolExecutor(max_workers=max_cluster_threads) as executor:
            future_to_task = {executor.submit(process_single_node, task): task for task in tasks}
            
            completed_count = 0
            for future in as_completed(future_to_task):
                try:
                    result = future.result()
                    if result is not None:
                        with excel_lock:
                            ws.append(result)
                    completed_count += 1
                    thread_safe_print(f"Completed {completed_count}/{len(tasks)} nodes", use_threading)
                    
                except Exception as e:
                    thread_safe_print(f"Task failed: {str(e)}", use_threading)
    else:
        # Single-threaded processing (original behavior)
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

                row = []
                row.append("EC")
                row.append("%s" % clusterId)
                row.append("%s" % instanceId)
                row.append("%s" % nodeRole)
                row.append("%s" % instanceDetails["CacheNodeType"])
                row.append("%s" % instanceDetails["PreferredAvailabilityZone"])
                row.append("%s" % snapshotRetentionLimit)

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
                    row.append(round(data_point / 60))
                row.append("%s" % instanceDetails["Engine"])
                row.append("")  # Empty qpf column
                ws.append(row)

    return wb


def get_reserved_instances_info(wb, clusters_info, use_threading=False):
    """Get reserved instances info"""
    reserved_instances = clusters_info["elc_reserved_instances"]
    ws = wb[RESERVED_INSTANCES_WORKSHEET_NAME]
    for instanceId, instanceDetails in reserved_instances.items():
        row = [
            ("%s" % instanceId),
            ("%s" % instanceDetails["count"]),
            ("%s," % instanceDetails["expiry_time"]),
        ]
        if use_threading:
            with excel_lock:
                ws.append(row)
        else:
            ws.append(row)
    return wb


def process_aws_account(config, section, outDir, use_threading=False, max_cluster_threads=1):
    """Process a single AWS account"""
    try:
        if use_threading:
            thread_safe_print(f"Starting processing for account: {section}", use_threading)
        else:
            print(f"Requesting information for the {section} nodes")
        
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

        clusters_info = get_clusters_info(session)

        wb = create_workbook(outDir, section, region_name)
        wb = get_running_instances_metrics(wb, clusters_info, session, use_threading, max_cluster_threads)
        wb = get_reserved_instances_info(wb, clusters_info, use_threading)

        output_file_path = "%s/%s-%s.xlsx" % (outDir, section, region_name)
        
        if use_threading:
            thread_safe_print(f"Writing output file {output_file_path}", use_threading)
            with excel_lock:
                wb.save(output_file_path)
            thread_safe_print(f"Completed processing for account: {section}", use_threading)
            return f"Successfully processed {section}"
        else:
            print(f"Writing output file {output_file_path}")
            wb.save(output_file_path)
            print("Done!")
            
    except Exception as e:
        error_msg = f"Error processing account {section}: {str(e)}"
        thread_safe_print(error_msg, use_threading)
        return error_msg


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
    parser.add_option(
        "--enable-threading",
        dest="enableThreading",
        action="store_true",
        default=False,
        help="Enable multithreaded processing for improved performance. Default: False (single-threaded)",
    )
    parser.add_option(
        "--max-account-threads",
        dest="maxAccountThreads",
        type="int",
        default=DEFAULT_MAX_ACCOUNT_THREADS,
        help=f"Maximum number of threads for processing AWS accounts in parallel. Default: {DEFAULT_MAX_ACCOUNT_THREADS}. Only used when --enable-threading is specified.",
    )
    parser.add_option(
        "--max-cluster-threads",
        dest="maxClusterThreads",
        type="int",
        default=DEFAULT_MAX_CLUSTER_THREADS,
        help=f"Maximum number of threads for processing clusters/nodes in parallel. Default: {DEFAULT_MAX_CLUSTER_THREADS}. Only used when --enable-threading is specified.",
    )

    (options, _) = parser.parse_args()

    if options.enableThreading:
        print(f"Multithreaded mode enabled with configuration:")
        print(f"  - Max account threads: {options.maxAccountThreads}")
        print(f"  - Max cluster threads: {options.maxClusterThreads}")
    else:
        print("Running in single-threaded mode (original behavior)")

    if not os.path.isdir(options.outDir):
        os.makedirs(options.outDir)

    if not os.path.isfile(options.configFile):
        print(f"Can't find the specified {options.configFile} configuration file")
        sys.exit(1)

    # Open and parse the configuration file.
    config = configparser.ConfigParser()
    config.read(options.configFile)

    if options.enableThreading and options.maxAccountThreads > 1:
        # Process AWS accounts in parallel
        account_tasks = []
        for section in config.sections():
            account_tasks.append((config, section, options.outDir, options.enableThreading, options.maxClusterThreads))

        print(f"Processing {len(account_tasks)} AWS accounts using {options.maxAccountThreads} threads")
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=options.maxAccountThreads) as executor:
            future_to_account = {
                executor.submit(process_aws_account, *task): task[1] for task in account_tasks
            }
            
            completed_accounts = 0
            for future in as_completed(future_to_account):
                account = future_to_account[future]
                try:
                    result = future.result()
                    print(f"[{completed_accounts + 1}/{len(account_tasks)}] {result}")
                except Exception as e:
                    print(f"Account {account} generated an exception: {e}")
                completed_accounts += 1

        end_time = time.time()
        execution_time = end_time - start_time
        print(f"\nAll processing completed in {execution_time:.2f} seconds")
    else:
        # Process AWS accounts sequentially (original behavior or single account threading)
        start_time = time.time() if options.enableThreading else None
        
        for section in config.sections():
            process_aws_account(config, section, options.outDir, options.enableThreading, options.maxClusterThreads)
        
        if options.enableThreading:
            end_time = time.time()
            execution_time = end_time - start_time
            print(f"\nAll processing completed in {execution_time:.2f} seconds")


if __name__ == "__main__":
    main()
